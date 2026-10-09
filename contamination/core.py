"""The policy engine behind the hooks.

Clean session: every hook returns at once (one dict lookup), nothing is asked, nothing is added.
Contaminated session: pure reads pass unless they reach a URL never seen; everything else stops.
A stop gets facts (by program), an explanation (by the explainer, bounded in time), then either a
block (flagrant cases), a native Hermes approval carrying the explanation, or — when Hermes would
not ask a human (``/yolo``, ``approvals.mode: off``, cron, ``-q``…) — a block that the user can
lift once with ``/contamination ok <ref>``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets as _secrets
import threading
import time
from collections import OrderedDict
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import hermes_compat as compat
from .classify import EFFECT, INTERNAL, READ, Settings, classify_call, source_of, strings_in
from .explainer import ExplainerConfig, build_user_prompt, explain
from .facts import ExplainerTarget, SecretBook, extract, max_risk, _SENSITIVE_PATH
from .render import (RISK_LABEL, action_summary, approval_message, auto_block_message, clean,
                     fallback_block_message, hhmm, source_line)
from .state import SessionState, Stop, Store, hermes_db_parent
from .urls import extract_domains, extract_urls, origin_url

logger = logging.getLogger(__name__)

RULE_PREFIX = "contamination:"
DEFAULT_MANUAL_TTL_MIN = 30.0
_SYNTHETIC_PREFIXES = ("[SYSTEM", "[System", "[CONTEXT COMPACTION", "[CONTEXT SUMMARY]", "[Runtime note:",
                       "[IMPORTANT:", "[PRIOR CONTEXT", "<task-notification>", "<system-reminder>")
_RELAYED_RESULT = re.compile(r"(?i)sub-?agent|delegat|kanban|webhook|a2a")
_CHOICES = {
    "once": "acceptée", "session": "acceptée (pour la session)", "always": "acceptée (toujours)",
    "deny": "refusée", "timeout": "sans réponse (refusée)", "cancelled": "annulée",
    "notify_failed": "non transmise (refusée)",
}

HELP = """/contamination — protection contre l'injection de prompt
• /contamination : état de la session et actions bloquées en attente
• /contamination ok <réf> : autorise UNE fois l'appel identique bloqué (puis dis à Hermes de réessayer)
• /contamination non <réf> : écarte une action bloquée
• /contamination voir <réf> : réaffiche l'explication d'un arrêt
Une session devient contaminée dès qu'elle lit du contenu externe ; /new repart d'une session propre."""


def _flatten(message: Any) -> str:
    if isinstance(message, str):
        return message
    if isinstance(message, list):
        parts = []
        for part in message:
            if isinstance(part, dict) and part.get("type") in ("text", "input_text") and isinstance(part.get("text"), str):
                parts.append(part["text"])
            elif isinstance(part, str):
                parts.append(part)
        return "\n".join(parts)
    return ""


def _is_synthetic(text: str) -> bool:
    return text.lstrip().startswith(_SYNTHETIC_PREFIXES)


def _first_real_user_message(history: Any) -> str:
    if not isinstance(history, list):
        return ""
    for msg in history:
        if isinstance(msg, dict) and msg.get("role") == "user":
            text = _flatten(msg.get("content"))
            if text.strip() and not _is_synthetic(text):
                return text
    return ""


def args_hash(tool: str, args: Any) -> str:
    canonical = json.dumps({"t": tool, "a": args}, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _result_text(result: Any, limit: int = 500_000) -> str:
    if isinstance(result, str):
        text = result[:limit]
        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            return text.replace("\\/", "/")
        return "\n".join(strings_in(parsed, limit=20_000))
    try:
        return "\n".join(strings_in(result, limit=20_000))[:limit]
    except Exception:
        return ""


class Engine:
    def __init__(self, *, store: Store, settings: Callable[[], Dict[str, Any]], secret_book: SecretBook,
                 explainer_config: Callable[[], ExplainerConfig] = ExplainerConfig.from_env, ctx: Any = None,
                 gate_status: Callable[[], Tuple[bool, str, bool]] = compat.gate_status,
                 hook_timeout: Callable[[], float] = compat.hook_timeout,
                 session_key: Callable[[], str] = compat.session_key,
                 current_session_id: Callable[[], str] = compat.current_session_id,
                 in_cron: Callable[[Any], bool] = compat.in_cron) -> None:
        self.store = store
        self._settings_source = settings
        self._settings_cache: Tuple[float, Dict[str, Any]] = (0.0, {})
        self.secrets = secret_book
        self._explainer_config = explainer_config
        self.ctx = ctx
        self._gate_status = gate_status
        self._hook_timeout = hook_timeout
        self._session_key = session_key
        self._current_session_id = current_session_id
        self._in_cron = in_cron
        self._rules: "OrderedDict[str, str]" = OrderedDict()  # rule_key -> session id (bounded)
        self._lock = threading.RLock()

    # --- settings
    def _raw_settings(self) -> Dict[str, Any]:
        ts, data = self._settings_cache
        if time.monotonic() - ts > 10.0:
            try:
                data = self._settings_source() or {}
            except Exception:
                data = {}
            self._settings_cache = (time.monotonic(), data)
        return data

    def settings(self) -> Settings:
        return Settings.from_mapping(self._raw_settings())

    def _fallback_mode(self) -> str:
        mode = str(self._raw_settings().get("fallback") or "auto").lower()
        return mode if mode in ("auto", "always", "never") else "auto"

    def _manual_ttl(self) -> float:
        try:
            return 60.0 * float(self._raw_settings().get("manual_ttl_minutes") or DEFAULT_MANUAL_TTL_MIN)
        except (TypeError, ValueError):
            return 60.0 * DEFAULT_MANUAL_TTL_MIN

    # --- hooks table
    def hooks(self) -> Dict[str, Callable[..., Any]]:
        return {
            "pre_llm_call": self.on_pre_llm_call,
            "pre_tool_call": self.on_pre_tool_call,
            "post_tool_call": self.on_post_tool_call,
            "post_approval_response": self.on_post_approval_response,
            "subagent_start": self.on_subagent_start,
            "on_session_reset": self.on_session_reset,
        }

    def _route_keys(self, sid: str) -> List[str]:
        """Keys that stay put while the session id rotates. The gateway key does; in the CLI the
        approval key *is* the session id, so the process (one conversation per CLI process) is added."""
        key = self._session_key()
        keys = [key] if key else []
        if not key or key == sid or key == "default" or key.startswith("process:"):
            keys.append(f"process:{os.getpid()}")
        return keys

    def _sid(self, kw: Dict[str, Any]) -> str:
        sid = str(kw.get("session_id") or "")
        if sid:
            return sid
        task = str(kw.get("task_id") or "")
        return (self.store.session_for_task(task) if task else "") or self._current_session_id() or ""

    # --- pre_llm_call: user messages, seen URLs, lineage
    def on_pre_llm_call(self, **kw: Any) -> None:
        sid = str(kw.get("session_id") or "")
        if not sid:
            return None
        keys = self._route_keys(sid)
        task = str(kw.get("task_id") or "")
        has_history = (not bool(kw.get("is_first_turn"))) if "is_first_turn" in kw else None
        state = self.store.resolve(sid, parent=str(kw.get("parent_session_id") or ""), has_history=has_history,
                                   session_key=keys, task_id=task)
        self.store.note_route(sid, keys, task)
        changed = False
        text = _flatten(kw.get("user_message"))
        if text.strip() and not _is_synthetic(text):
            if not state.initial_request and has_history:
                first = _first_real_user_message(kw.get("conversation_history"))
                if first and first.strip() != text.strip():
                    state.add_user_message(first)
            state.add_user_message(text)
            urls = extract_urls(text)
            urls += [u for d in extract_domains(text) for u in origin_url(d)]
            state.add_seen(urls)
            changed = True
        elif text.strip() and _RELAYED_RESULT.search(text[:400]):
            state.contaminate("notification", detail="résultat relayé (sous-agent, tâche, webhook)")
            changed = True
        platform = str(kw.get("platform") or "")
        if platform:
            state.platform = platform
            if platform in self.settings().untrusted_platforms:
                state.contaminate(f"message {platform}", detail="message entrant non fiable")
                changed = True
        if changed and state.contaminated:
            self.store.save(state)
        return None

    # --- pre_tool_call: the gate
    def on_pre_tool_call(self, **kw: Any) -> Optional[Dict[str, str]]:
        started = time.monotonic()
        tool = str(kw.get("tool_name") or "")
        args = kw.get("args") if isinstance(kw.get("args"), dict) else {}
        sid = self._sid(kw)
        if not sid or not tool:
            return None
        keys = self._route_keys(sid)
        task = str(kw.get("task_id") or "")
        state = self.store.resolve(sid, session_key=keys, task_id=task)
        self.store.note_route(sid, keys, task)
        if not state.contaminated:
            return None
        try:
            return self._gate(state, tool, args, kw, started)
        except Exception:
            # Never let an internal error turn into "allowed": ask a human with the bare facts we
            # can still produce, or block when no human can be asked. (If even this fails, the
            # exception reaches Hermes, which blocks the tool.)
            logger.exception("contamination: internal error while gating %s", tool)
            message = (source_line(state.sources, state.source_count) + "\nCe que Hermes veut faire : "
                       + action_summary(tool, args) + "\nAvis : erreur interne du plugin, décide toi-même.")
            human, why, _manual = self._gate_status()
            if human and not self._in_cron(self.ctx) and self._fallback_mode() != "always":
                return {"action": "approve", "message": message,
                        "rule_key": f"{RULE_PREFIX}err:{args_hash(tool, args)}:{_new_id()}"}
            return {"action": "block", "message": auto_block_message("le plugin a rencontré une erreur interne",
                                                                     action_summary(tool, args))}

    def _gate(self, state: SessionState, tool: str, args: Dict[str, Any], kw: Dict[str, Any],
              started: float) -> Optional[Dict[str, str]]:
        settings = self.settings()
        call = classify_call(tool, args, settings)
        if call.kind in (READ, INTERNAL):
            unseen = [u for u in call.urls if not state.is_seen(u)]
            leaked = self.secrets.find(strings_in(args)) if call.kind == READ else []
            if not unseen and not leaked:
                return None
        digest = args_hash(tool, args)
        rule_key = f"{RULE_PREFIX}{hashlib.sha256(state.session_id.encode()).hexdigest()[:8]}:{digest}"

        manual = self._consume_manual(state, tool, digest)
        if manual is not None:
            return None
        if rule_key in state.approved_rules:
            state.add_stop(Stop(id=_new_id(), ts=time.time(), tool=tool, summary=action_summary(tool, args),
                                risk="", decision="acceptée (déjà autorisée pour la session)", path="native",
                                rule_key=rule_key, args_hash=digest))
            self.store.save(state)
            return None

        cfg = self._explainer_config()
        facts = extract(tool, args, seen=state.is_seen, secrets=self.secrets, explainer=ExplainerTarget(cfg.url),
                        call_kind=call.kind)
        stop = Stop(id=_new_id(), ts=time.time(), tool=tool, summary=action_summary(tool, args),
                    risk=facts.risk_floor(), rule_key=rule_key, args_hash=digest,
                    tool_call_id=str(kw.get("tool_call_id") or ""))

        if facts.explainer_contact:
            return self._auto_block(state, stop, "l'action tente de joindre l'endpoint de l'explicateur")
        if facts.has_secrets and facts.network:
            what = ", ".join((facts.secret_values + facts.secrets)[:2])
            return self._auto_block(state, stop, f"l'action combine des secrets ({clean(what, 80)}) et un accès réseau")

        timeout = self._hook_timeout()
        budget = (timeout - 4.0) if timeout > 0 else cfg.timeout + 2.0
        deadline = started + max(2.0, budget)
        prompt = build_user_prompt(
            initial_request=state.initial_request, user_messages=state.user_messages,
            registry=[{"tool": s.tool, "summary": s.summary, "decision": s.decision} for s in state.registry],
            sources=[_source_label(s) for s in state.sources], facts=facts.as_list_for_explainer(),
            floor=facts.risk_floor(), tool=tool, args=args, delegated_goal=state.delegated_goal)
        outcome = explain(cfg, prompt, deadline)
        verdict = outcome.verdict
        risk = max_risk(facts.risk_floor(), verdict.risque if verdict else "faible")
        stop.risk = risk
        if verdict is not None:
            stop.summary = clean(verdict.resume, 300)
            if verdict.lien == "non" and risk == "eleve":
                return self._auto_block(state, stop, "l'action présente un risque élevé sans aucun lien avec la "
                                                     f"demande de l'utilisateur ({clean(verdict.raison_lien, 120)})")
        message = approval_message(
            sources=state.sources, source_count=state.source_count, summary=stop.summary,
            lien=verdict.lien if verdict else None, raison_lien=verdict.raison_lien if verdict else "",
            points=facts.points(), risk=risk, avis=verdict.avis if verdict else None,
            raison=verdict.raison if verdict else "", explainer_error=outcome.error if verdict is None else "")
        stop.message = message
        if outcome.error:
            logger.info("contamination: explainer unavailable for %s (%s, %.1fs)", tool, outcome.error, outcome.seconds)

        human, why, manual = self._gate_status()
        mode = self._fallback_mode()
        cron = self._in_cron(self.ctx)
        if mode == "always":
            human, why = False, "blocage systématique (réglage fallback: always)"
        if cron:
            human, why, manual = False, "tâche planifiée (cron)", False
        if human:
            stop.path = "native"
            with self._lock:
                self._rules[rule_key] = state.session_id
                self._rules.move_to_end(rule_key)
                while len(self._rules) > 2000:
                    self._rules.popitem(last=False)
            state.add_stop(stop)
            self.store.save(state)
            return {"action": "approve", "message": message, "rule_key": rule_key}

        allow_manual = manual and mode != "never"
        stop.path = "fallback"
        stop.decision = "bloquée (attend /contamination)" if allow_manual else "bloquée"
        stop.expires = time.time() + self._manual_ttl()
        state.add_stop(stop)
        self.store.save(state)
        return {"action": "block", "message": fallback_block_message(why, message, stop.id, allow_manual)}

    def _auto_block(self, state: SessionState, stop: Stop, reason: str) -> Dict[str, str]:
        stop.path = "auto-block"
        stop.decision = "bloquée"
        stop.message = reason
        state.add_stop(stop)
        self.store.save(state)
        return {"action": "block", "message": auto_block_message(reason, stop.summary)}

    def _consume_manual(self, state: SessionState, tool: str, digest: str) -> Optional[Stop]:
        now = time.time()
        for stop in reversed(state.registry):
            if stop.authorized and stop.tool == tool and stop.args_hash == digest:
                if stop.expires and stop.expires < now:
                    stop.authorized = False
                    stop.decision = "autorisation expirée"
                    self.store.save(state)
                    return None
                stop.authorized = False
                stop.decision = "acceptée (/contamination)"
                self.store.save(state)
                return stop
        return None

    # --- post_tool_call: contamination and decisions
    def on_post_tool_call(self, **kw: Any) -> None:
        tool = str(kw.get("tool_name") or "")
        sid = self._sid(kw)
        if not sid or not tool:
            return None
        status = str(kw.get("status") or "ok")
        args = kw.get("args") if isinstance(kw.get("args"), dict) else {}
        state = self.store.resolve(sid, session_key=self._route_keys(sid), task_id=str(kw.get("task_id") or ""))
        changed = False
        if status != "blocked":
            source = source_of(tool, args, kw.get("result"), self.settings())
            if source is not None:
                state.contaminate(source.tool, source.hosts, source.detail)
                changed = True
                try:
                    self.store.save(state)  # the flag first, before any parsing that could fail
                except Exception:
                    logger.exception("contamination: could not persist the contamination of %s", sid)
                text = _result_text(kw.get("result"))
                state.add_seen(extract_urls(text, limit=2000))
                state.add_seen(u for s in strings_in(args) for u in extract_urls(s))
            if _reads_secrets(tool, args):
                self.secrets.harvest(_result_text(kw.get("result"), limit=200_000))
        call_id = str(kw.get("tool_call_id") or "")
        if call_id:
            for stop in reversed(state.registry[-10:]):
                if stop.tool_call_id == call_id and stop.decision == "en attente":
                    if status == "blocked":
                        stop.decision = _decision_from_block(str(kw.get("error_message") or ""))
                    else:
                        stop.decision = "acceptée"
                    changed = True
                    break
        if changed and state.contaminated:
            self.store.save(state)
        return None

    def on_post_approval_response(self, **kw: Any) -> None:
        pattern = str(kw.get("pattern_key") or "")
        if not pattern.startswith("plugin_rule:" + RULE_PREFIX):
            return None
        rule_key = pattern[len("plugin_rule:"):]
        choice = str(kw.get("choice") or "")
        with self._lock:
            sid = self._rules.get(rule_key, "")
        if not sid:
            return None
        state = self.store.resolve(sid)
        for stop in reversed(state.registry):
            if stop.rule_key == rule_key and stop.path == "native" and stop.decision == "en attente":
                stop.decision = _CHOICES.get(choice, f"réponse inconnue ({clean(choice, 20)})")
                break
        if choice in ("session", "always") and rule_key not in state.approved_rules:
            state.approved_rules.append(rule_key)
        self.store.save(state)
        return None

    def on_subagent_start(self, **kw: Any) -> None:
        parent = str(kw.get("parent_session_id") or "")
        child = str(kw.get("child_session_id") or "")
        if not child:
            return None
        self.store.note_child(child, parent)
        state = self.store.resolve(child, parent=parent, has_history=False)
        goal = kw.get("child_goal")
        if goal:
            state.delegated_goal = str(goal)[:2000]
        if state.contaminated:
            self.store.save(state)
        return None

    def on_session_reset(self, **kw: Any) -> None:
        new_id = str(kw.get("new_session_id") or kw.get("session_id") or "")
        if new_id:
            self.store.note_fresh(new_id)
        return None

    # --- /contamination
    def command(self, raw_args: str = "") -> str:
        try:
            return self._command(raw_args or "")
        except Exception as exc:  # a slash command must answer, not raise
            logger.exception("contamination: /contamination failed")
            return f"/contamination : erreur interne ({type(exc).__name__})."

    def _current_state(self) -> Optional[SessionState]:
        current = self._current_session_id()
        sid = self.store.session_for_key(self._route_keys(current)) or current
        return self.store.resolve(sid) if sid else None

    def _command(self, raw: str) -> str:
        words = raw.split()
        sub = words[0].lower() if words else ""
        ref = words[1].lower() if len(words) > 1 else ""
        if sub in ("aide", "help", "?"):
            return HELP
        if sub in ("ok", "oui", "autoriser", "allow", "non", "refuser", "deny", "voir", "show"):
            if not ref:
                current = self._current_state()
                pending = [s for s in (current.registry if current else []) if s.decision.startswith("bloquée (attend")]
                if len(pending) == 1:
                    ref = pending[0].id
                else:
                    return "Précise la référence : /contamination " + sub + " <réf>\n" + self._status()
            state, stop = self.store.find_stop(ref)
            if stop is None or state is None:
                return f"Aucun arrêt avec la référence « {clean(ref, 20)} »."
            if sub in ("voir", "show"):
                return f"Réf. {stop.id} — {stop.tool} — {stop.decision}\n{stop.message or stop.summary}"
            if stop.path != "fallback" or not stop.decision.startswith("bloquée (attend"):
                if stop.path == "auto-block":
                    return (f"Réf. {stop.id} : bloquée automatiquement ({clean(stop.message, 160)}). "
                            "Elle ne peut pas être autorisée ici : relance-la toi-même dans une session propre (/new).")
                return f"Réf. {stop.id} : rien à autoriser (état : {stop.decision})."
            if sub in ("non", "refuser", "deny"):
                stop.decision = "refusée (/contamination)"
                self.store.save(state)
                return f"Réf. {stop.id} écartée."
            if stop.expires and stop.expires < time.time():
                stop.decision = "autorisation expirée"
                self.store.save(state)
                return f"Réf. {stop.id} : trop ancienne, l'autorisation a expiré. Redemande l'action à Hermes."
            ttl = self._manual_ttl()
            stop.authorized = True
            stop.expires = time.time() + ttl
            stop.decision = "autorisée une fois (attend le nouvel essai)"
            self.store.save(state)
            return (f"{stop.message}\n\n✅ Autorisé UNE fois pendant {int(ttl // 60)} min : dis à Hermes de réessayer "
                    f"exactement le même appel (réf. {stop.id}).")
        return self._status()

    def _status(self) -> str:
        state = self._current_state()
        if state is None:
            return "Session inconnue pour le plugin contamination.\n\n" + HELP
        if not state.contaminated:
            return "✅ Session propre : aucune lecture de contenu externe pour l'instant."
        lines = [source_line(state.sources, state.source_count) + f" depuis le {hhmm(state.contaminated_at)}"]
        if state.initial_request:
            lines.append("Demande initiale : « " + clean(state.initial_request, 160) + " »")
        pending = [s for s in state.registry if s.decision.startswith("bloquée (attend")]
        for stop in pending[-3:]:
            lines.append(f"\n⏸ Réf. {stop.id} — bloquée, en attente de ta décision :\n{stop.message}\n"
                         f"→ /contamination ok {stop.id} pour l'autoriser une fois")
        recent = [s for s in state.registry if s not in pending][-5:]
        if recent:
            lines.append("Derniers arrêts :")
            lines.extend(f"• {s.id} [{s.decision}] {s.tool} : {clean(s.summary, 90)}" for s in recent)
        lines.append("Pour repartir d'une session propre : /new")
        return "\n".join(lines)


def _source_label(source: Dict[str, Any]) -> str:
    label = str(source.get("tool") or "?")
    if source.get("hosts"):
        label += " (" + ", ".join(source["hosts"][:2]) + ")"
    elif source.get("detail"):
        label += f" ({source['detail']})"
    return label


def _reads_secrets(tool: str, args: Dict[str, Any]) -> bool:
    if tool == "read_file":
        return bool(_SENSITIVE_PATH.search(str(args.get("path") or "")))
    if tool == "terminal":
        command = str(args.get("command") or "")
        return bool(_SENSITIVE_PATH.search(command) or re.search(r"(?:^|[\s;&|])(?:env|printenv)\b", command))
    return False


def _decision_from_block(message: str) -> str:
    low = message.lower()
    if "timed out" in low or "silence is not consent" in low:
        return "sans réponse (refusée)"
    if "withdrawn" in low or "cancel" in low:
        return "annulée"
    if "denied" in low:
        return "refusée"
    if "no interactive user" in low or "no human" in low:
        return "bloquée (aucun humain)"
    return "refusée ou bloquée"


def _new_id() -> str:
    return _secrets.token_hex(3)


def build_engine(ctx: Any = None) -> Engine:
    """Engine wired to the live Hermes process."""
    store = Store(compat.data_dir, db_parent=hermes_db_parent(compat.hermes_home))

    def settings() -> Dict[str, Any]:
        if ctx is None:
            return {}
        out: Dict[str, Any] = {}
        for name in ("trusted_mcp_servers", "read_only_tools", "pass_tools", "effect_tools", "extra_sources",
                     "untrusted_platforms", "fallback", "manual_ttl_minutes"):
            try:
                value = ctx.get_config(name)
            except Exception:
                value = None
            if value is not None:
                out[name] = value
        return out

    engine = Engine(store=store, settings=settings, secret_book=SecretBook(), ctx=ctx)
    try:
        store.prune(30.0)
    except Exception:
        pass
    return engine
