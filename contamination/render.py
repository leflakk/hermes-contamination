"""Everything the plugin writes for humans or for the agent.

Rules: short lines readable on a phone, French, and nothing clickable — every URL, domain and IP is
defanged (``docs[.]python[.]org``, ``hxxps://``) because a Matrix client or homeserver fetching a
link preview is itself a way to leak data. Text coming from the explainer or from the action is
treated as untrusted: template markers are neutralised, markdown links and HTML are flattened.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, Optional, Sequence

from .urls import defang

RISK_LABEL = {"faible": "faible", "moyen": "moyen", "eleve": "élevé"}
LIEN_LABEL = {"oui": "oui", "partiel": "en partie", "non": "non"}

_MARKER_TAGS = (
    "think|thinking|reasoning|tool_call|tool_calls|tool_response|tool_result|tool_use|function_call|function|"
    "functions|tools|tool|im_start|im_end|im_sep|start_of_turn|end_of_turn|system|user|assistant|s|eos|bos|"
    "endoftext|answer|output|result|channel|message|instructions?|context"
)


def neutralize_markers(text: str) -> str:
    """Defuse chat-template and tool-call markers so a model reading *text* cannot mistake them for
    structure: ``<|im_start|>``, ``[INST]``, ``<think>``, ``<tool_call>``, ``<function=…>``…"""
    if not text:
        return text or ""
    text = re.sub(r"<\|([^|<>]{0,64})\|>", r"‹¦\1¦›", text)
    text = re.sub(r"(?i)\[(/?(?:INST|SYS|TOOL_CALLS|TOOL_RESULTS|AVAILABLE_TOOLS|SYSTEM_PROMPT|THINK|"
                  r"TOOL_CONTENT|IMG|MODEL_SETTINGS))\]", r"⟦\1⟧", text)
    text = re.sub(r"(?i)<<\s*(/?SYS)\s*>>", r"‹‹\1››", text)
    text = re.sub(rf"(?i)<(/?)({_MARKER_TAGS})(\b[^<>]{{0,80}})?>", lambda m: f"‹{m.group(1)}{m.group(2)}"
                  f"{m.group(3) or ''}›", text)
    text = re.sub(r"(?i)<(/?)(function|tool)=([^<>]{0,80})>", r"‹\1\2=\3›", text)
    return text.replace("<<<", "‹‹‹").replace(">>>", "›››")


def clean(text: Any, limit: int = 200) -> str:
    """One display line from untrusted text: no markup, no link, bounded."""
    text = neutralize_markers(str(text or ""))
    text = re.sub(r"!?\[([^\]]{0,200})\]\(([^)]{0,500})\)", r"\1 (\2)", text)
    text = text.replace("](", "] (").replace("<", "‹").replace(">", "›").replace("`", "'").replace("*", "∗")
    text = re.sub(r"\s+", " ", text).strip()
    text = defang(text)
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def source_line(sources: Sequence[Dict[str, Any]], count: int) -> str:
    if not sources:
        return "⚠️ Session exposée à du contenu externe"
    first = sources[0]
    label = str(first.get("tool") or "?")
    hosts = [h for h in first.get("hosts") or [] if h]
    if hosts:
        label += " : " + ", ".join(hosts[:2])
    elif first.get("detail"):
        label += " : " + str(first["detail"])
    more = count - 1
    suffix = f", +{more} autre{'s' if more > 1 else ''}" if more > 0 else ""
    return clean(f"⚠️ Session exposée à du contenu externe (via {label}{suffix})", 220)


def action_summary(tool: str, args: Dict[str, Any], limit: int = 170) -> str:
    """What the call is, written by program (used when the explainer gives nothing)."""
    args = args if isinstance(args, dict) else {}

    def q(value: Any, n: int = 140) -> str:
        return "« " + clean(value, n) + " »"

    if tool == "terminal":
        text = f"terminal {q(args.get('command'))}"
    elif tool == "execute_code":
        code = str(args.get("code") or "")
        lines = [l for l in code.splitlines() if l.strip() and not l.strip().startswith("#")]
        text = f"exécuter un script Python de {len(code.splitlines())} lignes, début {q(lines[0] if lines else '', 90)}"
    elif tool == "write_file":
        content = str(args.get("content") or "")
        text = f"écrire le fichier {q(args.get('path'), 90)} ({len(content.splitlines())} lignes)"
    elif tool == "patch":
        text = f"modifier le fichier {q(args.get('path') or 'voir le patch', 90)}"
    elif tool in ("web_extract", "web_crawl"):
        urls = args.get("urls") or args.get("url")
        urls = urls if isinstance(urls, list) else [urls]
        text = "lire la page " + ", ".join(q(u, 80) for u in urls[:2] if u)
    elif tool == "browser_navigate":
        text = f"ouvrir {q(args.get('url'), 120)} dans le navigateur"
    elif tool == "memory":
        text = f"mémoire ({args.get('action') or '?'}) {q(args.get('content') or args.get('new_text') or args.get('old_text'), 110)}"
    elif tool in ("cronjob_manage", "cronjob"):
        text = f"tâche planifiée ({args.get('action') or '?'}) {q(args.get('schedule') or '', 40)} {q(args.get('prompt') or args.get('script') or '', 90)}"
    elif tool == "delegate_task":
        tasks = args.get("tasks") if isinstance(args.get("tasks"), list) else []
        goal = (tasks[0].get("goal") if tasks and isinstance(tasks[0], dict) else None) or args.get("goal") or args.get("message")
        text = f"sous-agent ({args.get('action') or 'spawn'}) {q(goal or '', 120)}"
    else:
        compact = json.dumps(args, ensure_ascii=False, default=str)
        text = f"{tool} {q(compact, 130)}"
    return clean(text, limit)


def approval_message(*, sources: Sequence[Dict[str, Any]], source_count: int, summary: str, lien: Optional[str],
                     raison_lien: str, points: Sequence[str], risk: str, avis: Optional[str], raison: str,
                     explainer_error: str = "") -> str:
    """The text Hermes shows in its approval prompt ("Why it was flagged: …")."""
    lines = [source_line(sources, source_count)]
    if explainer_error:
        lines.append(f"Ce que Hermes veut faire : {summary} (explication indisponible : {clean(explainer_error, 60)})")
        lines.append("Lien avec ta demande : non évalué")
    else:
        lines.append(f"Ce que Hermes veut faire : {clean(summary, 300)}")
        link = LIEN_LABEL.get(lien or "", lien or "?")
        lines.append(f"Lien avec ta demande : {link} — {clean(raison_lien, 160)}")
    lines.append("Points d'attention : " + (clean(" ; ".join(points), 380) if points else "aucun"))
    if avis:
        verdict = "ACCEPTER" if avis == "accepter" else "REFUSER"
        lines.append(f"Avis : {verdict} (risque {RISK_LABEL.get(risk, risk)}) — {clean(raison, 160)}")
    else:
        lines.append(f"Avis : aucun avis automatique, décide d'après les faits (risque {RISK_LABEL.get(risk, risk)})")
    return "\n".join(lines)


_NO_BYPASS = ("Ne cherche pas à contourner ce blocage : pas de reformulation, pas d'autre outil, "
              "pas d'autre chemin vers le même résultat.")


def auto_block_message(reason: str, summary: str) -> str:
    """Tool result for a flagrant case blocked without asking."""
    return (f"BLOQUÉ par le plugin contamination : cette session a lu du contenu externe et {reason}. "
            f"Action demandée : {summary}. {_NO_BYPASS} Signale ce blocage tel quel à l'utilisateur. "
            "S'il veut vraiment cette action, il doit la relancer lui-même dans une session propre (/new).")


def fallback_block_message(why_no_human: str, explanation: str, stop_id: str, allow_manual: bool) -> str:
    """Tool result when no human approval can happen here (yolo, approvals off, cron, -q, …)."""
    head = (f"BLOQUÉ par le plugin contamination : cette session a lu du contenu externe et aucune validation "
            f"humaine n'est possible ici ({why_no_human}).")
    body = f"\nExplication pour l'utilisateur :\n{explanation}\n{_NO_BYPASS}"
    if allow_manual:
        tail = (f" Signale-le à l'utilisateur. Il peut autoriser une seule fois cet appel identique en tapant "
                f"« /contamination ok {stop_id} », puis te demander de réessayer exactement le même appel.")
    else:
        tail = " Signale-le à l'utilisateur ; cette action ne sera pas exécutée."
    return head + body + tail


def hhmm(ts: float) -> str:
    return time.strftime("%d/%m %H:%M", time.localtime(ts)) if ts else "?"
