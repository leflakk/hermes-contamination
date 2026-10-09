"""Guarded access to the parts of Hermes the hook payloads do not carry.

Every function here survives an API change: on any import or attribute error it returns the
answer that keeps the plugin safe. In particular ``gate_status`` answers "no human will be asked"
whenever it cannot prove the opposite, which turns stops into blocks with ``/contamination``
instead of risking an approval Hermes would grant on its own (``/yolo``, ``approvals.mode: off``,
cron, ``-q``). ``doctor()`` lists what is available so an update that breaks something is visible.

Verified against Hermes commit 0d69d07b (2026-10-06) and v0.21.6.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PLUGIN_NAME = "contamination"
_TRUTHY = {"1", "true", "yes", "on"}


def hermes_home() -> Path:
    try:
        from hermes_constants import get_hermes_home
        return Path(get_hermes_home())
    except Exception:
        return Path(os.environ.get("HERMES_HOME") or Path.home() / ".hermes")


def data_dir() -> Path:
    try:
        from plugins.plugin_storage import plugin_data_dir
        return Path(plugin_data_dir(PLUGIN_NAME))
    except Exception:
        path = hermes_home() / "plugin-data" / PLUGIN_NAME
        path.mkdir(parents=True, exist_ok=True)
        return path


def session_env(name: str) -> str:
    try:
        from gateway.session_context import get_session_env
        return str(get_session_env(name, "") or "")
    except Exception:
        return os.environ.get(name, "") or ""


def session_key() -> str:
    """Gateway session key (stable across compression and /new); a per-process key elsewhere."""
    key = ""
    try:
        from tools.approval_context import get_current_session_key
        key = str(get_current_session_key(default="") or "")
    except Exception:
        key = session_env("HERMES_SESSION_KEY")
    if key in ("", "default"):
        key = session_env("HERMES_SESSION_KEY")
    return key or f"process:{os.getpid()}"


def current_session_id() -> str:
    return session_env("HERMES_SESSION_ID")


def in_cron(ctx: Any = None) -> bool:
    if session_env("HERMES_CRON_SESSION").strip().lower() in _TRUTHY:
        return True
    try:
        return ctx is not None and ctx.current_cron_execution() is not None
    except Exception:
        return False


def hook_timeout() -> float:
    """Effective ``plugins.hook_callback_timeout`` (0 = no timeout)."""
    try:
        from hermes_cli.plugins import _resolve_hook_callback_timeout
        return float(_resolve_hook_callback_timeout())
    except Exception:
        return 30.0


def isolation_mode() -> str:
    try:
        from hermes_cli.config import load_config_readonly
        plugins = (load_config_readonly() or {}).get("plugins") or {}
        return str(plugins.get("isolation") or "in_process")
    except Exception:
        return "in_process"


def approve_supported() -> bool:
    """Does this Hermes turn a pre_tool_call ``approve`` into a human prompt? (Older ones ignore it,
    which would let the action run: in that case the plugin only ever blocks.)"""
    try:
        from hermes_cli import plugins as hp
        from tools.approval import request_tool_approval  # noqa: F401
        return hasattr(hp, "_resolve_block_from_details") or hasattr(hp, "resolve_pre_tool_block")
    except Exception:
        return False


def gate_status() -> Tuple[bool, str, bool]:
    """``(human, why, manual)``: *human* when Hermes' approval gate would put a plugin approval in
    front of a person right now; otherwise *why* not, and whether a person can still answer with
    ``/contamination`` (*manual*: yes under /yolo or approvals off, no in cron, ``-q`` or webhooks)."""
    if isolation_mode() == "host":
        return False, "plugin isolé hors du processus Hermes (plugins.isolation: host)", True
    if not approve_supported():
        return False, "cette version d'Hermes ne sait pas demander d'approbation pour un plugin", True
    try:
        from tools import approval as ap
        from tools import approval_context as ac
    except Exception:
        return False, "API d'approbation d'Hermes introuvable", True
    try:
        if ac._is_single_query_approval_context():
            return False, "requête unique (hermes chat -q)", False
        if ac._is_cron_approval_context():
            return False, "tâche planifiée (cron)", False
        if ac._is_unattended_platform_approval_context():
            return False, f"plateforme sans humain ({ac._get_session_platform() or '?'})", False
        is_cli = bool(ac._is_interactive_cli())
        is_gateway = bool(ac._is_gateway_approval_context())
    except Exception:
        return False, "contexte d'exécution illisible", True
    is_ask = os.environ.get("HERMES_EXEC_ASK", "").strip().lower() in _TRUTHY
    if not (is_cli or is_gateway or is_ask):
        return False, "aucun humain joignable (contexte non interactif)", False
    try:
        if ap.is_approval_bypass_active():
            mode = str(ac._get_approval_mode())
            return False, ("approvals.mode: off" if mode == "off" else "mode /yolo actif"), True
    except Exception:
        return False, "état des approbations illisible", True
    return True, "", True


def doctor() -> List[Tuple[str, bool, str]]:
    """``(check, ok, detail)`` rows describing the integration points."""
    rows: List[Tuple[str, bool, str]] = []
    try:
        from hermes_cli.plugins import VALID_HOOKS
        needed = {"pre_tool_call", "post_tool_call", "pre_llm_call", "post_approval_response", "subagent_start",
                  "on_session_reset"}
        missing = sorted(needed - set(VALID_HOOKS))
        rows.append(("hooks Hermes", not missing, "manquants : " + ", ".join(missing) if missing else "tous présents"))
    except Exception as exc:
        rows.append(("hooks Hermes", False, f"VALID_HOOKS illisible ({type(exc).__name__})"))
    rows.append(("approbation de plugin (approve)", approve_supported(), "request_tool_approval"))
    rows.append(("isolation des plugins", isolation_mode() != "host", isolation_mode()))
    try:
        from tools import approval_context as ac
        names = ["_get_approval_mode", "_is_single_query_approval_context", "_is_cron_approval_context",
                 "_is_unattended_platform_approval_context", "_is_interactive_cli", "_is_gateway_approval_context",
                 "get_current_session_key"]
        missing = [n for n in names if not hasattr(ac, n)]
        rows.append(("contexte d'approbation", not missing, "manquants : " + ", ".join(missing) if missing else "ok"))
        rows.append(("mode d'approbation", True, str(ac._get_approval_mode())))
    except Exception as exc:
        rows.append(("contexte d'approbation", False, type(exc).__name__))
    try:
        from tools.approval import is_approval_bypass_active  # noqa: F401
        rows.append(("détection /yolo et mode off", True, "ok"))
    except Exception as exc:
        rows.append(("détection /yolo et mode off", False, type(exc).__name__))
    try:
        from gateway.session_context import get_session_env  # noqa: F401
        rows.append(("variables de session", True, "ok"))
    except Exception as exc:
        rows.append(("variables de session", False, type(exc).__name__))
    timeout = hook_timeout()
    rows.append(("délai des hooks", timeout == 0 or timeout >= 15, f"{timeout:g} s"))
    rows.append(("dossier d'état", True, str(data_dir())))
    return rows
