"""Per-session contamination state.

A session is identified by the Hermes ``session_id``. That id is not stable over a whole
conversation: context compression mints a new id (no plugin hook fires), ``/new`` mints a new id,
subagents run under their own id, ``execute_code`` tool calls carry no id at all. The store keeps
enough breadcrumbs to follow a conversation across those changes:

* explicit parents (``pre_llm_call.parent_session_id``, ``subagent_start``);
* the gateway session key / task id that last pointed at a session (compression rotation);
* as a last resort the ``parent_session_id`` column of Hermes' own ``state.db``.

A new id with no history (``/new``, a brand-new chat) starts clean. Anything that carries history
inherits the contamination of where it came from. Contaminated sessions are written to
``<hermes home>/plugin-data/contamination/sessions/`` so the flag survives a restart; clean sessions
stay in memory.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import tempfile
import threading
import time
from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from .urls import normalize_url

logger = logging.getLogger(__name__)

SCHEMA = 1
MAX_USER_MESSAGES = 12
MAX_SEEN_URLS = 5000
MAX_REGISTRY = 60
MAX_SOURCES = 8


@dataclass
class Stop:
    """One stopped action and what became of it."""

    id: str
    ts: float
    tool: str
    summary: str
    risk: str
    decision: str = "en attente"
    path: str = "native"          # native | fallback | auto-block
    rule_key: str = ""
    args_hash: str = ""
    tool_call_id: str = ""
    message: str = ""             # the explanation shown (kept for /contamination)
    expires: float = 0.0          # fallback: authorisation window
    authorized: bool = False      # fallback: /contamination ok given, not yet used

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Stop":
        known = {k: data[k] for k in cls.__dataclass_fields__ if k in data}
        return cls(**known)


@dataclass
class SessionState:
    session_id: str
    created: float = field(default_factory=time.time)
    contaminated: bool = False
    contaminated_at: float = 0.0
    sources: List[Dict[str, Any]] = field(default_factory=list)
    source_count: int = 0
    initial_request: str = ""
    user_messages: List[str] = field(default_factory=list)
    seen_urls: List[str] = field(default_factory=list)
    registry: List[Stop] = field(default_factory=list)
    parent: str = ""
    lineage: str = ""
    delegated_goal: str = ""
    approved_rules: List[str] = field(default_factory=list)
    platform: str = ""
    _seen_index: Dict[str, None] = field(default_factory=dict, repr=False, compare=False)
    _lock: Any = field(default_factory=threading.RLock, repr=False, compare=False)

    def __post_init__(self) -> None:
        self._seen_index = dict.fromkeys(self.seen_urls)

    # --- serialisation
    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            data = {name: getattr(self, name) for name in self.__dataclass_fields__ if not name.startswith("_")}
            data["sources"] = [dict(s) for s in self.sources]
            data["user_messages"] = list(self.user_messages)
            data["seen_urls"] = list(self.seen_urls)
            data["approved_rules"] = list(self.approved_rules)
            data["registry"] = [asdict(s) for s in self.registry]
        data["schema"] = SCHEMA
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SessionState":
        fields = {k: data[k] for k in cls.__dataclass_fields__ if k in data and not k.startswith("_")}
        fields["registry"] = [Stop.from_dict(s) for s in data.get("registry", []) if isinstance(s, dict)]
        return cls(**fields)

    # --- mutations
    def contaminate(self, tool: str, hosts: Iterable[str] = (), detail: str = "") -> bool:
        """Mark contaminated; returns True when this call flipped a clean session."""
        with self._lock:
            return self._contaminate(tool, hosts, detail)

    def _contaminate(self, tool: str, hosts: Iterable[str], detail: str) -> bool:
        flipped = not self.contaminated
        if flipped:
            self.contaminated = True
            self.contaminated_at = time.time()
        self.source_count += 1
        if len(self.sources) < MAX_SOURCES:
            self.sources.append({"tool": tool, "hosts": [h for h in hosts if h][:5], "detail": detail,
                                 "ts": time.time()})
        return flipped

    def add_user_message(self, text: str) -> None:
        with self._lock:
            self._add_user_message(text)

    def _add_user_message(self, text: str) -> None:
        text = (text or "").strip()
        if not text:
            return
        if not self.initial_request:
            self.initial_request = text[:4000]
            return
        self.user_messages.append(text[:2000])
        del self.user_messages[:-MAX_USER_MESSAGES]

    def add_seen(self, urls: Iterable[str]) -> int:
        with self._lock:
            return self._add_seen(urls)

    def _add_seen(self, urls: Iterable[str]) -> int:
        added = 0
        for url in urls:
            norm = normalize_url(url)
            if norm and norm not in self._seen_index:
                self._seen_index[norm] = None
                self.seen_urls.append(norm)
                added += 1
        if len(self.seen_urls) > MAX_SEEN_URLS:
            drop = self.seen_urls[: len(self.seen_urls) - MAX_SEEN_URLS]
            del self.seen_urls[: len(drop)]
            for url in drop:
                self._seen_index.pop(url, None)
        return added

    def is_seen(self, url: str) -> bool:
        return normalize_url(url) in self._seen_index

    def add_stop(self, stop: Stop) -> None:
        with self._lock:
            self.registry.append(stop)
            del self.registry[:-MAX_REGISTRY]

    def stop(self, stop_id: str) -> Optional[Stop]:
        return next((s for s in reversed(self.registry) if s.id == stop_id), None)

    def inherit_from(self, parent: "SessionState", how: str) -> None:
        with self._lock, parent._lock:
            self._inherit_from(parent, how)

    def _inherit_from(self, parent: "SessionState", how: str) -> None:
        self.parent = parent.session_id
        self.lineage = how
        if not self.initial_request:
            self.initial_request = parent.initial_request
            self.user_messages = list(parent.user_messages)
        if parent.contaminated:
            self.contaminated = True
            self.contaminated_at = parent.contaminated_at or time.time()
            self.sources = [dict(s) for s in parent.sources]
            self.source_count = parent.source_count
            self._add_seen(parent.seen_urls)
            self.registry = [Stop.from_dict(asdict(s)) for s in parent.registry]
            self.approved_rules = []  # approvals are per session id: never carried over


def _safe_name(session_id: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_.-]", "_", session_id)[:80]
    if clean != session_id:
        clean += "-" + hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:10]
    return clean or "empty"


class Store:
    """Thread-safe session store (memory LRU + one JSON file per contaminated session)."""

    def __init__(self, base_dir: Callable[[], Path], db_parent: Optional[Callable[[str], Optional[str]]] = None,
                 capacity: int = 512) -> None:
        self._base_dir = base_dir
        self._db_parent = db_parent
        self._capacity = capacity
        self._lock = threading.RLock()
        self._mem: "OrderedDict[Tuple[str, str], SessionState]" = OrderedDict()
        self._child_parent: Dict[str, str] = {}
        self._fresh: Dict[str, float] = {}
        self._key_to_sid: Dict[str, str] = {}
        self._task_to_sid: "OrderedDict[str, str]" = OrderedDict()
        self._child_ids: set = set()

    # --- paths
    def _dir(self) -> Path:
        path = Path(self._base_dir()) / "sessions"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _home_key(self) -> str:
        try:
            return str(Path(self._base_dir()))
        except Exception:
            return ""

    def path_for(self, session_id: str) -> Path:
        return self._dir() / f"{_safe_name(session_id)}.json"

    # --- breadcrumbs
    def note_child(self, child_id: str, parent_id: str) -> None:
        if child_id and parent_id and child_id != parent_id:
            with self._lock:
                self._child_parent[child_id] = parent_id
                self._child_ids.add(child_id)

    def note_fresh(self, session_id: str) -> None:
        if session_id:
            with self._lock:
                self._fresh[session_id] = time.time()
                key = (self._home_key(), session_id)
                state = self._mem.get(key)
                if state is not None and not state.contaminated:
                    self._mem.pop(key, None)

    def note_route(self, session_id: str, session_key: Any = "", task_id: str = "") -> None:
        """Remember which session the given routing keys / task id currently point to (top-level only)."""
        if not session_id or session_id in self._child_ids:
            return
        keys = [session_key] if isinstance(session_key, str) else list(session_key or [])
        with self._lock:
            for key in keys:
                if key:
                    self._key_to_sid[key] = session_id
            if task_id:
                self._task_to_sid[task_id] = session_id
                self._task_to_sid.move_to_end(task_id)
                while len(self._task_to_sid) > 2048:
                    self._task_to_sid.popitem(last=False)

    def session_for_task(self, task_id: str) -> str:
        with self._lock:
            return self._task_to_sid.get(task_id or "", "")

    def session_for_key(self, session_key: Any) -> str:
        keys = [session_key] if isinstance(session_key, str) else list(session_key or [])
        with self._lock:
            return next((self._key_to_sid[k] for k in keys if k and k in self._key_to_sid), "")

    # --- load / create
    def resolve(self, session_id: str, *, parent: str = "", has_history: Optional[bool] = None,
                session_key: Any = "", task_id: str = "", _depth: int = 0) -> SessionState:
        """State for *session_id*, created (with inheritance) on first sight."""
        key = (self._home_key(), session_id)
        with self._lock:
            state = self._mem.get(key)
            if state is not None:
                self._mem.move_to_end(key)
                return state
            state = self._load(session_id)
            if state is None:
                state = SessionState(session_id=session_id)
                self._inherit(state, parent=parent, has_history=has_history, session_key=session_key,
                              task_id=task_id, depth=_depth)
                if state.contaminated:
                    self._save_locked(state)
            self._mem[key] = state
            while len(self._mem) > self._capacity:
                self._mem.popitem(last=False)
            return state

    def _inherit(self, state: SessionState, *, parent: str, has_history: Optional[bool], session_key: Any,
                 task_id: str, depth: int) -> None:
        sid = state.session_id
        how = ""
        parent = parent or self._child_parent.get(sid, "")
        if parent:
            how = "sous-agent" if sid in self._child_ids else "session parente"
        elif sid not in self._fresh and has_history is not False:
            predecessor = (self.session_for_key(session_key) if session_key else "") \
                or (self._task_to_sid.get(task_id, "") if task_id else "")
            if predecessor and predecessor != sid:
                parent, how = predecessor, "rotation (compression)"
            elif self._db_parent is not None:
                try:
                    parent = self._db_parent(sid) or ""
                except Exception:
                    parent = ""
                how = "lignée Hermes" if parent else ""
        if parent and parent != sid and depth < 8:
            parent_state = self.resolve(parent, _depth=depth + 1)
            state.inherit_from(parent_state, how)

    def _load(self, session_id: str) -> Optional[SessionState]:
        path = self.path_for(session_id)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except Exception as exc:
            # An unreadable file must not silently clear a contamination: treat as contaminated.
            logger.warning("contamination: unreadable state %s (%s); treating the session as contaminated", path, exc)
            state = SessionState(session_id=session_id)
            state.contaminate("état illisible", detail="fichier d'état corrompu")
            return state
        if not isinstance(data, dict) or data.get("session_id") != session_id:
            state = SessionState(session_id=session_id)
            state.contaminate("état illisible", detail="fichier d'état inattendu")
            return state
        return SessionState.from_dict(data)

    # --- persistence
    def save(self, state: SessionState) -> None:
        with self._lock:
            self._save_locked(state)

    def _save_locked(self, state: SessionState) -> None:
        if not state.contaminated:
            return
        path = self.path_for(state.session_id)
        payload = json.dumps(state.to_dict(), ensure_ascii=False)
        fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def find_stop(self, stop_id: str) -> Tuple[Optional[SessionState], Optional[Stop]]:
        """Locate a stop by id in memory, then on disk (most recent files first)."""
        stop_id = (stop_id or "").strip().lower()
        with self._lock:
            for state in reversed(self._mem.values()):
                stop = state.stop(stop_id)
                if stop is not None:
                    return state, stop
        try:
            files = sorted(self._dir().glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:200]
        except OSError:
            files = []
        for path in files:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if any(isinstance(s, dict) and s.get("id") == stop_id for s in data.get("registry", [])):
                state = self.resolve(str(data.get("session_id") or ""))
                return state, state.stop(stop_id)
        return None, None

    def prune(self, max_age_days: float = 30.0) -> int:
        cutoff = time.time() - max_age_days * 86400
        removed = 0
        try:
            for path in self._dir().glob("*.json"):
                if path.stat().st_mtime < cutoff:
                    path.unlink()
                    removed += 1
        except OSError:
            pass
        return removed


def hermes_db_parent(home: Callable[[], Path]) -> Callable[[str], Optional[str]]:
    """Read-only lookup of ``sessions.parent_session_id`` in Hermes' state.db (best effort)."""

    def lookup(session_id: str) -> Optional[str]:
        db = Path(home()) / "state.db"
        if not db.exists():
            return None
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=0.5)
        try:
            row = conn.execute("SELECT parent_session_id FROM sessions WHERE id = ?", (session_id,)).fetchone()
        finally:
            conn.close()
        return str(row[0]) if row and row[0] else None

    return lookup
