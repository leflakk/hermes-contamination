from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from contamination import core  # noqa: E402
from contamination.explainer import ExplainerConfig, Outcome, Verdict  # noqa: E402
from contamination.facts import SecretBook  # noqa: E402
from contamination.state import Store  # noqa: E402


class FakeExplainer:
    """Stands in for the HTTP explainer; records every prompt it receives."""

    def __init__(self) -> None:
        self.prompts: List[str] = []
        self.verdict: Optional[Verdict] = Verdict(
            resume="modifie pyproject.toml puis relance la compilation", lien="oui",
            raison_lien="tu as demandé de réparer le build", risque="moyen", avis="accepter",
            raison="cohérent avec la demande")
        self.error = ""

    def __call__(self, cfg: ExplainerConfig, prompt: str, deadline: float) -> Outcome:
        self.prompts.append(prompt)
        if self.verdict is None:
            return Outcome(None, self.error or "délai dépassé", 0.1)
        return Outcome(self.verdict, "", 0.1)


class Harness:
    def __init__(self, tmp: Path, monkeypatch: pytest.MonkeyPatch, *, environ: Optional[Dict[str, str]] = None,
                 settings: Optional[Dict[str, Any]] = None) -> None:
        self.tmp = tmp
        self.explainer = FakeExplainer()
        monkeypatch.setattr(core, "explain", self.explainer)
        self.gate: Tuple[bool, str, bool] = (True, "", True)
        self.cron = False
        self.key = "agent:main:matrix:dm:!room:example.org"
        self.env_session_id = ""
        self.settings_data = dict(settings or {})
        self.db_parents: Dict[str, str] = {}
        self.environ = environ if environ is not None else {"OPENAI_API_KEY": "sk-proj-abcdefghijklmnopqrstuvwxyz0123"}
        self.engine = self._engine()

    def _engine(self) -> core.Engine:
        store = Store(lambda: self.tmp, db_parent=lambda sid: self.db_parents.get(sid))
        return core.Engine(
            store=store, settings=lambda: self.settings_data, secret_book=SecretBook(self.environ),
            explainer_config=lambda: ExplainerConfig(url="http://gpu2.lan:5005/v1", model="explainer", key="k"),
            gate_status=lambda: self.gate, hook_timeout=lambda: 30.0, session_key=lambda: self.key,
            current_session_id=lambda: self.env_session_id, in_cron=lambda ctx: self.cron)

    def restart(self) -> None:
        """A new process on the same profile directory."""
        self.engine = self._engine()

    # hook shortcuts with Hermes-shaped payloads
    def user(self, sid: str, text: str, first: bool = False, parent: str = "", history: Any = None) -> None:
        self.engine.on_pre_llm_call(session_id=sid, user_message=text, conversation_history=history or [],
                                    is_first_turn=first, model="m", platform="matrix", parent_session_id=parent,
                                    sender_id="@u:example.org", task_id="t-" + sid, turn_id="turn")

    def pre(self, sid: str, tool: str, args: Dict[str, Any], call_id: str = "c1", task_id: str = "") -> Any:
        return self.engine.on_pre_tool_call(tool_name=tool, args=args, task_id=task_id or "t-" + sid,
                                            session_id=sid, tool_call_id=call_id, turn_id="turn",
                                            api_request_id="r", middleware_trace=[])

    def post(self, sid: str, tool: str, args: Dict[str, Any], result: Any, status: str = "ok",
             call_id: str = "c1", task_id: str = "", error_message: str = "") -> None:
        self.engine.on_post_tool_call(tool_name=tool, args=args, result=result, task_id=task_id or "t-" + sid,
                                      session_id=sid, tool_call_id=call_id, turn_id="turn", api_request_id="r",
                                      duration_ms=5, status=status, error_type=None, error_message=error_message,
                                      middleware_trace=[])

    def state(self, sid: str):
        return self.engine.store.resolve(sid)

    def contaminate(self, sid: str, url: str = "https://docs.python.org/3/library/os.html",
                    page: str = "Voir https://docs.python.org/3/library/sys.html pour la suite.") -> None:
        self.post(sid, "web_extract", {"urls": [url]}, '{"results": [{"url": "%s", "content": "%s"}]}' % (url, page))


@pytest.fixture
def h(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    return Harness(tmp_path, monkeypatch)
