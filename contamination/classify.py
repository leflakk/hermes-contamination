"""What a tool call is, as far as contamination is concerned.

Two questions, asked at two different moments:

* ``source_of`` (after the call, ``post_tool_call``): did this call bring external content into
  the conversation? If so the session becomes contaminated.
* ``classify_call`` (before the call, ``pre_tool_call``, contaminated sessions only): is it a pure
  read, an internal conversation tool, or an action with an effect? Unknown tools are effects.

Tool names come from the Hermes registry (v0.21, checked against commit 0d69d07b and v0.21.6).
Legacy aliases (``todo``, ``process``, ``cronjob``, single-underscore MCP names) are accepted too.
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from . import shell
from .urls import extract_urls, url_host

READ = "read"
INTERNAL = "internal"
EFFECT = "effect"

# Pure reads: no effect outside the conversation. URL-bearing reads are listed separately because
# a URL the session has never seen stops even a read (fabricated URLs are the exfiltration path).
PURE_READ_TOOLS = {
    "read_file", "search_files", "session_search", "skill_view", "skills_list", "read_terminal",
    "web_search", "x_search", "browser_snapshot", "browser_scroll", "browser_back", "browser_get_images",
    "browser_vision", "kanban_show", "kanban_list", "feishu_doc_read", "feishu_drive_list_comments",
    "feishu_drive_list_comment_replies", "yb_query_group_info", "yb_query_group_members",
    "yb_search_sticker", "browser_vault_list", "tool_search", "tool_describe",
}
URL_READ_TOOLS = {
    "web_extract": ("urls",), "web_crawl": ("url", "urls"), "browser_navigate": ("url",),
    "vision_analyze": ("image_url",), "video_analyze": ("video_url",),
}
# Conversation-internal tools: they only touch the agent's own scratch state or talk to the user
# in the same chat (like the final answer does). Stopping them would add questions without adding
# safety. Configurable: settings.pass_tools / settings.effect_tools.
INTERNAL_TOOLS = {"todo_list", "todo", "clarify", "react_to_message", "show_tip", "gui_tour", "focus_pane"}
# Multi-action tools whose listing actions are reads.
READ_ACTIONS = {
    "process_manage": {"list", "poll", "log", "wait"}, "process": {"list", "poll", "log", "wait"},
    "cronjob_manage": {"list"}, "cronjob": {"list"},
    "delegate_task": {"list"},
}

# Tools whose *results* are external content.
SOURCE_TOOLS = {
    "web_search", "web_extract", "web_crawl", "x_search", "feishu_doc_read", "feishu_drive_list_comments",
    "feishu_drive_list_comment_replies", "yb_query_group_info", "yb_query_group_members",
    "delegate_task", "read_window_below", "computer_use",
}
SOURCE_PREFIXES = ("browser_", "connectors__", "discord", "a2a_", "google_meet", "meet_")
NOT_SOURCES = ("browser_vault_",)

# Terminal commands whose output is downloaded content. Package managers and git transfers are
# deliberately excluded (user decision: too much friction while developing).
DOWNLOAD_COMMANDS = {
    "curl", "wget", "wget2", "aria2c", "axel", "http", "https", "httpie", "xh", "lynx", "w3m", "links",
    "elinks", "yt-dlp", "youtube-dl", "gallery-dl", "ftp", "lftp", "tftp", "nc", "ncat", "netcat", "socat",
    "telnet", "gh", "glab", "hub", "scp", "sftp", "rsync", "rclone", "s3cmd", "smbclient", "dig",
    "nslookup", "host", "whois", "pandoc", "w3m", "openssl",
}
PACKAGE_COMMANDS = {
    "pip", "pip3", "pipx", "uv", "uvx", "poetry", "pdm", "conda", "mamba", "micromamba", "npm", "npx", "pnpm",
    "yarn", "bun", "apt", "apt-get", "aptitude", "dnf", "yum", "zypper", "pacman", "apk", "brew", "port",
    "snap", "flatpak", "cargo", "rustup", "go", "gem", "bundle", "composer", "mvn", "gradle", "nix",
    "nix-env", "helm", "git", "hf", "huggingface-cli", "ollama", "docker", "podman",
}
_CODE_NETWORK = re.compile(
    r"\b(?:requests|httpx|aiohttp|urllib3?|http\.client|socket|ftplib|smtplib|imaplib|poplib|websockets?|"
    r"paramiko|pycurl|selenium|playwright|mechanize|scrapy|feedparser|yt_dlp|tweepy|praw|urlopen|"
    r"fetch\(|XMLHttpRequest|curl|wget)\b|https?://",
    re.IGNORECASE,
)


@dataclass
class Settings:
    """User settings (``plugins.entries.contamination.settings``); see README."""

    trusted_mcp_servers: List[str] = field(default_factory=list)
    read_only_tools: List[str] = field(default_factory=list)   # fnmatch patterns treated as pure reads
    pass_tools: List[str] = field(default_factory=list)        # treated as conversation-internal
    effect_tools: List[str] = field(default_factory=list)      # always stop (overrides the above)
    extra_sources: List[str] = field(default_factory=list)     # extra contaminating tools (patterns)
    untrusted_platforms: List[str] = field(default_factory=lambda: ["webhook", "msgraph_webhook", "email"])

    @classmethod
    def from_mapping(cls, data: Optional[Dict[str, Any]]) -> "Settings":
        data = data if isinstance(data, dict) else {}
        out = cls()
        for name in ("trusted_mcp_servers", "read_only_tools", "pass_tools", "effect_tools", "extra_sources",
                     "untrusted_platforms"):
            value = data.get(name)
            if isinstance(value, list):
                setattr(out, name, [str(v) for v in value if isinstance(v, (str, int))])
        return out


def _matches(name: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


def _sanitize_server(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", name or "")


def mcp_server(tool_name: str) -> Optional[str]:
    """MCP server part of an MCP tool name, or None. Current form ``mcp__<server>__<tool>``;
    legacy ``mcp_<server>_<tool>`` returns the whole remainder (server boundary ambiguous)."""
    if tool_name.startswith("mcp__"):
        return tool_name[5:].split("__", 1)[0]
    if tool_name.startswith("mcp_"):
        return tool_name[4:]
    return None


def is_trusted_mcp(tool_name: str, settings: Settings) -> bool:
    server = mcp_server(tool_name)
    if server is None:
        return False
    trusted = {_sanitize_server(t) for t in settings.trusted_mcp_servers}
    if tool_name.startswith("mcp__"):
        return server in trusted
    return any(server.startswith(t + "_") for t in trusted)


def strings_in(value: Any, limit: int = 2000) -> List[str]:
    """Every string inside *value* (nested dicts/lists), bounded."""
    out: List[str] = []
    stack = [value]
    while stack and len(out) < limit:
        item = stack.pop()
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            stack.extend(item.values())
            stack.extend(k for k in item.keys() if isinstance(k, str))
        elif isinstance(item, (list, tuple)):
            stack.extend(item)
    return out


def _all_urls(args: Dict[str, Any]) -> List[str]:
    return [u for s in strings_in(args) for u in extract_urls(s)]


def _action(args: Dict[str, Any]) -> str:
    return str(args.get("action") or "").strip().lower()


def _http(value: Any) -> bool:
    return isinstance(value, str) and bool(re.match(r"(?i)\s*(?:https?|ftp)://", value))


@dataclass
class CallClass:
    kind: str
    urls: List[str] = field(default_factory=list)  # URLs this call would fetch (unseen-URL rule)
    why: str = ""


def classify_call(tool_name: str, args: Dict[str, Any], settings: Settings) -> CallClass:
    """Pure read, conversation-internal, or effect (the default for anything unknown)."""
    args = args if isinstance(args, dict) else {}
    if _matches(tool_name, settings.effect_tools):
        return CallClass(EFFECT, why="settings.effect_tools")
    if _matches(tool_name, settings.pass_tools):
        return CallClass(INTERNAL, urls=_all_urls(args), why="settings.pass_tools")
    if _matches(tool_name, settings.read_only_tools):
        return CallClass(READ, urls=_all_urls(args), why="settings.read_only_tools")
    if tool_name in INTERNAL_TOOLS:
        # Shown in the chat: an unseen URL there could still leak through a link preview.
        return CallClass(INTERNAL, urls=_all_urls(args), why="outil interne à la conversation")
    if tool_name in PURE_READ_TOOLS:
        return CallClass(READ, urls=_all_urls(args), why="lecture")
    if tool_name in URL_READ_TOOLS:
        urls: List[str] = []
        for key in URL_READ_TOOLS[tool_name]:
            value = args.get(key)
            values = value if isinstance(value, list) else [value]
            for v in values:
                if isinstance(v, str) and v.strip():
                    found = extract_urls(v)
                    urls.extend(found if found else ([v.strip()] if _http(v) else []))
        return CallClass(READ, urls=urls, why="lecture d'URL")
    if tool_name == "browser_console":
        if not str(args.get("expression") or "").strip():
            return CallClass(READ, why="lecture de la console")
        return CallClass(EFFECT, why="exécute du JavaScript dans la page")
    if tool_name in READ_ACTIONS and _action(args) in READ_ACTIONS[tool_name]:
        return CallClass(READ, why=f"{tool_name}:{_action(args)}")
    if tool_name == "terminal":
        command = str(args.get("command") or "")
        if command.strip() and shell.is_pure_read(command):
            return CallClass(READ, why="commande shell en lecture pure")
        return CallClass(EFFECT, why="commande shell")
    if tool_name == "tool_call" and _is_connector_batch(args):
        # Hermes keeps the Tool Search wrapper for connector batches and runs pre_tool_call on each
        # entry: stopping the wrapper as well would ask twice for the same calls.
        return CallClass(INTERNAL, why="lot de connecteurs vérifié appel par appel")
    return CallClass(EFFECT, why="action")


def _is_connector_batch(args: Dict[str, Any]) -> bool:
    try:
        from tools.tool_search import resolve_underlying_call
        name, _args, err = resolve_underlying_call(args)
        return not err and name == "connectors__execute"
    except Exception:
        return False


@dataclass
class Source:
    tool: str
    hosts: List[str] = field(default_factory=list)
    detail: str = ""


def source_of(tool_name: str, args: Dict[str, Any], result: Any, settings: Settings) -> Optional[Source]:
    """The external source a finished call brought in, or None."""
    args = args if isinstance(args, dict) else {}
    hosts = _arg_hosts(args)
    if _matches(tool_name, settings.extra_sources):
        return Source(tool_name, hosts)
    if mcp_server(tool_name) is not None:
        if is_trusted_mcp(tool_name, settings):
            return None
        return Source(tool_name, hosts, detail=f"serveur MCP {mcp_server(tool_name)}")
    if tool_name.startswith(NOT_SOURCES):
        return None
    if tool_name in SOURCE_TOOLS or tool_name.startswith(SOURCE_PREFIXES):
        if not hosts and tool_name in ("web_search", "x_search"):
            hosts = _result_hosts(result)
        return Source(tool_name, hosts)
    if tool_name in ("vision_analyze", "video_analyze"):
        target = args.get("image_url") or args.get("video_url")
        if _http(target):
            return Source(tool_name, [url_host(str(target))])
        return None
    if tool_name == "terminal":
        return _terminal_source(str(args.get("command") or ""))
    if tool_name == "execute_code":
        code = str(args.get("code") or "")
        if _CODE_NETWORK.search(code):
            return Source(tool_name, hosts, detail="code avec accès réseau")
        return None
    return None


def _terminal_source(command: str) -> Optional[Source]:
    parsed = shell.parse(command)
    for cmd in parsed.commands:
        name = cmd.name.rsplit("/", 1)[-1]
        if name in PACKAGE_COMMANDS:
            continue
        joined = " ".join(cmd.args)
        if name in DOWNLOAD_COMMANDS or extract_urls(joined) or any(
                t.startswith(("/dev/tcp/", "/dev/udp/")) for _, t in cmd.redirects):
            hosts = [url_host(u) for u in extract_urls(joined)]
            return Source("terminal", [h for h in hosts if h], detail=f"téléchargement ({name})")
        if name in ("python", "python3", "node", "ruby", "perl", "php", "bash", "sh", "zsh", "deno") \
                and _CODE_NETWORK.search(joined):
            return Source("terminal", [], detail=f"code avec accès réseau ({name})")
    if parsed.error and re.search(r"\b(curl|wget|nc|ncat)\b|https?://", command):
        return Source("terminal", [], detail="téléchargement")
    return None


def _arg_hosts(args: Dict[str, Any]) -> List[str]:
    hosts: Dict[str, None] = {}
    for text in strings_in(args, limit=200):
        for url in extract_urls(text, limit=20):
            host = url_host(url)
            if host:
                hosts.setdefault(host, None)
    return list(hosts)[:10]


def _result_hosts(result: Any) -> List[str]:
    text = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False, default=str)
    hosts: Dict[str, None] = {}
    for url in extract_urls(text[:200_000], limit=50):
        host = url_host(url)
        if host:
            hosts.setdefault(host, None)
    return list(hosts)[:5]
