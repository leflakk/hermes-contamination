"""Facts extracted by program from a tool call.

The explainer LLM may describe an action, but it never decides what the action *touches*: these
facts are computed here, shown to the user as "Points d'attention", and set a risk floor the LLM
cannot lower. Patterns are deliberately broad; a false positive adds a line to a question the
user is being asked anyway, a false negative only removes a hint.
"""

from __future__ import annotations

import base64
import os
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from . import shell
from .classify import INTERNAL, READ, mcp_server, strings_in
from .urls import extract_urls, is_domain, url_host, url_payload_reasons

SeenFn = Callable[[str], bool]

RISK_ORDER = {"faible": 0, "moyen": 1, "eleve": 2}


def max_risk(*levels: str) -> str:
    return max((lvl for lvl in levels if lvl in RISK_ORDER), key=RISK_ORDER.__getitem__, default="faible")


# --- secrets -------------------------------------------------------------------------------------

_SENSITIVE_PATH = re.compile(
    r"""(?ix)(?:^|(?<=[\s'"=:/~(,]))(
        \.env(?!\.(?:example|sample|template|dist)\b)(?:\.[\w-]+)?(?![\w/])
      | \.netrc | \.git-credentials | \.npmrc | \.pypirc | \.pgpass | \.my\.cnf | \.htpasswd
      | \.ssh/(?:id_[\w.-]+(?<!\.pub)|[\w.-]*_key(?!\.pub)\b|authorized_keys|config\b)
      | \.aws/(?:credentials|config) | \.kube/config | \.docker/config\.json | \.gnupg\b
      | \.password-store | \.config/(?:gh/hosts\.yml|gcloud|hub\b|rclone/rclone\.conf|op/|Bitwarden)
      | \.azure/ | \.hermes/(?:[\w.-]+/)*(?:\.env|auth\.json|config\.yaml|state\.db)
      | (?:[\w.-]*[-_])?credentials\.(?:json|ya?ml|csv|txt) | /credentials\b | secrets?\.(?:ya?ml|json|toml|env)
      | tokens?\.json | service[-_]?account[\w.-]*\.json
      | id_(?:rsa|dsa|ecdsa|ed25519)(?!\.pub)\b | [\w.-]+\.(?:pem|key|p12|pfx|jks|keystore|kdbx|ovpn)\b
      | /etc/(?:shadow|gshadow|sudoers) | /proc/(?:self|\d+|\*)/environ
      | \.mozilla/firefox | \.config/(?:google-chrome|chromium|BraveSoftware) | Login\ Data | /Cookies\b
      | \.keychain\b | find-(?:generic|internet)-password | \.local/share/keyrings
    )""",
)
_SECRET_NAME = re.compile(r"(?i)(key|token|secret|passw|pwd|credential|auth|cookie|session|private|bearer|cert)")
# Stricter test for *values* worth tracking: names that hold a secret, not an identifier or a path.
_SECRET_VALUE_NAME = re.compile(r"(?i)(key|token|secret|passw|pwd|credential|cookie|private|bearer|_dsn$|database_url)")
_NOT_SECRET_NAME = re.compile(r"(?i)^(?:hermes_session_|term_session|xdg_session|session_manager|dbus_session)|"
                              r"(?:_file|_path|_dir|_keyring|keymap|keyboard|_id)$")


def _secret_value_name(name: str) -> bool:
    return bool(_SECRET_VALUE_NAME.search(name or "")) and not _NOT_SECRET_NAME.search(name or "")
_ENV_REF = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?|(?:os\.environ\s*\[\s*|getenv\(\s*|environ\.get\(\s*|"
                      r"process\.env\.|ENV\[\s*)['\"]?([A-Za-z_][A-Za-z0-9_]*)")
_ENV_DUMP = re.compile(r"(?:^|[\s;&|(])(?:env|printenv|export\s+-p|declare\s+-x|set)\s*(?:$|[|;&>)])|"
                       r"/proc/(?:self|\d+|\*)/environ|dict\(\s*os\.environ\s*\)|os\.environ\.(?:copy|items)\(|"
                       r"json\.dumps\(\s*os\.environ|str\(\s*os\.environ|print\(\s*os\.environ|process\.env\b(?!\.)")
_SECRET_LITERALS = [
    re.compile(p) for p in (
        r"sk-(?:proj-|ant-|or-|svcacct-)?[A-Za-z0-9_-]{20,}", r"gh[pousr]_[A-Za-z0-9]{30,}",
        r"github_pat_[A-Za-z0-9_]{40,}", r"glpat-[A-Za-z0-9_-]{20,}", r"xox[abposr]-[A-Za-z0-9-]{10,}",
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", r"AIza[0-9A-Za-z_-]{35}", r"ya29\.[0-9A-Za-z_-]{20,}",
        r"\bhf_[A-Za-z0-9]{30,}", r"\bsyt_[A-Za-z0-9_-]{10,}_[A-Za-z0-9]{10,}", r"\bxai-[A-Za-z0-9]{20,}",
        r"\br8_[A-Za-z0-9]{20,}", r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----",
        r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{24,}=*",
    )
]
_SECRET_TOOLS = {
    "browser_vault_fill": "remplit un identifiant enregistré dans une page web",
    "browser_vault_enter_code": "saisit un code d'authentification dans une page web",
    "browser_vault_unlock": "déverrouille le coffre de mots de passe",
    "browser_vault_save_login": "enregistre un identifiant dans le coffre",
}


class SecretBook:
    """Known secret values: secret-looking variables of the Hermes process environment plus values
    the session read from secret files. Kept in memory only, never written to disk."""

    def __init__(self, environ: Optional[Dict[str, str]] = None) -> None:
        self._variants: Dict[str, str] = {}  # variant -> label
        self.load_environ(environ if environ is not None else dict(os.environ))

    def load_environ(self, environ: Dict[str, str]) -> None:
        for name, value in environ.items():
            if _secret_value_name(name):
                self.add(value, name)

    def add(self, value: str, label: str) -> None:
        value = (value or "").strip().strip("'\"")
        if len(value) < 10 or value.lower() in ("true", "false", "none", "null") or value.startswith(("/", "~")) \
                or " " in value or len(set(value)) < 6:
            return
        for variant in _variants(value):
            if len(variant) >= 10:
                self._variants.setdefault(variant, label)

    def harvest(self, text: str) -> int:
        """Record ``NAME=value`` / ``"name": "value"`` pairs with secret-looking names from *text*."""
        count = 0
        for m in re.finditer(r"""(?im)^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*['"]?([^'"\s#]+)""", text or ""):
            if _secret_value_name(m.group(1)):
                self.add(m.group(2), m.group(1))
                count += 1
        for m in re.finditer(r""""([A-Za-z_][\w-]*)"\s*:\s*"([^"]{10,})\"""", text or ""):
            if _secret_value_name(m.group(1)):
                self.add(m.group(2), m.group(1))
                count += 1
        for pattern in _SECRET_LITERALS:
            for m in pattern.finditer(text or ""):
                self.add(m.group(0), "secret lu")
                count += 1
        return count

    def find(self, texts: Iterable[str]) -> List[str]:
        hits: Dict[str, None] = {}
        for text in texts:
            if len(text) < 10:
                continue
            for variant, label in self._variants.items():
                if variant in text:
                    hits.setdefault(label, None)
        return list(hits)

    def __len__(self) -> int:
        return len(self._variants)


def _variants(value: str) -> List[str]:
    raw = value.encode("utf-8", "ignore")
    out = [value, value[::-1], raw.hex(), raw.hex().upper()]
    quoted = urllib.parse.quote(value, safe="")
    if quoted != value:
        out.append(quoted)
    for encoder in (base64.b64encode, base64.urlsafe_b64encode, base64.b32encode):
        for pad in range(3):
            enc = encoder(b"\0" * pad + raw).decode("ascii").rstrip("=")
            core = enc[4:-4] if pad else enc[:-4]
            if len(core) >= 12:
                out.append(core)
    if len(value) >= 24:
        out.append(value[:16])
    return out


# --- other fact families --------------------------------------------------------------------------

_PERSIST_PATH = re.compile(
    r"""(?ix)(
        \.bashrc | \.bash_profile | \.bash_login | \.profile\b | \.zshrc | \.zprofile | \.zshenv | \.config/fish/
      | \.ssh/(?:authorized_keys|config|rc)\b | /etc/(?:cron|systemd|init\.d|rc\.local|profile|bash\.bashrc|environment|ld\.so\.preload|sudoers)
      | /var/spool/cron | \.config/systemd/ | \.config/autostart | Library/Launch(?:Agents|Daemons)
      | \.git/hooks/ | \.githooks | \.husky/ | \.hermes/ | \bAGENTS\.md | \bCLAUDE\.md | \.cursorrules
      | \.hermes\.md | \bHERMES\.md | \bSOUL\.md | \.github/workflows/ | \.gitlab-ci\.yml | \.vscode/(?:tasks|settings)\.json
      | \.pre-commit-config\.yaml | (?:site|user)customize\.py | \.pth\b | pip\.conf | \.condarc
    )""",
)
_PERSIST_CMD = re.compile(
    r"""(?ix)(?:^|[\s;&|(])(
        crontab\s+(?!-l\b)\S+ | systemctl\s+(?:--user\s+)?(?:enable|link|daemon-reload|edit|set-property)\b
      | \bat\s+(?:now|\d) | launchctl\s+(?:load|bootstrap|enable) | ssh-copy-id | update-rc\.d | chkconfig
      | git\s+config\s+.*core\.hooksPath | hermes\s+(?:cron|config|plugins?|skills?|memory|hooks|profile|gateway\s+install)\b
    )""",
)
_HIDDEN = [
    (re.compile(r"(?i)base64\s+(?:-\w*d\w*|--decode)|b64decode|atob\(|fromhex|unhexlify|xxd\s+-r|openssl\s+(?:enc|base64)\b.*-d\b"
                r"|zlib\.decompress|gzip\.decompress|marshal\.loads|codecs\.decode|rot13"), "décode des données cachées"),
    (re.compile(r"\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|ksh|python[\d.]*|perl|ruby|node|php)\b(?:\s+-\s*)?(?:$|[\s;&|)])"),
     "envoie du texte directement à un interpréteur (… | sh)"),
    (re.compile(r"(?:^|[\s;&|(])(?:eval|exec)\s+[\"'$`]|\beval\s*\(\s*(?:atob|base64|Buffer|unescape|decode)"
                r"|exec\(\s*(?:compile|base64|zlib|marshal|codecs|bytes\.fromhex|__import__)"), "évalue du code construit à la volée"),
    (re.compile(r"(?:\\x[0-9a-fA-F]{2}){6,}|(?:\\u[0-9a-fA-F]{4}){6,}"), "séquences d'échappement qui masquent du texte"),
    (re.compile(r"[A-Za-z0-9+/]{160,}={0,2}"), "long bloc encodé (base64)"),
    (re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f]"),
     "caractères invisibles ou de direction de texte"),
    (re.compile(r"(?i)powershell.*\s-(?:e|enc|encodedcommand)\s"), "commande PowerShell encodée"),
]
_PRIVILEGE = [
    (re.compile(r"(?:^|[\s;&|(`])(sudo|su|doas|pkexec|runuser)(?=\s|$)"), None),
    (re.compile(r"chmod\s+(?:-\w+\s+)*(?:[ugoa]*\+[rwx]*s|[0-7]?[2467][0-7]{3}\b)"), "chmod setuid"),
    (re.compile(r"\bsetcap\b|\bvisudo\b|/etc/sudoers|\bgpasswd\b|(?:^|\s)passwd\b|\bnsenter\b|\bchroot\b"), None),
    (re.compile(r"\bchown\s+(?:-\w+\s+)*root\b"), "chown root"),
    (re.compile(r"\busermod\b.*-a?G\s*\S*(?:sudo|wheel|docker|adm|root|lxd|libvirt)"), "ajout à un groupe privilégié"),
    (re.compile(r"\bdocker\s+run\b.*(?:--privileged|-v\s*/:/|--volume[= ]/:/|--pid[= ]host|--cap-add)"),
     "conteneur privilégié"),
    (re.compile(r"\b(?:insmod|modprobe|rmmod)\b"), "module noyau"),
    (re.compile(r"\bos\.set(?:e?[ug]id|re[ug]id)\b"), "changement d'identité du processus"),
]
_DESTRUCTION = [
    (re.compile(r"\brm\s+(?:-\w*[rRf]\w*|--recursive|--force)\b"), "suppression récursive ou forcée (rm -rf)", "eleve"),
    (re.compile(r"(?:^|[\s;&|(])rm\s"), "supprime des fichiers", "moyen"),
    (re.compile(r"\b(?:shred|wipefs|srm)\b|\bmkfs(?:\.\w+)?\b|\bdd\b[^|;&]*\bof=|\btruncate\b"), "efface ou écrase un disque/fichier", "eleve"),
    (re.compile(r"\bfind\b[^|;&]*\s-delete\b"), "suppression en masse (find -delete)", "eleve"),
    (re.compile(r"git\s+(?:reset\s+--hard|clean\s+-\w*f|push\b[^|;&]*(?:\s-f\b|--force)|branch\s+-D|checkout\s+--\s|"
                r"stash\s+(?:drop|clear)|filter-branch|update-ref\s+-d)"), "perte possible de travail git", "eleve"),
    (re.compile(r"(?i)\b(?:drop\s+(?:table|database|schema)|truncate\s+table|delete\s+from)\b|\bdropdb\b|flush(?:all|db)\b"),
     "suppression de données en base", "eleve"),
    (re.compile(r"\bdocker\s+(?:rm|rmi|system\s+prune|volume\s+(?:rm|prune)|container\s+prune|image\s+prune)\b|"
                r"\bkubectl\s+delete\b|\bterraform\s+destroy\b"), "supprime des ressources (conteneurs, cluster…)", "eleve"),
    (re.compile(r"shutil\.rmtree|\brmtree\(|os\.(?:remove|unlink|rmdir|removedirs)\(|\.unlink\("), "supprime des fichiers (code)", "moyen"),
]
_NETWORK_COMMANDS = {
    "curl", "wget", "wget2", "aria2c", "axel", "http", "https", "httpie", "xh", "lynx", "w3m", "links", "elinks",
    "yt-dlp", "youtube-dl", "gallery-dl", "ftp", "lftp", "tftp", "nc", "ncat", "netcat", "socat", "telnet",
    "gh", "glab", "hub", "scp", "sftp", "rsync", "rclone", "s3cmd", "smbclient", "dig", "nslookup", "host",
    "whois", "ssh", "ping", "traceroute", "mtr", "nmap", "mail", "sendmail", "mutt", "msmtp", "swaks",
    "twine", "openssl", "aws", "gcloud", "az", "kubectl", "pandoc",
}
_NETWORK_SUBCOMMANDS = {
    "git": {"push", "fetch", "pull", "clone", "ls-remote", "send-email", "submodule", "remote"},
    "pip": {"install", "download"}, "pip3": {"install", "download"}, "uv": {"add", "sync", "pip", "tool", "run"},
    "npm": {"install", "i", "ci", "publish", "add", "update"}, "pnpm": {"install", "add", "publish"},
    "yarn": {"add", "install", "publish"}, "cargo": {"install", "add", "publish", "build", "update"},
    "docker": {"push", "pull", "login", "build", "run"}, "apt": {"install", "update", "upgrade"},
    "apt-get": {"install", "update", "upgrade"},
}
_CODE_NETWORK = re.compile(
    r"\b(?:requests|httpx|aiohttp|urllib3?|http\.client|ftplib|smtplib|imaplib|poplib|websockets?|paramiko|"
    r"pycurl|urlopen|socket\.(?:socket|create_connection)|fetch\(|XMLHttpRequest)\b|https?://", re.IGNORECASE)
# Options whose value is a file or a payload, not a host (curl -o out.py, wget -O setup.py, ...).
_VALUE_OPTIONS = {"-o", "-O", "--output", "--output-document", "-d", "--data", "--data-binary", "--data-raw",
                  "--data-urlencode", "-F", "--form", "-H", "--header", "-T", "--upload-file", "-e", "-A",
                  "--user-agent", "-u", "--user", "-i", "-l", "-p", "-P", "-b", "--cookie", "-c", "--cookie-jar",
                  "--config", "-K", "-w", "--write-out", "-r", "--range", "-m", "--max-time"}
_RELAY_TOOLS = {
    "start_chat": ("démarre une nouvelle conversation avec un message écrit par Hermes "
                   "(elle ne serait pas marquée contaminée)", "eleve"),
    "kanban_create": ("crée une tâche pour un autre agent (elle démarrera hors de cette session)", "eleve"),
    "kanban_comment": ("ajoute un commentaire lu par un autre agent", "moyen"),
    "kanban_request_changes": ("renvoie une tâche à un autre agent avec des consignes", "moyen"),
    "a2a_send": ("envoie un message à un autre agent", "eleve"),
}
_NETWORK_TOOLS = {
    "web_extract", "web_crawl", "web_search", "x_search", "browser_navigate", "browser_click", "browser_type",
    "browser_press", "browser_exec", "browser_cdp", "browser_console", "browser_dialog", "browser_vault_fill",
    "browser_vault_enter_code", "image_generate", "video_generate", "text_to_speech", "vision_analyze",
    "video_analyze", "xai_video_edit", "xai_video_extend", "manage_connections", "manage_catalog",
}


@dataclass
class Facts:
    executes: List[str] = field(default_factory=list)
    hosts: List[str] = field(default_factory=list)
    unseen_urls: List[str] = field(default_factory=list)
    url_payload: List[str] = field(default_factory=list)
    secrets: List[str] = field(default_factory=list)
    secret_values: List[str] = field(default_factory=list)  # labels of known secret values found in args
    persistence: List[str] = field(default_factory=list)
    relay: List[str] = field(default_factory=list)
    hidden_code: List[str] = field(default_factory=list)
    privilege: List[str] = field(default_factory=list)
    destruction: List[Tuple[str, str]] = field(default_factory=list)  # (label, severity)
    writes: List[str] = field(default_factory=list)
    other: List[str] = field(default_factory=list)
    network: bool = False
    explainer_contact: bool = False
    floor_extra: str = "faible"

    @property
    def has_secrets(self) -> bool:
        return bool(self.secrets or self.secret_values)

    def risk_floor(self) -> str:
        level = self.floor_extra
        if self.has_secrets or self.persistence or self.hidden_code or self.privilege or self.url_payload \
                or self.explainer_contact:
            level = max_risk(level, "eleve")
        for _, severity in self.destruction:
            level = max_risk(level, severity)
        if self.executes or self.network or self.writes or self.unseen_urls or self.relay or self.other:
            level = max_risk(level, "moyen")
        return level

    def points(self, limit: int = 6) -> List[str]:
        """Short French lines for the user, most serious first."""
        out: List[str] = []
        if self.explainer_contact:
            out.append("contacte l'endpoint de l'explicateur")
        if self.secret_values:
            out.append("transporte la valeur d'un secret (" + ", ".join(self.secret_values[:3]) + ")")
        if self.secrets:
            out.append("accède à des secrets : " + ", ".join(self.secrets[:3]))
        if self.persistence:
            out.append("persistance : " + ", ".join(self.persistence[:2]))
        out.extend(self.relay[:2])
        if self.hidden_code:
            out.append("code caché ou encodé : " + ", ".join(self.hidden_code[:2]))
        if self.privilege:
            out.append("élévation de privilèges : " + ", ".join(self.privilege[:2]))
        for label, severity in self.destruction[:2]:
            out.append("destruction : " + label)
        if self.url_payload:
            out.append("données dans l'URL : " + ", ".join(self.url_payload[:2]))
        if self.unseen_urls:
            out.append("URL jamais vue : " + ", ".join(_short_url(u) for u in self.unseen_urls[:2]))
        if self.hosts:
            out.append("contacte : " + ", ".join(self.hosts[:4]) + (f" (+{len(self.hosts) - 4})" if len(self.hosts) > 4 else ""))
        elif self.network:
            out.append("utilise le réseau")
        out.extend(self.executes[:1])
        if self.writes:
            out.append("écrit : " + ", ".join(self.writes[:3]) + (f" (+{len(self.writes) - 3})" if len(self.writes) > 3 else ""))
        out.extend(self.other[:2])
        if len(out) > limit:
            out = out[:limit - 1] + [f"+{len(out) - limit + 1} autre(s) point(s)"]
        return out

    def as_list_for_explainer(self) -> List[str]:
        return self.points(limit=20)


def _short_url(url: str, limit: int = 70) -> str:
    text = re.sub(r"^\w+://", "", url)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _dedupe(items: Iterable[str]) -> List[str]:
    return list(dict.fromkeys(i for i in items if i))


class ExplainerTarget:
    """Host and port of the explainer endpoint, to flag any action that tries to reach it."""

    def __init__(self, url: str) -> None:
        self.host = url_host(url) if url else ""
        try:
            parsed = urllib.parse.urlsplit(url) if url else None
            self.port = parsed.port if parsed else None
        except ValueError:
            self.port = None

    def contacted_by(self, texts: Sequence[str]) -> bool:
        if not self.host or self.host in ("localhost", "127.0.0.1") and not self.port:
            return False
        for text in texts:
            for url in extract_urls(text):
                if url_host(url) == self.host:
                    return True
            if self.port and f"{self.host}:{self.port}" in text:
                return True
        return False


# Arguments that carry *content* (a file body, instructions for another agent) rather than the action
# itself: hosts or "rm -rf" written inside them are not something this call does.
CONTENT_ARGS = {
    "write_file": ("content",), "patch": ("new_string", "old_string", "patch"),
    "delegate_task": ("tasks", "goal", "context", "message"), "start_chat": ("message", "title"),
    "kanban_create": ("body", "title", "description"), "kanban_comment": ("body", "comment", "text"),
    "kanban_request_changes": ("body", "comment", "text", "reason"),
    "cronjob_manage": ("prompt",), "cronjob": ("prompt",),
    "image_generate": ("prompt",), "video_generate": ("prompt",), "text_to_speech": ("text", "instructions"),
}


def _split_args(tool_name: str, args: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    keys = CONTENT_ARGS.get(tool_name, ())
    action = {k: v for k, v in args.items() if k not in keys}
    content = {k: v for k, v in args.items() if k in keys}
    return strings_in(action), strings_in(content)


def extract(tool_name: str, args: Dict[str, Any], *, seen: SeenFn, secrets: SecretBook,
            explainer: Optional[ExplainerTarget] = None, call_kind: str = "effect") -> Facts:
    """All facts for one call. ``seen(url) -> bool`` tells whether a URL was already seen."""
    args = args if isinstance(args, dict) else {}
    facts = Facts()
    texts, content = _split_args(tool_name, args)
    every = texts + content

    # URLs: hosts, unseen ones, payload-looking ones (only unseen URLs can carry fabricated data).
    for url in _dedupe(u for t in texts for u in extract_urls(t)):
        host = url_host(url)
        if host:
            facts.hosts.append(host)
        if not seen(url):
            facts.unseen_urls.append(url)
            reasons = url_payload_reasons(url)
            if reasons:
                facts.url_payload.append(f"{reasons[0]} ({host or 'hôte inconnu'})")

    # Secrets: sensitive paths, secret variables, environment dumps (in the action itself), literal
    # tokens and known secret values (anywhere, content included).
    facts.secrets.extend(m.group(1) for t in texts for m in _SENSITIVE_PATH.finditer(t))
    for t in texts:
        for m in _ENV_REF.finditer(t):
            name = m.group(1) or m.group(2) or ""
            if _SECRET_NAME.search(name) and not _NOT_SECRET_NAME.search(name):
                facts.secrets.append("$" + name)
        if _ENV_DUMP.search(t):
            facts.secrets.append("toutes les variables d'environnement")
    if any(p.search(t) for t in every for p in _SECRET_LITERALS):
        facts.secrets.append("un jeton en clair")
    if tool_name in _SECRET_TOOLS:
        facts.secrets.append(_SECRET_TOOLS[tool_name])
    facts.secrets = _dedupe(facts.secrets)
    facts.secret_values = secrets.find(every)

    for pattern, label in _HIDDEN:
        if any(pattern.search(t) for t in every):
            facts.hidden_code.append(label)
    for pattern, label in _PRIVILEGE:
        for t in texts:
            m = pattern.search(t)
            if m:
                facts.privilege.append(label or m.group(0).strip(" ;&|(`"))
                break
    rm_rf = False
    for pattern, label, severity in _DESTRUCTION:
        if label == "supprime des fichiers" and rm_rf:
            continue
        if any(pattern.search(t) for t in texts):
            facts.destruction.append((label, severity))
            rm_rf = rm_rf or label.startswith("suppression récursive")
    if any(_PERSIST_CMD.search(t) for t in texts):
        facts.persistence.append("installe un démarrage ou une tâche automatique")

    if explainer is not None and explainer.contacted_by(every):
        facts.explainer_contact = True

    _tool_facts(tool_name, args, facts, "\n".join(texts), call_kind)

    if content and tool_name in CONTENT_ARGS and tool_name not in ("write_file", "patch"):
        mentioned = _dedupe(url_host(u) for t in content for u in extract_urls(t))[:3]
        flags = [label for pattern, label, _ in _DESTRUCTION if any(pattern.search(t) for t in content)][:1]
        if mentioned or flags:
            facts.other.append("les consignes transmises mentionnent : " + ", ".join(mentioned + flags))

    facts.hosts = _dedupe(facts.hosts)[:12]
    facts.persistence = _dedupe(facts.persistence)
    facts.hidden_code = _dedupe(facts.hidden_code)
    facts.privilege = _dedupe(facts.privilege)
    facts.destruction = list(dict.fromkeys(facts.destruction))
    facts.writes = _dedupe(facts.writes)
    facts.relay = _dedupe(facts.relay)
    if facts.hosts or facts.unseen_urls:
        facts.network = True
    return facts


def _tool_facts(tool: str, args: Dict[str, Any], facts: Facts, joined: str, call_kind: str) -> None:
    action = str(args.get("action") or "").strip().lower()
    if tool == "terminal":
        command = str(args.get("command") or "")
        facts.executes.append("exécute une commande sur ta machine" + (" (en arrière-plan)" if args.get("background") else ""))
        _shell_facts(command, facts)
    elif tool == "execute_code":
        code = str(args.get("code") or "")
        facts.executes.append("exécute du code Python sur ta machine")
        if _CODE_NETWORK.search(code):
            facts.network = True
        for m in re.finditer(r"""open\(\s*['"]([^'"]+)['"]\s*,\s*['"][wax+]""", code):
            facts.writes.append(m.group(1))
        for m in re.finditer(r"""Path\(\s*['"]([^'"]+)['"]\s*\)\s*\.write_(?:text|bytes)""", code):
            facts.writes.append(m.group(1))
        for m in re.finditer(r"""(?:subprocess\.\w+|os\.system|os\.popen)\(\s*(?:\[\s*)?['"]([^'"]+)""", code):
            _shell_facts(m.group(1), facts, executes=False)
        facts.persistence.extend(_persist_paths(facts.writes))
    elif tool in ("write_file", "patch"):
        path = str(args.get("path") or "")
        paths = [path] if path else []
        patch_text = str(args.get("patch") or "")
        paths += re.findall(r"(?m)^\*\*\* (?:Update|Add|Delete) File: (.+)$", patch_text)
        facts.writes.extend(paths)
        if tool == "write_file":
            facts.other.append("remplace tout le contenu du fichier")
        if re.search(r"(?m)^\*\*\* Delete File:", patch_text):
            facts.destruction.append(("supprime un fichier", "moyen"))
        facts.persistence.extend(_persist_paths(paths))
        if any(_SENSITIVE_PATH.search(p) for p in paths):
            facts.secrets.append("modifie un fichier de secrets")
    elif tool == "memory":
        verb = {"remove": "efface une entrée de", "replace": "réécrit une entrée de"}.get(action, "écrit dans")
        facts.persistence.append(f"{verb} la mémoire de Hermes (relue par les futures sessions)")
    elif tool == "skill_manage":
        ops = args.get("operations") if isinstance(args.get("operations"), list) else [args]
        actions = _dedupe(str((op or {}).get("action") or "") for op in ops if isinstance(op, dict))
        if any(a in ("delete", "remove_file") for a in actions):
            facts.destruction.append(("supprime un skill ou un de ses fichiers", "moyen"))
        facts.persistence.append("modifie les skills (instructions réutilisées par les futures sessions)")
        for op in ops:
            if isinstance(op, dict) and str(op.get("file_path") or "").endswith((".sh", ".py", ".js", ".bash")):
                facts.persistence.append("ajoute un script à un skill")
                break
    elif tool in ("cronjob_manage", "cronjob"):
        if action in ("remove", "delete"):
            facts.destruction.append(("supprime une tâche planifiée", "moyen"))
        elif action in ("run", "run_now", "trigger"):
            facts.executes.append("lance une tâche planifiée maintenant")
        else:
            facts.persistence.append("crée ou modifie une tâche planifiée (cron) qui tournera sans toi")
            if args.get("prompt"):
                facts.relay.append("la tâche démarrera une session propre avec un texte écrit par Hermes")
            if args.get("script"):
                facts.executes.append("la tâche exécutera un script")
        if args.get("deliver"):
            facts.other.append(f"livraison vers : {args.get('deliver')}")
    elif tool == "delegate_task":
        if action in ("steer",):
            facts.relay.append("envoie un message à un sous-agent en cours")
        elif action in ("stop",):
            facts.other.append("arrête un sous-agent")
        else:
            facts.relay.append("lance un sous-agent avec des consignes écrites par Hermes (il hérite de la contamination)")
    elif tool in _RELAY_TOOLS:
        label, severity = _RELAY_TOOLS[tool]
        facts.relay.append(label)
        facts.floor_extra = max_risk(facts.floor_extra, severity)
    elif tool in ("process_manage", "process"):
        if action in ("write", "submit"):
            facts.executes.append("envoie une entrée à un processus en cours")
            _shell_facts(str(args.get("data") or ""), facts, executes=False)
        elif action in ("kill", "close"):
            facts.other.append("arrête un processus")
        else:
            facts.other.append(f"process_manage {action or ''}".strip())
    elif tool.startswith("browser_"):
        labels = {
            "browser_click": "clique dans une page web", "browser_type": "tape du texte dans une page web",
            "browser_press": "appuie sur une touche dans une page web",
            "browser_exec": "exécute du code dans le navigateur", "browser_cdp": "pilote le navigateur à bas niveau",
            "browser_console": "exécute du JavaScript dans la page",
            "browser_dialog": "répond à une boîte de dialogue d'une page web",
        }
        if tool in labels:
            facts.other.append(labels[tool])
        facts.network = True
    elif mcp_server(tool) is not None:
        facts.other.append(f"appelle l'outil MCP « {tool} »")
        facts.network = True
    elif tool.startswith("connectors__"):
        facts.other.append(f"appelle le service connecté « {tool.split('__')[1] if '__' in tool else tool} »")
        facts.network = True
    elif tool in ("manage_catalog",):
        facts.persistence.append("installe ou modifie un élément du catalogue (skill, MCP, plugin)")
    elif tool in ("manage_connections",):
        facts.persistence.append("modifie les connexions à des services externes")
    elif tool in ("image_generate", "video_generate", "text_to_speech", "xai_video_edit", "xai_video_extend"):
        facts.other.append("envoie un texte à un service externe de génération")
        if args.get("output_path"):
            facts.writes.append(str(args["output_path"]))
    elif tool == "computer_use":
        facts.executes.append("contrôle la souris et le clavier de ton ordinateur")
    elif call_kind not in (READ, INTERNAL) and tool not in ("web_extract", "web_crawl", "browser_navigate",
                                                            "vision_analyze", "video_analyze"):
        facts.other.append(f"outil « {tool} » (effet non répertorié)")
    if tool in _NETWORK_TOOLS:
        facts.network = True


def _persist_paths(paths: Iterable[str]) -> List[str]:
    out = []
    for p in paths:
        m = _PERSIST_PATH.search(p or "")
        if m:
            out.append(f"modifie {m.group(1).strip()}")
    return out


def _shell_facts(command: str, facts: Facts, executes: bool = True) -> None:
    parsed = shell.parse(command)
    if parsed.ansi_c:
        facts.hidden_code.append("texte masqué par $'…'")
    if parsed.error:
        facts.other.append("commande shell difficile à lire")
    targets = shell.output_targets(parsed)
    for cmd in parsed.commands:
        name = cmd.name.rsplit("/", 1)[-1]
        args = cmd.args
        operands = [a for a in args if not a.startswith("-")]
        if name in _NETWORK_COMMANDS or (name in _NETWORK_SUBCOMMANDS and operands[:1]
                                         and operands[0] in _NETWORK_SUBCOMMANDS[name]):
            facts.network = True
            skip_next = False
            for a in args:
                if skip_next:
                    skip_next = False
                    continue
                if a in _VALUE_OPTIONS:
                    skip_next = True
                    continue
                urls = extract_urls(a)
                facts.hosts.extend(url_host(u) for u in urls)
                if urls or a.startswith("-"):
                    continue
                m = re.match(r"^(?:[\w.+-]+@)?([\w-]+(?:\.[\w-]+)+)(?::.*)?$", a)
                if m and (is_domain(m.group(1)) or re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", m.group(1))):
                    facts.hosts.append(m.group(1).lower())
            if name == "git" and operands[:1] == ["push"]:
                facts.other.append("pousse du code vers un dépôt distant")
        for op, target in cmd.redirects:
            m = re.match(r"/dev/(?:tcp|udp)/([^/]+)/", target)
            if m:
                facts.network = True
                facts.hosts.append(m.group(1))
        if name in ("cp", "mv", "install", "ln", "rsync") and len(operands) >= 2:
            targets.append(operands[-1])
        if name == "sed" and any(a.startswith("-i") or a.startswith("--in-place") for a in args):
            targets.extend(operands[1:])
        if name in ("touch", "mkdir", "chmod", "chown", "truncate") and operands:
            targets.extend(operands[1:] if name in ("chmod", "chown") else operands)
        if name == "git" and operands[:1] in (["commit"], ["merge"], ["rebase"], ["am"], ["apply"], ["checkout"], ["switch"]):
            facts.writes.append(f"dépôt git ({operands[0]})")
        if name in ("pip", "pip3", "uv", "npm", "pnpm", "yarn", "cargo", "apt", "apt-get", "brew", "gem", "go") \
                and operands[:1] and operands[0] in ("install", "add", "i", "ci", "sync", "get"):
            facts.other.append("installe des paquets")
    facts.writes.extend(targets[:10])
    facts.persistence.extend(_persist_paths(targets))
