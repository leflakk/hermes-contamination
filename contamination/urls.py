"""URL extraction, normalisation and defanging.

Two jobs that must never mix:

* *matching* (is this URL one the session has already seen?) works on a strict normal form
  where only the scheme and host are case-folded: a single extra byte in the path, query,
  user-info or fragment makes the URL "unseen", because that is exactly where an exfiltration
  payload goes;
* *display* (anything shown in Matrix) is defanged so that no client can turn a URL, a domain
  or an IP into a link or fetch a preview of it.
"""

from __future__ import annotations

import re
from typing import Iterable, List, Optional
from urllib.parse import urlsplit

from .tlds import TLDS

_SCHEMES = r"(?:https?|ftps?|sftp|wss?|git|ssh|file|gopher|ldap)"
URL_RE = re.compile(_SCHEMES + r"://[^\s<>\"'`{}|\\^]+", re.IGNORECASE)
# A hostname-shaped token: labels of letters/digits/hyphens joined by dots. Checked against the
# TLD list afterwards, so "setup.py" counts (".py" is Paraguay, Element links it) and
# "pyproject.toml" does not.
_DOMAIN_RE = re.compile(r"(?<![\w.-])((?:[^\W_](?:[\w-]{0,61}[^\W_])?\.)+([^\W\d_][\w-]{0,62}))(?![\w-])")
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_TRAILING = ".,;:!?'\")]}>»…"
_DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21, "ws": 80, "wss": 443, "ssh": 22, "sftp": 22}


def _trim(url: str) -> str:
    """Drop trailing punctuation that belongs to the sentence, keeping balanced parentheses."""
    while url and url[-1] in _TRAILING:
        if url[-1] == ")" and url.count("(") >= url.count(")"):
            break
        url = url[:-1]
    return url


def extract_urls(text: str, limit: int = 200) -> List[str]:
    """URLs in *text*, in order of appearance, without duplicates."""
    if not text:
        return []
    seen: dict = {}
    for match in URL_RE.finditer(text):
        url = _trim(match.group(0))
        if "://" in url and len(url.split("://", 1)[1]) > 0 and url not in seen:
            seen[url] = None
            if len(seen) >= limit:
                break
    return list(seen)


def _idna(host: str) -> str:
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return host


def normalize_url(url: str) -> str:
    """Strict normal form used for the "already seen" test (see module docstring)."""
    url = _trim(url.strip())
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").rstrip(".").lower()
        port: Optional[int] = parts.port
    except ValueError:
        return url
    if not scheme or not host:
        return url
    host = _idna(host)
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"  # IPv6 literal
    netloc = host
    if port is not None and port != _DEFAULT_PORTS.get(scheme):
        netloc = f"{host}:{port}"
    if "@" in parts.netloc:
        netloc = parts.netloc.rsplit("@", 1)[0] + "@" + netloc
    out = f"{scheme}://{netloc}{parts.path or '/'}"
    if parts.query or url.split("#", 1)[0].endswith("?"):
        out += "?" + parts.query
    if parts.fragment or url.endswith("#"):
        out += "#" + parts.fragment
    return out


def url_host(url: str) -> str:
    """Lower-cased host of *url* ("" when it has none)."""
    try:
        return (urlsplit(_trim(url.strip())).hostname or "").rstrip(".").lower()
    except ValueError:
        return ""


def origin_url(host: str) -> List[str]:
    """Root URLs a user means when they type a bare domain ("regarde docs.python.org")."""
    host = _idna(host.lower().rstrip("."))
    return [f"https://{host}/", f"http://{host}/"]


def is_domain(token: str) -> bool:
    match = _DOMAIN_RE.fullmatch(token)
    return bool(match) and match.group(2).lower() in TLDS


def extract_domains(text: str, limit: int = 100) -> List[str]:
    """Bare hostnames (with a real TLD) and IPv4 literals found in *text*."""
    found: dict = {}
    for match in _DOMAIN_RE.finditer(text or ""):
        if match.group(2).lower() in TLDS:
            found.setdefault(match.group(1).lower(), None)
        if len(found) >= limit:
            break
    for match in _IPV4_RE.finditer(text or ""):
        if all(0 <= int(part) <= 255 for part in match.group(0).split(".")):
            found.setdefault(match.group(0), None)
    return list(found)


_B64ISH = re.compile(r"^[A-Za-z0-9+/=_-]{16,}$")


def url_payload_reasons(url: str) -> List[str]:
    """Why *url* may be carrying data out (empty list when it looks like a plain address)."""
    reasons: List[str] = []
    raw = url.strip()
    if re.search(r"\$\(|\$\{|`|\$[A-Za-z_]", raw):
        reasons.append("valeur calculée insérée dans l'URL")
    try:
        parts = urlsplit(_trim(raw))
        host = parts.hostname or ""
    except ValueError:
        return reasons + ["URL mal formée"]
    if parts.username or parts.password:
        reasons.append("identifiants ou données avant le nom d'hôte")
    if parts.query:
        reasons.append("paramètres dans l'URL")
    if parts.fragment and len(parts.fragment) > 12:
        reasons.append("données après #")
    labels = host.split(".")
    if any(len(label) >= 25 for label in labels) or len(labels) >= 7:
        reasons.append("sous-domaine inhabituel (fuite possible par DNS)")
    for segment in parts.path.split("/"):
        if len(segment) >= 48 or (_B64ISH.match(segment) and _looks_random(segment)):
            reasons.append("segment de chemin qui ressemble à des données encodées")
            break
    return reasons


def _looks_random(token: str) -> bool:
    classes = sum(bool(re.search(p, token)) for p in (r"[a-z]", r"[A-Z]", r"\d"))
    return classes >= 3 or (classes == 2 and len(token) >= 24)


# --- display ------------------------------------------------------------------------------------

_SCHEME_RE = re.compile(r"\b(https?|ftps?|wss?)(?=://)", re.IGNORECASE)
_SCHEME_SWAP = {"http": "hxxp", "https": "hxxps", "ftp": "fxp", "ftps": "fxps", "ws": "wx", "wss": "wxs"}


def defang(text: str) -> str:
    """Make every URL, domain, e-mail domain, Matrix server name and IPv4 non-clickable."""
    if not text:
        return text
    text = _SCHEME_RE.sub(lambda m: _SCHEME_SWAP.get(m.group(1).lower(), m.group(1)), text)

    def _domain(match: "re.Match[str]") -> str:
        if match.group(2).lower() not in TLDS:
            return match.group(0)
        return match.group(0).replace(".", "[.]")

    text = _DOMAIN_RE.sub(_domain, text)
    return _IPV4_RE.sub(lambda m: m.group(0).replace(".", "[.]"), text)


def hosts_in(texts: Iterable[str], limit: int = 20) -> List[str]:
    """Hosts of every URL in *texts* (deduplicated, in order)."""
    out: dict = {}
    for text in texts:
        for url in extract_urls(text):
            host = url_host(url)
            if host:
                out.setdefault(host, None)
            if len(out) >= limit:
                return list(out)
    return list(out)
