"""A small, conservative POSIX-shell reader.

It does not run or expand anything. It splits a command line into simple commands, notes
redirections and every construct that executes something hidden from a plain reading
(``$( )``, backticks, process substitution, ANSI-C quoting, variable command names, heredocs with
substitutions), and decides whether the whole line is a *pure read*. Anything it does not fully
understand is reported as "not a pure read": a false "effect" only costs one question, a false
"read" would let an action through unseen.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

_OPERATORS = sorted(
    ["&&", "||", ";;", "|&", ">>", ">&", "&>>", "&>", "<<<", "<<-", "<<", "<&", "<>", ">|",
     ";", "&", "|", "<", ">", "(", ")"],
    key=len, reverse=True,
)
_SEPARATORS = {";", "&&", "||", "|", "|&", "&", "(", ")", ";;", "\n"}
_REDIRECTS = {">>", ">&", "&>>", "&>", "<<<", "<<-", "<<", "<&", "<>", ">|", "<", ">"}


@dataclass
class SimpleCommand:
    words: List[str] = field(default_factory=list)
    redirects: List[Tuple[str, str]] = field(default_factory=list)  # (operator, target)

    @property
    def name(self) -> str:
        return self.words[0] if self.words else ""

    @property
    def args(self) -> List[str]:
        return self.words[1:]


@dataclass
class ShellParse:
    commands: List[SimpleCommand] = field(default_factory=list)
    substitution: bool = False      # $( ), backticks, <( ), >( ), unquoted heredoc with $( )
    ansi_c: bool = False            # $'\x72\x6d' style quoting
    error: str = ""                 # unbalanced quotes, ...

    @property
    def names(self) -> List[str]:
        return [c.name for c in self.commands if c.name]


def parse(command: str) -> ShellParse:
    """Tokenise *command* into simple commands (see module docstring)."""
    out = ShellParse()
    tokens: List[Tuple[str, str]] = []  # ("w", word) | ("op", operator)
    text = command or ""
    i, n = 0, len(text)
    word: Optional[List[str]] = None
    pending_heredocs: List[Tuple[str, bool, bool]] = []  # (delimiter, strip_tabs, quoted)

    def end_word() -> None:
        nonlocal word
        if word is not None:
            tokens.append(("w", "".join(word)))
            word = None

    while i < n:
        c = text[i]
        if c in " \t\r":
            end_word()
            i += 1
            continue
        if c == "\n":
            end_word()
            tokens.append(("op", "\n"))
            i += 1
            if pending_heredocs:
                i = _consume_heredocs(text, i, pending_heredocs, out)
                pending_heredocs = []
            continue
        if c == "#" and word is None:
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "\\":
            if i + 1 < n and text[i + 1] == "\n":
                i += 2
                continue
            word = (word or []) + [text[i + 1] if i + 1 < n else ""]
            i += 2
            continue
        if c == "'":
            close = text.find("'", i + 1)
            if close < 0:
                out.error = "guillemet simple non fermé"
                return out
            word = (word or []) + [text[i + 1:close]]
            i = close + 1
            continue
        if c == "$" and i + 1 < n and text[i + 1] == "'":
            out.ansi_c = True
            close = i + 2
            while close < n and text[close] != "'":
                close += 2 if text[close] == "\\" else 1
            if close >= n:
                out.error = "guillemet $'…' non fermé"
                return out
            word = (word or []) + [text[i + 2:close]]
            i = close + 1
            continue
        if c == '"':
            j = i + 1
            buf: List[str] = []
            while j < n and text[j] != '"':
                if text[j] == "\\" and j + 1 < n:
                    buf.append(text[j + 1])
                    j += 2
                    continue
                if text[j] == "`" or (text[j] == "$" and j + 1 < n and text[j + 1] == "("):
                    out.substitution = True
                buf.append(text[j])
                j += 1
            if j >= n:
                out.error = "guillemet double non fermé"
                return out
            word = (word or []) + ["".join(buf)]
            i = j + 1
            continue
        if c == "`" or (c == "$" and i + 1 < n and text[i + 1] == "("):
            out.substitution = True
            word = (word or []) + [c]
            i += 1
            continue
        if c in ";&|<>()":
            end_word()
            op = next(o for o in _OPERATORS if text.startswith(o, i))
            if op == "(" and tokens and tokens[-1] in (("op", "<"), ("op", ">")):
                out.substitution = True  # <( ) / >( ) process substitution
            tokens.append(("op", op))
            i += len(op)
            if op in ("<<", "<<-"):
                i, delim, quoted = _read_heredoc_delimiter(text, i)
                if delim is None:
                    out.error = "délimiteur de heredoc illisible"
                    return out
                pending_heredocs.append((delim, op == "<<-", quoted))
                tokens.append(("w", delim))
            continue
        word = (word or []) + [c]
        i += 1
    end_word()

    current = SimpleCommand()
    k = 0
    while k < len(tokens):
        kind, value = tokens[k]
        if kind == "op" and value in _REDIRECTS:
            target = tokens[k + 1][1] if k + 1 < len(tokens) and tokens[k + 1][0] == "w" else ""
            if current.words and re.fullmatch(r"\d+", current.words[-1]) and _glued_fd(command, current.words[-1], value):
                current.words.pop()
            current.redirects.append((value, target))
            k += 2 if target else 1
            continue
        if kind == "op":
            if current.words or current.redirects:
                out.commands.append(current)
            current = SimpleCommand()
            k += 1
            continue
        current.words.append(value)
        k += 1
    if current.words or current.redirects:
        out.commands.append(current)
    return out


def _glued_fd(command: str, fd: str, op: str) -> bool:
    """True when "2>" style: the digits sit right against the operator in the source."""
    return (fd + op) in command


def _read_heredoc_delimiter(text: str, i: int) -> Tuple[int, Optional[str], bool]:
    n = len(text)
    while i < n and text[i] in " \t":
        i += 1
    m = re.match(r"""'([^']*)'|"([^"]*)"|\\?([A-Za-z0-9_\-.]+)""", text[i:])
    if not m:
        return i, None, False
    delim = next(g for g in m.groups() if g is not None)
    quoted = m.group(0)[0] in "'\"\\"
    return i + m.end(), delim, quoted


def _consume_heredocs(text: str, i: int, heredocs: List[Tuple[str, bool, bool]], out: ShellParse) -> int:
    n = len(text)
    for delim, strip_tabs, quoted in heredocs:
        while i < n:
            end = text.find("\n", i)
            line = text[i:] if end < 0 else text[i:end]
            i = n if end < 0 else end + 1
            if (line.lstrip("\t") if strip_tabs else line) == delim:
                break
            if not quoted and ("$(" in line or "`" in line):
                out.substitution = True
    return i


# --- pure-read decision -------------------------------------------------------------------------

Validator = Callable[[List[str]], bool]


def _any(_args: List[str]) -> bool:
    return True


def _none(args: List[str]) -> bool:
    return not args


def _without(*bad: str) -> Validator:
    def check(args: List[str]) -> bool:
        for arg in args:
            for opt in bad:
                if arg == opt or (opt.startswith("--") and arg.startswith(opt + "=")):
                    return False
                if not opt.startswith("--") and len(opt) == 2 and arg.startswith("-") \
                        and not arg.startswith("--") and opt[1] in arg[1:]:
                    return False
        return True
    return check


def _max_operands(limit: int, *bad: str) -> Validator:
    base = _without(*bad)

    def check(args: List[str]) -> bool:
        operands = [a for a in args if not a.startswith("-") or a == "-"]
        return base(args) and len(operands) <= limit
    return check


def _first_in(allowed: Sequence[str], rest: Validator = _any) -> Validator:
    def check(args: List[str]) -> bool:
        operands = [a for a in args if not a.startswith("-")]
        return bool(operands) and operands[0] in allowed and rest(args)
    return check


def _version_only(args: List[str]) -> bool:
    return args in (["--version"], ["-V"], ["version"])


_FIND_ACTIONS = ("-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls")


def _find(args: List[str]) -> bool:
    return not any(a in _FIND_ACTIONS for a in args)


_SED_PART = re.compile(
    r"""^\s*(?:(?:\d+|\$|/(?:[^/\\]|\\.)*/)(?:\s*,\s*(?:\d+|\$|/(?:[^/\\]|\\.)*/))?)?\s*!?\s*
        (?:[pdqnNg=]?
          |s/(?:[^/\\]|\\.)*/(?:[^/\\]|\\.)*/[gpiI0-9]*
          |s\|(?:[^|\\]|\\.)*\|(?:[^|\\]|\\.)*\|[gpiI0-9]*
          |s\#(?:[^#\\]|\\.)*\#(?:[^#\\]|\\.)*\#[gpiI0-9]*
          |y/(?:[^/\\]|\\.)*/(?:[^/\\]|\\.)*/)\s*$""",
    re.VERBOSE,
)


def _sed(args: List[str]) -> bool:
    scripts: List[str] = []
    operands: List[str] = []
    k = 0
    while k < len(args):
        a = args[k]
        if a in ("-e", "--expression"):
            if k + 1 >= len(args):
                return False
            scripts.append(args[k + 1])
            k += 2
            continue
        if a.startswith("--expression="):
            scripts.append(a.split("=", 1)[1])
        elif a in ("-f", "--file") or a.startswith("--file=") or a.startswith("--in-place"):
            return False
        elif a.startswith("-") and not a.startswith("--") and a != "-":
            if set(a[1:]) - set("nErsuz"):
                return False  # -i (in place), -f (script file) or anything unknown
        elif not a.startswith("--"):
            operands.append(a)
        k += 1
    if not scripts:
        if not operands:
            return False
        scripts.append(operands.pop(0))
    return all(_SED_PART.match(part) for script in scripts for part in re.split(r"[;\n]", script))


def _awk(args: List[str]) -> bool:
    program = None
    k = 0
    while k < len(args):
        a = args[k]
        if a in ("-f", "--file") or a.startswith("-f"):
            return False
        if a in ("-F", "-v", "--assign", "--field-separator"):
            k += 2
            continue
        if a.startswith("-"):
            k += 1
            continue
        program = a
        break
    if program is None:
        return False
    if "system" in program or "/inet" in program or re.search(r"(?<!\|)\|(?!\|)", program):
        return False
    return not re.search(r"\bprintf?\b[^;{}]*>", program)


_GIT_SIMPLE_READS = {
    "status", "log", "show", "diff", "rev-parse", "ls-files", "ls-tree", "cat-file", "blame", "annotate",
    "describe", "shortlog", "show-ref", "for-each-ref", "count-objects", "rev-list", "merge-base",
    "name-rev", "grep", "whatchanged", "version", "show-branch", "cherry", "diff-tree",
    "diff-index", "diff-files", "check-ignore", "check-attr", "var",
}
_GIT_BAD_OPTS = ("--output", "--ext-diff", "--textconv", "-O", "--open-files-in-pager", "--exec")


def _git(args: List[str]) -> bool:
    k = 0
    while k < len(args) and args[k].startswith("-"):
        a = args[k]
        if a in ("--no-pager", "-P", "--no-optional-locks", "--literal-pathspecs", "--no-replace-objects"):
            k += 1
            continue
        if a == "-C":
            k += 2
            continue
        if a.startswith("--git-dir=") or a.startswith("--work-tree="):
            k += 1
            continue
        return False  # -c, --exec-path, --config-env, ...
    if k >= len(args):
        return False
    sub, rest = args[k], args[k + 1:]
    if any(r == b or r.startswith(b + "=") for r in rest for b in _GIT_BAD_OPTS):
        return False
    if sub in _GIT_SIMPLE_READS:
        return True
    if sub == "branch":
        listing = {"-a", "-r", "-v", "-vv", "--list", "-l", "--all", "--remotes", "--show-current",
                   "--verbose", "--no-color", "--color", "--sort=-committerdate"}
        return all(r in listing or r.startswith("--sort=") or r.startswith("--format=") for r in rest)
    if sub == "tag":
        if any(r in ("-d", "--delete", "-a", "--annotate", "-s", "--sign", "-f", "--force", "-m", "-F", "-u")
               for r in rest):
            return False
        return not rest or rest[0] in ("-l", "--list", "-n") or all(r.startswith("--sort=") for r in rest)
    if sub == "remote":
        return not rest or rest in (["-v"], ["--verbose"]) or (rest[0] == "get-url" and len(rest) <= 3)
    if sub == "stash":
        return bool(rest) and rest[0] in ("list", "show")
    if sub == "config":
        reads = {"--get", "--get-all", "--get-regexp", "--list", "-l", "--show-origin", "--show-scope",
                 "--global", "--local", "--system", "--name-only", "-z", "--null"}
        return bool(rest) and any(r in ("--get", "--get-all", "--get-regexp", "--list", "-l") for r in rest) \
            and all(r in reads or not r.startswith("-") for r in rest)
    if sub == "reflog":
        return not rest or rest[0] == "show" or rest[0].startswith("-")
    if sub == "worktree":
        return rest[:1] == ["list"]
    if sub == "submodule":
        return rest[:1] == ["status"]
    if sub == "notes":
        return rest[:1] in (["list"], ["show"])
    return False


_SYSTEMCTL_READS = {"status", "show", "cat", "list-units", "list-unit-files", "list-timers", "is-active",
                    "is-enabled", "is-failed", "list-dependencies", "list-sockets", "list-jobs"}
_DOCKER_READS = {"ps", "images", "logs", "inspect", "version", "info", "top", "port", "diff", "history"}


def _systemctl(args: List[str]) -> bool:
    operands = [a for a in args if not a.startswith("-")]
    flags_ok = all(a in ("--user", "--no-pager", "--all", "-a", "--full", "-l", "--failed", "--plain", "--quiet", "-q")
                   or a.startswith("--type=") or a.startswith("--state=") or a.startswith("-n") or a.startswith("--lines")
                   or not a.startswith("-") for a in args)
    return flags_ok and bool(operands) and operands[0] in _SYSTEMCTL_READS


def _docker(args: List[str]) -> bool:
    operands = [a for a in args if not a.startswith("-")]
    if not operands:
        return False
    if operands[0] in _DOCKER_READS:
        return True
    return operands[:2] in (["image", "ls"], ["container", "ls"], ["network", "ls"], ["volume", "ls"],
                            ["compose", "ps"], ["compose", "logs"]) or operands[:1] == ["stats"] and "--no-stream" in args


def _pip(args: List[str]) -> bool:
    operands = [a for a in args if not a.startswith("-")]
    return _version_only(args) or (bool(operands) and operands[0] in ("list", "show", "freeze", "check"))


READ_COMMANDS: Dict[str, Validator] = {
    **dict.fromkeys(
        ["ls", "dir", "vdir", "cat", "tac", "head", "tail", "wc", "nl", "less", "more", "stat", "du",
         "df", "free", "uptime", "whoami", "id", "groups", "pwd", "echo", "printf", "true", "false", ":",
         "test", "[", "basename", "dirname", "realpath", "readlink", "which", "whereis", "type", "md5sum",
         "sha1sum", "sha224sum", "sha256sum", "sha384sum", "sha512sum", "b2sum", "cksum", "cmp", "comm",
         "diff", "column", "fold", "expand", "unexpand", "rev", "strings", "od", "hexdump", "base32",
         "base64", "cut", "paste", "join", "tr", "grep", "egrep", "fgrep", "zgrep", "zcat", "bzcat", "xzcat",
         "zless", "jq", "ps", "pgrep", "pstree", "lsof", "ss", "netstat", "lsblk", "findmnt", "nproc",
         "lscpu", "lsusb", "lspci", "uname", "arch", "locale", "tty", "sleep", "cd", "pushd", "popd", "dirs",
         "printenv", "seq", "numfmt", "sum", "look", "getconf"], _any),
    "env": _none, "history": _none, "hostname": _none, "mount": _none,
    "date": _without("-s", "--set"),
    "dmesg": _without("-C", "-c", "--clear", "--read-clear", "-D", "-E", "-n"),
    "journalctl": _without("--vacuum-size", "--vacuum-time", "--vacuum-files", "--rotate", "--flush",
                           "--sync", "--relinquish-var", "--smart-relinquish-var", "--setup-keys",
                           "--update-catalog"),
    "sort": _without("-o", "--output", "--compress-program"),
    "uniq": _max_operands(1),
    "xxd": _max_operands(1),
    "rg": _without("--pre", "--pre-glob", "--hostname-bin"),
    "fd": _without("-x", "--exec", "-X", "--exec-batch"),
    "fdfind": _without("-x", "--exec", "-X", "--exec-batch"),
    "find": _find, "sed": _sed, "awk": _awk, "gawk": _awk, "mawk": _awk, "nawk": _awk,
    "git": _git, "systemctl": _systemctl, "docker": _docker, "podman": _docker,
    "pip": _pip, "pip3": _pip,
    "python": _version_only, "python3": _version_only, "node": _version_only, "uv": _version_only,
    "npm": lambda a: _version_only(a) or a[:1] in (["ls"], ["list"]),
    "nvidia-smi": lambda a: all(x in ("-L", "--list-gpus", "-q", "--query") or x.startswith("--query-")
                                or x.startswith("--format=") or x.startswith("-i") or x.isdigit() for x in a),
    "tree": _without("-o"),
    "file": _without("-C", "--compile"),
    "ag": _without("--pager"),
    "command": lambda a: bool(a) and a[0] in ("-v", "-V"),
}

_NULL_TARGETS = {"/dev/null", "/dev/stdout", "/dev/stderr"}


def _redirects_are_reads(cmd: SimpleCommand) -> bool:
    for op, target in cmd.redirects:
        if target.startswith(("/dev/tcp/", "/dev/udp/")):
            return False  # bash opens a network connection for these paths
        if op in ("<", "<<", "<<-", "<<<", "<&"):
            continue
        if op in (">&",) and target in ("1", "2", "-"):
            continue
        if op in (">", ">>", "&>", "&>>", ">|") and target in _NULL_TARGETS:
            continue
        return False
    return True


def is_pure_read(command: str) -> bool:
    """True only when every simple command of *command* is a known read with safe arguments."""
    parsed = parse(command)
    if parsed.error or parsed.substitution or parsed.ansi_c or not parsed.commands:
        return False
    for cmd in parsed.commands:
        if not cmd.words:
            return False  # bare redirection such as "> file"
        name = cmd.name
        if "=" in name or "/" in name or "$" in name or name.startswith("-"):
            return False
        validator = READ_COMMANDS.get(name)
        if validator is None or not validator(cmd.args) or not _redirects_are_reads(cmd):
            return False
    return True


def output_targets(parsed: ShellParse) -> List[str]:
    """Files a command line writes through redirections or ``tee``."""
    targets: List[str] = []
    for cmd in parsed.commands:
        for op, target in cmd.redirects:
            if op in (">", ">>", "&>", "&>>", ">|") and target not in _NULL_TARGETS:
                targets.append(target)
            elif op == ">&" and target not in ("1", "2", "-"):
                targets.append(target)
        if cmd.name == "tee":
            targets.extend(a for a in cmd.args if not a.startswith("-"))
    return targets
