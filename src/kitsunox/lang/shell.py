"""Shell, PowerShell and batch text with comments and printed messages blanked.

The install rules read install scripts as text (`npm.install-script-loader`,
`npm.install-persistence`). A line that only prints, a help text telling the user what to run
(`echo "add: export PATH=... >> ~/.bashrc"`, `Write-Host 'irm https://x/install.ps1 | iex'`),
names what the script does not do. `mask_script_messages` blanks such lines and comment lines,
keeping every offset and line, so a match still points at the right line.

A line *prints* when it starts with `echo`, `printf`, `Write-Host`/`-Output`/`-Warning`/
`-Information`, or a function the script defines whose body only prints (`info() { echo -e
"  ${DIM}$1${NC}"; }`, `@ornexus/neocortex`'s `info`/`ok`/`warn`). It is a message, and blanked,
only when nothing in it outside its quoted text runs or writes: no pipe (`echo <base64> |
base64 -d | sh` runs), no redirect to a file (`echo 'export X=1' >> ~/.bashrc` writes one;
`>&2`, `>/dev/null` and `/dev/tty` don't), no `;`/`&&`/`||` (more commands follow), and no
command substitution anywhere (`echo "$(curl ...)"` runs `curl`).

`fetched_as_data` (round 9 Q1, `npm.install-download` v5) tells a `curl`/`wget` whose response
is captured into a variable and only ever used as data (`ID=$(curl -s https://host/uuid)`, sent
on as a request body) from one whose response runs or is saved.
"""

from __future__ import annotations

import re
from typing import Final

_COMMENT: Final = re.compile(r"^[ \t]*(?:#|REM\b|::|@REM\b).*$", re.MULTILINE | re.IGNORECASE)
PRINTERS: Final = (
    "echo",
    "@echo",
    "printf",
    "write-host",
    "write-output",
    "write-warning",
    "write-information",
)
_QUOTED: Final = re.compile(r""""(?:[^"\\\n]|\\.)*"|'[^'\n]*'""")
# Redirects that write nowhere a reader would care about.
_HARMLESS_REDIRECT: Final = re.compile(r"\d?>>?\s*(?:&\s*\d|/dev/(?:null|stderr|stdout|tty)\b)")
# A function definition: `name() {`, `function name {`, `function name() {`, PowerShell
# `function Name {` / `function Name($x) {`, with the body on the same line or the next lines.
_FUNCTION: Final = re.compile(
    r"^[ \t]*(?:function[ \t]+(?P<a>[\w-]+)[ \t]*(?:\([^)\n]*\))?|(?P<b>[\w-]+)[ \t]*\([ \t]*\))"
    r"[ \t]*\{(?P<rest>[^\n]*)$",
    re.MULTILINE | re.IGNORECASE,
)
# Statements a print-only function may have besides printing: locals, parameters, tests.
_BENIGN_STATEMENT: Final = re.compile(
    r"^(?:local\b|param\b|return\b|:$|\[\[?\s|\[\s|test\b|\$?\w+=|\}|\{|$)", re.IGNORECASE
)
MAX_FUNCTION_LINES: Final = 20


def mask_script_messages(text: str) -> str:
    """`text` with comment lines and message lines (module docstring) blanked; the same length
    and the same line breaks."""
    text = _COMMENT.sub(_blank, text)
    printers = PRINTERS + tuple(sorted(print_only_functions(text)))
    starts = re.compile(
        r"^[ \t]*(?:" + "|".join(re.escape(p) for p in printers) + r")(?![\w-]).*$",
        re.MULTILINE | re.IGNORECASE,
    )
    return starts.sub(lambda m: _blank(m) if only_prints(m.group(0)) else m.group(0), text)


def only_prints(line: str) -> bool:
    """Whether a printing line (it starts with a printer) does nothing but print."""
    if "$(" in line or "`" in line:
        return False
    outside = _HARMLESS_REDIRECT.sub(" ", _QUOTED.sub(" ", line))
    return not any(c in outside for c in "|;&><")


def print_only_functions(text: str) -> set[str]:
    """Names of the functions `text` defines whose every statement prints (`only_prints`
    lines) or is a local, a parameter, a test or a return."""
    names: set[str] = set()
    lines = text.split("\n")
    index = {m.start(): m for m in _FUNCTION.finditer(text)}
    offset = 0
    for n, line in enumerate(lines):
        match = index.get(offset)
        offset += len(line) + 1
        if match is None:
            continue
        name = match.group("a") or match.group("b")
        rest = match.group("rest").strip()
        if rest.endswith("}"):  # one line: `info() { echo -e "$1"; }`
            body = [rest[:-1]]
        else:
            body = [rest]
            for following in lines[n + 1 : n + 1 + MAX_FUNCTION_LINES]:
                if following.strip() == "}":
                    break
                body.append(following)
            else:
                continue  # no closing brace in reach: not a small printer
        if _prints_only(body):
            names.add(name.lower())
    return names


def _prints_only(body: list[str]) -> bool:
    printed = False
    for line in body:
        for statement in re.split(r";|&&|\|\|", _QUOTED.sub('""', line)):
            statement = statement.strip()
            word = statement.split(" ", 1)[0].lower() if statement else ""
            if word in PRINTERS:
                if _HARMLESS_REDIRECT.sub(" ", statement).count(">") or "|" in statement:
                    return False
                printed = True
            elif not _BENIGN_STATEMENT.match(statement):
                return False
    return printed


def _blank(match: re.Match[str]) -> str:
    return " " * len(match.group(0))


# `fetched_as_data` (2026-11-12, round 9 Q, `npm.install-download` v5): a constant `curl`/`wget`
# captured into a variable, `ID=$(curl -s 'https://host/api/x')`: nothing but options and the
# URL inside (no `$`, backtick, pipe or nested command), the whole line.
_CAPTURE: Final = re.compile(
    r"^[ \t]*(?:(?:local|export|readonly|declare)[ \t]+)?(?P<name>[A-Za-z_]\w*)="
    r"(?P<q>\"?)\$\([ \t]*(?P<tool>curl|wget)[ \t]+(?P<args>[^$`()|;&<>\n]*)\)(?P=q)[ \t]*$",
    re.MULTILINE,
)
# curl options that write the response to a file (`-o`, `-O`, also inside `-sSLo`), or read a
# config that may; wget writes a file unless told to write to stdout (`-O -`, `-qO-`).
_CURL_SAVES: Final = re.compile(
    r"(?:^|\s)(?:-[A-Za-z]*[oOK]|--(?:output|remote-name|remote-name-all|output-dir|config)\b)"
)
_WGET_STDOUT: Final = re.compile(r"(?:^|\s)(?:-[A-Za-z]*O\s*-|--output-document[= ]-)(?:\s|$)")
# A variable assignment and its value (quoted parts may span lines: `DATA='{ ... }'`).
_ASSIGN: Final = re.compile(
    r"^[ \t]*(?:(?:local|export|readonly|declare)[ \t]+)?(?P<name>[A-Za-z_]\w*)="
    r"(?P<value>(?:'[^']*'|\"(?:[^\"\\]|\\.)*\"|[^\s'\"`;&|()<>])*)",
    re.MULTILINE,
)
# A request option whose value is sent, never run or saved: data and headers.
_SENT: Final = re.compile(
    r"(?<!\S)(?:-d|--data(?:-raw|-binary|-urlencode)?|-H|--header|--post-data|--body-data)"
    r"(?:=|\s+)(?:[\"'][^\"']*|[^\"'\s]*)$"
)
_TEST: Final = re.compile(r"^\s*(?:if\s+|elif\s+|while\s+|until\s+|!\s*)?(?:\[\[?\s|test\s)")


def fetched_as_data(text: str, offset: int) -> bool:
    """Whether the `curl`/`wget` on the line at `offset` of a shell script fetches only data:
    a constant command captured into a variable (`_CAPTURE`) that keeps the response (curl with
    no `-o`/`-O`, wget with `-O -`), and whose text is never run or saved. Every use of the
    variable, and of each variable assigned from it (followed through assignments), is inside
    another assignment's value, a test (`[ ... ]`, `[[ ... ]]`, `test`), or the data or header
    of a `curl`/`wget` request (`-d "$DATA"`, `--post-data="$DATA"`). `@lightdash/cli`'s
    `track.sh` fetches a random UUID from `uuidgenerator.net` into `INSTALLATION_ID`, puts it in
    a JSON body and POSTs that to its analytics host: nothing it fetches runs or is saved."""
    start = text.rfind("\n", 0, offset) + 1
    capture = _CAPTURE.match(text, start)
    if capture is None or capture.end() < offset:
        return False
    args = capture.group("args")
    if capture.group("tool") == "curl" and _CURL_SAVES.search(args):
        return False
    if capture.group("tool") == "wget" and not _WGET_STDOUT.search(args):
        return False
    tainted = {capture.group("name")}
    values = [(m.start("value"), m.end("value"), m.group("name")) for m in _ASSIGN.finditer(text)]
    grew = True
    while grew:
        grew = False
        for begin, end, name in values:
            if name not in tainted and _uses_at(text[begin:end], tainted):
                tainted.add(name)
                grew = True
    for use in _uses_at(text, tainted):
        if capture.start() <= use < capture.end():
            continue
        if any(begin <= use < end for begin, end, _ in values):
            continue
        line_start = text.rfind("\n", 0, use) + 1
        line_end = text.find("\n", use)
        line = text[line_start : line_end if line_end >= 0 else len(text)]
        before = text[line_start:use]
        if re.search(r"(?<![\w-])(?:curl|wget)(?![\w-])", line) and not _risky(line):
            if _SENT.search(before):
                continue
        elif _TEST.match(line) and not _risky(line):
            continue
        return False
    return True


def _uses_at(text: str, names: set[str]) -> list[int]:
    pattern = r"\$\{?[#!]?(?:" + "|".join(re.escape(n) for n in sorted(names)) + r")(?!\w)"
    return [m.start() for m in re.finditer(pattern, text)]


# What on a line would run or save a value: a pipe, a redirect to a file, a command
# substitution, or a command that runs or writes text.
_RISKY_WORDS: Final = re.compile(
    r"(?<![\w-])(?:eval|exec|source|sh|bash|zsh|dash|ksh|node|python\d*(?:\.\d+)?|perl|ruby"
    r"|php|chmod|xargs|tee|install|mv|cp|dd|base64|openssl)(?![\w-])"
)


def _risky(line: str) -> bool:
    outside = _HARMLESS_REDIRECT.sub(" ", _QUOTED.sub('""', line))
    return (
        bool(_RISKY_WORDS.search(line))
        or "$(" in line
        or "`" in line
        or "|" in outside.replace("||", "")
        or ">" in outside
    )
