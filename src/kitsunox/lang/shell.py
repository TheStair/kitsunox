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
