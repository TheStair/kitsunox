"""What the files an npm install script runs can do (Stage 3).

Install scripts run on `npm install` with the user's privileges. `npm.install-hook` (Stage 1)
sees the hook's command line change; this rule sees the code behind it, including when the
command stays `node setup.js` and only `setup.js` changes.

`day1` (2026-10-28): an install-script file using network, process, the whole environment or
dynamic code: benign 0.9% of updates and 0.2% of new packages; malicious 70.2% and 33.7%.
"""

from __future__ import annotations

import difflib
import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Final

from kitsunox.core.models import Evidence, EvidenceKind, Finding, Severity
from kitsunox.core.rules import BaseRule
from kitsunox.ecosystems.npm.install import GYP_INLINE, loaded_files
from kitsunox.ecosystems.npm.rules.install_persistence import code_text
from kitsunox.ecosystems.npm.rules.install_shapes import (
    DELETES,
    INERT,
    OTHER_PACKAGE,
    RISKY_TEXT,
    SYSTEM_PATH,
    plain_text,
    unreadable,
    user_wide,
)
from kitsunox.ecosystems.npm.rules.metadata import INSTALL_HOOKS, scripts, snippet
from kitsunox.lang.agent_config import HOME_REFERENCE, names_agent_dir
from kitsunox.lang.javascript import (
    Capability,
    in_text,
    language_for,
    mask_printed_text,
)
from kitsunox.rules.capabilities import evidence
from kitsunox.rules.static import Obfuscated
from kitsunox.stages.ast import CodeChange
from kitsunox.util.text import collapse_runs

C = Capability
RISKY: Final = frozenset({C.NETWORK, C.PROCESS, C.ENV_ALL, C.DYNAMIC_CODE, C.DYNAMIC_REQUIRE})


class InstallScriptCode(BaseRule):
    """The code an install hook runs reaches the network, runs processes, takes the whole
    environment or runs dynamic code. For an update, only capabilities the install code didn't
    have before count.

    v2 (2026-10-30): the install code includes the package files it loads by a constant path
    (`install.followed_files`): +12 malicious `vm-day1` samples, +1 benign.

    v3 (2026-11-10, round 4): also install code that hides code past the edge of the screen
    (`hidden_code`: a run of `HIDDEN_RUN`+ spaces or tabs, then code that is not a comment or a
    message, on one line), in a file that is new or whose previous version had none. Its
    capabilities can be invisible too: `hauntview@0.2.9` (malicious, 2026-11-09) put an
    obfuscated loader behind 266 tabs on line 14 of `scripts/postinstall.mjs`; it finds its
    C2 through an Ethereum transaction and evals what it fetches, and Stage 3 saw only the
    file's honest `child_process` import. On the 1,710 verdicted live versions with install
    code and the 18 `vm-day1` samples checked, it fires on that version only.

    v4 (2026-11-10, round 5, `docs/proposals/precision-round5-J.md`): the whole environment
    doesn't count when every whole-`process.env` reference of the install code is a parameter's
    default value (`environment_injected`: `function f(env = process.env)`, `{ env =
    process.env } = {}`), the way code takes its environment so tests can pass another."""

    id = "npm.install-script-code"
    version = 4
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Install script runs risky code"

    def evaluate_code(self, change: CodeChange) -> Sequence[Finding]:
        if change.install is None:
            return ()
        risky = change.install.capabilities & RISKY
        if change.before is not None:
            risky -= change.install_before.capabilities if change.install_before else frozenset()
        if C.ENV_ALL in risky and environment_injected(change):
            risky -= {C.ENV_ALL}
        hidden = _hidden_install_code(change)
        if hidden:
            path, line, text = hidden[0]
            return (
                self.finding(
                    f"`npm install` runs {path}, which hides code past the edge of the screen "
                    f"(line {line}, after {HIDDEN_RUN}+ spaces or tabs)"
                    + (f" and uses {', '.join(sorted(c.value for c in risky))}" if risky else "")
                    + ". Only a reader who scrolls sideways sees it.",
                    Evidence(
                        kind=EvidenceKind.FILE_SPAN,
                        path=path,
                        line_start=line,
                        line_end=line,
                        snippet=text,
                    ),
                    *evidence(change.install, risky),
                ),
            )
        if not risky:
            return ()
        files = ", ".join(sorted({u.path for u in change.install.uses}))
        names = ", ".join(sorted(c.value for c in risky))
        return (
            self.finding(
                f"`npm install` runs {files}, which uses {names}"
                + (" (new to the install code)." if change.before is not None else "."),
                *evidence(change.install, risky),
            ),
        )


# A whole-`process.env` reference (as `TOUCHED`'s "the whole environment") and one that is a
# parameter's default value: `(env = process.env)`, `, env = process.env)`, `{ env =
# process.env } = {}`, also over line breaks.
_WHOLE_ENV: Final = re.compile(r"process\.env(?![\w$])(?!\s*(?:\.|\[|\?\.))")
_DEFAULT_ENV: Final = re.compile(r"[(,{]\s*[\w$]+\s*=\s*(process\.env)\s*(?=[,)}])")


def environment_injected(change: CodeChange) -> bool:
    """Every install file Stage 3 saw take the whole environment has at least one whole-
    `process.env` reference (comments and messages masked), and every such reference is a
    parameter's default value (`_DEFAULT_ENV`). Such code reads the variables it names from
    the object it is given; harvesting the environment needs the object itself
    (`JSON.stringify(process.env)`, `Object.entries(process.env)`, `{ ...process.env }`)."""
    install = change.install
    paths = {u.path for u in install.uses if u.use.capability is C.ENV_ALL} if install else set()
    if not paths:
        return False
    for path in paths:
        data = change.install_files.get(path)
        if data is None or language_for(path) is None:
            return False
        text = code_text(path, data)
        defaults = {m.start(1) for m in _DEFAULT_ENV.finditer(text)}
        whole = [m.start() for m in _WHOLE_ENV.finditer(text)]
        if not whole or any(start not in defaults for start in whole):
            return False
    return True


# Code pushed past the edge of the screen: a run of this many spaces or tabs, then code.
HIDDEN_RUN: Final = 100
_HIDDEN: Final = re.compile(rf"[ \t]{{{HIDDEN_RUN},}}(?=\S)")


def hidden_code(path: str, data: bytes) -> tuple[int, str] | None:
    """The first line of an install file with code after a run of `HIDDEN_RUN`+ spaces or tabs,
    as (1-based line, the code that follows), when that code is not a comment or a message
    (`code_text`): an ASCII-art banner in a `console.log` is not hidden code."""
    if b"\x00" in data[:8192]:
        return None
    raw = data.decode("utf-8", "replace").split("\n")
    if not any(_HIDDEN.search(line) for line in raw):
        return None
    masked = code_text(path, data).split("\n")
    language = language_for(path)
    offset = 0
    for n, line in enumerate(raw):
        for match in _HIDDEN.finditer(line):
            after = masked[n][match.end() : match.end() + 1] if n < len(masked) else ""
            if not after.strip() or after in "\"'`":
                continue
            start = offset + len(line[: match.end()].encode())
            if language is not None and in_text(data, language, start):
                continue  # a string's or a comment's own spaces
            return n + 1, " ".join(line[match.end() : match.end() + 160].split())
        offset += len(line.encode()) + 1
    return None


def _hidden_install_code(change: CodeChange) -> list[tuple[str, int, str]]:
    """Install files with hidden code (`hidden_code`) that is new: the file is new, or its
    previous version had none."""
    before = change.install_files_before or {}
    found = []
    for path, data in sorted(change.install_files.items()):
        if before.get(path) == data:
            continue
        if (hit := hidden_code(path, data)) is None:
            continue
        old = before.get(path)
        if old is not None and hidden_code(path, old) is not None:
            continue
        found.append((path, *hit))
    return found


MAX_DIFF_LINES: Final = 40  # changed lines shown per file
MAX_DIFF_LINE_CHARS: Final = 200  # a minified line is cut
MAX_FILES_SHOWN: Final = 3
# difflib is quadratic on lines that repeat without being junked (20,000 lines cycling 150
# values: 45 s); 2,000 such lines take 0.06 s. A longer file is reported changed, not diffed.
MAX_DIFFED_LINES: Final = 2_000
HUNK: Final = re.compile(r"@@ -\d+(?:,\d+)? \+(\d+)")  # a diff's own hunk header


class InstallScriptChanged(BaseRule):
    """A file an install hook runs changed since the previous version, or the hooks run a file
    they didn't before: what `npm install` executes changed even when the hook's command line
    didn't (`npm.install-hook` sees only the command). The evidence is the changed lines, so a
    reviewer reads the change itself. Only a version with a base whose files were read is
    compared; a new package has nothing to compare with.

    First VM day (2026-10-30): 39 of 52 changed hook commands changed only their own version
    string (`@pulumi/*`); their files are what this rule compares.

    v3 (2026-10-31): a file another install file loads (`install.loaded_files`: the followed
    ones) counts only when its change adds a risky use (`_adds_risky`). Library code a hook
    imports changes with most releases: 7 of the first 120 re-scored live reports were that
    alone, all benign (6 add no risky use). `vm-day1`: 2,503 malicious reported (was 2,506:
    three `aicp-tracker` versions, a family still reported through 1.0.7), 20 benign (was 21).

    v4 (2026-11-09): LOW, weight 1, when every changed file is the same code but for volatile
    strings (`VOLATILE`: versions in any form, dates and build stamps, digests and commit
    hashes, integrity values; same URL hosts) or for the text of messages it prints
    (`mask_printed_text`). Generated installers pin the release they download, a digest and a
    build date; a newly run, binary or too-long file, or one with any other change, keeps the
    MEDIUM. Of the 422 reviewed benign versions this rule alone reported, v4 no longer reports
    64 (50 volatile strings, 14 printed text); it loses no malicious, unwanted or unverified
    version and no `vm-day1` malicious sample (`docs/stages/ast.md`).

    v5 (2026-11-09, round 4, `docs/proposals/precision-round4-A.md`): content-aware. The
    finding stays MEDIUM only when the change touches what an attack needs (`touched`): a
    changed or added line, outside comments and messages, that runs a process, reaches the
    network, names a URL, IP address or host, holds encoded data or decodes it, names a
    credential or token, the home directory, a shell or package-manager command, the whole
    environment or dynamic code; a newly run file that does any of that; a binary; a file too
    long to diff that gains such a match. Otherwise (a refactor, an option, error handling, a
    template's text) it is LOW, weight 1, and says so; the diff stays in the evidence.

    v6 (2026-11-10, round 5, `docs/proposals/precision-round5-J.md`): what the previous install
    code already ran isn't touched (`touched`, `_Before`): a changed or newly run line that is a
    line of the previous install code in any file (moved, re-indented, a bundle chunk renamed)
    counts for nothing, and a URL counts only when who serves it is new (its host, and the
    repository owner on a code host: `_url_identity`)."""

    id = "npm.install-script-changed"
    version = 6
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Code an install script runs changed"

    def evaluate_code(self, change: CodeChange) -> Sequence[Finding]:
        before = change.install_files_before
        if before is None:
            return ()
        old_version = (change.previous_version or "").encode()
        new_version = change.snapshot.ref.version.encode()
        loaded = loaded_files(change.install_files)
        changed = [
            path
            for path, data in sorted(change.install_files.items())
            if not _same(before.get(path), data, old_version, new_version)
            and (path not in loaded or _adds_risky(change, path, before.get(path), data))
        ]
        if not changed:
            return ()
        since = f" since {change.previous_version}" if change.previous_version else ""
        parts = []
        for path in changed:
            old = before.get(path)
            if old is None:
                parts.append(f"{path} (newly run)")
            elif (counted := _counts(old, change.install_files[path])) is None:
                parts.append(f"{path} (too long to diff)")
            else:
                longest = (
                    f", longest added line {counted[2]:,} characters"
                    if counted[2] > MAX_DIFF_LINE_CHARS
                    else ""
                )
                parts.append(f"{path} (+{counted[0]} -{counted[1]} lines{longest})")
        minor = all(
            _unremarkable(path, before.get(path), change.install_files[path]) for path in changed
        )
        kinds = set() if minor else touched(change, changed)
        if not minor and not kinds and names_agent_dir(change.install_files) and user_wide(change):
            kinds.add(AGENT_USER_WIDE)  # where such code writes can't be told from the diff
        if minor:
            note = MINOR_NOTE
        elif kinds:
            note = TOUCHES.format(", ".join(sorted(kinds)))
        else:
            note = INERT_NOTE
        return (
            self.finding(
                f"`npm install` runs code that changed{since}: {', '.join(parts)}." + note,
                *(
                    _diff_evidence(path, before.get(path), change.install_files[path])
                    for path in changed[:MAX_FILES_SHOWN]
                ),
                severity=None if kinds else Severity.LOW,
                weight=None if kinds else 1.0,
            ),
        )


TOUCHES: Final = " The change touches {}."
# Install code that names an AI agent's directory and the home directory
# (`npm.install-agent-user-wide`'s test) may write agent configuration user-wide through code
# the diff doesn't show; a change to it keeps the MEDIUM (`@aweray/aweshell-cli@0.4.25`,
# `@easyhaloo/afk-opencode@1.2.1`, `@mobileaidev/ai-app-bridge`: unwanted, inert diffs).
AGENT_USER_WIDE: Final = "install code that names an AI agent's directory and the home directory"
INERT_NOTE: Final = (
    " The changed lines run no process, reach no network, URL or host, hold no encoded data,"
    " credential, home-directory path, shell or package-manager command, whole environment or"
    " dynamic code: nothing an attack needs (comments and messages aside)."
)
# What install code an attack changes touches, by kind, on code text with comments and
# messages masked (`code_text`). Stage 3's risky uses (`RISKY`) on those lines count as well.
TOUCHED: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (
        "processes",
        re.compile(
            r"(?<![\w$.])(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork|execa"
            r"|execaSync|execaCommand|execaCommandSync)\s*\(|child_process|\bBun\.spawn"
        ),
    ),
    (
        "the network",
        re.compile(
            r"\bhttps?\.(?:get|request)\s*\(|(?<![\w$.])fetch\s*\(|\baxios\b|(?<![\w$.])got\s*\("
            r"|\bWebSocket\b|\bnet\.(?:connect|createConnection|Socket)\b|\bdns\.\w+\s*\("
            r"|XMLHttpRequest|\bundici\b|[\"'`](?:node:)?(?:https?|net|dns|tls|dgram)[\"'`]"
        ),
    ),
    (
        "URLs or hosts",
        re.compile(
            r"[a-z][a-z0-9+.-]*://[^\s\"'`)<>\\]+|(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"
            r"|[\"'`@](?:[a-z0-9-]+\.)+(?:com|net|org|io|dev|app|xyz|top|site|online|ru|cn|me"
            r"|co|cc|tk|pw|link|live|info|biz|cloud|tech|pro|club|vip|shop|icu|ws|su|in)[\"'`/:]",
            re.IGNORECASE,
        ),
    ),
    (
        "encoded data",
        re.compile(
            r"[A-Za-z0-9+/]{100,}={0,2}|(?:[0-9a-fA-F]{2}){50,}|\batob\s*\(|fromCharCode"
            r"|Buffer\.from\([^)]{0,200}[\"'`](?:base64|hex)[\"'`]|(?:\\x[0-9a-fA-F]{2}){4}"
        ),
    ),
    (
        "credentials",
        re.compile(
            r"\.npmrc|\.ssh\b|id_rsa|id_ed25519|\.aws\b|\.git-credentials|\.docker/config"
            r"|\.kube/config|Login Data|Local State|keychain|wallet|/etc/(?:shadow|passwd)"
            r"|npm\s+publish|_authToken|registry\.npmjs\.org/-/|(?<![\w$])\.env\b(?![.\w])"
            r"|\b[A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|ACCESS_KEY)\b",
        ),
    ),
    ("the home directory", re.compile(HOME_REFERENCE.pattern + r"|getUserHome|\bHOME\b")),
    (
        "shell commands",
        re.compile(
            r"\b(?:curl|wget|powershell|pwsh|sudo|crontab|systemctl|launchctl|schtasks|setx|iex"
            r"|Invoke-WebRequest|Invoke-Expression|Invoke-RestMethod|certutil|bitsadmin|mshta"
            r"|rundll32|regsvr32|osascript)\b|\breg(?:\.exe)?\s+add\b|\b(?:ba|z)?sh\s+-c\b"
            r"|\|\s*(?:ba|z)?sh\b|\bchmod\s+[+0-7]"
        ),
    ),
    (
        "package-manager commands",
        re.compile(
            r"\b(?:npx|bunx|pnpx)\s|\b(?:npm|pnpm|yarn|bun)\s+(?:i|install|add|exec|dlx|x)\b"
            r"|\bpip3?\s+install\b|\bcargo\s+install\b|\bgo\s+install\b"
        ),
    ),
    ("the whole environment", re.compile(r"process\.env(?!\s*(?:\.|\[|\?\.))")),
    (
        "dynamic code",
        re.compile(
            r"(?<![\w$.])eval\s*\(|\bFunction\s*\(|\bvm\.(?:run\w*|Script|compileFunction)\b"
            r"|\bimport\(\s*(?![\s'\"`])|\brequire\(\s*(?![\s'\"`])"
        ),
    ),
)
HIDDEN_KIND: Final = "code hidden past the edge of the screen"
# A string literal in code of `LONG_STRING`+ characters: a packed payload or string table
# (`hauntview@0.2.9`'s loader starts with one) that no other kind need name.
LONG_KIND: Final = "a string literal of 4 KB or more"
LONG_STRING: Final = 4096
LONG_LITERAL: Final = re.compile(rf"""(["'`])(?:(?!\1)[^\\\n]|\\.){{{LONG_STRING},}}+\1""")
_USE_KIND: Final = {
    C.NETWORK: "the network",
    C.PROCESS: "processes",
    C.ENV_ALL: "the whole environment",
    C.DYNAMIC_CODE: "dynamic code",
    C.DYNAMIC_REQUIRE: "dynamic code",
}


def touched(change: CodeChange, paths: Sequence[str]) -> set[str]:
    """What the change to `paths` (install files that changed) touches, by kind (`TOUCHED`,
    and Stage 3's risky uses): on the changed and added lines of a diffable file; anywhere in
    a newly run file; for a file too long to diff, the matches it has that its previous
    version didn't. A binary file is "binary code".

    v6: what the previous install code already ran doesn't count (`_Before`). A line whose code
    (comments and messages masked, whitespace and volatile strings aside) is a line of the
    previous install code, in any file, was moved, re-indented or renamed with its file, not
    written: neither its matches nor its risky uses count. A URL counts only when its host is
    new to the install code (`_new_host`)."""
    before = change.install_files_before or {}
    seen = _Before(before)
    kinds: set[str] = set()
    for path in paths:
        new, old = _lf(change.install_files[path]), before.get(path)
        if b"\x00" in new[:8192] or (old is not None and b"\x00" in old[:8192]):
            kinds.add("binary code")
            continue
        text = code_text(path, new)
        masked = text.split("\n")
        uses = [
            (u.use.line, _USE_KIND[u.use.capability], (u.use.capability, u.use.detail))
            for u in (change.install.uses if change.install else ())
            if u.path == path and u.use.capability in RISKY
        ]
        if old is None:
            lines = set(range(len(masked)))
            if hidden_code(path, new) is not None:
                kinds.add(HIDDEN_KIND)
            if LONG_LITERAL.search(text):
                kinds.add(LONG_KIND)
        else:
            old = _lf(old)
            a, b = (
                old.decode("utf-8", "replace").split("\n"),
                new.decode("utf-8", "replace").split("\n"),
            )
            if not _diffable(a, b):
                before_text = code_text(path, old)
                kinds |= {
                    kind
                    for kind, token in _matches(text) - _matches(before_text)
                    if seen.counts(kind, token)
                }
                if hidden_code(path, new) is not None and hidden_code(path, old) is None:
                    kinds.add(HIDDEN_KIND)
                if _long_literals(text) - _long_literals(before_text):
                    kinds.add(LONG_KIND)
                continue
            matcher = difflib.SequenceMatcher(None, a, b, autojunk=False)
            lines = {
                n
                for tag, _, _, j1, j2 in matcher.get_opcodes()
                if tag in ("replace", "insert")
                for n in range(j1, j2)
            }
            if (hidden := hidden_code(path, new)) is not None and hidden[0] - 1 in lines:
                kinds.add(HIDDEN_KIND)
            if any(n < len(masked) and LONG_LITERAL.search(masked[n]) for n in lines):
                kinds.add(LONG_KIND)
        written = {n for n in lines if n < len(masked) and not seen.moved(masked[n])}
        kinds |= {
            kind
            for n in sorted(written)
            for kind, token in _matches(masked[n])
            if seen.counts(kind, token)
        }
        kinds |= {kind for line, kind, _ in uses if line - 1 in written}
    return kinds


class _Before:
    """The previous install code, as v6 of `touched` compares with it: its masked lines
    (whitespace collapsed, volatile strings masked) and who serves its URLs. A token it had,
    on a line that changed, still counts: ignoring those (round 5 J2) was rejected by the owner
    on 2026-11-10, since it loses `vm-day1`'s `gina@0.7.1` and `esoftplay@0.0.196`."""

    def __init__(self, before: Mapping[str, bytes]) -> None:
        texts = [
            code_text(path, _lf(data))
            for path, data in before.items()
            if b"\x00" not in data[:8192]
        ]
        self.lines = {_line_key(line) for text in texts for line in text.split("\n")}
        self.lines.discard("")
        self.hosts = {
            identity
            for text in texts
            for m in _URL.finditer(text)
            if (identity := _url_identity(m.group(0))) is not None
        }

    def moved(self, line: str) -> bool:
        return _line_key(line) in self.lines

    def counts(self, kind: str, token: str) -> bool:
        return kind != URL_KIND or _new_host(token, self.hosts)


URL_KIND: Final = "URLs or hosts"
_URL: Final = re.compile(r"[a-z][a-z0-9+.-]*://[^\s\"'`)<>\\]+", re.IGNORECASE)
_URL_PARTS: Final = re.compile(
    r"[a-z][a-z0-9+.-]*://\[?([^/\s\"'`)<>\\:\]]+)\]?(?::\d+)?(/[^?#\s\"'`)<>\\]*)?",
    re.IGNORECASE,
)
# Hosts where anyone can publish: the repository owner is part of who serves the file.
CODE_HOSTS: Final = frozenset(
    {
        "github.com",
        "raw.githubusercontent.com",
        "codeload.github.com",
        "gist.github.com",
        "gist.githubusercontent.com",
        "gitlab.com",
        "bitbucket.org",
        "api.github.com",
    }
)


def _url_identity(url: str) -> str | None:
    """Who serves `url`: its host, and on a code host (`CODE_HOSTS`) the repository owner too
    (`github.com/o`, `api.github.com/repos/o`); None when the host or that owner is built from a
    variable or a volatile string."""
    match = _URL_PARTS.match(url)
    if match is None:
        return None
    host = match.group(1).lower()
    if host in CODE_HOSTS:
        segments = [p for p in (match.group(2) or "").split("/") if p]
        if host == "api.github.com" and segments[:1] == ["repos"]:
            segments = segments[1:]
        host = f"{host}/{segments[0].lower()}" if segments else host
    return None if "$" in host or "\x00" in host or "{" in host else host


def _new_host(token: str, hosts: set[str]) -> bool:
    """A URL counts unless the previous install code named who serves it (`_url_identity`:
    the package's own release repository, the registry); an IP address, a bare host name, or a
    host or owner built from a variable always counts."""
    identity = _url_identity(token)
    return identity is None or identity not in hosts


def _line_key(line: str) -> str:
    return VOLATILE.sub("\x00", " ".join(line.split()))


def _long_literals(text: str) -> set[str]:
    return {m.group(0) for m in LONG_LITERAL.finditer(text)}


def _kinds(text: str) -> set[str]:
    return {kind for kind, pattern in TOUCHED if pattern.search(text)}


def _matches(text: str) -> set[tuple[str, str]]:
    """Every `TOUCHED` match of `text`, with volatile strings (`VOLATILE`) masked."""
    return {
        (kind, VOLATILE.sub("\x00", m.group(0)))
        for kind, pattern in TOUCHED
        for m in pattern.finditer(text)
    }


def _same(old: bytes | None, new: bytes, old_version: bytes, new_version: bytes) -> bool:
    """`new` runs the same code as `old`: equal once line endings are LF (`@tera-system/pro`
    0.2.33 converted its CRLF `install.js`, +0 -0 lines), or `old` with its own version string
    swapped for the new one (generated install scripts embed it: `workerd`'s `install.js`
    downloads `${pkg}@1.20261029.1`)."""
    if old is None:
        return False
    old, new = _lf(old), _lf(new)
    return old == new or (
        bool(old_version) and old_version in old and old.replace(old_version, new_version) == new
    )


# Strings a generated install script embeds that change with each release while the code stays
# the same: a version in any form (`1.2.3`, `v1.2.3-canary.4+b5`; not part of a dotted quad, so
# an IP address is never one), a date or build stamp (`2026-11-04`, `20261104`,
# `202611041730`), a digest or commit hash (7-12, 32, 40, 64, 96 or 128 hex digits with a
# letter and a digit), an integrity value (`sha512-...`).
_HEX: Final = (
    r"(?:[0-9a-f]{7,12}|[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{96}|[0-9a-f]{128})"
)
VOLATILE: Final = re.compile(
    r"sha(?:256|384|512)-[A-Za-z0-9+/]{43,86}={0,2}"
    r"|(?<![\w.])v?\d+\.\d+\.\d+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?(?:\+[0-9A-Za-z.-]+)?(?![\w.]*\.\d)"
    r"|\b\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?Z?)?\b"
    rf"|\b(?=[0-9a-f]*[a-f])(?=[0-9a-f]*\d){_HEX}\b"
    r"|\b20\d{6}(?:\d{2,6})?\b"
)
URL_HOST: Final = re.compile(r"""https?://([^\s"'`)<>\\/:]+)""", re.IGNORECASE)
MINOR_NOTE: Final = (
    " Only version strings, digests, dates or printed messages changed, so the code it runs"
    " is the same."
)


def _unremarkable(path: str, old: bytes | None, new: bytes) -> bool:
    """`new` is `old` but for volatile strings (`VOLATILE`, with the same URL hosts), the text
    of the messages it prints (`mask_printed_text`, JavaScript only), or both. A newly run or
    binary file never is."""
    if old is None or b"\x00" in new[:8192] or b"\x00" in old[:8192]:
        return False
    old, new = _lf(old), _lf(new)
    if _same_but_volatile(old, new):
        return True
    language = language_for(path)
    if language is None:
        return False
    masked_old, masked_new = mask_printed_text(old, language), mask_printed_text(new, language)
    return (
        masked_old is not None
        and masked_new is not None
        and _same_but_volatile(masked_old, masked_new)
    )


def _same_but_volatile(old: bytes, new: bytes) -> bool:
    a, b = old.decode("utf-8", "replace"), new.decode("utf-8", "replace")
    return VOLATILE.sub("\x00", a) == VOLATILE.sub("\x00", b) and sorted(
        {h.lower() for h in URL_HOST.findall(a)}
    ) == sorted({h.lower() for h in URL_HOST.findall(b)})


def _adds_risky(change: CodeChange, path: str, old: bytes | None, new: bytes) -> bool:
    """The change to `path` adds a line with a risky use (RISKY: a network or process module,
    the whole environment, dynamic code). A file too long to diff counts if it has one. Lines
    are split on LF only, as the parser numbers them."""
    lines = {
        u.use.line
        for u in (change.install.uses if change.install else ())
        if u.path == path and u.use.capability in RISKY
    }
    hidden = hidden_code(path, new)
    if hidden is not None and (old is None or hidden_code(path, old) is None):
        return True  # v5: code pushed off-screen hides its uses (`hauntview@0.2.9`)
    a = (old or b"").decode("utf-8", "replace").split("\n")
    b = new.decode("utf-8", "replace").split("\n")
    if not lines and not any(len(line) >= LONG_STRING for line in b):
        return False
    if not _diffable(a, b):
        return bool(lines) or bool(
            _long_literals(code_text(path, new)) - _long_literals(code_text(path, old or b""))
        )
    matcher = difflib.SequenceMatcher(None, a, b, autojunk=False)
    added = {
        n + 1
        for tag, _, _, j1, j2 in matcher.get_opcodes()
        if tag in ("replace", "insert")
        for n in range(j1, j2)
    }
    if lines & added:
        return True
    masked = code_text(path, new).split("\n")
    return any(n <= len(masked) and LONG_LITERAL.search(masked[n - 1]) for n in added)


def _lf(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n")


def _lines(data: bytes) -> list[str]:
    return data.decode("utf-8", "replace").splitlines()


def _diffable(old: list[str], new: list[str]) -> bool:
    return len(old) <= MAX_DIFFED_LINES and len(new) <= MAX_DIFFED_LINES


def _counts(old: bytes, new: bytes) -> tuple[int, int, int] | None:
    """Added and removed lines, and the length of the longest added line (the summary names it
    when a diff line is cut: `hauntview@0.2.9` read "+3 -1 lines" for 12.8 KB of new code);
    None for a file too long to diff."""
    a, b = _lines(old), _lines(new)
    if not _diffable(a, b):
        return None
    plus = minus = longest = 0
    for line in difflib.unified_diff(a, b, lineterm="", n=0):
        if line.startswith("+") and not line.startswith("+++"):
            plus += 1
            longest = max(longest, len(line) - 1)
        elif line.startswith("-") and not line.startswith("---"):
            minus += 1
    return plus, minus, longest


def _diff_evidence(path: str, old: bytes | None, new: bytes) -> Evidence:
    """The changed lines as a unified diff (one line of context), cut to MAX_DIFF_LINES lines
    of MAX_DIFF_LINE_CHARS characters; package text, escaped by every renderer. Long runs of
    spaces and tabs are collapsed to a counted marker before the cut (`util.text.collapse_runs`),
    so code a run pushes off screen is shown (`hauntview@0.2.9`: 266 tabs, then a loader)."""
    if b"\x00" in new[:8192] or (old is not None and b"\x00" in old[:8192]):
        return Evidence(kind=EvidenceKind.FILE_SPAN, path=path, snippet="(binary file changed)")
    a, b = _lines(old or b""), _lines(new)
    if not _diffable(a, b):
        text = f"(changed: {len(a)} lines before, {len(b)} now; too long to diff)"
        return Evidence(kind=EvidenceKind.FILE_SPAN, path=path, snippet=text)
    diff = list(difflib.unified_diff(a, b, lineterm="", n=1))[2:]
    first = next((int(m.group(1)) for h in diff if (m := HUNK.match(h))), None)
    shown = [collapse_runs(line)[:MAX_DIFF_LINE_CHARS] for line in diff[:MAX_DIFF_LINES]]
    if len(diff) > MAX_DIFF_LINES:
        shown.append(f"... {len(diff) - MAX_DIFF_LINES} more diff lines")
    return Evidence(
        kind=EvidenceKind.FILE_SPAN,
        path=path,
        line_start=first or None,
        snippet="\n".join(shown),
    )


# javascript-obfuscator's string-array rotation, minified or not: it shuffles the string array
# until a checksum of parseInt'd entries matches. Identifier renaming doesn't change it.
ROTATION_PROLOGUE: Final = re.compile(
    r"while\s*\(\s*!!\[\]\s*\)\s*\{\s*try\s*\{\s*(?:const|let|var)\s+[\w$]+\s*=\s*-?\(?\s*-?parseInt\("
)


class InstallScriptObfuscated(BaseRule):
    """A file `npm install` runs is obfuscated (javascript-obfuscator's `_0x` identifiers, the
    `static.obfuscated` test, on the first 256 KiB kept of each install file). The code runs
    with the user's privileges at install and reading it says nothing about what it does, so
    only a sandbox run (Stage 5) can; HIGH puts it in front of Stage 5's per-run cap and of the
    queue. For an update, only an obfuscated file that is new to the install code or changed
    counts: the same bytes ran before.

    Added 2026-10-31 at the owner's request ("flag it"): five packages reviewed as inconclusive
    run obfuscated code at install (`sppurt`, `motionchart-cli`, `sino-bc-cli`, `whybug`,
    `calculatorscool346`), scored 3-11, some outside Stage 5's cap of 30.

    v2 (2026-11-01): also javascript-obfuscator output whose identifiers were renamed (no
    `_0x`), by its string-array rotation prologue, `while(!![]){try{const x=parseInt(`, which
    only that tool writes. `sino-bc-cli`'s `dist/index.js` (`const bg=b;(function(c,d){...`)
    has it and no `_0x` identifier at all."""

    id = "npm.install-script-obfuscated"
    version = 2
    severity = Severity.HIGH
    weight = 4.0
    title = "Install script runs obfuscated code"
    _detector: Final = Obfuscated()

    def evaluate_code(self, change: CodeChange) -> Sequence[Finding]:
        before = change.install_files_before or {}
        found = []
        for path, data in sorted(change.install_files.items()):
            if before.get(path) == data:
                continue
            text = data.decode("utf-8", "replace")
            if matches := self._detector.evaluate_text(text):
                found.append(
                    (path, matches[0].line, f"{matches[0].explanation} {matches[0].snippet}")
                )
            elif rotation := ROTATION_PROLOGUE.search(text):
                line = text.count("\n", 0, rotation.start()) + 1
                start = max(0, rotation.start() - 60)
                snippet = text[start : rotation.end() + 60].replace("\n", " ")
                found.append(
                    (path, line, f"javascript-obfuscator's string-array rotation: {snippet}")
                )
        if not found:
            return ()
        paths = ", ".join(path for path, _, _ in found)
        new = " (new or changed since the previous version)" if change.before is not None else ""
        return (
            self.finding(
                f"`npm install` runs obfuscated code{new}: {paths}. Only a sandbox run can show "
                "what it does.",
                *(
                    Evidence(
                        kind=EvidenceKind.FILE_SPAN,
                        path=path,
                        line_start=line,
                        line_end=line,
                        snippet=snippet,
                    )
                    for path, line, snippet in found[:MAX_FILES_SHOWN]
                ),
            ),
        )


# Install hooks that only run a well-known build tool: node-gyp and the prebuilt-binary loaders
# that fall back to it, and development tools a published package runs at install by mistake
# (git hooks, a package-manager check, patches to its own dependencies). Whole command lines,
# compared exactly: `node-gyp rebuild && node x.js` is not one.
BUILD_TOOL_HOOKS: Final = frozenset(
    {
        "node-gyp-build",
        "node-gyp-build-optional-packages",
        "node-gyp rebuild",
        "node-gyp rebuild -j max",
        "prebuild-install",
        "prebuild-install || node-gyp rebuild",
        "node-pre-gyp install --fallback-to-build",
        "husky",
        "husky install",
        "npx only-allow pnpm",
        "npx only-allow yarn",
        "npx only-allow bun",
        "patch-package",
        # v3: the same check for npm, and its `-y` and `bunx` spellings; Open Collective's
        # thank-you banner.
        "npx only-allow npm",
        "npx -y only-allow npm",
        "npx -y only-allow pnpm",
        "bunx only-allow bun",
        "opencollective-postinstall",
        "node-gyp-build || node-gyp rebuild",
        "npx @mapbox/node-pre-gyp install --fallback-to-build",
        # v4: node-gyp-build that may fail quietly, or with a job count.
        "node-gyp-build || exit 0",
        "JOBS=${JOBS:-max} node-gyp-build",
    }
)
# v3: Playwright's browser download, when the package depends on Playwright (so the
# `playwright` npm runs is Playwright's own) and doesn't name a `playwright` bin itself.
# `--with-deps` (system packages through `apt-get`, decision 0015) is not on the list.
PLAYWRIGHT_HOOKS: Final = frozenset(
    {
        "playwright install",
        "playwright install chromium",
        "npx playwright install",
        "npx playwright install chromium",
    }
)
PLAYWRIGHT_PACKAGES: Final = frozenset({"playwright", "playwright-core", "@playwright/test"})
_LAUNCHERS: Final = frozenset({"npx", "bunx", "-y", "||"})


def tool_shadowed(manifest: Mapping[str, Any], commands: Iterable[str]) -> list[str]:
    """Tools the hooks run (`husky`, `patch-package`, `only-allow` after `npx`/`bunx`) that
    the package's own `bin` also names: npm links a package's bins before its install hooks
    run, so `"bin": {"husky": "x.js"}` makes `husky` the package's own code."""
    bin_field = manifest.get("bin")
    if isinstance(bin_field, Mapping):
        names = {str(k) for k in bin_field}
    elif isinstance(bin_field, str):
        name = manifest.get("name")
        names = {name.split("/")[-1]} if isinstance(name, str) else set()
    else:
        return []
    shadowed = {w for c in commands for w in c.split() if w not in _LAUNCHERS and w in names}
    return sorted(shadowed)


# v2: what a native add-on's `binding.gyp` asks `node` for so the compiler finds the headers of
# `node-addon-api` or `nan`: `<!(node -p "require('node-addon-api').include")`,
# `<!@(node -p "require('node-addon-api').gyp")`, `<!(node -e "require('nan')")`. It only
# prints a directory of an installed package; any other command, or any gyp action, still
# counts. (Before v4 `gyp_commands` cut an expansion at its first `)` before a quote, so the
# closing `)` and quote are optional here; since v4 it reads the whole expansion.)
HEADER_LOOKUP: Final = re.compile(
    r"""node\s+-[ep]\s+"require\(\\?'(?:node-addon-api|nan)\\?'\)?"""
    r"""(?:\.(?:include|include_dir|gyp|targets))?"?"""
)
# v3: tree-sitter's generated `binding.gyp` adds the grammar's external scanner to the
# sources when the file exists: `<!@(node -p "fs.existsSync('src/scanner.c') ? 'src/scanner.c'
# : ''")`, or (newer templates) `"has_scanner": "<!(node -p \"fs.existsSync('src/scanner.c')\")"`
# beside `<!(node -p "require('node-addon-api').targets")` (v3 adds `.targets` above).
# Before v4 the newer form arrived cut as `node -p "fs.existsSync('src/scanner.c'`, so the
# rest is optional.
SCANNER_LOOKUP: Final = re.compile(
    r"""node\s+-p\s+"fs\.existsSync\(\\?'src/scanner\.(c|cc)\\?'(?:\)"""
    r"""(?:\s*\?\s*\\?'src/scanner\.\1\\?'\s*:\s*\\?'\\?')?"?)?"""
)


# v4: two more ways to print a directory: `node-addon-api`'s own, without its `index.js`
# (`@ohos-ports/zlib`), and one of the package's directories as an absolute path
# (`node -p "require('path').resolve('lib')"`, `pwaos-addon`). Exact forms only.
PATH_LOOKUP: Final = re.compile(
    r"""node\s+-e\s+"console\.log\(require\.resolve\('node-addon-api'\)"""
    r"""\.replace\(/\[\\\\/\]index\.js\$/, ''\)\)\""""
    r"""|node\s+-p\s+"require\('path'\)\.resolve\('(?!\.\.)[\w-]+(?:/[\w-]+)*'\)\""""
)


def header_lookup(command: str) -> bool:
    """Whether a `binding.gyp` command only looks up `node-addon-api`'s or `nan`'s headers, or
    (v3) whether tree-sitter's `src/scanner.c` exists, or (v4) prints a directory
    (`PATH_LOOKUP`)."""
    command = command.strip()
    return (
        HEADER_LOOKUP.fullmatch(command) is not None
        or SCANNER_LOOKUP.fullmatch(command) is not None
        or PATH_LOOKUP.fullmatch(command) is not None
    )


# v4: a `binding.gyp` command that runs a package script with constant arguments
# (`<!@(node scripts/sources.mjs zint)`): how add-ons list the sources of vendored libraries.
# It counts only when that script (and what it loads) can do nothing but read the package:
# `gyp_scripts`.
GYP_NODE_FILE: Final = re.compile(
    r"node\s+(?:\./)?(?P<path>[\w./-]+\.(?:js|cjs|mjs))(?:\s+[\w.:=-]+)*"
)
# What writes, moves or opens a file (or deletes one: `DELETES`). A gyp action that writes is
# how `@atedone/workspace-bootstrap@0.0.1` (unwanted) left its state behind.
# The specific names count wherever they appear (`fs["writeFileSync"]`, `Reflect.apply(...)`);
# the short ones (`open`, `cp`, `link`, `write`) when called or quoted, and `write` not on
# `process.stdout`/`stderr`.
WRITES: Final = re.compile(
    r"\b(?:writeFile|appendFile|createWriteStream|mkdir|mkdtemp|copyFile|rename|symlink|chmod"
    r"|lchmod|chown|lchown|truncate|ftruncate|utimes|lutimes|futimes|writev|cpSync|openSync"
    r"|linkSync|writeSync)(?:Sync)?\b"
    r"|\b(?:open|cp|link)\s*\(|(?<!stdout\.)(?<!stderr\.)\bwrite\s*\("
    r"""|["'`](?:open|cp|link|write)["'`]"""
)


def gyp_scripts(change: CodeChange) -> list[str] | None:
    """The package scripts `binding.gyp` runs besides its header lookups, when every one of
    them is `node <script> <constant args>` and the scripts only read: JavaScript the parser
    and a reader see (`plain_text`, not `unreadable`), with no capability beyond `INERT`, no
    package loaded by name, no write (`WRITES`, `DELETES`), and none of S5's text guards
    (`RISKY_TEXT`, `SYSTEM_PATH`, `OTHER_PACKAGE`, home or agent directories); for an update,
    no capability the install code didn't have before. None when another command runs."""
    scripts_run = []
    for command in change.build_commands:
        if header_lookup(command):
            continue
        match = GYP_NODE_FILE.fullmatch(command.strip())
        if match is None or match.group("path") not in change.install_files:
            return None
        scripts_run.append(match.group("path"))
    if not scripts_run:
        return []
    install = change.install
    shipped = {p: c for p, c in change.install_files.items() if p != GYP_INLINE}
    if install is None:
        return None
    caps = {u.use.capability for u in install.uses if u.path != GYP_INLINE}
    text = "\n".join(c.decode("utf-8", "replace") for c in shipped.values())
    if (
        not caps <= INERT
        or any(p.path != GYP_INLINE for p in install.packages)
        or not all(language_for(p) is not None and plain_text(c) for p, c in shipped.items())
        or unreadable(text)
        or any(rx.search(text) for rx in (WRITES, DELETES, RISKY_TEXT, SYSTEM_PATH, OTHER_PACKAGE))
        or user_wide(change)
        or names_agent_dir(change.install_files)
    ):
        return None
    if change.before is not None and caps - (
        change.install_before.capabilities if change.install_before else frozenset()
    ):
        return None
    return sorted(set(scripts_run))


def _build_tool(command: str, manifest: Mapping[str, Any]) -> bool:
    if command in BUILD_TOOL_HOOKS:
        return True
    if command not in PLAYWRIGHT_HOOKS:
        return False
    declared = {
        **_mapping(manifest.get("dependencies")),
        **_mapping(manifest.get("devDependencies")),
        **_mapping(manifest.get("optionalDependencies")),
        **_mapping(manifest.get("peerDependencies")),
    }
    return any(name in declared for name in PLAYWRIGHT_PACKAGES)


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


class InstallBuildTool(BaseRule):
    """Every install hook of the version runs only a build tool (`BUILD_TOOL_HOOKS`), and its
    `binding.gyp` runs no command (`CodeChange.build_commands`, from `install.gyp_commands`).
    An explanation for Stage 4, not a signal: `correlate.EXPLAINED` makes `npm.install-hook`
    LOW, weight 1, when this is present. npm itself adds `install: node-gyp rebuild` to any
    package with a `binding.gyp`, so writing it out adds nothing; what the build runs is in the
    gyp file, and a gyp action or `<!(...)` expansion keeps the hook's own severity
    (`@atedone/workspace-bootstrap@0.0.1` ran its payload from a gyp action, 2026-10-31).

    Added 2026-11-08 (`docs/proposals/precision-round2.md`, F2): 12 benign live reports, no
    positive; none of the 433 `vm-day1` malicious samples reported only through the install
    rules has build-tool-only hooks.

    v2 (2026-11-09, `docs/proposals/precision-round3.md` X6): a `binding.gyp` command that only
    looks up `node-addon-api`'s or `nan`'s headers (`HEADER_LOOKUP`) is not counted: it is how
    most add-ons find them. Any other expansion or gyp action still keeps the hook's
    severity.

    v3 (2026-11-10, `docs/proposals/precision-round4-B.md`, B3): `only-allow npm` (and the
    `-y`/`bunx` spellings), `opencollective-postinstall`, `node-gyp-build || node-gyp rebuild`
    and `npx @mapbox/node-pre-gyp install --fallback-to-build` join the list; Playwright's
    browser download (`PLAYWRIGHT_HOOKS`) when the package depends on Playwright; tree-sitter's
    `src/scanner.c` test in `binding.gyp` counts as a lookup (`SCANNER_LOOKUP`); and a tool the
    package's own `bin` names (`tool_shadowed`) is the package's code, not the tool.

    v4 (2026-11-10, `docs/proposals/precision-round5-I.md`): `binding.gyp` is read with
    `ecosystems.npm.gyp` (every command expansion however it is embedded); a gyp command may
    also run a package script that only reads the package (`gyp_scripts`); and
    `node-gyp-build || exit 0` and
    `JOBS=${JOBS:-max} node-gyp-build` join the hook lines."""

    id = "npm.install-build-tool"
    version = 4
    severity = Severity.INFO
    weight = 0.0
    title = "Install hooks only run a build tool"

    def evaluate_code(self, change: CodeChange) -> Sequence[Finding]:
        declared = scripts(change.snapshot.manifest)
        hooks = {
            hook: declared[hook].strip() for hook in INSTALL_HOOKS if declared.get(hook, "").strip()
        }
        if (
            not hooks
            or not all(_build_tool(command, change.snapshot.manifest) for command in hooks.values())
            or tool_shadowed(change.snapshot.manifest, hooks.values())
        ):
            return ()
        listed = gyp_scripts(change)
        if listed is None:
            return ()
        gyp = (
            "only looks up `node-addon-api` or `nan` headers"
            if change.build_commands
            else "runs no command"
        )
        if any(SCANNER_LOOKUP.fullmatch(c.strip()) for c in change.build_commands):
            gyp = "only looks up headers and whether tree-sitter's `src/scanner.c` exists"
        if listed:
            gyp = (
                "only looks up headers and runs package scripts that read the package and "
                "print build inputs (" + ", ".join(f"`{p}`" for p in listed) + ")"
            )
        return (
            self.finding(
                "Every install hook only runs a build tool ("
                + ", ".join(f"`{hook}`: `{command}`" for hook, command in hooks.items())
                + f"), and `binding.gyp` {gyp}.",
                *(
                    Evidence(
                        kind=EvidenceKind.MANIFEST_FIELD,
                        path=f"package.json:scripts.{hook}",
                        after=snippet(command),
                    )
                    for hook, command in hooks.items()
                ),
            ),
        )


RULES: Final = (
    InstallScriptCode(),
    InstallScriptChanged(),
    InstallScriptObfuscated(),
    InstallBuildTool(),
)
