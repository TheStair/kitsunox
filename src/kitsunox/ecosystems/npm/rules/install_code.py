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
from collections.abc import Sequence
from typing import Final

from kitsunox.core.models import Evidence, EvidenceKind, Finding, Severity
from kitsunox.core.rules import BaseRule
from kitsunox.ecosystems.npm.install import loaded_files
from kitsunox.ecosystems.npm.rules.metadata import INSTALL_HOOKS, scripts, snippet
from kitsunox.lang.javascript import Capability
from kitsunox.rules.capabilities import evidence
from kitsunox.rules.static import Obfuscated
from kitsunox.stages.ast import CodeChange

C = Capability
RISKY: Final = frozenset({C.NETWORK, C.PROCESS, C.ENV_ALL, C.DYNAMIC_CODE, C.DYNAMIC_REQUIRE})


class InstallScriptCode(BaseRule):
    """The code an install hook runs reaches the network, runs processes, takes the whole
    environment or runs dynamic code. For an update, only capabilities the install code didn't
    have before count.

    v2 (2026-10-30): the install code includes the package files it loads by a constant path
    (`install.followed_files`): +12 malicious `vm-day1` samples, +1 benign."""

    id = "npm.install-script-code"
    version = 2
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Install script runs risky code"

    def evaluate_code(self, change: CodeChange) -> Sequence[Finding]:
        if change.install is None:
            return ()
        risky = change.install.capabilities & RISKY
        if change.before is not None:
            risky -= change.install_before.capabilities if change.install_before else frozenset()
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
    three `aicp-tracker` versions, a family still reported through 1.0.7), 20 benign (was 21)."""

    id = "npm.install-script-changed"
    version = 3
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
                parts.append(f"{path} (+{counted[0]} -{counted[1]} lines)")
        return (
            self.finding(
                f"`npm install` runs code that changed{since}: {', '.join(parts)}.",
                *(
                    _diff_evidence(path, before.get(path), change.install_files[path])
                    for path in changed[:MAX_FILES_SHOWN]
                ),
            ),
        )


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


def _adds_risky(change: CodeChange, path: str, old: bytes | None, new: bytes) -> bool:
    """The change to `path` adds a line with a risky use (RISKY: a network or process module,
    the whole environment, dynamic code). A file too long to diff counts if it has one. Lines
    are split on LF only, as the parser numbers them."""
    lines = {
        u.use.line
        for u in (change.install.uses if change.install else ())
        if u.path == path and u.use.capability in RISKY
    }
    if not lines:
        return False
    a = (old or b"").decode("utf-8", "replace").split("\n")
    b = new.decode("utf-8", "replace").split("\n")
    if not _diffable(a, b):
        return True
    matcher = difflib.SequenceMatcher(None, a, b, autojunk=False)
    added = {
        n + 1
        for tag, _, _, j1, j2 in matcher.get_opcodes()
        if tag in ("replace", "insert")
        for n in range(j1, j2)
    }
    return bool(lines & added)


def _lf(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n")


def _lines(data: bytes) -> list[str]:
    return data.decode("utf-8", "replace").splitlines()


def _diffable(old: list[str], new: list[str]) -> bool:
    return len(old) <= MAX_DIFFED_LINES and len(new) <= MAX_DIFFED_LINES


def _counts(old: bytes, new: bytes) -> tuple[int, int] | None:
    """Added and removed lines; None for a file too long to diff."""
    a, b = _lines(old), _lines(new)
    if not _diffable(a, b):
        return None
    plus = minus = 0
    for line in difflib.unified_diff(a, b, lineterm="", n=0):
        if line.startswith("+") and not line.startswith("+++"):
            plus += 1
        elif line.startswith("-") and not line.startswith("---"):
            minus += 1
    return plus, minus


def _diff_evidence(path: str, old: bytes | None, new: bytes) -> Evidence:
    """The changed lines as a unified diff (one line of context), cut to MAX_DIFF_LINES lines
    of MAX_DIFF_LINE_CHARS characters; package text, escaped by every renderer."""
    if b"\x00" in new[:8192] or (old is not None and b"\x00" in old[:8192]):
        return Evidence(kind=EvidenceKind.FILE_SPAN, path=path, snippet="(binary file changed)")
    a, b = _lines(old or b""), _lines(new)
    if not _diffable(a, b):
        text = f"(changed: {len(a)} lines before, {len(b)} now; too long to diff)"
        return Evidence(kind=EvidenceKind.FILE_SPAN, path=path, snippet=text)
    diff = list(difflib.unified_diff(a, b, lineterm="", n=1))[2:]
    first = next((int(m.group(1)) for h in diff if (m := HUNK.match(h))), None)
    shown = [line[:MAX_DIFF_LINE_CHARS] for line in diff[:MAX_DIFF_LINES]]
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
    }
)


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
    rules has build-tool-only hooks."""

    id = "npm.install-build-tool"
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
            or change.build_commands
            or not all(command in BUILD_TOOL_HOOKS for command in hooks.values())
        ):
            return ()
        return (
            self.finding(
                "Every install hook only runs a build tool ("
                + ", ".join(f"`{hook}`: `{command}`" for hook, command in hooks.items())
                + "), and `binding.gyp` runs no command.",
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
