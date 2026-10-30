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
from kitsunox.lang.javascript import Capability
from kitsunox.rules.capabilities import evidence
from kitsunox.stages.ast import CodeChange

C = Capability
RISKY: Final = frozenset({C.NETWORK, C.PROCESS, C.ENV_ALL, C.DYNAMIC_CODE, C.DYNAMIC_REQUIRE})


class InstallScriptCode(BaseRule):
    """The code an install hook runs reaches the network, runs processes, takes the whole
    environment or runs dynamic code. For an update, only capabilities the install code didn't
    have before count."""

    id = "npm.install-script-code"
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
    string (`@pulumi/*`); their files are what this rule compares."""

    id = "npm.install-script-changed"
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Code an install script runs changed"

    def evaluate_code(self, change: CodeChange) -> Sequence[Finding]:
        before = change.install_files_before
        if before is None:
            return ()
        old_version = (change.previous_version or "").encode()
        new_version = change.snapshot.ref.version.encode()
        changed = [
            path
            for path, data in sorted(change.install_files.items())
            if before.get(path) != data
            and not _only_version(before.get(path), data, old_version, new_version)
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


def _only_version(old: bytes | None, new: bytes, old_version: bytes, new_version: bytes) -> bool:
    """`new` is `old` with its own version string swapped for the new one (generated install
    scripts embed it: `workerd`'s `install.js` downloads `${pkg}@1.20261029.1`)."""
    return (
        old is not None
        and bool(old_version)
        and old_version in old
        and old.replace(old_version, new_version) == new
    )


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


RULES: Final = (InstallScriptCode(), InstallScriptChanged())
