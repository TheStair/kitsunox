"""npm rules that compare a version's registry metadata with its tarball (Stage 2).

The registry stores the manifest a publisher sends next to the tarball and does not check that
the two agree ("manifest confusion"). Stage 1 only sees the metadata, so a publisher can show it
one thing and ship another:

- `npm install` runs the install scripts from the tarball's `package.json`, so a hook that only
  the tarball has is invisible to Stage 1's `npm.install-hook`.
- `dist.unpackedSize` is declared, not measured; Stage 1 routes updates to Stage 2 by its growth
  (decision 0008), so understating it is a way around that. Overstating gains nothing.

On 1,069 live versions (2026-10-28) the declared size matched the real one exactly in every case,
and no tarball had an install hook the metadata lacked. The differences that did occur are npm's
own normalisation: the registry drops a `node_modules/.bin/` prefix (undone before comparing)
and adds `install: node-gyp rebuild` when the package has a `binding.gyp` (a hook only the
metadata has, which is not the dangerous direction and is not flagged).
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Final

from kitsunox.core.models import Evidence, EvidenceKind, Finding, Severity, VersionSnapshot
from kitsunox.core.rules import BaseRule
from kitsunox.ecosystems.npm.rules.metadata import INSTALL_HOOKS, scripts, snippet

SIZE_TOLERANCE_BYTES: Final = 1024
SIZE_TOLERANCE_RATIO: Final = 0.01


def _normalised(command: str) -> str:
    return " ".join(command.replace("node_modules/.bin/", "").split())


class HiddenInstallScript(BaseRule):
    """The tarball's `package.json` has an install hook the registry metadata doesn't show."""

    id = "npm.artifact.hidden-install-script"
    severity = Severity.HIGH
    weight = 5.0
    title = "Install script in the tarball that the registry metadata hides"

    def evaluate_artifact(
        self, snapshot: VersionSnapshot, files: Mapping[str, bytes]
    ) -> Sequence[Finding]:
        raw = files.get("package.json")
        if raw is None:
            return ()
        try:
            packed = json.loads(raw)
        except ValueError:
            return ()
        if not isinstance(packed, dict):
            return ()
        shown = scripts(snapshot.manifest)
        findings = []
        for hook, command in sorted(scripts(packed).items()):
            if hook not in INSTALL_HOOKS:
                continue
            if _normalised(command) == _normalised(shown.get(hook, "")):
                continue
            findings.append(
                self.finding(
                    f"`npm install` runs the tarball's `{hook}` script, but the registry "
                    "metadata shows "
                    + (f"`{snippet(shown[hook])}`." if hook in shown else "no such script."),
                    Evidence(
                        kind=EvidenceKind.MANIFEST_FIELD,
                        path=f"package.json:scripts.{hook}",
                        before=snippet(shown.get(hook)),
                        after=snippet(command),
                    ),
                )
            )
        return findings


class DeclaredSizeMismatch(BaseRule):
    """The files are bigger than `dist.unpackedSize` says: the routing signal was understated.

    Only understatement is flagged. Overstating gains an attacker nothing (a bigger growth
    routes the version to more analysis, and a version over the download cap is never fetched,
    so it can't be checked here). On DataDog samples, overstated mismatches were all files
    missing from the dataset's zips (e.g. 47 MB declared, 13 KB present), not attacks.
    """

    id = "npm.artifact.size-mismatch"
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Declared unpacked size doesn't match the tarball"

    def evaluate_artifact(
        self, snapshot: VersionSnapshot, files: Mapping[str, bytes]
    ) -> Sequence[Finding]:
        declared = snapshot.artifact.unpacked_size if snapshot.artifact else None
        if declared is None:
            return ()
        real = sum(len(content) for content in files.values())
        gap = real - declared
        if gap <= max(SIZE_TOLERANCE_BYTES, SIZE_TOLERANCE_RATIO * declared):
            return ()
        return (
            self.finding(
                f"The registry metadata declares {declared:,} bytes unpacked; the tarball's files "
                f"total {real:,} (understated by {gap:,}). Size growth decides whether an "
                "update's code is read at all, so an understated size can hide a payload.",
                Evidence(
                    kind=EvidenceKind.MANIFEST_FIELD,
                    path="dist.unpackedSize",
                    before=str(declared),
                    after=str(real),
                ),
            ),
        )


RULES: Final = (HiddenInstallScript(), DeclaredSizeMismatch())
