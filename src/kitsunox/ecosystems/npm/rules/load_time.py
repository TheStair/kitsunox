"""What loading (or installing) the package does unasked (Stage 3, npm).

`npm.load-fingerprint`: loading it reads the machine's identity, and its loaded code can send.
`npm.publish-at-load`: loading or installing it runs `npm publish` (below).

A payload that runs when the package is *loaded* (its entry point, or a file the entry loads:
`CodeChange.load`, `ecosystems.npm.entry.load_sources`) needs no install hook, so the install
rules never see it, and for a new package `code.capability-gained` says nothing either.
`archetype-index-sdk@1.0.0` (2026-11-08) was reported only through two `static.obfuscated`
findings: `dist/index.js` imports `telemetry-info.mjs`, which collects the host name, user
name and home directory, sends them to an outside host and starts a dropper. The commonest
such payload on `vm-day1` is the dependency-confusion probe moved from `preinstall` into
`index.js`: `os.hostname()`, `os.userInfo()` and `os.homedir()` read at module load and
posted away.

The rule fires when one loaded file reads at least two of `os.hostname()`, `os.userInfo()`,
`os.networkInterfaces()` and `os.homedir()` in code that runs at load (`lang.at_load`:
top level, functions called in place or passed to a call that runs, functions the running
code calls by name), and the loaded files use the network. Not counted:

- a file that is also one of the package's `bin` targets: a command-line program that
  `main` points at runs when `require`d, and reading the user's home and host name is a
  CLI's ordinary business (`codeam-cli`, `@mearl/native-host`: 6 of the 7 reviewed benign
  versions it fired on);
- on an update, anything the previous version's code already did (any of its files read two
  such facts at load).

MEDIUM (weight 3). Measured before building (`docs/stages/ast.md`): on `vm-day1` 0 of 1,500
benign samples, 310 malicious (42 not reported otherwise, 40 of them follow-ons); live 4
reports in 33.2 h that nothing else made (~3 a day).
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Mapping, Sequence
from typing import Final

from kitsunox.core.models import Evidence, EvidenceKind, Finding, Severity
from kitsunox.core.rules import BaseRule
from kitsunox.lang.javascript import Capability
from kitsunox.stages.ast import CodeChange, PathUse, Profile

MIN_IDENTITY_READS: Final = 2  # distinct identity reads (`hostname`, `userInfo`, ...) in one file
MAX_EVIDENCE: Final = 4


def fingerprints(
    where: Profile, skip: frozenset[str] = frozenset()
) -> dict[str, tuple[PathUse, ...]]:
    """The files (not in `skip`) that read at least MIN_IDENTITY_READS distinct facts of the
    machine's identity at load (`Profile.identity`), each with those reads."""
    by_path: dict[str, list[PathUse]] = {}
    for read in where.identity:
        if read.path not in skip:
            by_path.setdefault(read.path, []).append(read)
    return {
        path: tuple(reads)
        for path, reads in sorted(by_path.items())
        if len({r.use.detail for r in reads}) >= MIN_IDENTITY_READS
    }


def bin_files(manifest: Mapping[str, object]) -> frozenset[str]:
    """The package files `bin` names (a string or a map of command to path), as tree paths."""
    listed = manifest.get("bin")
    targets = (
        [listed]
        if isinstance(listed, str)
        else [t for t in listed.values() if isinstance(t, str)]
        if isinstance(listed, Mapping)
        else []
    )
    return frozenset(posixpath.normpath(t).removeprefix("./") for t in targets)


class LoadFingerprint(BaseRule):
    """Loading this version reads who and where the machine is, and its loaded code can send."""

    id = "npm.load-fingerprint"
    version = 1
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Loading it reads the machine's identity, and it can send"

    def evaluate_code(self, change: CodeChange) -> Sequence[Finding]:
        load = change.load
        if load is None or Capability.NETWORK not in load.capabilities:
            return ()
        found = fingerprints(load, skip=bin_files(change.snapshot.manifest))
        if not found or (change.before is not None and fingerprints(change.before)):
            return ()
        reads = [read for path_reads in found.values() for read in path_reads]
        names = ", ".join(sorted({f"`{r.use.detail}()`" for r in reads}))
        network = load.where(Capability.NETWORK)
        return (
            self.finding(
                f"Loading this version runs {names} (at module load, in "
                f"{', '.join(f'`{p}`' for p in found)}), and the files it loads use the "
                "network. A library seldom needs the machine's name, user or addresses the "
                "moment it is imported; the dependency-confusion probe and the import-time "
                "implant collect them there and send them away.",
                *(
                    Evidence(
                        kind=EvidenceKind.FILE_SPAN,
                        path=u.path,
                        line_start=u.use.line,
                        line_end=u.use.line,
                        snippet=f"[{u.use.capability.value}] {u.use.snippet}",
                    )
                    for u in (*reads[:MAX_EVIDENCE], *network[:1])
                ),
            ),
        )


# `npm.publish-at-load` (v1, 2026-11-09). Self-propagation is in the threat model (#9), and
# `static.npm-publish` (Stage 2, LOW) matches the text anywhere: release tooling mentions
# `npm publish` in scripts, docs and CLIs (350 reviewed benign versions, 0 positives). This
# rule reads only commands that *run* when the package is loaded or installed
# (`Profile.commands`, extractor v9: a `child_process`/`execa` call, or a same-file wrapper of
# one, that runs at load), on the files loading runs (`CodeChange.load`, without the `bin`
# targets: a CLI's `main` may be its `bin`) and the files the install hooks run
# (`CodeChange.install`). On an update, only if no file of the previous version did. The 46
# `*_z3n` spam packages on `vm-day1` (`main` re-publishes the user's project under random
# names in a loop) were reported by nothing; the `@emilgroup/*` worm runs it from
# `postinstall`. Measured before building (`docs/stages/ast.md`): `vm-day1` 105 malicious fire,
# 46 newly reported (the `*_z3n`), 0 of 1,452 benign; live 0 of 37,154 versions in 33.7 h;
# reviewed benign 0 of 1,434 with a tarball.
#
# `npm publish`, `pnpm publish`, `bun publish` (flags may come first: `npm --userconfig=x
# publish`), `yarn publish`, `yarn npm publish`. `npm run publish` runs a script, not this.
PUBLISH_COMMAND: Final = re.compile(
    r"\b(?:npm|pnpm|bun)(?:\.cmd)?\s+(?:--?[\w-]+(?:=\S+)?\s+){0,3}publish\b"
    r"|\byarn\s+(?:npm\s+)?publish\b"
)


def publishes(where: Profile | None, skip: frozenset[str] = frozenset()) -> tuple[PathUse, ...]:
    """The commands (`Profile.commands`, run at load) that publish to npm, outside `skip`."""
    if where is None:
        return ()
    return tuple(
        c for c in where.commands if c.path not in skip and PUBLISH_COMMAND.search(c.use.detail)
    )


class PublishAtLoad(BaseRule):
    """Loading or installing this version runs `npm publish`."""

    id = "npm.publish-at-load"
    version = 1
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Loading or installing it publishes to npm"

    def evaluate_code(self, change: CodeChange) -> Sequence[Finding]:
        loaded = publishes(change.load, skip=bin_files(change.snapshot.manifest))
        installed = publishes(change.install)
        found = (*loaded, *(c for c in installed if c not in loaded))
        if not found or (change.before is not None and publishes(change.before)):
            return ()
        when = " and ".join(w for w, hit in (("loaded", loaded), ("installed", installed)) if hit)
        return (
            self.finding(
                f"When the package is {when}, its code runs a command that publishes to npm "
                f"(in {', '.join(sorted({f'`{c.path}`' for c in found}))}), with whatever npm "
                "credentials the machine has. Release tools run `npm publish` when their "
                "user asks; code that does it unasked is spreading itself or someone's code: "
                "self-publishing spam republishes the user's project under new names, a worm "
                "republishes the user's packages with its payload.",
                *(
                    Evidence(
                        kind=EvidenceKind.FILE_SPAN,
                        path=c.path,
                        line_start=c.use.line,
                        line_end=c.use.line,
                        snippet=f"[{c.use.capability.value}] {c.use.snippet}",
                    )
                    for c in found[:MAX_EVIDENCE]
                ),
            ),
        )


RULES: Final = (LoadFingerprint(), PublishAtLoad())
