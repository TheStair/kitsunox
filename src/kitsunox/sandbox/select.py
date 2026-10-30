"""Stage 5 job selection: which of the versions Stage 4 reported are handed to package-analysis.

The entry rule: Stage 4 reported the version (its last decision is `correlate`, forwarded)
**and** the tarball's own `package.json` makes `npm install` run a hook (`tarball_hooks`).
package-analysis runs `npm install` on the tarball, so what matters is what npm reads: the
tarball, never the registry metadata, which a manifest-confusion package makes differ (round-2
review: a hidden `preinstall` was never analysed when selection read the packument). The
tarball is read with the project's safe extractor (`util.archive.extract_tar_gz`), nothing is
run. The hooks counted are non-empty `preinstall`, `install` and `postinstall` strings, plus
npm's implicit `install: node-gyp rebuild` when the package has a `binding.gyp` and declares
neither `install` nor `preinstall` (and doesn't set `"gypfile": false`), as npm's package.json
normalisation does.

Entrants are ordered by Stage 4's score (highest first; ties by ecosystem, name, version, the
`Change.sort_key`) and at most `cap` are selected; the rest are *deferred*. Selection is a pure
function of the inspected candidates and the cap, so a replay selects the same versions.
Nothing is dropped silently: every version that qualified, or whose tarball couldn't be
checked, but isn't analysed carries a `sandbox.not-run` INFO finding saying why (`NotRun`).

The tarball's package.json also gives the name npm installs it under (`TarballInfo.name`), and
the same pass lists every regular file the tarball holds (`TarballInfo.files`, the top
directory stripped, as npm unpacks it), which the rules use to tell a file npm unpacked from
one written into the package's directory during the run.
package-analysis's import phase runs `require(<lowercased -package>)`, so Stage 5 passes that
name, not the registry's, as `-package` when they differ (manifest confusion: round-3 review);
see `SandboxJob.install_name`.

The rules here are the ones Stage 5 applies from the stage rather than over observations:
`sandbox.not-run` (INFO), `sandbox.result-rejected` (MEDIUM; HIGH for a result too large to
read), `sandbox.install-failed` (INFO, the install exited non-zero, so the import phase never
ran; with no network on the airgapped VM, a missing dependency is the likely cause),
`sandbox.bundled` (INFO: the analysis is of a Kitsunox-built offline bundle, not the registry
tarball) and `sandbox.bundle-incomplete` (INFO: the version needs dependencies Kitsunox
couldn't bundle completely, so the registry tarball is exported and its offline install will
likely fail). The rules over a result's observations are in `kitsunox/rules/sandbox.py`.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Final, Literal

from kitsunox.core.models import Candidate, Evidence, EvidenceKind, Finding, Severity
from kitsunox.core.rules import BaseRule
from kitsunox.ecosystems.npm.rules.metadata import scripts
from kitsunox.sandbox.models import INSTALL_HOOKS, JobBundle
from kitsunox.sandbox.ossf import RESULT_TOO_LARGE
from kitsunox.stages.correlate import STAGE_ID as CORRELATE_STAGE
from kitsunox.stages.correlate import score
from kitsunox.util.archive import DEFAULT_LIMITS, ArchiveError, ExtractLimits, extract_tar_gz

STAGE_ID: Final = "sandbox"
DEFAULT_CAP: Final = 30
MANIFEST: Final = "package.json"
GYP_FILE: Final = "binding.gyp"
MAX_MANIFEST_BYTES: Final = 4 * 1024 * 1024
# A name npm accepts (validate-npm-package-name, legacy mixed case allowed): what a tarball's
# package.json must hold for its name to be passed to package-analysis.
NPM_NAME: Final = re.compile(
    r"(?:@[A-Za-z0-9~*-][A-Za-z0-9~*._-]*/)?[A-Za-z0-9~-][A-Za-z0-9~._-]*", re.ASCII
)
MAX_NAME_CHARS: Final = 214  # npm's limit

# `sandbox.not-run` reasons. Fixed strings (never package or analyser text), so a reviewer can
# group by them and a report can't be injected through them.
NOT_CAPTURED: Final = "tarball not captured"
NOT_IN_STORE: Final = "tarball not in blob store"
OVERSIZE: Final = "tarball over Stage 5's limit (128 MiB, or 512 MiB unpacked)"
# A tarball no earlier stage captured is downloaded by Stage 5 itself (a download; nothing is
# run). Not downloaded yet: over the call's download budget or a network failure, retried on
# the next live call (decision 0009).
TARBALL_PENDING: Final = "pending: the tarball is not downloaded yet (retried)"
TARBALL_FETCH_FAILED: Final = "tarball download failed"
TARBALL_UNREPRODUCIBLE: Final = "infra-error: the tarball could not be read from the run's snapshot"
INTEGRITY: Final = "tarball does not match its integrity"
UNEXTRACTABLE: Final = "tarball could not be extracted safely"
NO_MANIFEST: Final = "tarball has no readable package.json"
NOT_CONFIGURED: Final = "package-analysis results directory not configured"
PENDING: Final = "pending: exported for package-analysis"
EXPORT_FAILED: Final = "infra-error: the export could not be written"
ANALYSIS_INFRA: Final = "infra-error: package-analysis recorded an infrastructure error"
CACHE_UNREADABLE: Final = "infra-error: the cached result is unreadable"
# The offline dependency bundle couldn't be built yet: nothing is exported, the next live call
# tries again (decision 0009: a network failure is never a missing package).
BUNDLE_PENDING: Final = "pending: the dependency bundle hit a network failure (retried)"
BUNDLE_BUDGET: Final = "pending: over this call's download budget for dependency bundles"
# Replay rebuilds a bundle from the run's `sandbox-snapshot.json`; it must give the recorded key.
BUNDLE_UNREPRODUCIBLE: Final = (
    "infra-error: the dependency bundle could not be rebuilt from the run's snapshot"
)


def deferred(cap: int) -> str:
    return f"deferred: over the per-tick cap of {cap}"


class NotRun(BaseRule):
    """`sandbox.not-run`: the version qualified for Stage 5 (or its tarball couldn't be
    checked) but has no usable analysis. INFO and weight 0: not running proves nothing either
    way, so it never moves the score."""

    id = "sandbox.not-run"
    version = 2
    severity = Severity.INFO
    weight = 0.0
    title = "Install not analysed in the sandbox"

    def because(self, reason: str) -> Finding:
        return self.finding(
            f"Stage 5 has no package-analysis result for this version's install: {reason}.",
            Evidence(kind=EvidenceKind.METADATA, snippet=reason),
        )


NOT_RUN: Final = NotRun()


class ResultRejected(BaseRule):
    """`sandbox.result-rejected`: package-analysis's result for this version failed validation
    or couldn't be read, so nothing it recorded was analysed. Scored (MEDIUM, 3, like
    `sandbox.truncated`), not INFO: the package chooses most of the result (paths, argv, output),
    so one that could break its own record would otherwise erase every finding at no cost. A
    misplaced or mis-run result shows up here too; that is visible and fixable (replace the file:
    the import retries), while a silent loss is neither.

    A result over `ossf.MAX_RESULT_BYTES` (`RESULT_TOO_LARGE`) is HIGH, 5 (version 3): a benign
    npm install records a few MB at most, while a package can inflate its own record past the
    cap with a few thousand failed `stat`s of long paths (round-3 review), which at MEDIUM
    would trade a CRITICAL finding for a 3. The file is rejected, not read in part: a prefix
    can't be validated against the schema, and package-analysis sorts files and commands, so
    the package would choose what falls past the cut anyway."""

    id = "sandbox.result-rejected"
    version = 3
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Sandbox result rejected"
    too_large_severity: Final = Severity.HIGH
    too_large_weight: Final = 5.0

    def because(self, reason: str) -> Finding:
        too_large = reason == RESULT_TOO_LARGE
        found = self.finding(
            f"package-analysis analysed this version's install, but its result was rejected "
            f"({reason}), so nothing it recorded was analysed. "
            + (
                f"Real installs record far less than {MAX_RESULT_MIB} MiB: a package that "
                "inflates its own record may be hiding what it did. "
                if too_large
                else "A package that can break the record may be hiding what it did. "
            )
            + "Its behavior is unseen.",
            Evidence(kind=EvidenceKind.METADATA, snippet=reason),
            severity=self.too_large_severity if too_large else None,
        )
        return found.model_copy(update={"weight": self.too_large_weight}) if too_large else found


RESULT_REJECTED: Final = ResultRejected()


MAX_LISTED: Final = 10  # names shown in a bundle finding's explanation


def _listed(names: Sequence[str]) -> str:
    shown = ", ".join(names[:MAX_LISTED])
    more = len(names) - MAX_LISTED
    return shown + (f" and {more} more" if more > 0 else "")


class Bundled(BaseRule):
    """`sandbox.bundled`: package-analysis was given a **Kitsunox-built offline bundle**, not
    the registry tarball as published (`sandbox/bundle.py`;
    `docs/proposals/offline-dependency-bundle.md`): the package's own files byte for byte, its
    `package.json` rewritten only to list every dependency in `bundleDependencies` (and copy
    required peers into `dependencies`), and every dependency npm would install at the run's
    `as_of` added under its `node_modules/`, so `npm install` runs every hook without a
    network. INFO and weight 0: it says what was analysed, so a reviewer reads dependency
    activity, nested paths and the rewritten `package.json` for what they are."""

    id = "sandbox.bundled"
    version = 1
    severity = Severity.INFO
    weight = 0.0
    title = "Analysed as a Kitsunox offline bundle"

    def because(self, bundle: JobBundle) -> Finding:
        assumes = bundle.assumes
        platform = "/".join(assumes.get(k, "?") for k in ("os", "cpu", "libc"))
        changed = ", ".join(bundle.package_json_changes) or "nothing"
        notes = []
        if bundle.supplied_by_package:
            notes.append(f"{bundle.supplied_by_package} shipped by the package itself (kept)")
        if bundle.skipped:
            notes.append(f"{bundle.skipped} optional packages skipped (platform or engines)")
        if bundle.predicted_network:
            notes.append(
                f"{bundle.predicted_network} expected to need the network to install "
                "(native builds or install-time downloads), which fails offline"
            )
        return self.finding(
            "package-analysis analysed a Kitsunox-built offline bundle of this version, not "
            "the registry tarball as published: the package's own files unchanged except "
            f"package.json ({changed} rewritten), plus {bundle.added} dependencies under its "
            f"node_modules/ (top level: {_listed(bundle.top_level) or 'none'}), resolved as npm "
            f"{assumes.get('npm', '?')} on node {assumes.get('node', '?')} ({platform}) would "
            "at the run's time. Dependency activity is in the record too, under the package's "
            "node_modules/."
            + (f" Of the packages: {'; '.join(notes)}." if notes else "")
            + f" Registry tarball sha256 {bundle.original_sha256}; bundle tar sha256 "
            f"{bundle.tar_sha256}.",
            Evidence(
                kind=EvidenceKind.METADATA,
                snippet=f"{bundle.format}: {bundle.added} dependencies added",
            ),
        )


BUNDLED: Final = Bundled()


class BundleIncomplete(BaseRule):
    """`sandbox.bundle-incomplete`: the tarball's `package.json` needs dependencies, and
    Kitsunox couldn't bundle them completely (an unresolvable or non-registry spec, a
    required package for another platform, a cap, an original it can't repack faithfully), so
    package-analysis gets the registry tarball as published. On the airgapped VM npm can't
    fetch the rest, and it resolves the whole tree before any hook runs, so the install will
    likely fail with nothing run (`sandbox.install-failed`). INFO and weight 0: a reason the
    analysis may show nothing, never a verdict. `reason` is a fixed string; `missing` names
    unresolved required dependencies (package text, escaped by renderers)."""

    id = "sandbox.bundle-incomplete"
    version = 1
    severity = Severity.INFO
    weight = 0.0
    title = "No complete offline bundle: the install will likely fail"

    def because(self, reason: str, missing: Sequence[str] = ()) -> Finding:
        named = f" Unresolved: {_listed(missing)}." if missing else ""
        return self.finding(
            "This version's package.json needs dependencies, and Kitsunox could not build a "
            f"complete offline bundle of them ({reason}), so package-analysis gets the "
            "registry tarball as published. The analysis is airgapped, and npm resolves the "
            "whole dependency tree before it runs any hook, so the install will most likely "
            f"fail before any hook runs, and an empty record says nothing.{named}",
            Evidence(kind=EvidenceKind.METADATA, snippet=reason),
        )


BUNDLE_INCOMPLETE: Final = BundleIncomplete()
MAX_RESULT_MIB: Final = 32  # ossf.MAX_RESULT_BYTES, for the explanation


class InstallFailed(BaseRule):
    """`sandbox.install-failed`: package-analysis's `npm install` of the tarball exited
    non-zero (the install phase ended `error_analysis`), so the import phase never ran and the
    hooks may not have run either. INFO and weight 0: a failure proves nothing, but the run must
    not read as an analysis of the package's behavior. The analysis is airgapped (no network for
    the sandbox or the VM), so this is expected for a tarball that needs registry dependencies
    it doesn't ship: npm resolves the whole tree before it runs any hook. Version 2: the
    explanation no longer depends on a network mode."""

    id = "sandbox.install-failed"
    version = 2
    severity = Severity.INFO
    weight = 0.0
    title = "Install failed in the sandbox"

    def because(self) -> Finding:
        return self.finding(
            "npm install of this tarball failed in package-analysis's sandbox, so the import "
            "phase never ran and the install hooks may not have run. The analysis is "
            "airgapped (no network), so an install that needs registry dependencies the "
            "tarball doesn't ship fails before any hook runs. What was recorded before the "
            "failure was still analysed.",
            Evidence(kind=EvidenceKind.METADATA, snippet="install error_analysis (airgapped)"),
        )


INSTALL_FAILED: Final = InstallFailed()

Status = Literal["selected", "deferred", "no-hook", "unchecked"]
Inspection = tuple[str, ...] | str  # the tarball's hooks, or why it couldn't be checked


@dataclass(frozen=True)
class Entry:
    """One version Stage 4 reported, and what selection decided about it. `reason` is set for
    `unchecked` (a fixed not-run reason)."""

    candidate: Candidate
    status: Status
    hooks: tuple[str, ...] = ()
    reason: str | None = None


def reported(candidate: Candidate) -> bool:
    """Stage 4 reported this version: its last decision is Stage 4's, and forwarded."""
    last = candidate.history[-1] if candidate.history else None
    return last is not None and last.stage == CORRELATE_STAGE and last.forwarded


def manifest_hooks(manifest: object, has_gyp: bool) -> tuple[str, ...]:
    """The hooks `npm install` runs for this package.json, in the order npm runs them."""
    if not isinstance(manifest, dict):
        return ()
    declared = {k for k, v in scripts(manifest).items() if k in INSTALL_HOOKS and v.strip()}
    if (
        has_gyp
        and "install" not in declared
        and "preinstall" not in declared
        and manifest.get("gypfile") is not False
    ):
        declared.add("install")  # npm's implicit `node-gyp rebuild`
    return tuple(h for h in INSTALL_HOOKS if h in declared)


@dataclass(frozen=True)
class TarballInfo:
    """What the tarball's own package.json says: the hooks npm runs for it, and the name npm
    installs it under (None when it holds no valid npm name); and the paths of every regular
    file in the tarball, the top directory stripped (what npm unpacks into the package's
    directory; links and unsafe paths, which `extract_tar_gz` skips, are not listed)."""

    hooks: tuple[str, ...]
    name: str | None
    files: frozenset[str] = frozenset()
    # The parsed package.json (leniently: `json.loads`), for the bundle step to decide whether
    # the package needs dependencies at all.
    manifest: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)


def manifest_name(manifest: dict[object, object]) -> str | None:
    name = manifest.get("name")
    if isinstance(name, str) and len(name) <= MAX_NAME_CHARS and NPM_NAME.fullmatch(name):
        return name
    return None


def inspect_tarball(tarball: bytes, limits: ExtractLimits = DEFAULT_LIMITS) -> TarballInfo | str:
    """The tarball's own package.json (npm strips the top directory, usually `package/`), or
    a not-run reason. The tarball is untrusted: extracted in memory with the project's limits,
    the manifest size-capped, and a manifest nested deeper than the JSON decoder's recursion
    limit is unreadable, never a crash. One pass: `include` sees every regular file's safe path
    (and so lists them all), and only the manifest and `binding.gyp` are read."""
    names: set[str] = set()

    def include(path: str) -> bool:
        names.add(path)
        return path in (MANIFEST, GYP_FILE)

    try:
        tree = extract_tar_gz(tarball, strip_components=1, include=include, limits=limits)
    except ArchiveError:
        return UNEXTRACTABLE
    raw = tree.files.get(MANIFEST)
    if raw is None or len(raw) > MAX_MANIFEST_BYTES:
        return NO_MANIFEST
    try:
        manifest = json.loads(raw)
    except ValueError, RecursionError:
        return NO_MANIFEST
    if not isinstance(manifest, dict):
        return NO_MANIFEST
    return TarballInfo(
        manifest_hooks(manifest, GYP_FILE in tree.files),
        manifest_name(manifest),
        frozenset(names),
        manifest,
    )


def tarball_hooks(tarball: bytes) -> Inspection:
    """The hooks the tarball's own package.json makes npm run, or a not-run reason."""
    info = inspect_tarball(tarball)
    return info if isinstance(info, str) else info.hooks


def priority(candidate: Candidate) -> tuple[float, str, str, str]:
    """Highest Stage 4 score first, then the existing sort key."""
    return (-score(candidate.findings), *candidate.change.sort_key)


def select(
    inspected: Sequence[tuple[Candidate, Inspection]], cap: int = DEFAULT_CAP
) -> tuple[Entry, ...]:
    """Each version Stage 4 reported (`reported`), with its tarball inspected, in Stage 4's
    order, with its selection status."""
    if cap < 0:
        raise ValueError("cap must not be negative")
    ranked = sorted(
        (i for i, (_, found) in enumerate(inspected) if isinstance(found, tuple) and found),
        key=lambda i: priority(inspected[i][0]),
    )
    chosen = set(ranked[:cap])

    def entry(i: int) -> Entry:
        candidate, found = inspected[i]
        if isinstance(found, str):
            return Entry(candidate, "unchecked", reason=found)
        if not found:
            return Entry(candidate, "no-hook")
        return Entry(candidate, "selected" if i in chosen else "deferred", found)

    return tuple(entry(i) for i in range(len(inspected)))
