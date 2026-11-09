"""Stage 3: capability analysis. What a version's code can do, compared with the version before.

For every JavaScript/TypeScript file of a version, `lang.javascript` lists the capabilities it
uses (network, processes, files, the whole environment, dynamic code). A version's **profile** is
the union over its files, each capability with the places it is used. The **delta** is what the
new version's profile has that the base's doesn't: code that gained the ability to reach the
network, or to run processes, is the change a reviewer needs to see.

Per-file results are a pure function of (content, language, extractor version), so they are
cached on disk by content hash; like Stage 2, a file seen in any earlier version or package is
not parsed again. See `docs/stages/ast.md`.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Final, Protocol

import httpx
from pydantic import Field

from kitsunox.core.models import (
    Candidate,
    Finding,
    PackageBatch,
    Record,
    Severity,
    StageDecision,
    VersionSnapshot,
)
from kitsunox.core.run import DataDir, EcosystemFactory
from kitsunox.lang.agent_config import agent_files
from kitsunox.lang.javascript import (
    EXTRACTOR_VERSION,
    Capability,
    FileCapabilities,
    PackageLoad,
    Use,
    analyse_source,
    language_for,
)
from kitsunox.stages.ingest import write_jsonl
from kitsunox.stages.static import ArtifactFiles, Unavailable
from kitsunox.stages.triage import at_least
from kitsunox.util.files import atomic_write
from kitsunox.util.hashing import sha256_hex
from kitsunox.util.http import FetchMode, HttpFetcher, Snapshot

STAGE_ID: Final = "ast"
DEFAULT_THRESHOLD: Final = Severity.MEDIUM

Tree = Mapping[str, bytes]


class CapabilityCache:
    """Per-file capabilities by (content hash, language), on disk, per extractor version."""

    def __init__(self, root: Path | None) -> None:
        self.dir = root / f"v{EXTRACTOR_VERSION}" if root else None

    def get(self, content: bytes, language: str) -> FileCapabilities:
        digest = sha256_hex(content)
        path = self.dir / digest[:2] / f"{digest}-{language}.json" if self.dir else None
        if path is not None and path.exists():
            try:
                return FileCapabilities.model_validate(json.loads(path.read_bytes()))
            except ValueError:
                pass  # a damaged entry is a miss: recompute and overwrite it
        result = analyse_source(content, language)
        if path is not None:
            atomic_write(path, result.model_dump_json().encode())
        return result


class PathUse(Record):
    path: str
    use: Use


class PathPackage(Record):
    path: str
    load: PackageLoad


class Profile(Record):
    """Capabilities of one version's code, with where each is used (paths sorted); the
    packages its own files load by name (not files under `node_modules/`), the packages
    it ships under `node_modules/`, and the reads of the machine's identity that run when a
    file is loaded (`FileCapabilities.identity_at_load`)."""

    uses: tuple[PathUse, ...] = ()
    files_parsed: int = 0
    files_with_errors: int = 0
    packages: tuple[PathPackage, ...] = ()
    bundled: frozenset[str] = frozenset()
    identity: tuple[PathUse, ...] = ()

    @property
    def capabilities(self) -> frozenset[Capability]:
        return frozenset(u.use.capability for u in self.uses)

    def where(self, capability: Capability) -> tuple[PathUse, ...]:
        return tuple(u for u in self.uses if u.use.capability == capability)


def profile(tree: Tree, cache: CapabilityCache, *, paths: frozenset[str] | None = None) -> Profile:
    """The profile of `tree`, or of only `paths` within it (e.g. an install script's files)."""
    uses: list[PathUse] = []
    identity: list[PathUse] = []
    packages: list[PathPackage] = []
    bundled: set[str] = set()
    parsed = errors = 0
    for path in sorted(tree):
        if paths is not None and path not in paths:
            continue
        vendored = bundled_package(path)
        if vendored is not None:
            bundled.add(vendored)
        language = language_for(path)
        if language is None:
            continue
        result = cache.get(tree[path], language)
        parsed += 1
        errors += result.parse_errors
        uses.extend(PathUse(path=path, use=use) for use in result.uses)
        identity.extend(PathUse(path=path, use=use) for use in result.identity_at_load)
        if vendored is None:
            packages.extend(PathPackage(path=path, load=load) for load in result.packages)
    return Profile(
        uses=tuple(uses),
        files_parsed=parsed,
        files_with_errors=errors,
        packages=tuple(packages),
        bundled=frozenset(bundled),
        identity=tuple(identity),
    )


def bundled_package(path: str) -> str | None:
    """The package a file under `node_modules/` belongs to (the outermost one), or None."""
    parts = path.split("/")
    if "node_modules" not in parts:
        return None
    rest = parts[parts.index("node_modules") + 1 :]
    if rest and rest[0].startswith("@"):
        return "/".join(rest[:2]) if len(rest) > 1 else None
    return rest[0] if rest else None


def added(base: Profile | None, new: Profile) -> frozenset[Capability]:
    """Capabilities `new` has that `base` doesn't; everything, for a new package."""
    return new.capabilities - (base.capabilities if base else frozenset())


class CodeChange(Record):
    """What a Stage 3 rule sees for one version: its capability profile, the profile of the
    version before it (None for a new package), the profile of the files its install
    scripts run (None if it has no install script naming a package file), and the profile of
    the files loading it runs (`LoadEntries`; None if the stage was given none or the version
    has no entry file)."""

    snapshot: VersionSnapshot
    before: Profile | None
    after: Profile
    install: Profile | None = None
    install_before: Profile | None = None
    # The files the install hooks name (`InstallEntries`), for diffing: path -> bytes, each cut
    # at MAX_INSTALL_FILE_BYTES. `install_files_before` is None when there is no base.
    install_files: dict[str, bytes] = Field(default_factory=dict)
    install_files_before: dict[str, bytes] | None = None
    previous_version: str | None = None
    # Commands the version's own build files make its install run besides the hooks
    # (`BuildCommands`; npm: `binding.gyp`'s actions and command expansions). Empty when the
    # ecosystem has none or the stage was given no `build_commands`.
    build_commands: tuple[str, ...] = ()
    # The agent configuration the install code may copy (`agent_config.agent_files`: skills,
    # agent settings and the scripts their hooks name), when it names an agent directory.
    agent_files: dict[str, bytes] = Field(default_factory=dict)
    load: Profile | None = None

    @property
    def added(self) -> frozenset[Capability]:
        return added(self.before, self.after)


class CodeRule(Protocol):
    @property
    def id(self) -> str: ...

    @property
    def version(self) -> int: ...

    def evaluate_code(self, change: CodeChange) -> Sequence[Finding]: ...


# What an install script runs, as path -> code: the files its command names, and code it passes
# inline (an ecosystem's choice of virtual path). `ecosystems.npm.install.install_sources`.
InstallEntries = Callable[[Tree], Mapping[str, bytes]]
# The commands a tree's build files run at install, besides its hooks (an ecosystem's choice:
# `ecosystems.npm.install.gyp_commands`).
BuildCommands = Callable[[Tree], Sequence[str]]
# The files of a tree that loading the package runs: its entry points and the package files
# they load (an ecosystem's choice: `ecosystems.npm.entry.load_sources`).
LoadEntries = Callable[[Tree], Mapping[str, bytes]]
MAX_INSTALL_FILE_BYTES: Final = 256 * 1024  # of each install file kept for the diff


def install_files(tree: Tree, install_entries: InstallEntries | None) -> dict[str, bytes]:
    """The code `tree`'s install hooks run, each cut at MAX_INSTALL_FILE_BYTES."""
    sources = install_entries(tree) if install_entries else {}
    return {path: bytes(sources[path][:MAX_INSTALL_FILE_BYTES]) for path in sorted(sources)}


def analyse_batch(
    batch: PackageBatch,
    trees: Callable[[VersionSnapshot], Tree | Unavailable],
    cache: CapabilityCache,
    rules: Sequence[CodeRule],
    *,
    install_entries: InstallEntries | None = None,
    build_commands: BuildCommands | None = None,
    load_entries: LoadEntries | None = None,
    threshold: Severity = DEFAULT_THRESHOLD,
) -> PackageBatch:
    """Run Stage 3 on a batch. Each version is compared with its `change.previous` (the base,
    or an earlier version in the batch), so a capability is attributed to the version that
    gained it, even if a later version in the burst drops it again. A version with no previous
    is a new package even if the batch holds an earlier placeholder (`0.0.0-stage` before
    `1.4.0`): npm says nothing came before it, so it gained nothing. A previous that is
    neither the base nor in the batch is fetched (`@bike4mind/cli` publishes snapshots of many
    branches at once, each following its own branch's last snapshot; without its files every
    capability of their install code counted as new). A previous whose files are unavailable
    leaves nothing to compare with, so `before` is None as well."""
    profiles: dict[str, tuple[Profile, Profile | None, dict[str, bytes]]] = {}
    unavailable: set[str] = set()

    def load(snapshot: VersionSnapshot) -> None:
        tree = trees(snapshot)
        if isinstance(tree, Unavailable):
            unavailable.add(snapshot.ref.version)
            return
        profiles[snapshot.ref.version] = (
            profile(tree, cache),
            _install_profile(tree, cache, install_entries),
            install_files(tree, install_entries),
        )

    if batch.base is not None:
        load(batch.base)
    updated = []
    for candidate in batch.versions:
        snapshot = candidate.change.new
        previous = candidate.change.previous
        if (
            previous is not None
            and previous.ref.version not in profiles
            and previous.ref.version not in unavailable
        ):
            load(previous)
        before, install_before, files_before = (
            profiles.get(previous.ref.version, (None, None, None))
            if previous
            else (None, None, None)
        )
        tree = trees(snapshot)
        if isinstance(tree, Unavailable):
            decision = StageDecision(
                stage=STAGE_ID, forwarded=False, reason=f"files unavailable: {tree.reason}"
            )
            updated.append(_with(candidate, (), decision))
            continue
        after = profile(tree, cache)
        install = _install_profile(tree, cache, install_entries)
        files = install_files(tree, install_entries)
        change = CodeChange(
            snapshot=snapshot,
            before=before,
            after=after,
            install=install,
            install_before=install_before,
            install_files=files,
            install_files_before=files_before,
            previous_version=previous.ref.version if previous else None,
            build_commands=tuple(build_commands(tree)) if build_commands else (),
            agent_files=agent_files(tree, files),
            load=_load_profile(tree, cache, load_entries),
        )
        findings = tuple(f for rule in rules for f in rule.evaluate_code(change))
        flagged = sorted({f.rule_id for f in findings if at_least(f.severity, threshold)})
        decision = StageDecision(
            stage=STAGE_ID,
            forwarded=bool(flagged),
            reason=f"rules: {', '.join(flagged)}" if flagged else "no signal",
        )
        updated.append(_with(candidate, findings, decision))
        profiles[snapshot.ref.version] = (after, install, files)
    return batch.model_copy(update={"versions": tuple(updated)})


def code_change(
    snapshot: VersionSnapshot,
    tree: Tree,
    base_tree: Tree | None,
    cache: CapabilityCache,
    install_entries: InstallEntries | None = None,
    previous_version: str | None = None,
    build_commands: BuildCommands | None = None,
    load_entries: LoadEntries | None = None,
) -> CodeChange:
    """The `CodeChange` for one version against one base (evaluation uses this directly)."""
    files = install_files(tree, install_entries)
    return CodeChange(
        snapshot=snapshot,
        before=profile(base_tree, cache) if base_tree is not None else None,
        after=profile(tree, cache),
        install=_install_profile(tree, cache, install_entries),
        install_before=(
            _install_profile(base_tree, cache, install_entries) if base_tree is not None else None
        ),
        install_files=files,
        install_files_before=(
            install_files(base_tree, install_entries) if base_tree is not None else None
        ),
        previous_version=previous_version,
        build_commands=tuple(build_commands(tree)) if build_commands else (),
        agent_files=agent_files(tree, files),
        load=_load_profile(tree, cache, load_entries),
    )


def _load_profile(
    tree: Tree, cache: CapabilityCache, load_entries: LoadEntries | None
) -> Profile | None:
    """The profile of the files loading the package runs (real package files, so `paths`)."""
    paths = frozenset(load_entries(tree)) if load_entries else frozenset()
    return profile(tree, cache, paths=paths) if paths else None


def _install_profile(
    tree: Tree, cache: CapabilityCache, install_entries: InstallEntries | None
) -> Profile | None:
    sources = install_entries(tree) if install_entries else {}
    return profile(sources, cache) if sources else None


def _with(
    candidate: Candidate, findings: tuple[Finding, ...], decision: StageDecision
) -> Candidate:
    return candidate.model_copy(
        update={
            "findings": candidate.findings + findings,
            "history": (*candidate.history, decision),
        }
    )


def ast_run(
    run_dir: Path,
    files: Callable[[VersionSnapshot], Tree | Unavailable],
    cache: CapabilityCache,
    rules: Sequence[CodeRule],
    *,
    install_entries: InstallEntries | None = None,
    build_commands: BuildCommands | None = None,
    load_entries: LoadEntries | None = None,
    workers: int = 8,
) -> tuple[PackageBatch, ...]:
    """Stage 3 over a run that Stage 2 has processed: reads `static.jsonl`, writes `ast.jsonl`
    (the same batches in the same order, with Stage 3 findings and decisions). `files` must be
    thread-safe; parsers are per thread."""
    lines = [line for line in (run_dir / "static.jsonl").read_bytes().splitlines() if line]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        batches = tuple(
            pool.map(
                lambda line: analyse_batch(
                    PackageBatch.load_json(line),
                    files,
                    cache,
                    rules,
                    install_entries=install_entries,
                    build_commands=build_commands,
                    load_entries=load_entries,
                ),
                lines,
            )
        )
    write_jsonl(run_dir / "ast.jsonl", batches)
    return batches


def record_ast(
    data: DataDir,
    run_id: str,
    factory: EcosystemFactory,
    rules: Sequence[CodeRule],
    *,
    install_entries: InstallEntries | None = None,
    build_commands: BuildCommands | None = None,
    load_entries: LoadEntries | None = None,
    workers: int = 8,
    client: httpx.Client | None = None,
) -> tuple[PackageBatch, ...]:
    """Stage 3 on a run Stage 2 has processed. Tarballs come from the blob store through the
    immutable index (Stage 2 fetched and recorded them); anything not there is fetched but not
    recorded, since Stage 2's snapshot is what retention keeps. The caller holds the lock."""
    fetcher = HttpFetcher(
        store=data.blobs,
        snapshot=Snapshot(),
        mode=FetchMode.RECORD,
        immutable_index=data.immutable_index,
        client=client,
    )
    try:
        return ast_run(
            data.run_dir(run_id),
            ArtifactFiles(factory(fetcher)),
            CapabilityCache(data.root / "cache" / "ast"),
            rules,
            install_entries=install_entries,
            build_commands=build_commands,
            load_entries=load_entries,
            workers=workers,
        )
    finally:
        fetcher.close()
