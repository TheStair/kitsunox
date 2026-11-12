"""Stage 4 wiring for npm git dependencies (decision 0020): the install code of a dependency a
release installs from a GitHub repository, read as the release's own.

`web3-mev-error-decoder@0.1.0` (2026-11-09, malicious) shipped a clean tarball and the
dependency `"multicall-error-decoder": "github:outgoingyang/multicall-error-decoder"`. npm
clones that repository and runs its `install` hook, which decrypted strings and downloaded and
started a payload. Only `npm.dependency.non-registry` (Stage 1) fired; Stages 2-3 read the
release's tarball, which had none of it.

For each dependency a version adds or changes (`wanted`: what `npm.dependency.non-registry`
reads) that names a GitHub repository (`gitdep.github_spec`):

1. **Resolve** the reference to a commit with the repository's refs (the ref advertisement the
   repository comparison fetches, `RepoMemory.refs`), as of the run.
2. **Fetch** the archive at that commit through the run's fetcher (immutable index: once per
   commit, recorded in the run's snapshot, pruned with `--keep-repo-days` like every
   `codeload.github.com` archive) and **extract** it with `extract_archive` under
   `DEPENDENCY_LIMITS`, in the comparison pool's worker processes. Only the files npm runs at
   install are kept (`read_dependency`).
3. **Analyse** them with the rules that read a release's install code (`analyse`): Stage 1's
   `npm.install-hook`, Stage 2's file rules on those files, Stage 3's code rules, as if the
   dependency were a new package (or, for a commit bump of the same repository, an update of
   the commit the previous release pinned), and apply the explanations within it
   (`correlate.explained`).

`npm.git-dependency` (`ecosystems/npm/rules/git_dependency.py`) shows the findings with
`dep:<name>@<commit12>/` paths, scored like the release's own. A dependency that can't be read
(a deleted repository, a missing ref, an archive over the limits, the run's cap, another host)
keeps today's `npm.dependency.non-registry` alone, plus an INFO note. Its own git dependencies
are listed, not followed. Network failures are retried in Stage 4's passes and never taken for
a missing repository (decision 0009).
"""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Mapping, Sequence
from concurrent.futures import Executor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial
from typing import Any, Final

from kitsunox.core.models import (
    Candidate,
    Change,
    Evidence,
    EvidenceKind,
    Finding,
    PackageVersionRef,
    PublishInfo,
    VersionSnapshot,
)
from kitsunox.core.rules import RuleContext, Versioned, rules_fingerprint
from kitsunox.ecosystems.npm.gitdep import (
    GitHubSpec,
    github_spec,
    non_registry,
    npm_runs,
    presented_manifest,
    read_manifest,
    redacted,
    resolve,
)
from kitsunox.ecosystems.npm.gyp import GYP_FILE
from kitsunox.ecosystems.npm.install import gyp_commands, install_sources
from kitsunox.ecosystems.npm.rules.metadata import (
    InstallHook,
    fetches_nothing,
    is_registry_spec,
    npm_local_path,
    runtime_dependencies,
    snippet,
)
from kitsunox.githost.github import GitHub, extract_archive
from kitsunox.lang.agent_config import agent_files
from kitsunox.lang.javascript import Capability, language_for
from kitsunox.rules.static import RULES as STATIC_RULES
from kitsunox.stages.ast import CapabilityCache, Profile, code_change
from kitsunox.stages.code import CODE_RULES
from kitsunox.stages.correlate import (
    CorrelationContext,
    SourceDependency,
    explained,
)
from kitsunox.stages.repo import NetworkRequests, RepoMemory
from kitsunox.stages.static import (
    BaseFiles,
    ContentCache,
    LoadedFiles,
    content_matches,
    new_contents,
)
from kitsunox.util.archive import ExtractLimits
from kitsunox.util.http import FetchError, HttpFetcher, TransientFetchError

# A dependency's repository holds its sources and tests; a payload repository is small
# (multicall-error-decoder: 96 KB). Smaller than `REPO_LIMITS`: what is read is only its
# install code, and a dependency over these limits is noted as not read.
DEPENDENCY_LIMITS: Final = ExtractLimits(
    max_compressed_bytes=64 * 1024 * 1024,
    max_total_bytes=512 * 1024 * 1024,
    max_file_bytes=64 * 1024 * 1024,
    max_files=100_000,
)
# Distinct git dependencies (repository + reference) one run reads, in run order. Measured on
# the live runs on disk (190 runs, 2026-10-29..11-12): 174 versions added or changed a GitHub
# dependency, 175 distinct specs in all, at most a few dozen in one run.
MAX_GIT_DEPENDENCIES: Final = 200
# ... of which one package (all its versions in the run) may claim at most this many.
MAX_PER_PACKAGE: Final = 10
MAX_NESTED: Final = 20
MAX_REACHES: Final = 3  # evidence lines per capability in the summary
# Lines shown in the summary besides the capability uses (evidence for reviewers, never
# scored): where the install code decrypts data, starts a process, writes a file, downloads.
_CALLS: Final = (
    (
        "decrypt",
        re.compile(
            r"\b(?:createDecipheriv|createDecipher|privateDecrypt|publicDecrypt)\b"
            r"|\bsubtle\s*\.\s*decrypt\b"
        ),
    ),
    ("start", re.compile(r"\b(?:spawn|spawnSync|exec|execSync|execFile|execFileSync|fork)\s*\(")),
    ("write", re.compile(r"\b(?:writeFile|writeFileSync|createWriteStream|appendFileSync)\s*\(")),
    ("download", re.compile(r"\bfetch\w*\s*\(|\bhttps?\s*\.\s*(?:get|request)\s*\(|\baxios\b")),
)
_REGISTRY_TARBALL: Final = re.compile(r"^https?://registry\.(?:npmjs\.org|yarnpkg\.com)/", re.I)
NOT_GITHUB: Final = "a repository on another git host: only GitHub repositories are read"
GITHUB_OTHER: Final = "a GitHub URL that is neither a repository nor its archive (a release asset)"
URL_NOT_FETCHED: Final = (
    "a tarball URL on another host is not fetched: the host may be the dependency's author's,"
    " who would see the request and could answer it differently (decision 0020)"
)
_HTTP: Final = re.compile(r"^https?://(?:[^@/\s]*@)?(?P<host>[^/:#?\s]+)", re.IGNORECASE)
_GITHUB_HOSTS: Final = frozenset(
    {"github.com", "www.github.com", "codeload.github.com", "objects.githubusercontent.com"}
)
_GIT_HOSTS: Final = frozenset({"gitlab.com", "www.gitlab.com", "bitbucket.org"})
EPOCH: Final = datetime(1970, 1, 1, tzinfo=UTC)


def wanted(change: Change) -> list[tuple[str, str]]:
    """The runtime dependencies (`dependencies`, `optionalDependencies`) this version adds or
    changes that npm fetches from outside the registry: a git repository or a URL, not a local
    path, a protocol npm can't fetch, or a registry tarball URL. Sorted by name."""
    new = runtime_dependencies(change.new.manifest)
    old = runtime_dependencies(change.previous.manifest) if change.previous else {}
    found = []
    for name, spec in sorted(new.items()):
        text = spec.strip()
        if old.get(name) == spec or is_registry_spec(text) or fetches_nothing(text):
            continue
        if text.startswith(("file:", "link:")) or npm_local_path(text):
            continue
        if _REGISTRY_TARBALL.match(text):
            continue
        found.append((name, spec))
    return found


def not_read(spec: str) -> str:
    """Why a non-registry dependency that isn't a GitHub repository is not read."""
    match = _HTTP.match(spec.strip())
    if match is None:
        return NOT_GITHUB  # another git host (GitLab, Bitbucket, a company's server)
    host = match["host"].lower()
    if host in _GITHUB_HOSTS:
        return GITHUB_OTHER
    if host in _GIT_HOSTS:
        return NOT_GITHUB
    return URL_NOT_FETCHED


@dataclass(frozen=True)
class DependencyFiles:
    """What `npm install` runs of a dependency, from its archive: its manifest as written
    (`raw`, None when it has none), its scripts as the install rules read them (`npm_runs`),
    and the files those reach: `package.json` (with those scripts), the install code
    (`install_sources`), the gyp files and the agent configuration the install code may copy."""

    raw: bytes | None
    files: dict[str, bytes] = field(default_factory=dict)
    held: dict[str, tuple[str, ...]] = field(default_factory=dict)
    nested: tuple[str, ...] = ()

    @property
    def manifest(self) -> dict[str, Any]:
        return read_manifest(self.files.get("package.json")) or {}


def read_dependency(tree: Mapping[str, bytes], spec: GitHubSpec) -> DependencyFiles:
    """The part of a dependency's tree (already under `spec.path`) its install runs."""
    raw = tree.get("package.json")
    manifest = read_manifest(raw)
    if manifest is None:
        return DependencyFiles(raw=None)
    slots, held = npm_runs(manifest, spec.hooks)
    presented = json.dumps(presented_manifest(manifest, slots), indent=2).encode()
    view = {**tree, "package.json": presented}
    sources = install_sources(view)
    kept = {"package.json": presented}
    kept |= {p: view[p] for p in sources if p in view}
    kept |= {p: view[p] for p in view if p == GYP_FILE or p.endswith((".gyp", ".gypi"))}
    kept |= agent_files(view, sources)
    nested = tuple(
        f"{name}: {snippet(redacted(value))}" for name, value in non_registry(manifest).items()
    )[:MAX_NESTED]
    return DependencyFiles(raw=raw, files=kept, held=dict(held), nested=nested)


def _extract_dependency(
    limits: ExtractLimits, spec: GitHubSpec, body: bytes
) -> DependencyFiles | str:
    """In a pool worker: extract the archive (under `spec.path`) and keep what install runs."""
    try:
        tree = extract_archive(body, limits=limits, directory=spec.path)
    except ValueError as exc:
        return str(exc)
    del body
    return read_dependency(tree.files, spec)


def _snapshot(files: DependencyFiles, fallback: str, commit: str) -> VersionSnapshot:
    """The dependency as a release the rules can read: named as its manifest names it, at its
    commit (what the rules' "since <version>" then says)."""
    manifest = files.manifest
    name = manifest.get("name")
    return VersionSnapshot(
        ref=PackageVersionRef(
            ecosystem="npm",
            name=name if isinstance(name, str) and name else fallback,
            version=commit[:12],
        ),
        publish=PublishInfo(),
        manifest=manifest,
    )


STATIC_CACHE: Final = ContentCache(None, STATIC_RULES)  # in memory: a pure function of content
CAPABILITIES: Final = CapabilityCache(None)
INNER_RULES: Final[tuple[Versioned, ...]] = (InstallHook(), *STATIC_RULES, *CODE_RULES)


def analyse(
    files: DependencyFiles,
    commit: str,
    base: tuple[DependencyFiles, str] | None = None,
    *,
    as_of: datetime = EPOCH,
    label: str = "dependency",
) -> tuple[tuple[Finding, ...], tuple[Evidence, ...]]:
    """The install rules on a dependency's install code (`files`, at `commit`), as a new
    package's, or against `base` (the files at the commit the previous release pinned) as an
    update's; explained within the dependency. Then what the install code reaches, as evidence
    (`reaches`). Paths are relative to the dependency; `label` names it when its manifest has
    no name."""
    snapshot = _snapshot(files, label, commit)
    before = _snapshot(base[0], label, base[1]) if base is not None else None
    base_files = base[0] if base is not None else None
    change = Change(new=snapshot, previous=before)
    findings: list[Finding] = list(InstallHook().evaluate(change, RuleContext(as_of=as_of)))
    # Stage 2's file rules read the manifest as written (its line numbers), not as presented.
    scanned = {**files.files, "package.json": files.raw or files.files.get("package.json", b"")}
    base_scanned = (
        {**base_files.files, "package.json": base_files.raw or b""}
        if base_files is not None
        else None
    )
    loaded = LoadedFiles("npm", files.files)
    findings += [
        m.finding(item.path)
        for item, content in new_contents(base_scanned, [(snapshot.ref.version, scanned)])
        for m in content_matches(item, content, BaseFiles(base_scanned), STATIC_CACHE, loaded)
    ]
    code = code_change(
        snapshot,
        files.files,
        base_files.files if base_files is not None else None,
        CAPABILITIES,
        install_sources,
        before.ref.version if before is not None else None,
        build_commands=gyp_commands,
    )
    findings += [f for rule in CODE_RULES for f in rule.evaluate_code(code)]
    return explained(findings), _reaches(code.install, code.install_files)


def _reaches(profile: Profile | None, install: Mapping[str, bytes]) -> tuple[Evidence, ...]:
    """What the install code uses, by capability (a few places each), and where its
    JavaScript decrypts data, starts a process, writes a file or downloads (`_CALLS`; the first
    such line of each file, a few in all): shown to reviewers, never scored."""
    found: list[Evidence] = []
    if profile is not None:
        for capability in Capability:
            uses = [u for u in profile.uses if u.use.capability == capability][:MAX_REACHES]
            found += [
                Evidence(
                    kind=EvidenceKind.FILE_SPAN,
                    path=u.path,
                    line_start=u.use.line,
                    line_end=u.use.line,
                    snippet=f"[{capability.value}] {u.use.snippet}",
                )
                for u in uses
            ]
    shown: dict[str, int] = {}
    for path in sorted(install):
        if language_for(path) is None:
            continue  # JavaScript and TypeScript; a shell script's lines are in the profile
        lines = install[path].decode("utf-8", "replace").splitlines()
        for label, pattern in _CALLS:
            for line_no, line in enumerate(lines, 1):
                if shown.get(label, 0) >= MAX_REACHES:
                    break
                if pattern.search(line):
                    shown[label] = shown.get(label, 0) + 1
                    found.append(
                        Evidence(
                            kind=EvidenceKind.FILE_SPAN,
                            path=path,
                            line_start=line_no,
                            line_end=line_no,
                            snippet=f"[{label}] {snippet(line.strip())}",
                        )
                    )
                    break  # the first such line of each file
    return tuple(found)


@dataclass
class _Slot:
    lock: threading.Lock = field(default_factory=threading.Lock)
    value: SourceDependency | None = None


def base_commit(change: Change, name: str, spec: GitHubSpec) -> str | None:
    """The commit the previous release pinned for the same dependency, when it pinned one by
    full id in the same repository (a commit bump): the dependency's code is then compared
    with it, as an update is with its previous release. A tag or branch then is not used: it
    resolves to today's commit, not the one installed then."""
    if change.previous is None:
        return None
    before = runtime_dependencies(change.previous.manifest).get(name)
    old = github_spec(before) if before is not None else None
    if old is None or old.committish is None or not re.fullmatch(r"[0-9a-f]{40}", old.committish):
        return None
    same = (old.owner.lower(), old.name.lower(), old.path, old.tarball) == (
        spec.owner.lower(),
        spec.name.lower(),
        spec.path,
        spec.tarball,
    )
    return old.committish if same else None


class NpmGitDependencyLookup:
    """Reads the install code of the GitHub dependencies a version adds or changes (a
    `SourceDependencyLookup`). Requests go through `fetcher` (the run's: recorded in its
    snapshot, so a replay reads the same) with their own `RepoMemory`, so each repository's
    refs and each archive go to the network at most once a pass, extraction is bounded and
    runs in `pool` when given, and network failures come back `transient`.

    `plan` picks, in run order, the dependencies to read: each package (all its versions in
    the run) at most `per_package` distinct ones, the run at most `cap`; the rest are noted as
    over the cap. Without a plan (the evaluation predictor) nothing is capped. Each
    (dependency, base commit) is read once for the run; a network failure is forgotten at
    `new_pass`."""

    def __init__(
        self,
        fetcher: HttpFetcher,
        *,
        pool: Executor | None = None,
        cap: int | None = MAX_GIT_DEPENDENCIES,
        per_package: int | None = MAX_PER_PACKAGE,
        as_of: datetime | None = None,
    ) -> None:
        self.github = GitHub(fetcher, limits=DEPENDENCY_LIMITS)
        self.memory = RepoMemory(pool=pool)
        self.cap = cap
        self.per_package = per_package
        self.as_of = as_of
        self._lock = threading.Lock()
        self._allowed: frozenset[tuple[object, ...]] | None = None
        self._planned = 0
        self._slots: dict[tuple[object, ...], _Slot] = {}

    def plan(self, candidates: Sequence[Candidate], ctx: CorrelationContext) -> int:
        allowed: dict[tuple[object, ...], None] = {}
        wanted_keys: set[tuple[object, ...]] = set()
        claimed: dict[str, set[tuple[object, ...]]] = {}
        for candidate in candidates:
            package = candidate.change.new.ref.name
            for _, spec in wanted(candidate.change):
                found = github_spec(spec)
                if found is None:
                    continue
                key = found.key
                wanted_keys.add(key)
                if key in allowed:
                    continue
                mine = claimed.setdefault(package, set())
                if self.per_package is not None and len(mine) >= self.per_package:
                    continue
                if self.cap is not None and len(allowed) >= self.cap:
                    continue
                allowed[key] = None
                mine.add(key)
        with self._lock:
            self._allowed = frozenset(allowed)
            self._planned = len(wanted_keys)
            if self.as_of is None:
                self.as_of = ctx.as_of
        return len(allowed)

    def __call__(self, candidate: Candidate) -> tuple[SourceDependency, ...]:
        change = candidate.change
        out = []
        for name, spec in wanted(change):
            shown = snippet(redacted(spec)) or ""
            found = github_spec(spec)
            if found is None:
                out.append(SourceDependency(name=name, spec=shown, unavailable=not_read(spec)))
                continue
            with self._lock:
                capped = self._allowed is not None and found.key not in self._allowed
            if capped:
                out.append(
                    SourceDependency(
                        name=name, spec=shown, unavailable="over the run's git dependency cap"
                    )
                )
                continue
            read = self._read(found, base_commit(change, name, found))
            out.append(read.model_copy(update={"name": name, "spec": shown}))
        return tuple(out)

    def new_pass(self) -> None:
        self.memory.new_pass()
        with self._lock:
            for slot in self._slots.values():
                if slot.value is not None and slot.value.transient:
                    slot.value = None

    def requests(self) -> NetworkRequests:
        return self.memory.requests()

    def stats(self) -> Mapping[str, object]:
        with self._lock:
            values = [s.value for s in self._slots.values() if s.value is not None]
            allowed = len(self._allowed) if self._allowed is not None else self._planned
        unavailable = {
            f"{v.repo or '?'} {v.how or ''}".strip(): v.unavailable or ""
            for v in values
            if v.unavailable is not None
        }
        return {
            "cap": self.cap,
            "per_package": self.per_package,
            "rules": rules_fingerprint(INNER_RULES),
            "wanted": self._planned,
            "capped": max(0, self._planned - allowed),
            "read": sum(v.unavailable is None for v in values),
            "unavailable": len(unavailable),
            "with_findings": sum(bool(v.findings) for v in values),
            "errors": dict(sorted(unavailable.items())),
        }

    def _read(self, spec: GitHubSpec, base: str | None) -> SourceDependency:
        key: tuple[object, ...] = (*spec.key, base)
        with self._lock:
            slot = self._slots.setdefault(key, _Slot())
        with slot.lock:
            if slot.value is None:
                slot.value = self._fetch(spec, base)
            return slot.value

    def _fetch(self, spec: GitHubSpec, base: str | None) -> SourceDependency:
        """Resolve, fetch and analyse one dependency. A network failure (`TransientFetchError`,
        including the memory's `RepoNetworkError`) comes back `transient`; a deleted
        repository, a missing ref or an unreadable archive comes back `unavailable`."""
        repo = spec.repo
        found = SourceDependency(name="", spec="", repo=str(repo))
        try:
            refs = self.memory.refs(self.github, repo)
            if refs is None:
                why = f"repository {repo} not found (deleted, renamed or private)"
                return found.model_copy(update={"unavailable": why})
            resolved = resolve(spec, refs)
            if resolved is None:
                why = f"`{spec.reference}` not found in {repo}"
                return found.model_copy(update={"unavailable": why})
            commit, how = resolved
            found = found.model_copy(update={"commit": commit, "how": how})
            files = self._files(spec, commit)
        except TransientFetchError as exc:
            why = f"network: {exc}"[:300]
            return found.model_copy(update={"unavailable": why, "transient": True})
        except (FetchError, ValueError) as exc:  # an archive over the limits, HTTP 404
            return found.model_copy(update={"unavailable": f"archive: {exc}"[:300]})
        if files.raw is None:
            why = "no package.json at that commit: npm can't install it"
            return found.model_copy(update={"unavailable": why})
        before = None
        if base is not None and base != commit:
            try:
                before = self._files(spec, base)
            except TransientFetchError as exc:
                why = f"network: {exc}"[:300]
                return found.model_copy(update={"unavailable": why, "transient": True})
            except FetchError, ValueError:  # the earlier commit is gone: read as new
                before = None
        compared = (
            (before, base)
            if base is not None and before is not None and before.raw is not None
            else None
        )
        findings, reaches = analyse(
            files, commit, compared, as_of=self.as_of or EPOCH, label=str(repo)
        )
        return found.model_copy(
            update={
                "base_commit": compared[1] if compared is not None else None,
                "hooks": files.held,
                "findings": findings,
                "reaches": reaches,
                "nested": files.nested,
            }
        )

    def _files(self, spec: GitHubSpec, commit: str) -> DependencyFiles:
        if self.memory.pool is not None:
            job = partial(_extract_dependency, self.github.limits, spec)
            return self.memory.compared_in_pool(self.github, spec.repo, commit, spec.path, job)
        with self.memory.archive(self.github, spec.repo, commit, spec.path) as tree:
            return read_dependency(tree, spec)
