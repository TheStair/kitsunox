"""Stage 4 wiring for npm: the rule set, known-malware records, dependency lookups and
repository comparison that `kitsunox correlate` and `collect` use. Kept apart from
`stages/correlate.py`, which is ecosystem-agnostic (like `stages/code.py` for Stage 3)."""

from __future__ import annotations

import itertools
import math
import threading
from collections.abc import Iterable, Mapping, Sequence
from concurrent.futures import Executor
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Final

import httpx

from kitsunox.core.models import Candidate, Severity, Window
from kitsunox.core.run import CORRELATE_SNAPSHOT, DataDir, RunManifest
from kitsunox.core.watchlist import Watchlist
from kitsunox.ecosystems.npm.packument import Packument, publish_info
from kitsunox.ecosystems.npm.registry import NpmEcosystem
from kitsunox.ecosystems.npm.repo import NpmLocator
from kitsunox.ecosystems.npm.rules.correlate import RULES as NPM_CORRELATION_RULES
from kitsunox.ecosystems.npm.rules.correlate import (
    foreign_added_dependencies,
    undeclared_lookups,
)
from kitsunox.evaluation.labels import label_store
from kitsunox.githost.github import GitHub
from kitsunox.rules.repo import RULES as REPO_RULES
from kitsunox.stages.correlate import (
    CandidateFile,
    CorrelationContext,
    CorrelationRule,
    DependencyRecord,
    DependencyStatus,
    DependencyVersion,
    RepoLookup,
    correlate_run,
)
from kitsunox.stages.repo import (
    NetworkRequests,
    RepoComparison,
    RepoMemory,
    compare,
    compare_pool,
    with_history,
    with_trust,
)
from kitsunox.stages.static import ArtifactFiles, Unavailable
from kitsunox.stages.triage import at_least
from kitsunox.util.http import FetchError, FetchMode, HttpFetcher, Snapshot, TransientFetchError

NPM: Final = "npm"
CORRELATION_RULES: Final[tuple[CorrelationRule, ...]] = (*NPM_CORRELATION_RULES, *REPO_RULES)
# Explanations of a lookup that failed on the network: the same text for every version that
# needed the failed request (e.g. `network: o/r refs unavailable`), so `correlate.jsonl` doesn't
# depend on which worker thread asked first. The errors are in `correlate.json`.
REPO_NETWORK: Final = "network: "
PACKAGE_FILES_NETWORK: Final = "package files: network failure; Stage 2 retries next tick"
# Distinct dependency names one run may look up in the registry, per started day of its
# window (`dependency_cap`). Measured on run `20261029T221803Z-npm` (24 hours, 110,084
# versions): 628 names pass the prefilter (`foreign_added_dependencies`), ~27 an hourly tick,
# median 29 KB each. 1,000 a day covers a catch-up run of any length and bounds a burst (~30 MB
# a day at the median).
MAX_DEPENDENCY_LOOKUPS: Final = 1_000
# ... of which one release may claim at most this many (names no earlier release claimed), so a
# single release with 2,000 junk dependencies (404s count: we can't tell before asking) can't
# use up the run's cap. On the same day, 487 versions added foreign dependencies; the most was
# 34 (`@tabaxal/web@0.1.0-alpha.0`), then 22 and 16. At 40 no release of that day loses a name.
# The allowance is per package, shared by all its versions in the run: 25 versions of one
# throwaway package each adding 40 junk names would otherwise use up an hourly run's cap.
MAX_LOOKUPS_PER_RELEASE: Final = 40


class NpmRepoLookup:
    """Compare a candidate's release with its repository (a `RepoLookup`). The release's files
    come through the same fetcher (Stage 2 already fetched them, so from the immutable index).
    A failure leaves the version without a comparison rather than failing the run (Stage 4 adds
    evidence; it is not a gate), but a repository request that failed on the network is marked
    `transient`, so `correlate_run` tries it again (decision 0009). A failed request isn't
    recorded, so the retry goes to the network. `RepoMemory` keeps refs for the run, and each
    failed request for the pass, so the versions needing it don't each wait out the fetcher's
    back-off; they all get the same explanation (`REPO_NETWORK` + the `RepoNetworkError`).

    Release files that failed on the network (`files_transient`) are not retried here: Stage 2
    failed on the same tarball (Stage 4 reads only versions Stage 2 read, and its fetches sit in
    the immutable index), marked it, and `collect` redoes the run from Stage 1 next tick.

    With a GitHub token, a clean comparison of a version an earlier stage found something
    MEDIUM or above in also gets the repository's facts (`with_trust`): only those versions
    can be cleared by an established match (`repo.established-match`), and asking for every
    watched update would spend ~10 times the API quota. Every compared update gets its
    history (`with_history`): the previous release's commit from the refs already fetched,
    the release commit's date when a tag found it (~500 requests a day, measured 2026-11-06),
    and, for the same flagged versions, how the two commits relate."""

    def __init__(
        self, fetcher: HttpFetcher, *, pool: Executor | None = None, token: str | None = None
    ) -> None:
        self.files = ArtifactFiles(NpmEcosystem(fetcher))
        self.github = GitHub(fetcher, token=token)
        self.locator = NpmLocator()
        self.memory = RepoMemory(pool=pool)

    def new_pass(self) -> None:
        self.memory.new_pass()

    def requests(self) -> NetworkRequests:
        return self.memory.requests()

    def __call__(self, candidate: Candidate) -> RepoComparison | None:
        tree = self.files(candidate.change.new)
        if isinstance(tree, Unavailable):
            if tree.transient:
                return RepoComparison(unavailable=PACKAGE_FILES_NETWORK, files_transient=True)
            return RepoComparison(unavailable=f"package files {tree.reason}"[:300])
        try:
            comparison = compare(
                candidate.change, tree, self.locator, self.github, memory=self.memory
            )
        except TransientFetchError as exc:  # a `RepoNetworkError`: names the request only
            return RepoComparison(unavailable=f"{REPO_NETWORK}{exc}"[:300], transient=True)
        except FetchError as exc:  # not the network: e.g. a malformed ref advertisement
            return RepoComparison(unavailable=str(exc)[:300])
        flagged = any(at_least(f.severity, Severity.MEDIUM) for f in candidate.findings)
        if flagged:
            comparison = with_trust(comparison, self.github, self.memory)
        return with_history(
            comparison, candidate.change, self.locator, self.github, self.memory, ask_range=flagged
        )


def repo_lookup(
    fetcher: HttpFetcher, *, pool: Executor | None = None, token: str | None = None
) -> RepoLookup:
    return NpmRepoLookup(fetcher, pool=pool, token=token)


@dataclass
class _Slot:
    lock: threading.Lock = field(default_factory=threading.Lock)
    record: DependencyRecord | None = None


# Packuments fetched and parsed at once by the dependency lookups (the rest wait): eight
# workers parsing large ones at the same time took Stage 4 to 7 GB at its start on 2026-10-30.
PACKUMENTS_IN_MEMORY: Final = 3


def dependency_cap(window: Window) -> int:
    """The run's lookup cap: `MAX_DEPENDENCY_LOOKUPS` per started day of its window."""
    days = math.ceil((window.end - window.start) / timedelta(days=1))
    return MAX_DEPENDENCY_LOOKUPS * max(1, days)


class NpmDependencyLookup:
    """Registry records of dependencies (a `DependencyLookup`): the dependency's packument,
    fetched through the run's fetcher (so it is recorded in `correlate-snapshot.json` and a
    replay serves it), with the same request Stage 0 sends. Not kept across runs: packuments
    change.

    `plan` (called by `correlate_run`) picks the names to look up from what
    `foreign_added_dependencies` yields: updates first (on an update this is the one signal
    Stages 2-3 can't supply; a new package's code they read anyway), then new packages, each in
    run order. Each release may claim at most `per_release` names that no earlier release
    claimed, in the order the rule lists them (by package.json key), and the run at most `cap`.
    Other names answer `CAPPED` without a request. Without a plan (the evaluation predictor)
    nothing is capped, and names are fetched when first asked.

    A request that fails on the network, after the fetcher's own attempts, answers `FAILED`
    (`transient`) until `new_pass`, so the versions depending on it don't each wait out the
    back-off, and `correlate_run` retries it. Any other fetch failure (a replay miss, an
    oversized response) and a document that isn't the package's packument (not JSON, a captive
    portal page, another name) answer `FAILED` for the run, with the same text in the rule, so a
    replay of a run that failed reads the same. The rule then says it was not evaluated
    (decision 0009). Only a 404 is `MISSING`."""

    def __init__(
        self,
        fetcher: HttpFetcher,
        *,
        cap: int | None = MAX_DEPENDENCY_LOOKUPS,
        per_release: int | None = MAX_LOOKUPS_PER_RELEASE,
    ) -> None:
        self.npm = NpmEcosystem(fetcher)
        self.cap = cap
        self.per_release = per_release
        self._lock = threading.Lock()
        self._parsing = threading.BoundedSemaphore(PACKUMENTS_IN_MEMORY)
        self._slots: dict[str, _Slot] = {}
        self._allowed: frozenset[str] | None = None
        self._planned = 0
        self._limited = 0  # packages with names over `per_release`
        self._undeclared = 0  # names planned from `undeclared_lookups`
        self._errors: dict[str, str] = {}  # names whose record is FAILED: why
        self._sent: set[str] = set()  # this pass's requests (RECORD mode)
        self._failed: dict[str, str] = {}  # this pass's network failures

    def plan(self, candidates: Sequence[Candidate], ctx: CorrelationContext) -> tuple[str, ...]:
        # Two passes rather than a list: `candidates` may be read from disk (`RunVersions`).
        ordered = itertools.chain(
            (c for c in candidates if c.change.previous is not None),
            (c for c in candidates if c.change.previous is None),
        )
        wanted: dict[str, None] = {}
        allowed: dict[str, None] = {}
        limited: set[tuple[str, str]] = set()  # releases with names over `per_release`
        claimed_by: dict[str, int] = {}  # package name -> names it claimed, over all its versions
        # Packages the code loads without declaring them (`undeclared_lookups`) come after every
        # declared dependency, in the same order, so they never take a declared one's place.
        undeclared: list[tuple[tuple[str, str], tuple[str, ...]]] = []

        def claim(release: tuple[str, str], names: Iterable[str]) -> None:
            package = release[0]
            claimed = claimed_by.get(package, 0)
            for name in names:
                wanted.setdefault(name)
                if name in allowed:
                    continue
                if self.per_release is not None and claimed >= self.per_release:
                    limited.add(release)
                elif self.cap is None or len(allowed) < self.cap:
                    allowed[name] = None
                    claimed += 1
            claimed_by[package] = claimed

        for candidate in ordered:
            ref = candidate.change.new.ref
            added = foreign_added_dependencies(candidate.change, ctx.watchlist)
            claim((ref.name, ref.version), (d.target for d in added))
            if loads := undeclared_lookups(candidate, ctx.watchlist):
                undeclared.append(((ref.name, ref.version), tuple(load.name for load in loads)))
        for release, names in undeclared:
            claim(release, names)
        with self._lock:
            self._planned = len(wanted)
            self._undeclared = len({n for _, names in undeclared for n in names})
            self._limited = len(limited)
            self._allowed = frozenset(allowed)
        return tuple(allowed)

    def __call__(self, name: str) -> DependencyRecord:
        with self._lock:
            if self._allowed is not None and name not in self._allowed:
                return DependencyRecord(name=name, status=DependencyStatus.CAPPED)
            slot = self._slots.setdefault(name, _Slot())
        with slot.lock:
            if slot.record is None:
                slot.record = self._fetch(name)
            return slot.record

    def new_pass(self) -> None:
        """Forget the lookups that failed on the network (they are asked again) and the last
        pass's requests. Permanent failures are kept for the run."""
        with self._lock:
            for slot in self._slots.values():
                if slot.record is not None and slot.record.transient:
                    slot.record = None
            self._sent.clear()
            self._failed.clear()

    def requests(self) -> NetworkRequests:
        """Names this pass asked the registry for (in a recording run Stage 4's snapshot
        starts empty and each name is asked once a pass, so each went to the network), and the
        error of each that failed there."""
        with self._lock:
            return NetworkRequests(sent=len(self._sent), errors=tuple(sorted(self._failed.items())))

    def _fetch(self, name: str) -> DependencyRecord:
        if self.npm.fetcher.mode is FetchMode.RECORD:
            with self._lock:
                self._sent.add(name)
        try:
            with self._parsing:  # a packument can be 256 MB, several GB once parsed
                packument = self.npm.packument(name)
                record = dependency_record(packument) if packument is not None else None
        except TransientFetchError as exc:
            return self._failed_record(name, str(exc), network=True)
        except FetchError as exc:  # a replay miss, an oversized body, a 4xx other than 404
            return self._failed_record(name, str(exc), network=False)
        except ValueError as exc:  # not JSON, or not this package's document
            return self._failed_record(name, f"malformed packument: {exc}", network=False)
        except RecursionError:  # nested deeper than the JSON parser goes: hostile, not a crash
            return self._failed_record(
                name, "malformed packument: nested too deeply", network=False
            )
        with self._lock:
            self._errors.pop(name, None)  # recovered in a retry pass
        if record is None:
            return DependencyRecord(name=name, status=DependencyStatus.MISSING)
        return record

    def _failed_record(self, name: str, error: str, *, network: bool) -> DependencyRecord:
        with self._lock:
            self._errors[name] = error[:300]
            if network:
                self._failed[name] = error[:300]
        return DependencyRecord(name=name, status=DependencyStatus.FAILED, transient=network)

    def stats(self) -> Mapping[str, object]:
        with self._lock:
            records = [s.record for s in self._slots.values() if s.record is not None]
            allowed = len(self._allowed) if self._allowed is not None else self._planned
            return {
                "cap": self.cap,
                "per_release": self.per_release,
                "names": self._planned,
                "undeclared": self._undeclared,
                "capped": max(0, self._planned - allowed),
                "releases_limited": self._limited,
                "looked_up": len(records),
                "found": sum(r.status is DependencyStatus.FOUND for r in records),
                "missing": sum(r.status is DependencyStatus.MISSING for r in records),
                "failed": sum(r.status is DependencyStatus.FAILED for r in records),
                "errors": dict(sorted(self._errors.items())),
            }


def dependency_record(packument: Packument) -> DependencyRecord:
    """Every version with a publish time, oldest first, with the accounts its manifest names
    (none for a version the registry no longer lists)."""
    versions = []
    for version, moment in packument.version_times.items():
        manifest = packument.versions.get(version)
        accounts: tuple[str, ...] = ()
        if manifest is not None:
            info = publish_info(manifest, moment)
            accounts = tuple(sorted({*info.maintainers, *filter(None, [info.publisher])}))
        versions.append(DependencyVersion(version=version, published_at=moment, accounts=accounts))
    versions.sort(key=lambda v: (v.published_at, v.version))
    return DependencyRecord(
        name=packument.name,
        status=DependencyStatus.FOUND,
        versions=tuple(versions),
        maintainers=packument.maintainers,
    )


def run_watchlist(data: DataDir, manifest: RunManifest) -> Watchlist | None:
    """The watchlist the run's Stage 0 used (checked against its recorded SHA-256), if any."""
    if manifest.watchlist_id is None:
        return None
    return data.watchlists.load(
        manifest.ecosystem, manifest.watchlist_id, sha256=manifest.watchlist_sha256
    )


def run_correlate_stage(
    data: DataDir,
    run_id: str,
    *,
    workers: int = 8,
    client: httpx.Client | None = None,
    seed: Snapshot | None = None,
    github_token: str | None = None,
) -> CandidateFile:
    """Stage 4 on a run Stage 3 has processed, with the run's watchlist. Repository and
    dependency requests are recorded in `correlate-snapshot.json` next to the run; a `seed`
    (the run's own earlier snapshot, when re-scoring) serves what it holds as recorded. With a
    `github_token`, clean comparisons get repository facts from the API (`NpmRepoLookup`). The
    caller holds the lock."""
    run_dir = data.run_dir(run_id)
    manifest = RunManifest.load_json((run_dir / "manifest.json").read_bytes())
    labels_id = label_store(data).latest_id(NPM, not_after=manifest.as_of)
    labels = label_store(data).load(NPM, labels_id) if labels_id else None
    snapshot = seed if seed is not None else Snapshot()
    fetcher = HttpFetcher(
        store=data.blobs,
        snapshot=snapshot,
        mode=FetchMode.RECORD,
        immutable_index=data.immutable_index,
        client=client,
    )
    ctx = CorrelationContext(
        as_of=manifest.as_of,
        known_bad=labels,
        watchlist=run_watchlist(data, manifest),
        dependencies=NpmDependencyLookup(fetcher, cap=dependency_cap(manifest.window)),
    )
    try:
        with compare_pool() as pool:  # archives are extracted in worker processes
            candidates = correlate_run(
                run_dir,
                ctx,
                CORRELATION_RULES,
                repo=repo_lookup(fetcher, pool=pool, token=github_token),
                workers=workers,
            )
    finally:
        fetcher.close()
    snapshot.save(run_dir / CORRELATE_SNAPSHOT)
    return candidates
