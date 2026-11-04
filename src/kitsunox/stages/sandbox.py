"""Stage 5: dynamic analysis by OpenSSF package-analysis, pipeline side. See
`docs/stages/sandbox.md`.

package-analysis is run by the project owner, on their own airgapped analysis VM, following its
own documentation; Kitsunox never runs it, Docker or package code. So an analysis is
asynchronous: one call exports tarballs, the owner analyses them (perhaps days later, on
another machine), a later call imports the results. Each live call of
`run_sandbox_stage(data, run_id, results=...)`:

1. **imports** (`sandbox/results.py`): for every job exported by an *active* run
   (`active_runs`: every unpruned run up to this run's `as_of`, by the runs' own manifests, no
   clock; newest first, at most `MAX_ACTIVE_RUNS`), reads its result from the configured
   results root, as hostile data, into `data/sandbox/<key>/`. A result is imported however
   late it arrives, as long as the run that exported it hasn't been pruned (round-3 review:
   results over 48 hours late were silently never imported);
2. **refreshes** every other active run whose recorded answers have changed since it was
   rendered (a pending job now has a result, or a rejection was replaced), by rendering it
   again with the cap it was rendered with, so a result reaches the run that exported it. The
   run ids are returned: their reports need rebuilding;
3. **renders** this run:
   - inspects each version Stage 4 reported: its tarball, through the run's own fetch records,
     and what the tarball's `package.json` says: the hooks npm runs and the name npm installs
     it under, with the tarball's file list (`sandbox/select.py`);
   - selects those with a hook, highest score first, at most `cap` (the rest *deferred*);
   - for each selected version whose `package.json` needs dependencies, builds the **offline
     dependency bundle** (below), in score order;
   - for each selected version, builds the `SandboxJob` and its key; applies the rules to an
     accepted cached result (with the analysed tarball's file list, `shipped`, and a bundle's
     dependency names, `bundled_deps`), records a cached rejection as
     `sandbox.result-rejected`, and otherwise exports the tarball (or bundle) for
     package-analysis (`sandbox/spool.py`) and marks the version `pending`;
   - writes `sandbox.jsonl` (every version Stage 4 reported, in Stage 4's order: its Stage 4
     `Candidate` plus Stage 5's findings and a `StageDecision(stage="sandbox",
     forwarded=True)`) and `sandbox.json` (cap, network, rule fingerprint, counts, each
     version's key, and each key's answer: `accepted` with the result's sha256, `rejected` with
     its reason, `pending`, `export-failed`, `unconfigured` or `cache-unreadable`).

It also returns, per active run older than `overdue_after` (default `OVERDUE_AFTER`, by
`as_of`), how many of its exported jobs still have no answer at all, for the caller to tell the
owner (`SandboxStageResult.overdue`).

**The gate** is the results root: with `results=None` nothing is exported or imported
(selected versions say "not configured"), but results already cached are still applied.

**Airgapped.** Every exported job is for package-analysis on the owner's airgapped VM
(`-fully-offline -nopull -offline`, `sandbox/spool.py`); there is no online mode.
`sandbox.json` records `"network": "airgapped"` for the reader.

**Offline dependency bundles** (`sandbox/bundle.py`, `docs/proposals/offline-dependency-
bundle.md`). Without a network, `npm install` of a tarball with registry dependencies fails
before any hook runs. So a selected version whose tarball's `package.json` needs dependencies
is exported as a Kitsunox-built bundle: its own files plus every dependency npm would install
at the run's `as_of`, resolved, fetched and integrity-checked through this stage's
`HttpFetcher`, recorded in `sandbox-snapshot.json` next to the run (so the export replays), and
read only with `extract_tar_gz`. Then:

- **complete**: the bundle is exported (`<key>.tgz`, with its `BundleRecord` as
  `<key>.bundle.json`); the job's key is over the bundle's uncompressed tar and dependency
  set; the version gets `sandbox.bundled` (INFO), and the rules get the bundle's file list
  and the names it added;
- **incomplete or not bundleable** (an unresolved required dependency, a cap, an original
  that can't be repacked faithfully, a definite fetch error): the registry tarball is exported
  under its usual key, with `unbundled_reason`, and the version gets `sandbox.bundle-incomplete`
  (INFO: the offline install will likely fail);
- **a network failure** (`TransientFetchError`, decision 0009): nothing is exported for the
  version, which reads `pending` (`BUNDLE_PENDING`); later live calls try again (the run counts
  as stale until it is bundled), and the rest of this call stops bundling. A call also stops
  bundling once it has downloaded `bundle_budget` new bytes (`BUNDLE_BUDGET`; jobs are bundled
  in score order).

A live rendering reuses the job a run already exported for a version (with its record), so
refreshing a run never changes a key that a result may be on its way for. Without a results root
nothing is fetched: bundles are rebuilt only from the run's own snapshot. Replay rebuilds every
bundle from the snapshot in REPLAY mode and requires the recorded key (else the version reads
`BUNDLE_UNREPRODUCIBLE`); versions recorded as unbundled or pending are reproduced from
`sandbox.json` ("bundles").

**The tarball's file list.** The rules get the analysed tarball's file list (`shipped`: every
regular file, the top directory stripped, from the same `extract_tar_gz` pass that reads the
hooks; for a bundle, the bundle's list, its dependencies included), so `sandbox.download-exec`
can tell a file npm unpacked into the package's directory from one written there during the
run. It is recomputed on every rendering (from the blob store, or the bundle and its record),
replay included; a tarball that can't be read has no job anyway.

**What an answer becomes.** Every accepted result goes through the rules
(`kitsunox.rules.sandbox.apply_rules` by default), whatever its status: an `infra-error` result
(a phase ended `error_other`, or no install phase) also gets a `sandbox.not-run` INFO saying
so, and a failed install (`error_analysis`: npm exited non-zero, as installs that need registry
dependencies the tarball doesn't ship do without a network) a `sandbox.install-failed` INFO,
since what was recorded before the failure is still evidence but the import phase never ran. A
rejected result is `sandbox.result-rejected` (MEDIUM; HIGH for a result too large to read). The
pipeline's own cache being unreadable is a `sandbox.not-run` (INFO).

Stage 5 only adds: it never sets `forwarded=False` and never removes a finding. A version that
qualified but wasn't analysed says why with a `sandbox.not-run` INFO finding.

**Replay and determinism.** `replay=True` touches neither the results root nor the export, and
imports and refreshes nothing: each key's answer is the one the run's `sandbox.json` recorded
(an accepted result is re-parsed from the cache, and must be the recorded file; anything else
is reproduced from the record), so over the same data it writes a byte-identical
`sandbox.jsonl`, however many results arrived since. A run's `sandbox.jsonl` and `sandbox.json`
do change when a refresh renders it again (pending -> analysed); replay reproduces the latest
rendering. Nothing here reads the clock. The caller holds `DataDir.lock()`.
"""

from __future__ import annotations

import json
import shutil
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Final, Literal, Protocol, get_args

import httpx

from kitsunox.core.models import Candidate, Finding, StageDecision
from kitsunox.core.rules import rules_fingerprint
from kitsunox.core.run import SANDBOX_SNAPSHOT, DataDir, RunManifest
from kitsunox.rules.sandbox import RULES, apply_rules
from kitsunox.sandbox.bundle import (
    BundleError,
    BundleRecord,
    UnresolvedSpec,
    make_bundle,
    registry_packuments,
    registry_tarball_url,
    wants_bundle,
)
from kitsunox.sandbox.models import (
    NETWORK,
    Observation,
    SandboxJob,
    SandboxRule,
    SandboxRun,
)
from kitsunox.sandbox.ossf import SandboxResult
from kitsunox.sandbox.results import (
    SANDBOX_INFO,
    CacheProblem,
    ImportOutcome,
    ImportRecord,
    RejectedResult,
    import_results,
    load_accepted,
    load_cached,
    peek,
)
from kitsunox.sandbox.select import (
    ANALYSIS_INFRA,
    BUNDLE_BUDGET,
    BUNDLE_INCOMPLETE,
    BUNDLE_PENDING,
    BUNDLE_UNREPRODUCIBLE,
    BUNDLED,
    CACHE_UNREADABLE,
    DEFAULT_CAP,
    EXPORT_FAILED,
    INSTALL_FAILED,
    INTEGRITY,
    NOT_CAPTURED,
    NOT_CONFIGURED,
    NOT_IN_STORE,
    NOT_RUN,
    OVERSIZE,
    PENDING,
    RESULT_REJECTED,
    STAGE_ID,
    TARBALL_FETCH_FAILED,
    TARBALL_PENDING,
    TARBALL_UNREPRODUCIBLE,
    Entry,
    Inspection,
    TarballInfo,
    deferred,
    inspect_tarball,
    priority,
    reported,
    select,
)
from kitsunox.sandbox.spool import (
    CACHE_DIR,
    KEY_PATTERN,
    MAX_TARBALL_UNPACKED_BYTES,
    TARBALL_LIMITS,
    TarballIndex,
    build_job,
    export_jobs,
    exported_file,
    exported_jobs,
    load_tarball,
    read_bundle_record,
    tarball_name,
)
from kitsunox.stages.correlate import CandidateFile, score
from kitsunox.util.disk import DiskSpaceError
from kitsunox.util.files import atomic_write
from kitsunox.util.hashing import sha256_hex
from kitsunox.util.http import (
    BlobStore,
    FetchedResponse,
    FetchError,
    FetchMode,
    HttpFetcher,
    Snapshot,
    SnapshotEntry,
    TransientFetchError,
    request_key,
)

# 8: one dependency file may take the bundle's whole unpacked cap (was extract_tar_gz's 64 MiB);
#    Stage 5 downloads the tarballs no earlier stage captured, up to 128 MiB (was 16 MB)
# 7: bundle format 2 (file modes, npm's reading of links/BOM/repeated keys, arborist's queue
#    order, peer sets and REPLACE, new caps and incomplete reasons), unbundled "internal-error"
# 6: offline dependency bundles (bundled jobs, sandbox-snapshot.json, "bundles" in sandbox.json)
# 5: airgapped only (no network mode), the tarball's file list given to the rules
# 4: network mode, install name, import over every unpruned run, install-failed
STAGE_VERSION: Final = 8
BUNDLE_BUDGET_BYTES: Final = 2 * 1024 * 1024 * 1024  # new bytes downloaded per live call
MAX_MISSING: Final = 20  # unresolved required dependencies recorded per version
MAX_SPEC_SHOWN: Final = 120  # characters of each one's spec
SANDBOX_JSONL: Final = "sandbox.jsonl"
MAX_ACTIVE_RUNS: Final = 400  # runs imported into and refreshed per call (7 days hourly: 168)
OVERDUE_AFTER: Final = timedelta(days=2)  # exported jobs still unanswered after this are told

Bucket = Literal["analysed", "infra_error", "rejected", "pending", "deferred", "not_run", "no_hook"]
State = Literal[
    "accepted", "rejected", "pending", "export-failed", "unconfigured", "cache-unreadable"
]
# What the bundle step made of a selected version that needs dependencies (`sandbox.json`
# "bundles"): exported as a bundle; exported as the registry tarball (`reason`); not exported
# yet (network failure or budget: `reason`, retried); no job (`reason`: not configured and not
# in the run's snapshot, or replay couldn't rebuild it).
BundleState = Literal["bundled", "unbundled", "pending", "unavailable"]


class Analyse(Protocol):
    """The rules over one result (`kitsunox.rules.sandbox.apply_rules` by default). `shipped`
    is the analysed tarball's file list (`select.TarballInfo.files`, or a bundle's), None when
    unknown; `bundled_deps` the folder names a bundle added (None: not a bundle)."""

    def __call__(
        self,
        candidate: Candidate,
        run: SandboxRun,
        observations: Sequence[Observation],
        *,
        shipped: frozenset[str] | None = None,
        bundled_deps: frozenset[str] | None = None,
    ) -> Sequence[Finding]: ...


_TARBALL_REASONS: Final = {"missing": NOT_IN_STORE, "oversize": OVERSIZE, "integrity": INTEGRITY}
# Why Stage 5's own download of a tarball gave nothing, recorded so a replay says the same.
_FETCH_REASONS: Final = frozenset({TARBALL_PENDING, TARBALL_FETCH_FAILED})
STAGING_DIR: Final = "staging"  # in CACHE_DIR: bundles built this call, until exported


@dataclass(frozen=True)
class Answer:
    """What a key's analysis was when a run was rendered (`sandbox.json` "answers")."""

    state: State
    result_sha256: str | None = None
    reason: str | None = None

    def as_json(self) -> dict[str, str | None]:
        return {"state": self.state, "result_sha256": self.result_sha256, "reason": self.reason}


@dataclass(frozen=True)
class SandboxStageResult:
    candidates: tuple[Candidate, ...]  # what this run's `sandbox.jsonl` now holds
    refreshed: tuple[str, ...] = ()  # earlier runs rendered again: rebuild their reports
    imported: Mapping[str, ImportOutcome] = field(default_factory=dict)  # key -> outcome
    # run id -> how many of its exported jobs have no answer yet, for runs older than
    # `overdue_after`: the owner hasn't analysed them (or copied the results back).
    overdue: Mapping[str, int] = field(default_factory=dict)


def evaluate_each(rules: Sequence[SandboxRule]) -> Analyse:
    """An `Analyse` that runs `rules` one by one (for tests and custom rule sets; the default
    is `apply_rules`)."""

    def analyse(
        candidate: Candidate,
        run: SandboxRun,
        observations: Sequence[Observation],
        *,
        shipped: frozenset[str] | None = None,
        bundled_deps: frozenset[str] | None = None,
    ) -> tuple[Finding, ...]:
        return tuple(
            f
            for rule in rules
            for f in rule.evaluate(
                candidate, run, observations, shipped=shipped, bundled_deps=bundled_deps
            )
        )

    return analyse


# --- what a run recorded -----------------------------------------------------------------------


def _recorded(run_dir: Path) -> dict[str, object] | None:
    try:
        raw = json.loads((run_dir / SANDBOX_INFO).read_bytes())
    except OSError, ValueError:
        return None
    return raw if isinstance(raw, dict) else None


_STATES: Final[Mapping[object, State]] = {s: s for s in get_args(State)}


def recorded_answers(run_dir: Path) -> dict[str, Answer]:
    """The answers a run's `sandbox.json` recorded, by key (malformed entries ignored)."""
    raw = _recorded(run_dir)
    answers = raw.get("answers") if raw is not None else None
    if not isinstance(answers, dict):
        return {}
    found: dict[str, Answer] = {}
    for key, value in answers.items():
        if not (isinstance(key, str) and KEY_PATTERN.fullmatch(key) and isinstance(value, dict)):
            continue
        state, sha, reason = value.get("state"), value.get("result_sha256"), value.get("reason")
        known = _STATES.get(state) if isinstance(state, str) else None
        if (
            known is not None
            and (sha is None or isinstance(sha, str))
            and (reason is None or isinstance(reason, str))
        ):
            found[key] = Answer(known, sha, reason)
    return found


def recorded_cap(run_dir: Path) -> int | None:
    raw = _recorded(run_dir)
    cap = raw.get("cap") if raw is not None else None
    return cap if isinstance(cap, int) and not isinstance(cap, bool) and cap >= 0 else None


def _cap_of(run_dir: Path) -> int:
    """The cap a run was rendered with, so rendering it again selects the same versions."""
    cap = recorded_cap(run_dir)
    return DEFAULT_CAP if cap is None else cap


@dataclass(frozen=True)
class RecordedBundle:
    """What a run's `sandbox.json` recorded for a version's bundle ("bundles")."""

    state: BundleState
    reason: str | None = None
    missing: tuple[str, ...] = ()

    def as_json(self) -> dict[str, object]:
        return {"state": self.state, "reason": self.reason, "missing": list(self.missing)}


_BUNDLE_STATES: Final[Mapping[object, BundleState]] = {s: s for s in get_args(BundleState)}
_PENDING_REASONS: Final = frozenset({BUNDLE_PENDING, BUNDLE_BUDGET})
_UNAVAILABLE_REASONS: Final = frozenset({NOT_CONFIGURED, BUNDLE_UNREPRODUCIBLE})


def recorded_bundles(run_dir: Path) -> dict[str, RecordedBundle]:
    """The bundle states a run's `sandbox.json` recorded, by version (malformed ignored)."""
    raw = _recorded(run_dir)
    bundles = raw.get("bundles") if raw is not None else None
    if not isinstance(bundles, dict):
        return {}
    found: dict[str, RecordedBundle] = {}
    for ref, value in bundles.items():
        if not (isinstance(ref, str) and isinstance(value, dict)):
            continue
        state = value.get("state")
        known = _BUNDLE_STATES.get(state) if isinstance(state, str) else None
        reason, missing = value.get("reason"), value.get("missing", [])
        if (
            known is not None
            and (reason is None or isinstance(reason, str))
            and isinstance(missing, list)
            and all(isinstance(m, str) for m in missing)
        ):
            found[ref] = RecordedBundle(known, reason, tuple(missing))
    return found


def recorded_tarballs(run_dir: Path) -> dict[str, str]:
    """Version -> why Stage 5's own download of its tarball gave nothing (`_FETCH_REASONS`),
    as the last rendering recorded it ("tarballs" in sandbox.json)."""
    info = _recorded(run_dir)
    raw = info.get("tarballs") if info is not None else None
    if not isinstance(raw, dict):
        return {}
    return {
        ref: reason
        for ref, reason in raw.items()
        if isinstance(ref, str) and isinstance(reason, str) and reason in _FETCH_REASONS
    }


def recorded_keys(run_dir: Path) -> dict[str, str]:
    """The keys a run's `sandbox.json` recorded, by version."""
    raw = _recorded(run_dir)
    keys = raw.get("keys") if raw is not None else None
    if not isinstance(keys, dict):
        return {}
    return {
        ref: key
        for ref, key in keys.items()
        if isinstance(ref, str) and isinstance(key, str) and KEY_PATTERN.fullmatch(key)
    }


# --- fetching for bundles -----------------------------------------------------------------------


@dataclass
class _Budget:
    """New bytes the bundle step may still download in one live call, shared by every run it
    renders; and whether the network failed this call (then bundling stops until the next)."""

    limit: int
    spent: int = 0
    network_failed: bool = False

    @property
    def exhausted(self) -> bool:
        return self.spent >= self.limit


class _BundleFetcher(HttpFetcher):
    """The stage's `HttpFetcher` for one run's bundles, counting the bytes it downloads (a
    snapshot or immutable-index hit costs nothing) against the call's budget."""

    def __init__(
        self,
        budget: _Budget,
        *,
        store: BlobStore,
        snapshot: Snapshot,
        mode: FetchMode,
        immutable_index: Path,
        client: httpx.Client | None,
    ) -> None:
        super().__init__(
            store=store,
            snapshot=snapshot,
            mode=mode,
            immutable_index=immutable_index,
            client=client,
        )
        self.budget = budget
        self.owns_client = client is None

    def get(
        self, url: str, *, headers: Mapping[str, str] | None = None, immutable: bool = False
    ) -> FetchedResponse:
        fresh = self.needs_network(url, headers=headers, immutable=immutable)
        response = super().get(url, headers=headers, immutable=immutable)
        if fresh:
            self.budget.spent += len(response.body)
        return response


def _load_snapshot(path: Path) -> Snapshot:
    try:
        return Snapshot.load(path)
    except FileNotFoundError:
        return Snapshot()
    except OSError, ValueError:  # damaged: RECORD starts again; REPLAY then can't rebuild
        return Snapshot()


# --- rendering one run --------------------------------------------------------------------------


@dataclass
class _Context:
    data: DataDir
    run_id: str
    results: Path | None
    analyse: Analyse
    replay: bool
    recorded: Mapping[str, Answer]  # replay: the answers to reproduce
    as_of: datetime | None = None  # the run's `as_of`, for resolving bundles
    bundles: Mapping[str, RecordedBundle] = field(default_factory=dict)  # recorded
    keys: Mapping[str, str] = field(default_factory=dict)  # recorded keys, by version
    tarballs: Mapping[str, str] = field(default_factory=dict)  # recorded download outcomes
    fetched: dict[str, str] = field(default_factory=dict)  # this rendering's, to record
    exported: Mapping[str, SandboxJob] = field(default_factory=dict)  # live: by version
    budget: _Budget = field(default_factory=lambda: _Budget(BUNDLE_BUDGET_BYTES))
    client: httpx.Client | None = None
    fetcher: _BundleFetcher | None = None

    @property
    def cache(self) -> Path:
        return self.data.root / CACHE_DIR

    @property
    def staging(self) -> Path:
        return self.data.root / CACHE_DIR / STAGING_DIR / self.run_id

    @property
    def mode(self) -> FetchMode:
        """RECORD only for a live call with a results root; otherwise bundles are rebuilt from
        the run's snapshot alone, never fetched."""
        live = not self.replay and self.results is not None
        return FetchMode.RECORD if live else FetchMode.REPLAY

    def bundle_fetcher(self) -> _BundleFetcher:
        """The stage's fetcher for this run: bundle dependencies and the tarballs no earlier
        stage captured, recorded in `sandbox-snapshot.json`."""
        if self.fetcher is None:
            self.fetcher = _BundleFetcher(
                self.budget,
                store=self.data.blobs,
                snapshot=_load_snapshot(self.data.run_dir(self.run_id) / SANDBOX_SNAPSHOT),
                mode=self.mode,
                immutable_index=self.data.immutable_index,
                client=self.client,
            )
        return self.fetcher

    def close(self) -> None:
        """Save the bundle step's snapshot (live) and close the fetcher."""
        fetcher, self.fetcher = self.fetcher, None
        if fetcher is None:
            return
        try:
            if fetcher.mode is FetchMode.RECORD:
                fetcher.snapshot.save(self.data.run_dir(self.run_id) / SANDBOX_SNAPSHOT)
        finally:
            if fetcher.owns_client:
                fetcher.close()


@dataclass(frozen=True)
class _Plan:
    """What a selected version is exported as. `job` is None when nothing can be exported yet
    (`state` pending or unavailable, `reason` why). `staged` and `record` are a bundle built in
    this call; a reused bundle (already in the export) has neither. A built bundle waits on
    disk, not in memory: a call can build `cap` of them, each up to 128 MiB."""

    job: SandboxJob | None
    shipped: frozenset[str] | None
    bundled_deps: frozenset[str] | None = None
    state: BundleState | None = None  # None: the package needs no dependencies
    reason: str | None = None
    missing: tuple[str, ...] = ()
    staged: Path | None = None  # a bundle built this call, on disk until exported
    record: bytes | None = None

    @property
    def findings(self) -> tuple[Finding, ...]:
        if self.state == "bundled" and self.job is not None and self.job.bundle is not None:
            return (BUNDLED.because(self.job.bundle),)
        if self.state == "unbundled" and self.reason is not None:
            return (BUNDLE_INCOMPLETE.because(self.reason, self.missing),)
        return ()

    def recorded(self) -> RecordedBundle | None:
        if self.state is None:
            return None
        return RecordedBundle(self.state, self.reason, self.missing)


@dataclass(frozen=True)
class _Outcome:
    candidate: Candidate
    bucket: Bucket
    key: str | None = None
    answer: Answer | None = None
    install_failed: bool = False


def _with(candidate: Candidate, findings: Sequence[Finding], reason: str) -> Candidate:
    decision = StageDecision(stage=STAGE_ID, forwarded=True, reason=reason)
    return candidate.model_copy(
        update={
            "findings": (*candidate.findings, *findings),
            "history": (*candidate.history, decision),
        }
    )


def _not_run(
    candidate: Candidate,
    reason: str,
    bucket: Bucket = "not_run",
    key: str | None = None,
    answer: Answer | None = None,
) -> _Outcome:
    findings = (NOT_RUN.because(reason),)
    return _Outcome(_with(candidate, findings, f"not run: {reason}"), bucket, key, answer)


def _analysed(
    candidate: Candidate,
    result: SandboxResult,
    ctx: _Context,
    key: str,
    plan: _Plan,
) -> _Outcome:
    """The rules over a result's observations, whatever its status."""
    run = result.run
    found = tuple(
        ctx.analyse(
            candidate,
            run,
            result.observations,
            shipped=plan.shipped,
            bundled_deps=plan.bundled_deps,
        )
    )
    bucket: Bucket = "analysed"
    if install_failed(run):
        found = (*found, INSTALL_FAILED.because())
    if run.status == "infra-error":
        found, bucket = (*found, NOT_RUN.because(ANALYSIS_INFRA)), "infra_error"
    reason = f"analysed ({run.status}); score {score(found):g}"
    answer = Answer("accepted", run.result_sha256)
    return _Outcome(_with(candidate, found, reason), bucket, key, answer, install_failed(run))


def install_failed(run: SandboxRun) -> bool:
    """npm install exited non-zero: the install phase ended `error_analysis`."""
    return any(p.phase == "install" and p.status == "error_analysis" for p in run.phases)


def _rejected(candidate: Candidate, rejected: RejectedResult | Answer, key: str) -> _Outcome:
    reason = rejected.reason or "rejected"
    finding = RESULT_REJECTED.because(reason)
    answer = Answer("rejected", rejected.result_sha256, reason)
    return _Outcome(
        _with(candidate, (finding,), f"result rejected: {reason}"), "rejected", key, answer
    )


def _cache_problem(candidate: Candidate, problem: CacheProblem, key: str) -> _Outcome:
    reason = f"{CACHE_UNREADABLE} ({problem.reason})"
    return _not_run(candidate, reason, key=key, answer=Answer("cache-unreadable", None, reason))


_RECORDED_REASONS: Final[Mapping[str, tuple[str, Bucket]]] = {
    "pending": (PENDING, "pending"),
    "export-failed": (EXPORT_FAILED, "not_run"),
    "unconfigured": (NOT_CONFIGURED, "not_run"),
}


def _replayed(candidate: Candidate, job: SandboxJob, ctx: _Context, plan: _Plan) -> _Outcome:
    """The answer the run recorded for `job.key`, reproduced. A key it didn't record (the run
    was never rendered) reads as unconfigured: replay never imports or exports."""
    answer = ctx.recorded.get(job.key, Answer("unconfigured"))
    match answer.state:
        case "accepted":
            accepted = load_accepted(ctx.cache, job.key, answer.result_sha256)
            if isinstance(accepted, SandboxResult):
                return _analysed(candidate, accepted, ctx, job.key, plan)
            problem = accepted or CacheProblem("cache: the recorded result is missing")
            return _cache_problem(candidate, problem, job.key)
        case "rejected":
            return _rejected(candidate, answer, job.key)
        case "cache-unreadable":
            reason = answer.reason or CACHE_UNREADABLE
            return _not_run(candidate, reason, key=job.key, answer=answer)
        case _:
            reason, bucket = _RECORDED_REASONS[answer.state]
            return _not_run(candidate, reason, bucket, job.key, answer)


@dataclass(frozen=True)
class _Inspected:
    entry: SnapshotEntry | None
    hooks: Inspection
    name: str | None = None  # the tarball's own package.json name
    files: frozenset[str] | None = None  # the tarball's file list (`TarballInfo.files`)
    needs_bundle: bool = False  # its package.json needs dependencies (`bundle.wants_bundle`)


def _inspect(candidate: Candidate, index: TarballIndex, ctx: _Context) -> _Inspected:
    snapshot = candidate.change.new
    artifact = snapshot.artifact
    if artifact and artifact.unpacked_size and artifact.unpacked_size > MAX_TARBALL_UNPACKED_BYTES:
        return _Inspected(None, OVERSIZE)
    recorded = index.find(snapshot)
    if recorded is None:
        fetched = _download(candidate, ctx)
        if isinstance(fetched, str):
            return _Inspected(None, fetched)
        recorded = fetched
    tarball = load_tarball(ctx.data.blobs, recorded, snapshot)
    if isinstance(tarball, str):
        return _Inspected(recorded, _TARBALL_REASONS[tarball])
    info = inspect_tarball(tarball, TARBALL_LIMITS)
    if isinstance(info, TarballInfo):
        return _Inspected(recorded, info.hooks, info.name, info.files, wants_bundle(info.manifest))
    return _Inspected(recorded, info)


def _download(candidate: Candidate, ctx: _Context) -> SnapshotEntry | str:
    """A reported version's tarball that no earlier stage captured (over Stage 2's size cap,
    or reported by Stage 4 after Stage 1 passed it over), downloaded through the stage's
    fetcher: the entry it recorded, or a not-run reason. Only a live call with a results root
    downloads; a replay reads the run's snapshot and, on a miss, says what the live call
    recorded. The bytes count against the call's budget."""
    snapshot = candidate.change.new
    artifact = snapshot.artifact
    if artifact is None or not registry_tarball_url(artifact.url):
        return NOT_CAPTURED
    ref = str(snapshot.ref)
    live = ctx.mode is FetchMode.RECORD
    if not live and not ctx.replay:
        return NOT_CAPTURED  # no results root: nothing is exported, so nothing is fetched
    fetcher = ctx.bundle_fetcher()
    if live and fetcher.needs_network(artifact.url, immutable=True):
        if ctx.tarballs.get(ref) == TARBALL_FETCH_FAILED:
            return _fetch_outcome(ctx, ref, TARBALL_FETCH_FAILED)  # definite: not tried again
        if ctx.budget.network_failed or ctx.budget.exhausted:
            return _fetch_outcome(ctx, ref, TARBALL_PENDING)
    try:
        response = fetcher.get(artifact.url, immutable=True)
    except TransientFetchError:  # decision 0009: retried on the next live call
        ctx.budget.network_failed = True
        return _fetch_outcome(ctx, ref, TARBALL_PENDING)
    except FetchError:
        if live:  # definite: a size limit, a refused redirect
            return _fetch_outcome(ctx, ref, TARBALL_FETCH_FAILED)
        recorded = ctx.tarballs.get(ref)
        return _fetch_outcome(ctx, ref, recorded) if recorded else TARBALL_UNREPRODUCIBLE
    ok = response.ok
    del response  # read again, verified, by `load_tarball`
    if not ok:
        return _fetch_outcome(ctx, ref, TARBALL_FETCH_FAILED)
    entry = fetcher.snapshot.entries.get(request_key(artifact.url, None))
    return entry if entry is not None else TARBALL_UNREPRODUCIBLE


def _fetch_outcome(ctx: _Context, ref: str, reason: str) -> str:
    ctx.fetched[ref] = reason
    return reason


def _staged(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except OSError:
        return None


def _tarball(ctx: _Context, candidate: Candidate, entry: SnapshotEntry) -> bytes | None:
    loaded = load_tarball(ctx.data.blobs, entry, candidate.change.new)
    return None if isinstance(loaded, str) else loaded


def _record_files(raw: bytes | None, job: SandboxJob) -> frozenset[str] | None:
    """A bundle's file list from its record, when the record is the job's."""
    if raw is None or job.bundle is None:
        return None
    try:
        record = BundleRecord.load_json(raw)
    except ValueError:
        return None
    if record.tar_sha256 != job.bundle.tar_sha256:
        return None
    return frozenset(record.files)


def _missing(unresolved: Sequence[UnresolvedSpec]) -> tuple[str, ...]:
    """The unresolved required dependencies, as `name@spec` (package text; a spec is cut to
    `MAX_SPEC_SHOWN` characters, since a package can make it megabytes long)."""
    named = sorted(
        {
            f"{u.name}@{u.spec[:MAX_SPEC_SHOWN]}{'...' if len(u.spec) > MAX_SPEC_SHOWN else ''}"
            for u in unresolved
            if not u.optional
        }
    )
    return tuple(named[:MAX_MISSING])


def _reusable(previous: SandboxJob | None, base: SandboxJob, ctx: _Context) -> bool:
    """`previous` (what this run exported for the version) still describes it: same tarball
    and name, and, for a bundle, its file is still in the export."""
    if previous is None or previous.ref != base.ref or previous.package != base.package:
        return False
    if previous.bundle is None:
        return previous.tarball_sha256 == base.tarball_sha256 and bool(previous.unbundled_reason)
    return previous.bundle.original_sha256 == base.tarball_sha256 and exported_file(
        ctx.data, ctx.run_id, previous
    )


def _plan(entry: Entry, found: _Inspected, ctx: _Context) -> _Plan:
    """What a selected version is exported as: the registry tarball (it needs no dependencies,
    or they couldn't be bundled), or its offline bundle (built, or reused from the export)."""
    candidate = entry.candidate
    assert found.entry is not None  # noqa: S101 (inspection found the tarball)
    snapshot = candidate.change.new
    base = build_job(snapshot, found.entry.sha256, entry.hooks, install_name=found.name)
    if not found.needs_bundle:
        return _Plan(base, found.files)
    ref = str(snapshot.ref)
    recorded = ctx.bundles.get(ref)

    def unbundled(reason: str, missing: tuple[str, ...] = ()) -> _Plan:
        job = base.model_copy(update={"unbundled_reason": reason})
        return _Plan(job, found.files, None, "unbundled", reason, missing)

    def unavailable(reason: str) -> _Plan:
        return _Plan(None, None, state="unavailable", reason=reason)

    if ctx.replay and recorded is not None:  # reproduce what the bundle step can't redo
        match recorded.state:
            case "unbundled":
                return unbundled(recorded.reason or "unbundled", recorded.missing)
            case "pending":
                reason = recorded.reason if recorded.reason in _PENDING_REASONS else None
                return _Plan(None, None, state="pending", reason=reason or BUNDLE_PENDING)
            case "unavailable":
                reason = recorded.reason if recorded.reason in _UNAVAILABLE_REASONS else None
                return unavailable(reason or BUNDLE_UNREPRODUCIBLE)
    previous = ctx.exported.get(ref)
    if not ctx.replay and previous is not None and _reusable(previous, base, ctx):
        if previous.bundle is None:
            missing = recorded.missing if recorded is not None else ()
            return unbundled(previous.unbundled_reason or "unbundled", missing)
        shipped = _record_files(read_bundle_record(ctx.data, ctx.run_id, previous), previous)
        deps = frozenset(previous.bundle.dependencies)
        return _Plan(previous, shipped, deps, "bundled")
    return _build(candidate, found, base, ctx, unbundled, unavailable)


def _build(
    candidate: Candidate,
    found: _Inspected,
    base: SandboxJob,
    ctx: _Context,
    unbundled: _Unbundled,
    unavailable: _Unavailable,
) -> _Plan:
    """Build the bundle through the stage's fetcher (`ctx.mode`)."""
    live = ctx.mode is FetchMode.RECORD
    if live and ctx.budget.network_failed:
        return _Plan(None, None, state="pending", reason=BUNDLE_PENDING)
    if live and ctx.budget.exhausted:
        return _Plan(None, None, state="pending", reason=BUNDLE_BUDGET)
    if ctx.as_of is None:
        return unbundled("run-manifest-unreadable")
    assert found.entry is not None  # noqa: S101 (inspection found the tarball)
    original = _tarball(ctx, candidate, found.entry)
    if original is None:
        return unbundled("original-not-repackable: unreadable")
    fetcher = ctx.bundle_fetcher()
    try:
        built = make_bundle(
            original,
            packuments=registry_packuments(fetcher),
            fetcher=fetcher,
            as_of=ctx.as_of,
        )
    except BundleError as exc:
        return unbundled(f"{exc.reason}: {exc.detail}")
    except TransientFetchError:  # decision 0009: never a missing package; retried later
        ctx.budget.network_failed = True
        return _Plan(None, None, state="pending", reason=BUNDLE_PENDING)
    except FetchError:
        if not live:  # a replay miss: the run's snapshot doesn't hold this bundle
            reason = BUNDLE_UNREPRODUCIBLE if ctx.replay else NOT_CONFIGURED
            return unavailable(reason)
        return unbundled("fetch-error")  # definite: a refused redirect, a size limit, a 403
    except DiskSpaceError:
        raise  # the machine, not this package
    except Exception:  # a bug on one package's input must never stop the stage for every run
        # A fixed reason, never the exception's text: the outcome is recorded ("bundles" in
        # sandbox.json) and a replay reproduces it from there.
        return unbundled("internal-error")
    record = built.record
    if record.status != "complete":
        return unbundled(
            f"incomplete: {', '.join(record.incomplete_reasons)}", _missing(record.unresolved)
        )
    bundle = record.job_bundle()
    job = build_job(
        candidate.change.new,
        sha256_hex(built.data),
        base.hooks,
        install_name=base.install_name,
        bundle=bundle,
    )
    if ctx.replay and ctx.keys.get(str(base.ref), job.key) != job.key:
        return unavailable(BUNDLE_UNREPRODUCIBLE)
    staged = None
    if not ctx.replay:
        staged = ctx.staging / tarball_name(job)
        atomic_write(staged, built.data)
    raw = record.model_dump_json(indent=2).encode() + b"\n"
    return _Plan(
        job,
        frozenset(record.files),
        frozenset(bundle.dependencies),
        "bundled",
        staged=staged,
        record=None if ctx.replay else raw,
    )


class _Unbundled(Protocol):
    def __call__(self, reason: str, missing: tuple[str, ...] = ()) -> _Plan: ...


class _Unavailable(Protocol):
    def __call__(self, reason: str) -> _Plan: ...


def _render(
    data: DataDir,
    run_id: str,
    *,
    results: Path | None,
    analyse: Analyse,
    fingerprinted: Sequence[SandboxRule],
    cap: int,
    replay: bool,
    budget: _Budget,
    client: httpx.Client | None,
) -> tuple[Candidate, ...]:
    run_dir = data.run_dir(run_id)
    # Streamed: a catch-up run's 110k candidates are ~4 GB as objects; Stage 5 keeps only the
    # reported ones (about 1%).
    stage4 = CandidateFile(run_dir / "correlate.jsonl")
    try:
        kept = [c for c in stage4 if reported(c)]
    finally:
        stage4.close()
    manifest = _as_of(data, run_id)
    ctx = _Context(
        data=data,
        run_id=run_id,
        results=results,
        analyse=analyse,
        replay=replay,
        recorded=recorded_answers(run_dir) if replay else {},
        as_of=manifest.as_of if manifest is not None else None,
        bundles=recorded_bundles(run_dir),
        keys=recorded_keys(run_dir) if replay else {},
        tarballs=recorded_tarballs(run_dir),
        budget=budget,
        client=client,
    )
    index = TarballIndex.for_run(run_dir)
    shutil.rmtree(ctx.staging, ignore_errors=True)  # left by a call that died
    try:
        return _render_with(ctx, kept, index, fingerprinted, cap)
    finally:
        shutil.rmtree(ctx.staging, ignore_errors=True)


def _render_with(
    ctx: _Context,
    kept: Sequence[Candidate],
    index: TarballIndex,
    fingerprinted: Sequence[SandboxRule],
    cap: int,
) -> tuple[Candidate, ...]:
    data, run_id, run_dir = ctx.data, ctx.run_id, ctx.data.run_dir(ctx.run_id)
    replay, results = ctx.replay, ctx.results
    plans: dict[int, _Plan] = {}
    try:
        # Highest score first, so the download budget goes to the versions that matter most.
        found = {
            i: _inspect(kept[i], index, ctx)
            for i in sorted(range(len(kept)), key=lambda i: priority(kept[i]))
        }
        inspected = [found[i] for i in range(len(kept))]
        entries = select([(c, i.hooks) for c, i in zip(kept, inspected, strict=True)], cap)
        if not replay and results is not None and any(i.needs_bundle for i in inspected):
            ctx.exported = {str(job.ref): job for job in exported_jobs(data, run_id)}
        chosen = [i for i, e in enumerate(entries) if e.status == "selected"]
        for position in sorted(chosen, key=lambda i: priority(entries[i].candidate)):
            plans[position] = _plan(entries[position], inspected[position], ctx)
    finally:
        ctx.close()

    outcomes: list[_Outcome | None] = []
    to_export: list[tuple[int, SandboxJob, Candidate]] = []
    for position, entry in enumerate(entries):
        outcome = _process(entry, ctx, cap, plans.get(position))
        if isinstance(outcome, tuple):
            job, candidate = outcome
            to_export.append((position, job, candidate))
            outcomes.append(None)
        else:
            outcomes.append(outcome)

    # One at a time, so at most one tarball or bundle is in memory (each up to 128 MiB).
    exported: set[str] = set()
    for position, job, candidate in to_export:
        plan = plans[position]
        if job.bundle is not None and plan.staged is None:
            exported.add(job.key)  # reused: already in the export, listed in its jobs.json
            continue
        original = inspected[position].entry
        assert original is not None  # noqa: S101 (a selected entry has its tarball)
        body = _staged(plan.staged) if plan.staged is not None else None
        if body is None and job.bundle is None:
            body = _tarball(ctx, candidate, original)
        if body is not None:
            records = {job.key: plan.record} if plan.record is not None else None
            exported |= export_jobs(data, run_id, [(job, body)], records)
        del body
    for position, job, candidate in to_export:
        if job.key in exported:
            outcomes[position] = _not_run(candidate, PENDING, "pending", job.key, Answer("pending"))
        else:
            failed = Answer("export-failed")
            outcomes[position] = _not_run(candidate, EXPORT_FAILED, key=job.key, answer=failed)

    final = [o for o in outcomes if o is not None]
    written = tuple(o.candidate for o in final)
    atomic_write(
        run_dir / SANDBOX_JSONL, "".join(f"{c.model_dump_json()}\n" for c in written).encode()
    )
    buckets = Counter(o.bucket for o in final)
    answers = {o.key: o.answer for o in final if o.key and o.answer}
    states = {
        str(entries[i].candidate.change.new.ref): rec
        for i, plan in sorted(plans.items())
        if (rec := plan.recorded()) is not None
    }
    by_state = Counter(rec.state for rec in states.values())
    info = {
        "stage_version": STAGE_VERSION,
        "rules": rules_fingerprint(
            [
                *fingerprinted,
                NOT_RUN,
                RESULT_REJECTED,
                INSTALL_FAILED,
                BUNDLED,
                BUNDLE_INCOMPLETE,
            ]
        ),
        "cap": cap,
        "network": NETWORK,
        "counts": {
            "reported": len(entries),
            "selected": sum(e.status == "selected" for e in entries),
            "analysed": buckets["analysed"],
            "install_failed": sum(o.install_failed for o in final),
            "infra_error": buckets["infra_error"],
            "rejected": buckets["rejected"],
            "pending": buckets["pending"],
            "deferred": buckets["deferred"],
            "not_run": buckets["not_run"],
            "bundled": by_state["bundled"],
            "unbundled": by_state["unbundled"],
            "bundle_pending": by_state["pending"],
            "tarball_pending": sum(r == TARBALL_PENDING for r in ctx.fetched.values()),
        },
        "keys": {str(o.candidate.change.new.ref): o.key for o in final if o.key},
        "answers": {key: answers[key].as_json() for key in sorted(answers)},
        "bundles": {ref: states[ref].as_json() for ref in sorted(states)},
        "tarballs": dict(sorted(ctx.fetched.items())),
    }
    atomic_write(run_dir / SANDBOX_INFO, (json.dumps(info, indent=2) + "\n").encode())
    return written


def _process(
    entry: Entry, ctx: _Context, cap: int, plan: _Plan | None
) -> _Outcome | tuple[SandboxJob, Candidate]:
    """What an entry becomes; a job and its candidate when its tarball is to be exported."""
    candidate = entry.candidate
    match entry.status:
        case "unchecked":
            reason = entry.reason or NOT_CAPTURED
            return _not_run(
                candidate, reason, "pending" if reason == TARBALL_PENDING else "not_run"
            )
        case "deferred":
            return _not_run(candidate, deferred(cap), "deferred")
        case "no-hook":
            return _Outcome(_with(candidate, (), "no install hook"), "no_hook")
        case "selected":
            assert plan is not None  # noqa: S101 (every selected entry was planned)
            if plan.job is None:
                reason = plan.reason or BUNDLE_PENDING
                bucket: Bucket = "pending" if plan.state == "pending" else "not_run"
                return _not_run(candidate, reason, bucket)
            extra = plan.findings
            if extra:
                candidate = candidate.model_copy(update={"findings": (*candidate.findings, *extra)})
            if ctx.replay:
                return _replayed(candidate, plan.job, ctx, plan)
            return _live(candidate, plan.job, ctx, plan)


def _live(
    candidate: Candidate, job: SandboxJob, ctx: _Context, plan: _Plan
) -> _Outcome | tuple[SandboxJob, Candidate]:
    cached = load_cached(ctx.cache, job.key)
    match cached:
        case SandboxResult():
            return _analysed(candidate, cached, ctx, job.key, plan)
        case RejectedResult():
            return _rejected(candidate, cached, job.key)
        case CacheProblem():
            return _cache_problem(candidate, cached, job.key)
        case None if ctx.results is None:
            return _not_run(candidate, NOT_CONFIGURED, key=job.key, answer=Answer("unconfigured"))
        case None:
            return job, candidate


# --- importing and refreshing -------------------------------------------------------------------


def _as_of(data: DataDir, run_id: str) -> RunManifest | None:
    try:
        return RunManifest.load_json((data.run_dir(run_id) / "manifest.json").read_bytes())
    except OSError, ValueError:
        return None


def active_runs(data: DataDir, run_id: str) -> tuple[str, ...]:
    """The unpruned runs whose `as_of` is at or before `run_id`'s (and `run_id` itself),
    newest first (ties by run id), at most `MAX_ACTIVE_RUNS`; by the runs' own manifests,
    never the clock. Exports are pruned with their run, so these are all the runs a result
    can still reach. `(run_id,)` when `run_id` has no readable manifest."""
    current = _as_of(data, run_id)
    runs = data.root / "runs"
    if current is None or not runs.is_dir():
        return (run_id,)
    found = []
    for run_dir in sorted(p for p in runs.iterdir() if p.is_dir()):
        if (run_dir / "retention.json").exists():
            continue
        manifest = current if run_dir.name == run_id else _as_of(data, run_dir.name)
        if manifest is not None and manifest.as_of <= current.as_of:
            found.append((manifest.as_of, run_dir.name))
    newest = [name for _, name in sorted(found, reverse=True)][:MAX_ACTIVE_RUNS]
    return tuple(newest) if run_id in newest else (run_id, *newest[: MAX_ACTIVE_RUNS - 1])


def overdue_jobs(
    data: DataDir, run_id: str, runs: Sequence[str], after: timedelta
) -> dict[str, int]:
    """For each of `runs` exported more than `after` before `run_id`'s `as_of`: how many of its
    exported jobs have no answer in the cache (neither accepted nor rejected)."""
    current = _as_of(data, run_id)
    if current is None:
        return {}
    cache = data.root / CACHE_DIR
    overdue: dict[str, int] = {}
    for run in sorted(runs):
        manifest = _as_of(data, run)
        if manifest is None or current.as_of - manifest.as_of <= after:
            continue
        waiting = sum(peek(cache, job.key) is None for job in exported_jobs(data, run))
        if waiting:
            overdue[run] = waiting
    return overdue


def _current_answer(cache: Path, key: str) -> Answer | None:
    """The cache's answer for `key` now, in recorded form (None: nothing usable cached), from
    its small records only (`peek`): the result itself is parsed when the run is rendered."""
    match peek(cache, key):
        case ImportRecord() as record:
            return Answer("accepted", record.result_sha256)
        case RejectedResult() as rejected:
            return Answer("rejected", rejected.result_sha256, rejected.reason)
        case None:
            return None


def stale(data: DataDir, run_id: str) -> bool:
    """A key the run recorded as not accepted has another answer in the cache now, or a
    version's bundle or tarball download is still pending (a network failure or the budget:
    both are retried)."""
    run_dir = data.run_dir(run_id)
    if any(b.state == "pending" for b in recorded_bundles(run_dir).values()):
        return True
    if TARBALL_PENDING in recorded_tarballs(run_dir).values():
        return True
    cache = data.root / CACHE_DIR
    for key, answer in recorded_answers(run_dir).items():
        if answer.state == "accepted":
            continue
        current = _current_answer(cache, key)
        if current is not None and current != answer:
            return True
    return False


def run_sandbox_stage(
    data: DataDir,
    run_id: str,
    *,
    results: Path | None,
    rules: Sequence[SandboxRule] | None = None,
    cap: int = DEFAULT_CAP,
    overdue_after: timedelta = OVERDUE_AFTER,
    replay: bool = False,
    client: httpx.Client | None = None,
    bundle_budget: int = BUNDLE_BUDGET_BYTES,
) -> SandboxStageResult:
    """Stage 5 over a run Stage 4 has processed (see the module docstring). `rules=None`
    applies Stage 5's rules (`kitsunox.rules.sandbox`); a sequence replaces them (tests).
    `client` is the HTTP client for the bundle step's fetcher (tests pass a mock transport;
    None: the fetcher's own). `bundle_budget` caps the new bytes the bundle step downloads in
    this call, over every run it renders."""
    budget = _Budget(bundle_budget)
    analyse = apply_rules if rules is None else evaluate_each(rules)
    fingerprinted = RULES if rules is None else rules
    imported: dict[str, ImportOutcome] = {}
    refreshed: list[str] = []
    overdue: dict[str, int] = {}
    if not replay and results is not None:
        active = active_runs(data, run_id)
        jobs = [job for r in active for job in exported_jobs(data, r)]
        imported = import_results(results, data.root / CACHE_DIR, jobs)
        for earlier in active:
            if earlier == run_id or not stale(data, earlier):
                continue
            run_dir = data.run_dir(earlier)
            try:
                _render(
                    data,
                    earlier,
                    results=results,
                    analyse=analyse,
                    fingerprinted=fingerprinted,
                    cap=_cap_of(run_dir),
                    replay=False,
                    budget=budget,
                    client=client,
                )
            except OSError, ValueError:  # an earlier run's own files are unreadable
                continue
            refreshed.append(earlier)
        overdue = overdue_jobs(data, run_id, active, overdue_after)
    candidates = _render(
        data,
        run_id,
        results=results,
        analyse=analyse,
        fingerprinted=fingerprinted,
        cap=cap,
        replay=replay,
        budget=budget,
        client=client,
    )
    return SandboxStageResult(candidates, tuple(sorted(refreshed)), imported, overdue)
