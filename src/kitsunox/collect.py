"""`kitsunox collect`: one unattended tick of data collection, run hourly by launchd.

Each tick, in order:

1. Rebuild the watchlist if the newest is older than `WATCHLIST_MAX_AGE` (~12 min, 1 GB).
2. Sync OSV labels if the newest set is older than `LABELS_MAX_AGE` (~15 s, 220 MB).
3. Record a chained ingest run continuing from the checkpoint (see `core/run.py`).
4. Triage the run (Stage 1), run Stage 2 on its batches, then Stage 3 on the same versions,
   then Stage 4 (correlation, repository comparison, score) and the run's report. Stage 2 is
   what captures tarballs: npm deletes malicious ones, often within hours, so they are fetched
   in the same tick. Runs from the last `STAGES_CATCH_UP` with unfinished stages are resumed
   first, oldest first, from the first stage whose output is missing (from Stage 1 if Stage 2
   hit network failures; cached tarballs and results make this cheap).
5. If a Stage 5 results root is configured (`sandbox_results`, from `SANDBOX_RESULTS_ENV`),
   Stage 5 on each run whose stages ran this tick: import package-analysis results the owner
   brought back, refresh the runs they answer, export this run's tarballs for the airgapped
   analysis VM (`stages/sandbox.py`, decision 0014). Without one, Stage 5 is skipped.
6. Prune runs older than `keep_days` (repository archives: `keep_repo_days`, default the same),
   with Stage 5's exports and unused results, if the last prune is older than `PRUNE_EVERY`
   or free disk space is below `PRUNE_BELOW`.
6b. Live evaluation (decision 0019), before the prune: each run whose stages ran this tick
   gets its decision ledger (`evaluation/ledger.py`) with this process's rule versions; once
   every `LIVE_EVAL_EVERY`, missing ledgers are backfilled, the due review samples drawn, and
   the live dataset, confusion matrices and a results-log line written under
   `data/eval/live/` (`evaluation/live.py`). Read-only on run outputs; never feeds a score.
7. Scan runs not scanned yet for registry takedowns (npm's `0.0.1-security` holder), kept in
   `data/takedowns/` (`evaluation/confirmations.py`): the queue flags reviewed and queued
   versions removed after the fact. A flag only, never a score.
8. Rebuild the review queue (`reporting/queue.py`) over the last `keep_days` of reports.

The tick returns a `Tick` (manifest, reports written, failed steps); `kitsunox collect` posts it
as a brief Discord update when a webhook is configured (`notify.py`, decision 0011).

Steps 1, 2 and 4-8 are best-effort: a failure is logged, and the tick carries on with the
previous watchlist or label set, because a missed ingest is lost data while a stale list is not.
If the registry is unreachable, or a run hits an outage (`IngestDegradedError`), the tick logs
it and stops without writing anything: the checkpoint stays put, so the next tick covers the gap
(up to `MAX_CHAIN_GAP`, 7 days). See decision 0009.

**Disk space** (`util/disk.py`; a full disk crashed the VM twice on 2026-11-03). The tick
measures free space first. Below `PRUNE_BELOW` it prunes before anything else; below
`STOP_BELOW` it writes nothing (the checkpoint stays put, so the next tick covers the gap). It
checks again before each stage step and before Stage 5, skipping what is left of the tick
when space runs low (those runs resume on a later tick), and prunes at the end. Inside a step,
the blob store refuses writes below `disk.BLOB_FLOOR`, which stops that step the same way.

This module only wires existing pieces together. It may read the clock, since it decides *when*
to fetch; the runs it records still carry an explicit `as_of`. The caller holds `DataDir.lock()`.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import traceback
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import Final

import httpx

from kitsunox import __version__
from kitsunox.core.models import PackageBatch
from kitsunox.core.retention import held_digests, prune, small_tarballs, update_hold
from kitsunox.core.rules import RuleContext
from kitsunox.core.run import (
    CORRELATE_SNAPSHOT,
    STATIC_SNAPSHOT,
    DataDir,
    IngestDegradedError,
    IngestRequest,
    RunManifest,
    record_ingest,
    record_watchlist,
)
from kitsunox.core.watchlist import MONTHLY_CUTOFF
from kitsunox.ecosystems.npm.packument import ECOSYSTEM as NPM
from kitsunox.ecosystems.npm.packument import is_security_holder
from kitsunox.ecosystems.npm.registry import (
    ECOSYSTEMS_REGISTRY,
    REGISTRY_URL,
    NpmEcosystem,
    packument_url,
)
from kitsunox.evaluation.confirmations import TAKEDOWNS_DIR, scan_takedowns
from kitsunox.evaluation.harness import sync_labels
from kitsunox.evaluation.labels import label_store
from kitsunox.evaluation.ledger import (
    LIVE_DIR,
    backfill,
    ledgers,
    pipeline_fingerprints,
    write_ledger,
)
from kitsunox.evaluation.live import LiveSources, hold_requests, run_live_eval
from kitsunox.evaluation.sample import write_samples
from kitsunox.githost.github import TOKEN_ENV, is_archive_url
from kitsunox.notify import Tick
from kitsunox.reporting.publish import publish_report
from kitsunox.reporting.queue import build_queue, write_queue
from kitsunox.reporting.report import REPORT_DIR, Report
from kitsunox.sandbox.results import SANDBOX_INFO, prune_sandbox
from kitsunox.sandbox.select import DEFAULT_CAP
from kitsunox.sandbox.spool import export_dir, exported_jobs
from kitsunox.stages.code import run_code_stage
from kitsunox.stages.correlate import repo_network_failures, repo_over_budget
from kitsunox.stages.review import run_correlate_stage
from kitsunox.stages.sandbox import OVERDUE_AFTER, run_sandbox_stage
from kitsunox.stages.static import WILL_RETRY, needs_retry, record_static
from kitsunox.stages.triage import triage_run
from kitsunox.util.disk import GIB, DiskSpaceError, free_bytes, gib
from kitsunox.util.env import env_value
from kitsunox.util.files import atomic_write
from kitsunox.util.http import FetchError, Snapshot

WATCHLIST_MAX_AGE = timedelta(days=7)
LABELS_MAX_AGE = timedelta(hours=20)
PRUNE_EVERY = timedelta(hours=20)
# Live evaluation (decision 0019): once a day, before the prune.
LIVE_EVAL_EVERY: Final = timedelta(hours=20)
# Review samples are drawn only for the last days: older days' tarballs are gone.
LIVE_SAMPLE_DAYS: Final = 2
# Free space at which the tick prunes whatever PRUNE_EVERY says, and below which it starts no
# ingest or stage step. A 10-hour catch-up (55k changes) wrote ~20 GB; an hourly tick ~2 GB.
PRUNE_BELOW: Final = 60 * GIB
STOP_BELOW: Final = 25 * GIB
# The review queue's window, independent of retention: a pruned run keeps its report.
QUEUE_DAYS: Final = 7
# Tarballs of malicious packages are usually deleted within a day or two; later retries are moot.
STAGES_CATCH_UP = timedelta(hours=48)
DEFAULT_KEEP_DAYS = 7
REPORT_ONLY = 5  # a `start` for `_stages`: Stages 1-4 are done, only the report is missing
# Where the owner puts package-analysis's results (each export's `results/` contents). Not a
# secret; set in the environment or `.env`. Unset: `collect` skips Stage 5.
SANDBOX_RESULTS_ENV = "KITSUNOX_SANDBOX_RESULTS"

LIVE_STATE: Final = "live-eval.json"  # in data/state/: when live-eval last ran
PIPELINE: Final = pipeline_fingerprints()  # the rule versions this process's stages run

Log = Callable[[str], None]


def collect(
    data: DataDir,
    *,
    now: datetime,
    keep_days: int = DEFAULT_KEEP_DAYS,
    keep_repo_days: int | None = None,
    log: Log,
    clients: Callable[[], httpx.Client] | None = None,
    sandbox_results: pathlib.Path | None = None,
) -> Tick:
    """`clients` makes a fresh HTTP client per step (each step closes its own); tests pass a
    mock. Default: a real client per step. `sandbox_results` is Stage 5's results root (None:
    no Stage 5). Returns what the tick did: the new run's manifest (None if the registry
    couldn't be read), the reports written, and the steps that failed."""

    def client() -> httpx.Client | None:
        return clients() if clients else None

    failed: list[str] = []
    reports: list[Report] = []

    def best_effort(step: str, action: Callable[[], str]) -> None:
        try:
            log(f"{step}: {action()}")
        except Exception as exc:  # unattended: keep collecting with the previous data
            log(f"{step}: FAILED ({type(exc).__name__}: {exc}) at {where(exc)}; continuing")
            failed.append(step)

    lowest = free_bytes(data.root)
    pruned = False

    def room(step: str) -> bool:
        """Whether there is room to start `step`; if not, say so once and skip it."""
        nonlocal lowest
        free = free_bytes(data.root)
        lowest = min(lowest, free)
        if free >= STOP_BELOW:
            return True
        log(f"disk: {gib(free)} free, below {gib(STOP_BELOW)}: {step} skipped (resumed later)")
        if "disk" not in failed:
            failed.append("disk")
        return False

    def prune_now(why: str) -> None:
        nonlocal pruned
        pruned = True
        best_effort(f"prune{why}", lambda: _prune(data, now, keep_days, keep_repo_days))

    def finish(manifest: RunManifest | None) -> Tick:
        free = free_bytes(data.root)
        return Tick(
            manifest=manifest,
            reports=tuple(reports),
            failed=tuple(failed),
            disk_free=free,
            disk_lowest=min(lowest, free),
            disk_low="disk" in failed,
        )

    log(f"disk: {gib(lowest)} free")
    if lowest < PRUNE_BELOW:
        prune_now(f" (disk low, {gib(lowest)} free)")
    if not room("this tick"):
        return finish(None)

    if _age(data.watchlists.latest_id(NPM), now) > WATCHLIST_MAX_AGE:
        best_effort("watchlist", lambda: _watchlist(data, now, client()))
    if _age(label_store(data).latest_id(NPM), now) > LABELS_MAX_AGE:
        best_effort("labels", lambda: _labels(data, now, client()))

    request = IngestRequest(as_of=now, chain=True)
    try:
        manifest = record_ingest(data, NpmEcosystem, request, client=client())
    except (FetchError, IngestDegradedError) as exc:
        log(f"ingest: OFFLINE or outage, nothing written; the next tick catches up ({exc})")
        return finish(None)
    except DiskSpaceError as exc:
        log(f"ingest: {exc}; nothing written, the next tick catches up")
        failed.append("disk")
        prune_now(" (disk low)")
        return finish(None)
    chain = f"chained from {manifest.chained_from}" if manifest.chained_from else "NOT chained"
    if manifest.feed_head is not None and manifest.cursor_until < manifest.feed_head:
        left = manifest.feed_head - manifest.cursor_until
        chain += f", catching up ({left} of the feed left for the next ticks)"
    log(
        f"ingest: run {manifest.run_id}, feed ({manifest.cursor_since}, {manifest.cursor_until}], "
        f"{manifest.packages_seen} packages, {manifest.change_count} changes, "
        f"{manifest.skipped_count} skipped ({manifest.transient_skipped} on the network, "
        f"retried next tick; {len(manifest.retried)} retried from earlier), {chain}, "
        f"window covered: {manifest.window_covered}"
    )

    staged: list[str] = []

    def stages(run_id: str, start: int = 1) -> Callable[[], str]:
        def action() -> str:
            summary, report = run_stages(data, run_id, client, start)
            reports.append(report)
            staged.append(run_id)
            return summary

        return action

    def sandbox(run_id: str, results: pathlib.Path) -> Callable[[], str]:
        return lambda: run_sandbox(data, run_id, results, client())

    for run_id, start in _stages_pending(data, now, exclude=manifest.run_id):
        if not room(f"stages of {run_id}"):
            break
        resume = f"Stage {start}" if start < REPORT_ONLY else "the report"
        best_effort(f"stages (catch-up {run_id} from {resume})", stages(run_id, start))
    if "disk" not in failed and room(f"stages of {manifest.run_id}"):
        best_effort("stages", stages(manifest.run_id))
    if sandbox_results is not None and "disk" not in failed and room("Stage 5"):
        for run_id in staged:
            best_effort(f"sandbox {run_id}", sandbox(run_id, sandbox_results))
    for run_id in staged:  # what the stages just decided, with this code's rule versions
        best_effort(f"ledger {run_id}", partial(_ledger, data, run_id))

    last_live = _last_live_eval(data)
    due = last_live is None or now - last_live > LIVE_EVAL_EVERY
    if "disk" not in failed and due and room("live-eval"):
        best_effort("live-eval", lambda: _live_eval(data, now))

    last_prune = _last_prune(data)
    free = free_bytes(data.root)
    lowest = min(lowest, free)
    if free < PRUNE_BELOW:
        prune_now(f" (disk low, {gib(free)} free)")
    elif not pruned and (last_prune is None or now - last_prune > PRUNE_EVERY):
        prune_now("")
    best_effort("takedowns", lambda: _takedowns(data))
    best_effort("queue", lambda: _queue(data, max(keep_days, QUEUE_DAYS)))
    tick = finish(manifest)
    log(f"disk: {gib(tick.disk_free or 0)} free (lowest this tick {gib(tick.disk_lowest or 0)})")
    return tick


def _watchlist(data: DataDir, now: datetime, client: httpx.Client | None) -> str:
    watchlist, _, _ = record_watchlist(
        data,
        ecosystem=NPM,
        registry=ECOSYSTEMS_REGISTRY,
        built_at=now,
        min_monthly_downloads=MONTHLY_CUTOFF,
        client=client,
    )
    return f"built {watchlist.id} ({len(watchlist.entries)} packages)"


def run_stages(
    data: DataDir,
    run_id: str,
    client: Callable[[], httpx.Client | None],
    start: int = 1,
    *,
    seeded: bool = False,
) -> tuple[str, Report]:
    """Stages 1-4 and the report on one run, from Stage `start` (a catch-up resumes where
    outputs are missing; `REPORT_ONLY` redoes just the report). Each fetching stage gets its own
    client (fetchers close theirs). `seeded` (a re-score) starts Stages 2 and 4 from the run's
    own snapshots, so what they recorded is served as it was then."""
    run_dir = data.run_dir(run_id)

    def seed(name: str) -> Snapshot | None:
        path = run_dir / name
        return Snapshot.load(path) if seeded and path.exists() else None

    parts = []
    if start <= 4:
        # The old report no longer matches what is about to be rewritten. Without its index
        # (written last), a tick killed before the new report resumes as REPORT_ONLY.
        (run_dir / REPORT_DIR / "index.md").unlink(missing_ok=True)
    # Each stage's result is reduced to the counts its log line needs, then dropped, before the
    # next stage starts: a stage returns its whole output (Stage 1 ~33 KB a change), so holding
    # them all is what made Stage 3 of the 4-day catch-up start with ~21 GB already in use
    # (docs/proposals/streaming-stages.md).
    if start <= 2:
        manifest = RunManifest.load_json((run_dir / "manifest.json").read_bytes())
        candidates, forwarded = triage_run(run_dir, RuleContext(as_of=manifest.as_of))
        triaged = len(candidates)
        stage1 = sum(c.history[-1].reason.startswith("rules:") for c in candidates)
        del candidates, forwarded
        batches = record_static(
            data, run_id, NpmEcosystem, client=client(), seed=seed(STATIC_SNAPSHOT)
        )
        read = stage2 = missing = 0
        for decision in (c.history[-1] for b in batches for c in b.versions):
            read += 1
            stage2 += decision.forwarded
            missing += decision.reason.startswith("files unavailable")
        retry = " (network failures: retried next tick)" if needs_retry(batches) else ""
        del batches
        parts.append(
            f"{triaged} triaged, {stage1} flagged by Stage 1; {read} versions "
            f"read by Stage 2, {stage2} flagged, {missing} without files{retry}"
        )
    if start <= 3:
        coded = run_code_stage(data, run_id, client=client())
        stage3 = sum(c.history[-1].forwarded for b in coded for c in b.versions)
        del coded
        parts.append(f"{stage3} flagged by Stage 3")
    if start <= 4:
        # A `CandidateFile`: Stage 4's versions are read from disk on each pass, never held.
        versions = run_correlate_stage(
            data,
            run_id,
            client=client(),
            seed=seed(CORRELATE_SNAPSHOT),
            github_token=env_value(TOKEN_ENV),
        )
        compared = sum(
            any(
                f.rule_id == "repo.compared" and "No comparison" not in f.explanation
                for f in c.findings
            )
            for c in versions
        )
        uncompared = repo_network_failures(versions)
        over_budget = repo_over_budget(versions)
        del versions
        parts.append(
            f"{compared} compared with their repository"
            + (f", {uncompared} not compared (network)" if uncompared else "")
            + (f", {over_budget} over the comparison budget" if over_budget else "")
        )
    report = publish_report(data.run_dir(run_id))
    if start <= 4 and (failing := report.dependency_network_failures()[0]):
        parts.append(f"{failing} dependency lookups failed (network)")
    parts.append(f"{report.reported} to review (report/index.md)")
    return "; ".join(parts), report


# What a re-score rewrites, kept once under `RESCORE_ORIGINALS` as the tick wrote it.
RESCORED_OUTPUTS: Final = (
    "triage.jsonl",
    "batches.jsonl",
    "static.jsonl",
    STATIC_SNAPSHOT,
    "ast.jsonl",
    "correlate.jsonl",
    "correlate.json",
    CORRELATE_SNAPSHOT,
    REPORT_DIR,
)
RESCORE_ORIGINALS: Final = "before-rescore"
RESCORE_INFO: Final = "rescore.json"


def rescore_run(
    data: DataDir, run_id: str, client: Callable[[], httpx.Client | None], now: datetime
) -> str:
    """Stages 1-4 and the report again on a finished run, with the current rules, from the
    run's recorded inputs: its changes, and its Stage 2 and 4 snapshots as seeds (`run_stages`
    with `seeded`), so only requests today's rules newly need go to the network. Reports
    written by older rules otherwise stay in the queue until their run is pruned. The first
    re-score keeps the tick's outputs under `before-rescore/`. Verdicts are by version, so they
    carry over. The caller holds the lock."""
    run_dir = data.run_dir(run_id)
    if not (run_dir / "correlate.jsonl").exists():
        raise ValueError(f"{run_id}: Stage 4 has not run; `collect` finishes it")
    originals = run_dir / RESCORE_ORIGINALS
    if not originals.exists():
        staging = run_dir / f"{RESCORE_ORIGINALS}.partial"
        shutil.rmtree(staging, ignore_errors=True)
        staging.mkdir()
        for name in RESCORED_OUTPUTS:
            source = run_dir / name
            if source.is_dir():
                shutil.copytree(source, staging / name)
            elif source.exists():
                shutil.copy2(source, staging / name)
        staging.rename(originals)
    before = Report.model_validate_json((originals / REPORT_DIR / "report.json").read_bytes())
    summary, report = run_stages(data, run_id, client, seeded=True)
    info = {
        "rescored_at": now.isoformat(),
        "tool_version": __version__,
        "reported_before": before.reported,
        "reported": report.reported,
    }
    atomic_write(run_dir / RESCORE_INFO, json.dumps(info, indent=2).encode() + b"\n")
    return f"{summary}; was {before.reported} to review"


def run_sandbox(
    data: DataDir,
    run_id: str,
    results: pathlib.Path | None,
    client: httpx.Client | None,
    *,
    cap: int = DEFAULT_CAP,
    replay: bool = False,
) -> str:
    """Stage 5 on a run Stage 4 has processed (`run_sandbox_stage`), summarised in one line.
    A live call then rebuilds the report of the run and of every earlier run it refreshed
    (results arrived for them), since reports include Stage 5's findings."""
    outcome = run_sandbox_stage(
        data, run_id, results=results, cap=cap, replay=replay, client=client
    )
    if not replay:
        for rendered in (run_id, *outcome.refreshed):
            publish_report(data.run_dir(rendered))
    counts = json.loads((data.run_dir(run_id) / SANDBOX_INFO).read_bytes())["counts"]
    parts = [
        f"{counts['selected'] + counts['deferred']} of {counts['reported']} reported versions "
        f"have install hooks ({counts['deferred']} over the cap of {cap})",
        f"{counts['analysed']} analysed ({counts['install_failed']} install failed), "
        f"{counts['pending']} awaiting analysis, {counts['rejected']} results rejected",
        f"{counts['bundled']} bundled, {counts['unbundled']} not bundleable",
    ]
    if counts["bundle_pending"]:
        parts[-1] += f", {counts['bundle_pending']} bundles retried later"
    if not replay and results is not None:
        jobs = len(exported_jobs(data, run_id))
        parts.append(f"export: {jobs} jobs in {export_dir(data, run_id)}")
        accepted = sum(o == "accepted" for o in outcome.imported.values())
        rejected = sum(o == "rejected" for o in outcome.imported.values())
        if accepted or rejected:
            parts.append(f"imported {accepted} results ({rejected} rejected)")
    if outcome.refreshed:
        parts.append(f"{len(outcome.refreshed)} earlier runs updated")
    if outcome.overdue:
        parts.append(
            f"{sum(outcome.overdue.values())} jobs from {len(outcome.overdue)} runs still "
            f"unanalysed after {OVERDUE_AFTER.days} days"
        )
    return "; ".join(parts)


def _resume_from(run_dir: pathlib.Path) -> int | None:
    """The first stage whose output is missing (or, for Stage 2, hit network failures)."""
    static = run_dir / "static.jsonl"
    if not static.exists() or _static_needs_retry(static):
        return 1
    if not (run_dir / "ast.jsonl").exists():
        return 3
    if not (run_dir / "correlate.jsonl").exists():
        return 4
    if not _report_complete(run_dir / REPORT_DIR):
        return REPORT_ONLY
    return None


def _static_needs_retry(path: pathlib.Path) -> bool:
    """`needs_retry` over a Stage 2 output, read a line at a time: only lines holding the
    `WILL_RETRY` text are parsed (the 4-day catch-up's `static.jsonl` is 1.7 GB, ~7.5 GB as
    objects, and this runs for every pending run on every tick). The parsed decision confirms
    it, since an evidence snippet can hold the same text. The text is plain ASCII, so it is
    written into the JSON unescaped."""
    marker = WILL_RETRY.encode()
    with path.open("rb") as handle:
        return any(
            marker in line and needs_retry((PackageBatch.load_json(line),)) for line in handle
        )


def _report_complete(directory: pathlib.Path) -> bool:
    """`index.md` is written last; `report.json` must also load (a damaged file, or one written
    with another schema version, is rebuilt: that is cheap, Stage 4 isn't redone)."""
    if not (directory / "index.md").exists():
        return False
    try:
        Report.load_json((directory / "report.json").read_bytes())
    except OSError, ValueError:
        return False
    return True


def _takedowns(data: DataDir) -> str:
    log, runs, added = scan_takedowns(data, NPM, is_security_holder)
    return (
        f"{added} new in {runs} runs, {len(log.takedowns)} kept "
        f"({TAKEDOWNS_DIR}/{NPM}.json; flags only, never scored)"
    )


def _queue(data: DataDir, days: int) -> str:
    queue = build_queue(data, NPM, days=days)
    if queue is None:
        return "no reports yet"
    write_queue(data, queue)
    skipped = f", {len(queue.skipped)} unreadable reports left out" if queue.skipped else ""
    return (
        f"{queue.packages} packages ({queue.versions} versions) from {len(queue.runs)} runs"
        f"{skipped} (queue/index.md)"
    )


def _stages_pending(data: DataDir, now: datetime, *, exclude: str) -> list[tuple[str, int]]:
    """Recent runs with unfinished stages, oldest first, with the stage to resume from."""
    runs = data.root / "runs"
    pending = []
    for run_dir in sorted(runs.iterdir()) if runs.exists() else ():
        manifest_path = run_dir / "manifest.json"
        if run_dir.name == exclude or not manifest_path.exists():
            continue
        if (run_dir / "retention.json").exists():
            continue
        manifest = RunManifest.load_json(manifest_path.read_bytes())
        if now - manifest.as_of > STAGES_CATCH_UP:
            continue
        start = _resume_from(run_dir)
        if start is not None:
            pending.append((run_dir.name, start))
    return pending


def _labels(data: DataDir, now: datetime, client: httpx.Client | None) -> str:
    labels, _, _ = sync_labels(data, ecosystem=NPM, fetched_at=now, client=client)
    return f"synced {labels.id} ({labels.record_count} records)"


def _prune(data: DataDir, now: datetime, keep_days: int, keep_repo_days: int | None) -> str:
    store = label_store(data)
    labels_id = store.latest_id(NPM)
    if labels_id is None:
        return "skipped: no label set to decide which packuments to keep"
    labels = store.load(NPM, labels_id)
    held, hold = hold_now(data, now)
    report = prune(
        data,
        now=now,
        keep_days=keep_days,
        pinned_names=labels.labels.keys(),
        metadata_url=packument_url,
        keep_archive_days=keep_repo_days,
        is_archive=is_archive_url,
        held=held,
    )
    exports, results = prune_sandbox(data, labels.labels.keys())
    path = data.root / "state" / "prune.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"last": now.isoformat()}) + "\n")
    sandbox = f"; Stage 5: {exports} exports, {results} results" if exports or results else ""
    return (
        f"{len(report.runs_pruned)} runs pruned, {report.blobs_pinned} blobs pinned, "
        f"{report.blobs_deleted} blobs deleted ({report.bytes_freed / 1e9:.2f} GB){sandbox}; "
        f"{hold}"
    )


def is_npm_tarball(url: str) -> bool:
    return url.startswith(f"{REGISTRY_URL}/") and url.endswith(".tgz")


def hold_now(data: DataDir, now: datetime) -> tuple[set[str], str]:
    """Update the label hold (decision 0019) and return what it keeps, before a prune. If the
    update fails, the hold as last written is kept; if that can't be read either, the prune
    goes ahead without it: a full disk crashes the VM, a lost tarball doesn't."""
    try:
        live = data.root / LIVE_DIR
        requests = [
            *small_tarballs(data, is_artifact=is_npm_tarball),
            *hold_requests(data.root, live),
        ]
        hold, report = update_hold(data, requests, now=now)
    except Exception as exc:  # the prune must still run
        try:
            kept = held_digests(data, now)
        except Exception:
            return set(), f"hold: UNREADABLE ({type(exc).__name__}), nothing held"
        return kept, f"hold: update FAILED ({type(exc).__name__}: {exc}), {len(kept)} kept"
    capped = (
        f", {report.dropped} dropped over the {hold.cap_bytes / 1e9:.0f} GB cap "
        f"({report.dropped_bytes / 1e9:.2f} GB)"
        if report.dropped
        else ""
    )
    return hold.digests(now), (
        f"hold: {report.held} blobs ({report.held_bytes / 1e9:.2f} GB), +{report.added}, "
        f"{report.expired} expired, {report.missing} gone{capped}"
    )


def where(exc: BaseException) -> str:
    """The innermost frames of the traceback (file:line in function), for an unattended log."""
    frames = traceback.extract_tb(exc.__traceback__)[-3:]
    return " < ".join(
        f"{os.path.basename(f.filename)}:{f.lineno} {f.name}" for f in reversed(frames)
    )


def _age(record_id: str | None, now: datetime) -> timedelta:
    if record_id is None:
        return timedelta.max
    return now - datetime.strptime(record_id, "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)


def _ledger(data: DataDir, run_id: str) -> str:
    path = write_ledger(data.root / "runs", data.root / LIVE_DIR, run_id, pipeline=PIPELINE)
    return f"written ({path.name})" if path else "not written (unfinished, or already there)"


def _live_eval(data: DataDir, now: datetime) -> str:
    """Ledgers missing (re-scored runs too), the due review samples, then the live dataset,
    matrices and a results-log line (decision 0019)."""
    if label_store(data).latest_id(NPM) is None:
        return "skipped: no label set yet"
    live = data.root / LIVE_DIR
    written = backfill(data.root / "runs", live)
    newest = max((lg.header.as_of for lg in ledgers(live)), default=None)
    since = (newest - timedelta(days=LIVE_SAMPLE_DAYS)).date() if newest else None
    samples = write_samples(data.root / "runs", live, since=since)
    report, line, _ = run_live_eval(LiveSources(data.root, live), built_at=now)
    state = data.root / "state" / LIVE_STATE
    atomic_write(state, json.dumps({"last": now.isoformat()}).encode() + b"\n")
    headline = report.windows["all"].matrices["behaviour"]
    return (
        f"labels {line.label_set}: {headline.tp} of {headline.tp + headline.fn} flag-worthy "
        f"reported, {headline.fp} reported benign ({line.newly_labeled} newly labeled, "
        f"{line.newly_reported} of them reported); {len(written)} ledgers, {len(samples)} "
        f"samples drawn, {line.sample_unreviewed} sampled versions to review "
        f"({LIVE_DIR}/reports/{report.dataset}.md)"
    )


def _last_live_eval(data: DataDir) -> datetime | None:
    path = data.root / "state" / LIVE_STATE
    try:
        last = json.loads(path.read_bytes()).get("last")
    except OSError, ValueError:
        return None
    return datetime.fromisoformat(last) if isinstance(last, str) else None


def _last_prune(data: DataDir) -> datetime | None:
    path = data.root / "state" / "prune.json"
    if not path.exists():
        return None
    last = json.loads(path.read_text()).get("last")
    return datetime.fromisoformat(last) if isinstance(last, str) else None
