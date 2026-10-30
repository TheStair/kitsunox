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
   with Stage 5's exports and unused results, if the last prune is older than `PRUNE_EVERY`.
7. Rebuild the review queue (`reporting/queue.py`) over the last `keep_days` of reports.

The tick returns a `Tick` (manifest, reports written, failed steps); `kitsunox collect` posts it
as a brief Discord update when a webhook is configured (`notify.py`, decision 0011).

Steps 1, 2 and 4-7 are best-effort: a failure is logged, and the tick carries on with the
previous watchlist or label set, because a missed ingest is lost data while a stale list is not.
If the registry is unreachable, or a run hits an outage (`IngestDegradedError`), the tick logs
it and stops without writing anything: the checkpoint stays put, so the next tick covers the gap
(up to `MAX_CHAIN_GAP`, 7 days). See decision 0009.

This module only wires existing pieces together. It may read the clock, since it decides *when*
to fetch; the runs it records still carry an explicit `as_of`. The caller holds `DataDir.lock()`.
"""

from __future__ import annotations

import json
import os
import pathlib
import traceback
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx

from kitsunox.core.models import PackageBatch
from kitsunox.core.retention import prune
from kitsunox.core.rules import RuleContext
from kitsunox.core.run import (
    DataDir,
    IngestDegradedError,
    IngestRequest,
    RunManifest,
    record_ingest,
    record_watchlist,
)
from kitsunox.core.watchlist import MONTHLY_CUTOFF
from kitsunox.ecosystems.npm.packument import ECOSYSTEM as NPM
from kitsunox.ecosystems.npm.registry import ECOSYSTEMS_REGISTRY, NpmEcosystem, packument_url
from kitsunox.evaluation.harness import sync_labels
from kitsunox.evaluation.labels import label_store
from kitsunox.githost.github import is_archive_url
from kitsunox.notify import Tick
from kitsunox.reporting.publish import publish_report
from kitsunox.reporting.queue import build_queue, write_queue
from kitsunox.reporting.report import REPORT_DIR, Report
from kitsunox.sandbox.results import SANDBOX_INFO, prune_sandbox
from kitsunox.sandbox.select import DEFAULT_CAP
from kitsunox.sandbox.spool import export_dir, exported_jobs
from kitsunox.stages.code import run_code_stage
from kitsunox.stages.correlate import repo_network_failures
from kitsunox.stages.review import run_correlate_stage
from kitsunox.stages.sandbox import OVERDUE_AFTER, run_sandbox_stage
from kitsunox.stages.static import needs_retry, record_static
from kitsunox.stages.triage import triage_run
from kitsunox.util.http import FetchError

WATCHLIST_MAX_AGE = timedelta(days=7)
LABELS_MAX_AGE = timedelta(hours=20)
PRUNE_EVERY = timedelta(hours=20)
# Tarballs of malicious packages are usually deleted within a day or two; later retries are moot.
STAGES_CATCH_UP = timedelta(hours=48)
DEFAULT_KEEP_DAYS = 7
REPORT_ONLY = 5  # a `start` for `_stages`: Stages 1-4 are done, only the report is missing
# Where the owner puts package-analysis's results (each export's `results/` contents). Not a
# secret; set in the environment or `.env`. Unset: `collect` skips Stage 5.
SANDBOX_RESULTS_ENV = "KITSUNOX_SANDBOX_RESULTS"

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

    if _age(data.watchlists.latest_id(NPM), now) > WATCHLIST_MAX_AGE:
        best_effort("watchlist", lambda: _watchlist(data, now, client()))
    if _age(label_store(data).latest_id(NPM), now) > LABELS_MAX_AGE:
        best_effort("labels", lambda: _labels(data, now, client()))

    request = IngestRequest(as_of=now, chain=True)
    try:
        manifest = record_ingest(data, NpmEcosystem, request, client=client())
    except (FetchError, IngestDegradedError) as exc:
        log(f"ingest: OFFLINE or outage, nothing written; the next tick catches up ({exc})")
        return Tick(manifest=None, failed=tuple(failed))
    chain = f"chained from {manifest.chained_from}" if manifest.chained_from else "NOT chained"
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
        resume = f"Stage {start}" if start < REPORT_ONLY else "the report"
        best_effort(f"stages (catch-up {run_id} from {resume})", stages(run_id, start))
    best_effort("stages", stages(manifest.run_id))
    if sandbox_results is not None:
        for run_id in staged:
            best_effort(f"sandbox {run_id}", sandbox(run_id, sandbox_results))

    last_prune = _last_prune(data)
    if last_prune is None or now - last_prune > PRUNE_EVERY:
        best_effort("prune", lambda: _prune(data, now, keep_days, keep_repo_days))
    best_effort("queue", lambda: _queue(data, keep_days))
    return Tick(manifest=manifest, reports=tuple(reports), failed=tuple(failed))


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
    data: DataDir, run_id: str, client: Callable[[], httpx.Client | None], start: int = 1
) -> tuple[str, Report]:
    """Stages 1-4 and the report on one run, from Stage `start` (a catch-up resumes where
    outputs are missing; `REPORT_ONLY` redoes just the report). Each fetching stage gets its own
    client (fetchers close theirs)."""
    run_dir = data.run_dir(run_id)
    parts = []
    if start <= 4:
        # The old report no longer matches what is about to be rewritten. Without its index
        # (written last), a tick killed before the new report resumes as REPORT_ONLY.
        (run_dir / REPORT_DIR / "index.md").unlink(missing_ok=True)
    if start <= 2:
        manifest = RunManifest.load_json((run_dir / "manifest.json").read_bytes())
        candidates, _ = triage_run(run_dir, RuleContext(as_of=manifest.as_of))
        batches = record_static(data, run_id, NpmEcosystem, client=client())
        decisions = [c.history[-1] for b in batches for c in b.versions]
        stage1 = sum(c.history[-1].reason.startswith("rules:") for c in candidates)
        stage2 = sum(d.forwarded for d in decisions)
        missing = sum(d.reason.startswith("files unavailable") for d in decisions)
        retry = " (network failures: retried next tick)" if needs_retry(batches) else ""
        parts.append(
            f"{len(candidates)} triaged, {stage1} flagged by Stage 1; {len(decisions)} versions "
            f"read by Stage 2, {stage2} flagged, {missing} without files{retry}"
        )
    if start <= 3:
        coded = run_code_stage(data, run_id, client=client())
        parts.append(
            f"{sum(c.history[-1].forwarded for b in coded for c in b.versions)} flagged by Stage 3"
        )
    if start <= 4:
        versions = run_correlate_stage(data, run_id, client=client())
        compared = sum(
            any(
                f.rule_id == "repo.compared" and "No comparison" not in f.explanation
                for f in c.findings
            )
            for c in versions
        )
        uncompared = repo_network_failures(versions)
        parts.append(
            f"{compared} compared with their repository"
            + (f", {uncompared} not compared (network)" if uncompared else "")
        )
    report = publish_report(data.run_dir(run_id))
    if start <= 4 and (failing := report.dependency_network_failures()[0]):
        parts.append(f"{failing} dependency lookups failed (network)")
    parts.append(f"{report.reported} to review (report/index.md)")
    return "; ".join(parts), report


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
    if not static.exists() or needs_retry(
        PackageBatch.load_json(line) for line in static.read_bytes().splitlines() if line.strip()
    ):
        return 1
    if not (run_dir / "ast.jsonl").exists():
        return 3
    if not (run_dir / "correlate.jsonl").exists():
        return 4
    if not _report_complete(run_dir / REPORT_DIR):
        return REPORT_ONLY
    return None


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
    report = prune(
        data,
        now=now,
        keep_days=keep_days,
        pinned_names=labels.labels.keys(),
        metadata_url=packument_url,
        keep_archive_days=keep_repo_days,
        is_archive=is_archive_url,
    )
    exports, results = prune_sandbox(data, labels.labels.keys())
    path = data.root / "state" / "prune.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"last": now.isoformat()}) + "\n")
    sandbox = f"; Stage 5: {exports} exports, {results} results" if exports or results else ""
    return (
        f"{len(report.runs_pruned)} runs pruned, {report.blobs_pinned} blobs pinned, "
        f"{report.blobs_deleted} blobs deleted ({report.bytes_freed / 1e9:.2f} GB){sandbox}"
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


def _last_prune(data: DataDir) -> datetime | None:
    path = data.root / "state" / "prune.json"
    if not path.exists():
        return None
    last = json.loads(path.read_text()).get("last")
    return datetime.fromisoformat(last) if isinstance(last, str) else None
