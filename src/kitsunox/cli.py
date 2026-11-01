"""Command-line entry point. Pipeline commands are added as each stage lands."""

import os
import plistlib
import shutil
import sys
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer

from kitsunox import __version__
from kitsunox.collect import (
    DEFAULT_KEEP_DAYS,
    RESCORE_INFO,
    SANDBOX_RESULTS_ENV,
    collect,
    rescore_run,
    run_sandbox,
    run_stages,
    where,
)
from kitsunox.core.retention import prune
from kitsunox.core.rules import RuleContext
from kitsunox.core.run import (
    DataDir,
    DataDirBusyError,
    IngestRequest,
    PopularityMode,
    RunManifest,
    WatchlistMissingError,
    changes_digest,
    record_ingest,
    record_watchlist,
    replay_ingest,
)
from kitsunox.core.watchlist import MONTHLY_CUTOFF
from kitsunox.ecosystems.npm.packument import ECOSYSTEM as NPM
from kitsunox.ecosystems.npm.packument import is_security_holder
from kitsunox.ecosystems.npm.registry import ECOSYSTEMS_REGISTRY, NpmEcosystem, packument_url
from kitsunox.evaluation.confirmations import scan_takedowns
from kitsunox.evaluation.harness import (
    PREDICTOR_NAMES,
    make_dataset,
    make_predictor,
    run_eval,
    sync_datadog,
    sync_labels,
)
from kitsunox.evaluation.labels import label_store
from kitsunox.evaluation.metrics import render_markdown
from kitsunox.githost.github import is_archive_url
from kitsunox.notify import (
    WEBHOOK_ENV,
    TickRecord,
    append_tick,
    crash_due,
    crash_record,
    load_state,
    post_update,
    read_ticks,
    render_crash,
    render_daily,
    render_tick,
    save_state,
    summary_due,
    tick_record,
)
from kitsunox.reporting.publish import publish_report
from kitsunox.reporting.queue import build_queue, write_queue
from kitsunox.reporting.report import REPORT_DIR, Report
from kitsunox.reporting.verdicts import (
    OWNER,
    VERDICTS,
    append_verdict,
    current,
    probes,
    read_verdicts,
    tally,
    verdict_record,
)
from kitsunox.sandbox.results import prune_sandbox
from kitsunox.sandbox.select import DEFAULT_CAP
from kitsunox.stages.code import run_code_stage
from kitsunox.stages.review import run_correlate_stage
from kitsunox.stages.static import record_static
from kitsunox.stages.triage import triage_run
from kitsunox.util.env import env_value

app = typer.Typer(help="Flag likely software supply chain attacks in recent npm releases.")
ingest_app = typer.Typer(help="Stage 0: collect recent releases into Change records.")
app.add_typer(ingest_app, name="ingest")
watchlist_app = typer.Typer(help="Popularity watchlists (packages always analyzed in depth).")
app.add_typer(watchlist_app, name="watchlist")
labels_app = typer.Typer(help="Ground-truth malware labels (OSV MAL- records).")
app.add_typer(labels_app, name="labels")
eval_app = typer.Typer(help="Evaluation: build datasets from runs and score predictors.")
app.add_typer(eval_app, name="eval")
samples_app = typer.Typer(help="Known-malicious samples from third-party datasets.")
app.add_typer(samples_app, name="samples")
data_app = typer.Typer(help="Data directory maintenance.")
app.add_typer(data_app, name="data")
schedule_app = typer.Typer(
    help="Run `kitsunox collect` on a schedule (macOS launchd or Linux systemd)."
)
app.add_typer(schedule_app, name="schedule")

LAUNCHD_LABEL = "local.kitsunox.collect"
SYSTEMD_UNIT = "kitsunox-collect"
SYSTEMD_USER_DIR = Path.home() / ".config" / "systemd" / "user"

DataDirOption = Annotated[
    Path,
    typer.Option(
        "--data-dir",
        envvar="KITSUNOX_DATA_DIR",
        help="Where caches and runs are stored (gitignored).",
    ),
]
DEFAULT_DATA_DIR = Path(os.environ.get("KITSUNOX_DATA_DIR", "data"))


def _print_version(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version", callback=_print_version, is_eager=True, help="Show version and exit."
        ),
    ] = False,
) -> None:
    """Kitsunox supply chain attack triage pipeline."""


AsOfOption = Annotated[
    datetime | None,
    typer.Option(help="End of the window, in UTC (YYYY-MM-DDTHH:MM:SS). Default: now."),
]
WindowHoursOption = Annotated[float, typer.Option(min=0.01)]
SinceSeqOption = Annotated[
    int | None, typer.Option(help="Feed position to start after. Default: checkpoint.")
]
UntilSeqOption = Annotated[
    int | None, typer.Option(help="Last feed position to read. Default: feed head.")
]
LookbackSeqOption = Annotated[
    int, typer.Option(help="Feed positions to scan when there's no checkpoint.")
]
WorkersOption = Annotated[int, typer.Option(min=1, max=64)]
PopularityOption = Annotated[
    PopularityMode,
    typer.Option(help="watchlist: prebuilt list (fast). api: per-package lookups (slow)."),
]
WatchlistOption = Annotated[
    str | None, typer.Option(help="Watchlist id. Default: newest built before --as-of.")
]
ChainOption = Annotated[
    bool, typer.Option(help="Continue from the previous run: window starts where it ended.")
]


@ingest_app.command("record")
def ingest_record(
    data_dir: DataDirOption = DEFAULT_DATA_DIR,
    as_of: AsOfOption = None,
    window_hours: WindowHoursOption = 24.0,
    since_seq: SinceSeqOption = None,
    until_seq: UntilSeqOption = None,
    lookback_seq: LookbackSeqOption = 400_000,
    workers: WorkersOption = 8,
    popularity: PopularityOption = PopularityMode.WATCHLIST,
    watchlist: WatchlistOption = None,
    chain: ChainOption = False,
) -> None:
    """Fetch recent npm changes and write a replayable run."""
    request = _ingest_request(
        as_of, window_hours, since_seq, until_seq, lookback_seq, workers, popularity, watchlist
    )
    data = DataDir(data_dir)
    try:
        with data.lock():
            manifest = _record(data, replace(request, chain=chain))
    except DataDirBusyError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    _print_summary(manifest, data_dir)


@app.command("run")
def run_cmd(
    data_dir: DataDirOption = DEFAULT_DATA_DIR,
    as_of: AsOfOption = None,
    window_hours: WindowHoursOption = 24.0,
    since_seq: SinceSeqOption = None,
    until_seq: UntilSeqOption = None,
    lookback_seq: LookbackSeqOption = 400_000,
    workers: WorkersOption = 8,
    popularity: PopularityOption = PopularityMode.WATCHLIST,
    watchlist: WatchlistOption = None,
) -> None:
    """The whole pipeline once: record a run (as `ingest record`), then Stages 1-4 and its
    report. Like `ingest record` without --since-seq/--until-seq, it moves the change-feed
    checkpoint that `collect` continues from: use its own --data-dir for demos while the
    scheduled collection runs."""
    request = _ingest_request(
        as_of, window_hours, since_seq, until_seq, lookback_seq, workers, popularity, watchlist
    )
    data = DataDir(data_dir)
    try:
        with data.lock():
            manifest = _record(data, request)
            _print_summary(manifest, data_dir)
            summary, _ = run_stages(data, manifest.run_id, lambda: None)
    except DataDirBusyError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"stages:   {summary}")
    typer.echo(f"saved to {data.run_dir(manifest.run_id)}/report/index.md")


def _ingest_request(
    as_of: datetime | None,
    window_hours: float,
    since_seq: int | None,
    until_seq: int | None,
    lookback_seq: int,
    workers: int,
    popularity: PopularityMode,
    watchlist: str | None,
) -> IngestRequest:
    moment = as_of or datetime.now(UTC)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return IngestRequest(
        as_of=moment,
        window_hours=window_hours,
        since=since_seq,
        until=until_seq,
        lookback=lookback_seq,
        workers=workers,
        popularity=popularity,
        watchlist_id=watchlist,
    )


def _record(data: DataDir, request: IngestRequest) -> RunManifest:
    """Stage 0; the caller holds the lock."""
    try:
        return record_ingest(data, NpmEcosystem, request)
    except WatchlistMissingError as exc:
        typer.echo(f"{exc}. Run `kitsunox watchlist build` first, or pass --popularity none.")
        raise typer.Exit(code=2) from exc


@ingest_app.command("replay")
def ingest_replay(run_id: str, data_dir: DataDirOption = DEFAULT_DATA_DIR) -> None:
    """Re-run Stage 0 offline from a run's snapshot and check the output is identical."""
    data = DataDir(data_dir)
    manifest = RunManifest.load_json((data.run_dir(run_id) / "manifest.json").read_bytes())
    digest = changes_digest(replay_ingest(data, NpmEcosystem, run_id))
    if digest != manifest.changes_sha256:
        typer.echo(f"MISMATCH: recorded {manifest.changes_sha256}, replayed {digest}", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"identical: {digest}")


@watchlist_app.command("build")
def watchlist_build(
    data_dir: DataDirOption = DEFAULT_DATA_DIR,
    min_monthly_downloads: Annotated[
        int, typer.Option(help="Cutoff (last-month downloads). Default is about 10k/week.")
    ] = MONTHLY_CUTOFF,
) -> None:
    """Build the npm watchlist from packages.ecosyste.ms (about 1 GB transferred, ~10 min)."""
    watchlist, path, sha = record_watchlist(
        DataDir(data_dir),
        ecosystem=NPM,
        registry=ECOSYSTEMS_REGISTRY,
        built_at=datetime.now(UTC),
        min_monthly_downloads=min_monthly_downloads,
    )
    typer.echo(f"watchlist {watchlist.id}: {len(watchlist.entries)} packages")
    typer.echo(f"saved to {path} (sha256 {sha})")


@labels_app.command("sync")
def labels_sync(data_dir: DataDirOption = DEFAULT_DATA_DIR) -> None:
    """Download OSV malware records for npm (~220 MB) and save a label set."""
    labels, path, sha = sync_labels(DataDir(data_dir), ecosystem=NPM, fetched_at=datetime.now(UTC))
    typer.echo(
        f"label set {labels.id}: {labels.record_count} malware records "
        f"for {len(labels.labels)} packages"
    )
    typer.echo(f"saved to {path} (sha256 {sha})")


@app.command("triage")
def triage_cmd(run_id: str, data_dir: DataDirOption = DEFAULT_DATA_DIR) -> None:
    """Stage 1: run the metadata rules on a recorded run; write triage.jsonl and the package
    batches for Stage 2 (batches.jsonl) into the run directory."""
    data = DataDir(data_dir)
    manifest = RunManifest.load_json((data.run_dir(run_id) / "manifest.json").read_bytes())
    candidates, batches = triage_run(data.run_dir(run_id), RuleContext(as_of=manifest.as_of))
    reasons: dict[str, int] = {}
    for candidate in candidates:
        decision = candidate.history[-1]
        if decision.forwarded:
            key = next(
                (k for k in ("rules", "unpacked size grew") if decision.reason.startswith(k)),
                decision.reason,
            )
            reasons[key] = reasons.get(key, 0) + 1
    forwarded = sum(reasons.values())
    typer.echo(
        f"{len(candidates)} changes, {forwarded} forwarded ({dict(sorted(reasons.items()))})"
    )
    versions = sum(len(b.versions) for b in batches)
    typer.echo(f"{len(batches)} package batches for Stage 2 ({versions} versions)")
    typer.echo(f"saved to {data.run_dir(run_id)}/triage.jsonl and batches.jsonl")


@app.command("static")
def static_cmd(
    run_id: str,
    data_dir: DataDirOption = DEFAULT_DATA_DIR,
    workers: Annotated[int, typer.Option(help="Parallel package batches.")] = 8,
) -> None:
    """Stage 2: fetch the tarballs of a triaged run's batches and run the file rules; write
    static.jsonl and the fetch record (static-snapshot.json) into the run directory."""
    data = DataDir(data_dir)
    run_dir = data.run_dir(run_id)
    if not (run_dir / "batches.jsonl").exists():
        typer.echo(f"no batches.jsonl in {run_dir}: run `kitsunox triage {run_id}` first", err=True)
        raise typer.Exit(code=2)
    with data.lock():
        batches = record_static(data, run_id, NpmEcosystem, workers=workers)
    decisions = [c.history[-1] for b in batches for c in b.versions]
    flagged = sum(d.forwarded for d in decisions)
    unavailable = sum(d.reason.startswith("files unavailable") for d in decisions)
    typer.echo(
        f"{len(batches)} batches, {len(decisions)} versions: {flagged} flagged, "
        f"{unavailable} without files"
    )
    typer.echo(f"saved to {run_dir}/static.jsonl")


@app.command("ast")
def ast_cmd(
    run_id: str,
    data_dir: DataDirOption = DEFAULT_DATA_DIR,
    workers: Annotated[int, typer.Option(help="Parallel package batches.")] = 8,
) -> None:
    """Stage 3: parse the JS/TS of a run Stage 2 has processed and compare capabilities with
    the previous version; write ast.jsonl into the run directory."""
    data = DataDir(data_dir)
    run_dir = data.run_dir(run_id)
    if not (run_dir / "static.jsonl").exists():
        typer.echo(f"no static.jsonl in {run_dir}: run `kitsunox static {run_id}` first", err=True)
        raise typer.Exit(code=2)
    with data.lock():
        batches = run_code_stage(data, run_id, workers=workers)
    decisions = [c.history[-1] for b in batches for c in b.versions]
    flagged = sum(d.forwarded for d in decisions)
    typer.echo(f"{len(batches)} batches, {len(decisions)} versions: {flagged} flagged")
    typer.echo(f"saved to {run_dir}/ast.jsonl")


@app.command("correlate")
def correlate_cmd(
    run_id: str,
    data_dir: DataDirOption = DEFAULT_DATA_DIR,
    workers: Annotated[int, typer.Option(help="Parallel package batches.")] = 8,
) -> None:
    """Stage 4: correlate a run Stage 3 has processed (known-malware lookups, comparison with
    the source repository, score); write correlate.jsonl into the run directory."""
    data = DataDir(data_dir)
    run_dir = data.run_dir(run_id)
    if not (run_dir / "ast.jsonl").exists():
        typer.echo(f"no ast.jsonl in {run_dir}: run `kitsunox ast {run_id}` first", err=True)
        raise typer.Exit(code=2)
    with data.lock():
        versions = run_correlate_stage(data, run_id, workers=workers)
    reported = [c for c in versions if c.history[-1].forwarded]
    typer.echo(f"{len(versions)} versions: {len(reported)} to report")
    for c in sorted(reported, key=lambda c: -c.score)[:20]:
        typer.echo(f"  {c.score:5.1f}  {c.change.new.ref}  {c.history[-1].reason}")
    typer.echo(f"saved to {run_dir}/correlate.jsonl")


@app.command("report")
def report_cmd(run_id: str, data_dir: DataDirOption = DEFAULT_DATA_DIR) -> None:
    """Write a run's report from Stage 4's output: report/report.json (canonical), plus
    report/index.md and one Markdown page per reported version."""
    data = DataDir(data_dir)
    run_dir = data.run_dir(run_id)
    if not (run_dir / "correlate.jsonl").exists():
        typer.echo(
            f"no correlate.jsonl in {run_dir}: run `kitsunox correlate {run_id}` first", err=True
        )
        raise typer.Exit(code=2)
    with data.lock():
        report = publish_report(run_dir)
    typer.echo(f"{report.versions} versions, {report.reported} to review")
    typer.echo(f"saved to {run_dir}/report/index.md")


ResultsOption = Annotated[
    Path | None,
    typer.Option(
        "--results",
        help="Stage 5's results root: where you put package-analysis's results/ contents "
        f"(default: {SANDBOX_RESULTS_ENV} from the environment or .env). Without one, nothing "
        "is exported or imported.",
    ),
]


def _sandbox_results(results: Path | None) -> Path | None:
    if results is not None:
        return results
    try:
        configured = env_value(SANDBOX_RESULTS_ENV)
    except (OSError, UnicodeError) as exc:
        typer.echo(f"{SANDBOX_RESULTS_ENV}: .env unreadable ({type(exc).__name__})", err=True)
        return None
    return Path(configured) if configured else None


@app.command("sandbox")
def sandbox_cmd(
    run_id: str,
    data_dir: DataDirOption = DEFAULT_DATA_DIR,
    results: ResultsOption = None,
    cap: Annotated[int, typer.Option(min=0, help="Versions exported per run.")] = DEFAULT_CAP,
    replay: Annotated[
        bool, typer.Option(help="Reproduce the run's recorded Stage 5 output; no import, export.")
    ] = False,
) -> None:
    """Stage 5 on a run Stage 4 has processed: import package-analysis results from the results
    root, then export the reported versions with install hooks for the airgapped analysis VM
    (see docs/stages/sandbox.md); write sandbox.jsonl into the run directory."""
    data = DataDir(data_dir)
    run_dir = data.run_dir(run_id)
    if not (run_dir / "correlate.jsonl").exists():
        typer.echo(
            f"no correlate.jsonl in {run_dir}: run `kitsunox correlate {run_id}` first", err=True
        )
        raise typer.Exit(code=2)
    root = None if replay else _sandbox_results(results)
    if root is not None and not root.is_dir():
        typer.echo(f"results root {root} is not a directory", err=True)
        raise typer.Exit(code=2)
    try:
        with data.lock():
            summary = run_sandbox(data, run_id, root, None, cap=cap, replay=replay)
    except DataDirBusyError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(summary)
    if root is None and not replay:
        typer.echo(f"no results root ({SANDBOX_RESULTS_ENV} or --results): nothing exported")
    typer.echo(f"saved to {run_dir}/sandbox.jsonl")


@app.command("queue")
def queue_cmd(
    data_dir: DataDirOption = DEFAULT_DATA_DIR,
    days: Annotated[int, typer.Option(min=1)] = DEFAULT_KEEP_DAYS,
) -> None:
    """Write the review queue: every run's report over the last DAYS before the newest one,
    one entry per package (queue/queue.json and queue/index.md). `collect` does this after
    each tick."""
    data = DataDir(data_dir)
    with data.lock():
        queue = build_queue(data, NPM, days=days)
        if queue is None:
            typer.echo("no run has a report yet: run `kitsunox report <run_id>` first", err=True)
            raise typer.Exit(code=2)
        directory = write_queue(data, queue)
    typer.echo(
        f"{queue.packages} packages ({queue.versions} versions) to review from "
        f"{len(queue.runs)} runs; by highest severity: {queue.by_severity}"
    )
    if queue.skipped:
        typer.echo(f"unreadable reports left out: {', '.join(queue.skipped)}", err=True)
    typer.echo(f"saved to {directory}/index.md")


@app.command("takedowns")
def takedowns_cmd(data_dir: DataDirOption = DEFAULT_DATA_DIR) -> None:
    """Scan runs not scanned yet for registry takedowns (npm's `0.0.1-security` holding
    package) and list every one kept (data/takedowns/). `collect` scans after each tick; the
    queue flags versions removed after the fact. Never part of a score."""
    data = DataDir(data_dir)
    with data.lock():
        log, runs, added = scan_takedowns(data, NPM, is_security_holder)
    for takedown in log.takedowns:
        typer.echo(
            f"{takedown.published_at:%Y-%m-%d %H:%M} {takedown.name!r} {takedown.version} "
            f"(run {takedown.run_id})"
        )
    typer.echo(f"{added} new in {runs} runs scanned; {len(log.takedowns)} takedowns kept")


@app.command("rescore")
def rescore_cmd(
    run_ids: Annotated[list[str] | None, typer.Argument(help="Runs to re-score.")] = None,
    data_dir: DataDirOption = DEFAULT_DATA_DIR,
    queued: Annotated[
        bool, typer.Option("--queued", help="Every run in the review queue's window.")
    ] = False,
    days: Annotated[int, typer.Option(min=1)] = DEFAULT_KEEP_DAYS,
    skip_rescored: Annotated[
        bool, typer.Option("--skip-rescored", help="Leave runs that were re-scored already.")
    ] = False,
) -> None:
    """Run Stages 1-4 and the report again on finished runs with the current rules, from each
    run's recorded inputs (only requests the current rules newly need go to the network), then
    rebuild the queue. The tick's outputs are kept once under `before-rescore/`. Takes the lock
    one run at a time, so a scheduled tick can run in between."""
    data = DataDir(data_dir)
    runs = list(run_ids or [])
    if queued:
        queue = build_queue(data, NPM, days=days)
        runs += [r for r in (queue.runs if queue else ()) if r not in runs]
    if skip_rescored:
        runs = [r for r in runs if not (data.run_dir(r) / RESCORE_INFO).exists()]
    if not runs:
        typer.echo("no runs to re-score", err=True)
        raise typer.Exit(code=2)
    try:
        for run_id in runs:
            with data.lock():
                summary = rescore_run(data, run_id, lambda: None, datetime.now(UTC))
                queue = build_queue(data, NPM, days=days)
                if queue is not None:
                    write_queue(data, queue)
            typer.echo(f"{run_id}: {summary}")
    except DataDirBusyError as exc:
        typer.echo(f"stopped before {run_id}: {exc}", err=True)
        raise typer.Exit(code=3) from exc


@app.command("view")
def view_cmd(
    data_dir: DataDirOption = DEFAULT_DATA_DIR,
    host: Annotated[
        str, typer.Option(help="Address to listen on: loopback unless --allow-remote.")
    ] = "127.0.0.1",
    port: Annotated[int, typer.Option(min=0, max=65535)] = 8000,
    allow_remote: Annotated[
        bool,
        typer.Option(
            "--allow-remote",
            help="Allow one specific non-loopback address. There is no login and no TLS, so "
            "verdicts can't be recorded there.",
        ),
    ] = False,
    read_only: Annotated[
        bool, typer.Option("--read-only", help="Show no verdict forms and record nothing.")
    ] = False,
) -> None:
    """Browse the review queue and run reports in a local web page, and record reviewers'
    verdicts (malicious, inconclusive, benign). Safe to run beside `collect`: it takes no lock
    and writes only the verdict log. Ctrl-C stops it."""
    from kitsunox.web import RemoteBindRefusedError, serve  # http.server only when needed

    try:
        serve(
            data_dir,
            host,
            port,
            allow_remote=allow_remote,
            read_only=read_only,
            announce=lambda url: typer.echo(f"serving {data_dir} at {url} (Ctrl-C to stop)"),
        )
    except (RemoteBindRefusedError, OSError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc


@app.command("verdict")
def verdict_cmd(
    run_id: str,
    rank: Annotated[int, typer.Argument(min=1)],
    verdict: Annotated[str, typer.Argument(help="malicious, inconclusive, benign or reopened.")],
    note: Annotated[str, typer.Option(help="Why (shown with the verdict).")] = "",
    by: Annotated[str, typer.Option(help="Who records it (a-z, 0-9, _ and -).")] = OWNER,
    probe: Annotated[
        bool, typer.Option("--probe", help="Tag it a security researcher's probe.")
    ] = False,
    data_dir: DataDirOption = DEFAULT_DATA_DIR,
) -> None:
    """Record a verdict on entry RANK of run RUN_ID's report, as the viewer does: the version
    leaves the review queue and is listed under its verdict."""
    parsed = VERDICTS.get(verdict)
    if parsed is None:
        typer.echo("verdict must be malicious, inconclusive, benign or reopened", err=True)
        raise typer.Exit(code=2)
    data = DataDir(data_dir)
    try:
        report = Report.load_json((data.run_dir(run_id) / REPORT_DIR / "report.json").read_bytes())
    except (OSError, ValueError) as exc:
        typer.echo(f"no readable report for run {run_id} ({type(exc).__name__})", err=True)
        raise typer.Exit(code=2) from exc
    entry = next((e for e in report.entries if e.rank == rank), None)
    if entry is None:
        typer.echo(f"run {run_id} has no entry {rank}", err=True)
        raise typer.Exit(code=2)
    try:
        record = verdict_record(
            report,
            entry,
            parsed,
            by=by,
            note=note,
            tags=("probe",) if probe else (),
            at=datetime.now(UTC),
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    append_verdict(data.root, record)
    tags = "".join(f" [{t}]" for t in record.tags)
    typer.echo(f"{entry.name}@{entry.version}: {parsed}{tags} (by {by})")


@app.command("verdicts")
def verdicts_cmd(
    kind: Annotated[str | None, typer.Argument(help="Only this verdict.")] = None,
    data_dir: DataDirOption = DEFAULT_DATA_DIR,
) -> None:
    """The versions reviewers have given a verdict, most recent first, and the tally."""
    now = current(read_verdicts(DataDir(data_dir).root, NPM))
    counts = tally(now)
    typer.echo(
        ", ".join(
            f"{n} {k}" + (f" (probes: {p})" if (p := probes(now, k)) else "")
            for k, n in counts.items()
        )
    )
    for record in sorted(now.values(), key=lambda r: r.at, reverse=True):
        if kind is None or record.verdict == kind:
            note = f": {record.note}" if record.note else ""
            tags = "".join(f" [{t}]" for t in record.tags)
            typer.echo(
                f"{record.verdict:12} {record.name}@{record.version}{tags} ({record.by}, "
                f"{record.at:%Y-%m-%d %H:%M}){note}"
            )


@samples_app.command("datadog")
def samples_datadog(
    data_dir: DataDirOption = DEFAULT_DATA_DIR,
    compromised: Annotated[
        int | None, typer.Option(help="Max compromised_lib samples (shape A). Default: all.")
    ] = None,
    intent: Annotated[
        int, typer.Option(help="Max malicious_intent samples (shape B), deterministic subset.")
    ] = 2000,
) -> None:
    """Import npm samples from the DataDog malicious-software-packages dataset. Zips stay
    encrypted on disk; only their registry metadata is read, in memory. Nothing is executed."""
    sample_set, path, sha = sync_datadog(
        DataDir(data_dir),
        fetched_at=datetime.now(UTC),
        limits={"compromised_lib": compromised, "malicious_intent": intent},
    )
    by_shape: dict[str, int] = {}
    for sample in sample_set.samples:
        by_shape[sample.shape] = by_shape.get(sample.shape, 0) + 1
    typer.echo(
        f"sample set {sample_set.id}: {len(sample_set.samples)} samples "
        f"{dict(sorted(by_shape.items()))}, {len(sample_set.failures)} failed"
    )
    typer.echo(f"saved to {path} (sha256 {sha})")


@eval_app.command("build")
def eval_build(
    name: str,
    data_dir: DataDirOption = DEFAULT_DATA_DIR,
    benign_per_stratum: Annotated[int, typer.Option(min=1)] = 500,
    min_benign_age_days: Annotated[int, typer.Option(min=0)] = 30,
    labels: Annotated[str | None, typer.Option(help="Label set id. Default: newest.")] = None,
) -> None:
    """Build dataset NAME from all recorded npm runs and the newest label set."""
    try:
        dataset, path, sha = make_dataset(
            DataDir(data_dir),
            ecosystem=NPM,
            name=name,
            built_at=datetime.now(UTC),
            label_set_id=labels,
            benign_per_stratum=benign_per_stratum,
            min_benign_age_days=min_benign_age_days,
        )
    except LookupError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"dataset {name}: {len(dataset.samples)} samples from {len(dataset.runs)} runs")
    for key, count in dataset.counts().items():
        typer.echo(f"  {key:28s} {count}")
    typer.echo(f"benign population: {dataset.population}")
    if dataset.excluded:
        typer.echo(f"excluded: {dataset.excluded}")
    typer.echo(f"saved to {path} (sha256 {sha})")


@eval_app.command("run")
def eval_run(
    name: str,
    predictor: Annotated[
        str, typer.Option(help=f"One of: {', '.join(PREDICTOR_NAMES)}.")
    ] = "popularity-only",
    data_dir: DataDirOption = DEFAULT_DATA_DIR,
) -> None:
    """Score a predictor on dataset NAME and print a Markdown table."""
    if predictor not in PREDICTOR_NAMES:
        typer.echo(
            f"unknown predictor {predictor!r}; choose from {', '.join(PREDICTOR_NAMES)}", err=True
        )
        raise typer.Exit(code=2)
    data = DataDir(data_dir)
    chosen = make_predictor(data, NPM, predictor)
    report = run_eval(data, ecosystem=NPM, dataset_name=name, predictor=chosen)
    typer.echo(render_markdown(report))
    notes = getattr(chosen, "notes", None)
    if notes:
        typer.echo(f"notes: {dict(sorted(notes.items()))}")


@app.command("collect")
def collect_cmd(
    data_dir: DataDirOption = DEFAULT_DATA_DIR,
    keep_days: Annotated[int, typer.Option(min=1)] = DEFAULT_KEEP_DAYS,
    keep_repo_days: Annotated[
        int | None,
        typer.Option(
            min=1, help="Keep Stage 4's repository archives this long (default: KEEP_DAYS)."
        ),
    ] = None,
    notify: Annotated[
        bool,
        typer.Option(
            help=f"Post to the Discord webhook in {WEBHOOK_ENV} (environment or .env), if one "
            "is set: the day before's summary on the first tick of a UTC day, and a crash at "
            "most once a day."
        ),
    ] = True,
    notify_each_tick: Annotated[
        bool, typer.Option(help="Also post a brief update after every tick.")
    ] = False,
) -> None:
    """One unattended collection tick: refresh watchlist/labels when stale, record a chained
    ingest run, run Stages 1-4 and the report, prune old runs, then post the daily summary when
    one is due. Exits 0 without doing anything (and without posting) if another tick is
    running."""

    def log(message: str) -> None:
        typer.echo(f"{datetime.now(UTC):%Y-%m-%dT%H:%M:%SZ} {message}")

    webhook: str | None = None
    if notify:
        try:
            webhook = env_value(WEBHOOK_ENV)
        except (OSError, UnicodeError) as exc:  # a broken .env must not stop collection
            log(f"notify: off, .env unreadable ({type(exc).__name__})")
    sandbox_results = _sandbox_results(None)
    data = DataDir(data_dir)
    try:
        with data.lock():
            log("collect: start")
            started = datetime.now(UTC)
            try:
                tick = collect(
                    data,
                    now=started,
                    keep_days=keep_days,
                    keep_repo_days=keep_repo_days,
                    log=log,
                    sandbox_results=sandbox_results,
                )
            except Exception as exc:
                elapsed = datetime.now(UTC) - started
                _record_tick(
                    data, crash_record(exc, where(exc), started=started, elapsed=elapsed), log
                )
                _post_crash(data, webhook, render_crash(exc, where(exc), started=started), log)
                raise
            elapsed = datetime.now(UTC) - started
            _record_tick(data, tick_record(tick, started=started, elapsed=elapsed), log)
            if notify_each_tick:
                post_update(webhook, render_tick(tick, started=started, elapsed=elapsed), log)
            _post_daily(data, webhook, log)
            log("collect: done")
    except DataDirBusyError as exc:
        log(f"collect: skipped, {exc}")


def _record_tick(data: DataDir, record: TickRecord, log: Callable[[str], None]) -> None:
    try:
        append_tick(data.root / "state", record)
    except OSError as exc:  # the tick log feeds a notification; it must not fail the tick
        log(f"notify: tick log not written ({type(exc).__name__})")


def _post_crash(
    data: DataDir, webhook: str | None, content: str, log: Callable[[str], None]
) -> None:
    """A crash, at most once a day (`notify.CRASH_EVERY`): a crash loop posts once."""
    state_dir = data.root / "state"
    state, now = load_state(state_dir), datetime.now(UTC)
    if webhook is None or not crash_due(state, now):
        return
    if post_update(webhook, content, log):
        try:
            save_state(state_dir, state.model_copy(update={"crash_posted": now}))
        except OSError as exc:
            log(f"notify: state not written ({type(exc).__name__})")


def _post_daily(data: DataDir, webhook: str | None, log: Callable[[str], None]) -> None:
    """The day before's summary, on the first tick of a UTC day that finds it unposted."""
    if webhook is None:
        return
    state_dir = data.root / "state"
    state, ticks = load_state(state_dir), read_ticks(state_dir)
    day = summary_due(state, ticks, datetime.now(UTC))
    if day is None:
        return
    run_ids = sorted({r for t in ticks if t.started.date() == day for r in t.reports})
    reports = []
    for run_id in run_ids:
        try:
            path = data.run_dir(run_id) / REPORT_DIR / "report.json"
            reports.append(Report.load_json(path.read_bytes()))
        except OSError, ValueError:  # pruned, damaged or another schema: left out
            continue
    verdicts = read_verdicts(data.root, NPM)
    if post_update(webhook, render_daily(day, ticks, reports, verdicts), log):
        try:
            save_state(state_dir, state.model_copy(update={"daily_posted": day}))
        except OSError as exc:
            log(f"notify: state not written ({type(exc).__name__})")


@data_app.command("prune")
def data_prune(
    data_dir: DataDirOption = DEFAULT_DATA_DIR,
    keep_days: Annotated[int, typer.Option(min=1)] = DEFAULT_KEEP_DAYS,
    keep_repo_days: Annotated[
        int | None,
        typer.Option(
            min=1, help="Keep Stage 4's repository archives this long (default: KEEP_DAYS)."
        ),
    ] = None,
) -> None:
    """Drop HTTP bodies of runs older than KEEP_DAYS (they can no longer be replayed), keeping
    packuments of packages with OSV malware records, and compress their changes."""
    data = DataDir(data_dir)
    labels_id = label_store(data).latest_id(NPM)
    if labels_id is None:
        typer.echo("no label set; run `kitsunox labels sync` first", err=True)
        raise typer.Exit(code=2)
    labels = label_store(data).load(NPM, labels_id)
    try:
        with data.lock():
            report = prune(
                data,
                now=datetime.now(UTC),
                keep_days=keep_days,
                pinned_names=labels.labels.keys(),
                metadata_url=packument_url,
                keep_archive_days=keep_repo_days,
                is_archive=is_archive_url,
            )
            exports, results = prune_sandbox(data, labels.labels.keys())
    except DataDirBusyError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"{len(report.runs_pruned)} runs pruned, {report.blobs_pinned} blobs pinned, "
        f"{report.blobs_deleted} blobs deleted ({report.bytes_freed / 1e9:.2f} GB freed); "
        f"Stage 5: {exports} exports, {results} results removed"
    )


@schedule_app.command("plist")
def schedule_plist(
    data_dir: DataDirOption = DEFAULT_DATA_DIR,
    interval_minutes: Annotated[int, typer.Option(min=10)] = 60,
    keep_repo_days: Annotated[
        int | None,
        typer.Option(
            min=1, help="Keep Stage 4's repository archives this long (default: KEEP_DAYS)."
        ),
    ] = None,
) -> None:
    """Print a launchd agent that runs `kitsunox collect` every INTERVAL_MINUTES. Install it
    with: kitsunox schedule plist > ~/Library/LaunchAgents/local.kitsunox.collect.plist &&
    launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/local.kitsunox.collect.plist"""
    job = _collect_job(data_dir, keep_repo_days)
    agent = {
        "Label": LAUNCHD_LABEL,
        "ProgramArguments": job.argv,
        "WorkingDirectory": str(job.project),
        "StartInterval": interval_minutes * 60,
        "RunAtLoad": False,
        "StandardOutPath": str(job.log),
        "StandardErrorPath": str(job.log),
        "EnvironmentVariables": {"PATH": job.path},
        "ProcessType": "Background",
        "LowPriorityIO": True,
    }
    sys.stdout.buffer.write(plistlib.dumps(agent))


@schedule_app.command("systemd")
def schedule_systemd(
    data_dir: DataDirOption = DEFAULT_DATA_DIR,
    interval_minutes: Annotated[int, typer.Option(min=10)] = 60,
    keep_repo_days: Annotated[
        int | None,
        typer.Option(
            min=1, help="Keep Stage 4's repository archives this long (default: KEEP_DAYS)."
        ),
    ] = None,
    unit_dir: Annotated[Path, typer.Option(help="Where to write the units.")] = SYSTEMD_USER_DIR,
) -> None:
    """Write a systemd user service and timer that run `kitsunox collect` every
    INTERVAL_MINUTES, counted from the start of the previous tick (a tick never overlaps
    itself). Enable it with: systemctl --user daemon-reload && systemctl --user enable --now
    kitsunox-collect.timer, and `loginctl enable-linger` so it runs while logged out."""
    job = _collect_job(data_dir, keep_repo_days)
    log = _systemd_path(job.log)
    service = (
        "[Unit]\n"
        "Description=Kitsunox collection tick\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"ExecStart={' '.join(_systemd_exec_arg(arg) for arg in job.argv)}\n"
        f"WorkingDirectory={_systemd_path(job.project)}\n"
        f"Environment={_systemd_quoted(('PATH=' + job.path).replace('%', '%%'))}\n"
        f"StandardOutput=append:{log}\n"
        f"StandardError=append:{log}\n"
        "Nice=10\n"
        "IOSchedulingClass=idle\n"
    )
    timer = (
        "[Unit]\n"
        "Description=Run the Kitsunox collection tick periodically\n"
        "\n"
        "[Timer]\n"
        "OnBootSec=5min\n"
        f"OnUnitActiveSec={interval_minutes}min\n"
        "AccuracySec=1min\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )
    unit_dir.mkdir(parents=True, exist_ok=True)
    for name, content in ((f"{SYSTEMD_UNIT}.service", service), (f"{SYSTEMD_UNIT}.timer", timer)):
        (unit_dir / name).write_text(content, encoding="utf-8")
        typer.echo(f"wrote {unit_dir / name}")


@dataclass(frozen=True, slots=True)
class _CollectJob:
    argv: list[str]
    project: Path
    log: Path
    path: str  # PATH for the job: system binaries and uv


def _collect_job(data_dir: Path, keep_repo_days: int | None) -> _CollectJob:
    """The scheduled command line, shared by the launchd and systemd units."""
    uv = shutil.which("uv")
    if uv is None:
        typer.echo("uv not found on PATH", err=True)
        raise typer.Exit(code=2)
    project = Path.cwd().resolve()
    data = data_dir.resolve()
    for path in (uv, str(project), str(data)):
        # A newline would end a unit-file line; edge whitespace is trimmed by systemd.
        if path != path.strip() or any(ord(c) < 0x20 or ord(c) == 0x7F for c in path):
            typer.echo(f"unsupported path for a scheduled job: {path!r}", err=True)
            raise typer.Exit(code=2)
    log = data / "logs" / "collect.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    argv = [
        uv,
        "run",
        "--frozen",
        "--project",
        str(project),
        "kitsunox",
        "collect",
        "--data-dir",
        str(data),
        *(["--keep-repo-days", str(keep_repo_days)] if keep_repo_days else []),
    ]
    return _CollectJob(argv=argv, project=project, log=log, path=f"/usr/bin:/bin:{Path(uv).parent}")


# Unit-file settings parse values differently (systemd.service(5), systemd.exec(5)):
# ExecStart= has specifiers (`%`), variables (`$`) and C-style quoting; Environment= has
# specifiers and quoting but no variables; paths (WorkingDirectory=, append:) are taken
# literally apart from specifiers. `_collect_job` has already refused control characters.


def _systemd_exec_arg(value: str) -> str:
    escaped = value.replace("%", "%%").replace("$", "$$")
    if escaped and not any(c in escaped for c in " \t\"'\\;"):
        return escaped
    return _systemd_quoted(escaped)


def _systemd_quoted(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _systemd_path(path: Path) -> str:
    return str(path).replace("%", "%%")


def _print_summary(manifest: RunManifest, data_dir: Path) -> None:
    typer.echo(f"run:      {manifest.run_id}  ({data_dir / 'runs' / manifest.run_id})")
    typer.echo(
        f"window:   {manifest.window.start.isoformat()} .. {manifest.window.end.isoformat()}"
    )
    typer.echo(f"feed:     ({manifest.cursor_since}, {manifest.cursor_until}]")
    if manifest.chained_from:
        typer.echo(f"chained:  from {manifest.chained_from}")
    if manifest.window_covered is False and manifest.feed_start_estimate is not None:
        typer.echo(
            f"WARNING:  the feed range only reaches back to about "
            f"{manifest.feed_start_estimate.isoformat()}, "
            "after the window start. Releases before that are missed unless their package "
            "changed again. Use an earlier --since-seq or a larger --lookback-seq.",
            err=True,
        )
    typer.echo(f"packages: {manifest.packages_seen} seen")
    typer.echo(f"changes:  {manifest.change_count}")
    typer.echo(f"skipped:  {manifest.skipped_count}")
    popularity = manifest.popularity_mode.value
    if manifest.watchlist_id:
        popularity += f" ({manifest.watchlist_id})"
    typer.echo(f"popularity: {popularity}, failed lookups: {manifest.popularity_failures}")
