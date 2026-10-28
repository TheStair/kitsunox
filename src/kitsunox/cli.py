"""Command-line entry point. Pipeline commands are added as each stage lands."""

import os
import plistlib
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer

from kitsunox import __version__
from kitsunox.collect import DEFAULT_KEEP_DAYS, collect
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
from kitsunox.ecosystems.npm.registry import ECOSYSTEMS_REGISTRY, NpmEcosystem, packument_url
from kitsunox.evaluation.harness import (
    PREDICTOR_NAMES,
    label_store,
    make_dataset,
    make_predictor,
    run_eval,
    sync_datadog,
    sync_labels,
)
from kitsunox.evaluation.metrics import render_markdown
from kitsunox.stages.static import record_static
from kitsunox.stages.triage import triage_run

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
schedule_app = typer.Typer(help="Run `kitsunox collect` on a schedule (macOS launchd).")
app.add_typer(schedule_app, name="schedule")

LAUNCHD_LABEL = "local.kitsunox.collect"

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


@ingest_app.command("record")
def ingest_record(
    data_dir: DataDirOption = DEFAULT_DATA_DIR,
    as_of: Annotated[
        datetime | None,
        typer.Option(help="End of the window (UTC if no offset). Default: now."),
    ] = None,
    window_hours: Annotated[float, typer.Option(min=0.01)] = 24.0,
    since_seq: Annotated[
        int | None, typer.Option(help="Feed position to start after. Default: checkpoint.")
    ] = None,
    until_seq: Annotated[
        int | None, typer.Option(help="Last feed position to read. Default: feed head.")
    ] = None,
    lookback_seq: Annotated[
        int, typer.Option(help="Feed positions to scan when there's no checkpoint.")
    ] = 400_000,
    workers: Annotated[int, typer.Option(min=1, max=64)] = 8,
    popularity: Annotated[
        PopularityMode,
        typer.Option(help="watchlist: prebuilt list (fast). api: per-package lookups (slow)."),
    ] = PopularityMode.WATCHLIST,
    watchlist: Annotated[
        str | None, typer.Option(help="Watchlist id. Default: newest built before --as-of.")
    ] = None,
    chain: Annotated[
        bool,
        typer.Option(help="Continue from the previous run: window starts where it ended."),
    ] = False,
) -> None:
    """Fetch recent npm changes and write a replayable run."""
    moment = as_of or datetime.now(UTC)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    request = IngestRequest(
        as_of=moment,
        window_hours=window_hours,
        since=since_seq,
        until=until_seq,
        lookback=lookback_seq,
        workers=workers,
        popularity=popularity,
        watchlist_id=watchlist,
        chain=chain,
    )
    data = DataDir(data_dir)
    try:
        with data.lock():
            manifest = record_ingest(data, NpmEcosystem, request)
    except DataDirBusyError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    except WatchlistMissingError as exc:
        typer.echo(f"{exc}. Run `kitsunox watchlist build` first, or pass --popularity none.")
        raise typer.Exit(code=2) from exc
    _print_summary(manifest, data_dir)


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
) -> None:
    """One unattended collection tick: refresh watchlist/labels when stale, record a chained
    ingest run, prune old runs. Exits 0 without doing anything if another tick is running."""

    def log(message: str) -> None:
        typer.echo(f"{datetime.now(UTC):%Y-%m-%dT%H:%M:%SZ} {message}")

    data = DataDir(data_dir)
    try:
        with data.lock():
            log("collect: start")
            collect(data, now=datetime.now(UTC), keep_days=keep_days, log=log)
            log("collect: done")
    except DataDirBusyError as exc:
        log(f"collect: skipped, {exc}")


@data_app.command("prune")
def data_prune(
    data_dir: DataDirOption = DEFAULT_DATA_DIR,
    keep_days: Annotated[int, typer.Option(min=1)] = DEFAULT_KEEP_DAYS,
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
            )
    except DataDirBusyError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"{len(report.runs_pruned)} runs pruned, {report.blobs_pinned} blobs pinned, "
        f"{report.blobs_deleted} blobs deleted ({report.bytes_freed / 1e9:.2f} GB freed)"
    )


@schedule_app.command("plist")
def schedule_plist(
    data_dir: DataDirOption = DEFAULT_DATA_DIR,
    interval_minutes: Annotated[int, typer.Option(min=10)] = 60,
) -> None:
    """Print a launchd agent that runs `kitsunox collect` every INTERVAL_MINUTES. Install it
    with: kitsunox schedule plist > ~/Library/LaunchAgents/local.kitsunox.collect.plist &&
    launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/local.kitsunox.collect.plist"""
    uv = shutil.which("uv")
    if uv is None:
        typer.echo("uv not found on PATH", err=True)
        raise typer.Exit(code=2)
    project = Path.cwd().resolve()
    data = data_dir.resolve()
    log = data / "logs" / "collect.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    agent = {
        "Label": LAUNCHD_LABEL,
        "ProgramArguments": [
            uv,
            "run",
            "--frozen",
            "--project",
            str(project),
            "kitsunox",
            "collect",
            "--data-dir",
            str(data),
        ],
        "WorkingDirectory": str(project),
        "StartInterval": interval_minutes * 60,
        "RunAtLoad": False,
        "StandardOutPath": str(log),
        "StandardErrorPath": str(log),
        "EnvironmentVariables": {"PATH": "/usr/bin:/bin:" + str(Path(uv).parent)},
        "ProcessType": "Background",
        "LowPriorityIO": True,
    }
    sys.stdout.buffer.write(plistlib.dumps(agent))


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
