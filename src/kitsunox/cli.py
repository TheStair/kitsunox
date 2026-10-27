"""Command-line entry point. Pipeline commands are added as each stage lands."""

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer

from kitsunox import __version__
from kitsunox.core.run import (
    DataDir,
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
from kitsunox.ecosystems.npm.registry import ECOSYSTEMS_REGISTRY, NpmEcosystem
from kitsunox.evaluation.harness import make_dataset, run_eval, sync_labels
from kitsunox.evaluation.metrics import PREDICTORS, render_markdown

app = typer.Typer(help="Flag likely software supply chain attacks in recent npm releases.")
ingest_app = typer.Typer(help="Stage 0: collect recent releases into Change records.")
app.add_typer(ingest_app, name="ingest")
watchlist_app = typer.Typer(help="Popularity watchlists (packages always analyzed in depth).")
app.add_typer(watchlist_app, name="watchlist")
labels_app = typer.Typer(help="Ground-truth malware labels (OSV MAL- records).")
app.add_typer(labels_app, name="labels")
eval_app = typer.Typer(help="Evaluation: build datasets from runs and score predictors.")
app.add_typer(eval_app, name="eval")

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
    )
    try:
        manifest = record_ingest(DataDir(data_dir), NpmEcosystem, request)
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
        str, typer.Option(help=f"One of: {', '.join(PREDICTORS)}.")
    ] = "popularity-only",
    data_dir: DataDirOption = DEFAULT_DATA_DIR,
) -> None:
    """Score a predictor on dataset NAME and print a Markdown table."""
    if predictor not in PREDICTORS:
        typer.echo(
            f"unknown predictor {predictor!r}; choose from {', '.join(PREDICTORS)}", err=True
        )
        raise typer.Exit(code=2)
    report = run_eval(
        DataDir(data_dir), ecosystem=NPM, dataset_name=name, predictor=PREDICTORS[predictor]()
    )
    typer.echo(render_markdown(report))


def _print_summary(manifest: RunManifest, data_dir: Path) -> None:
    typer.echo(f"run:      {manifest.run_id}  ({data_dir / 'runs' / manifest.run_id})")
    typer.echo(
        f"window:   {manifest.window.start.isoformat()} .. {manifest.window.end.isoformat()}"
    )
    typer.echo(f"feed:     ({manifest.cursor_since}, {manifest.cursor_until}]")
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
