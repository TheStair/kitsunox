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
    RunManifest,
    changes_digest,
    record_ingest,
    replay_ingest,
)
from kitsunox.ecosystems.npm.registry import NpmEcosystem

app = typer.Typer(help="Flag likely software supply chain attacks in recent npm releases.")
ingest_app = typer.Typer(help="Stage 0: collect recent releases into Change records.")
app.add_typer(ingest_app, name="ingest")

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
    )
    manifest = record_ingest(DataDir(data_dir), NpmEcosystem, request)
    _print_summary(manifest, data_dir)


@ingest_app.command("replay")
def ingest_replay(run_id: str, data_dir: DataDirOption = DEFAULT_DATA_DIR) -> None:
    """Re-run Stage 0 offline from a run's snapshot and check the output is identical."""
    data = DataDir(data_dir)
    manifest = RunManifest.model_validate_json(
        (data.run_dir(run_id) / "manifest.json").read_bytes()
    )
    digest = changes_digest(replay_ingest(data, NpmEcosystem, run_id))
    if digest != manifest.changes_sha256:
        typer.echo(f"MISMATCH: recorded {manifest.changes_sha256}, replayed {digest}", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"identical: {digest}")


def _print_summary(manifest: RunManifest, data_dir: Path) -> None:
    typer.echo(f"run:      {manifest.run_id}  ({data_dir / 'runs' / manifest.run_id})")
    typer.echo(
        f"window:   {manifest.window.start.isoformat()} .. {manifest.window.end.isoformat()}"
    )
    typer.echo(f"feed:     ({manifest.cursor_since}, {manifest.cursor_until}]")
    typer.echo(f"packages: {manifest.packages_seen} seen")
    typer.echo(f"changes:  {manifest.change_count}")
    typer.echo(f"skipped:  {manifest.skipped_count}")
