"""``kitsunox`` command-line entry point."""

from __future__ import annotations

import sys
from pathlib import Path

import structlog
import typer

from kitsunox.config import get_settings

app = typer.Typer(
    add_completion=False,
    help="Tiered detection of supply chain attacks in package registries.",
)
log = structlog.get_logger("kitsunox.cli")


def _configure_logging() -> None:
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ]
    )


@app.callback()
def _main() -> None:
    _configure_logging()


@app.command("db-init")
def db_init() -> None:
    """Create/upgrade the SQLite schema (alembic upgrade head)."""
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
    command.upgrade(cfg, "head")
    typer.echo(f"schema up to date: {get_settings().db_url}")


@app.command("intel-sync")
def intel_sync() -> None:
    """Refresh the local threat-intel mirror (OSV npm export + OpenSSF malicious-packages)."""
    from kitsunox.threatintel.sync import load_index, sync_all

    counts = sync_all()
    typer.echo(f"synced: {counts}")
    idx = load_index()
    typer.echo(f"malicious index: {len(idx)} hits across {len(idx.by_package)} packages")

    try:
        from kitsunox.db.repo import open_repo
        from kitsunox.eval.incidents import load_incident_labels_into_db

        with open_repo() as repo:
            n = load_incident_labels_into_db(repo)
        typer.echo(f"incident labels loaded: {n}")
    except NotImplementedError:
        typer.echo("incident label loader not implemented yet (eval/incidents.py) — skipped")


@app.command("listen")
def listen(
    once: bool = typer.Option(False, help="Process the current backlog then exit (no polling)."),
    max_events: int = typer.Option(0, help="Stop after N events (0 = unlimited)."),
) -> None:
    """Consume the npm _changes feed, pre-score, and run Tier 0 on routed events."""
    from kitsunox.analysis.tier0.iocs import IOCChecker
    from kitsunox.ingest.changes_feed import ChangesFeedClient, iter_changes
    from kitsunox.ingest.registry_client import RegistryClient
    from kitsunox.pipeline import handle_change

    settings = get_settings()
    ioc_checker = IOCChecker(settings=settings)  # load the malicious index once
    with (
        ChangesFeedClient(settings) as feed,
        RegistryClient(settings) as registry,
    ):
        from kitsunox.db.repo import open_repo

        with open_repo() as repo:
            start = feed.resolve_start_seq(repo.get_cursor())
        log.info("listening", start_seq=start, feed_start=settings.feed_start)

        seen = 0
        for row in iter_changes(
            start_seq=start,
            feed=feed,
            on_cursor=_persist_cursor,
            stop_when_caught_up=once,
        ):
            handle_change(row, registry=registry, ioc_checker=ioc_checker)
            seen += 1  # noqa: SIM113 - not an enumerate loop; may early-return
            if max_events and seen >= max_events:
                log.info("max_events reached", seen=seen)
                return


def _persist_cursor(last_seq: int) -> None:
    from kitsunox.db.repo import open_repo

    with open_repo() as repo:
        repo.set_cursor(last_seq)


@app.command("scan")
def scan(target: str = typer.Argument(..., help="package@version, e.g. event-stream@3.3.6")) -> None:
    """Run Tier 0 against a single published version (ad hoc, no feed)."""
    from kitsunox.analysis.scanner import run_tier0
    from kitsunox.ingest.registry_client import RegistryClient
    from kitsunox.ir import Ecosystem, PackageRef, PublishEvent

    if "@" not in target.lstrip("@"):
        raise typer.BadParameter("expected package@version")
    name, version = target.rsplit("@", 1)

    event = PublishEvent(ref=PackageRef(ecosystem=Ecosystem.NPM, name=name), version=version)
    with RegistryClient(get_settings()) as client:
        result = run_tier0(event, client=client)

    tarball_state = "ok" if result.tarball_available else "MISSING"
    typer.echo(f"{name}@{version}  status={result.status}  tarball={tarball_state}")
    for f in result.findings:
        loc = f":{f.line}" if f.line else ""
        typer.echo(f"  [{f.severity.value:8}] {f.rule_id}  {f.file_path or ''}{loc}")
        typer.echo(f"           {f.rationale}")
    if result.notes:
        typer.echo(f"  notes: {'; '.join(result.notes)}")
    if not result.findings:
        typer.echo("  (no findings)")


@app.command("backfill")
def backfill(
    incident: str = typer.Option("", help="Incident key (default: all). See eval/incidents.py."),
) -> None:
    """Reconstruct historical incident publishes and score Tier 0 detection."""
    from kitsunox.eval.backfill import run_backfill
    from kitsunox.eval.incidents import INCIDENTS, get_incident
    from kitsunox.ingest.registry_client import RegistryClient

    targets = [get_incident(incident)] if incident else INCIDENTS
    with RegistryClient(get_settings()) as client:
        for inc in targets:
            try:
                report = run_backfill(inc, client=client)
                typer.echo(report.render())
            except NotImplementedError as exc:
                typer.echo(f"[{inc.key}] backfill not implemented: {exc}", err=True)
                sys.exit(1)


if __name__ == "__main__":  # pragma: no cover
    app()
