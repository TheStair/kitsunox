import json
import plistlib
from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

from conftest import Router
from kitsunox import __version__
from kitsunox.cli import app
from kitsunox.core.run import DataDir, IngestRequest, PopularityMode, record_ingest
from kitsunox.ecosystems.npm.registry import FEED_PAGE_LIMIT, REPLICATE_URL, NpmEcosystem

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == __version__


def recorded_run(tmp_path: Path, router: Router) -> str:
    router.add_json(f"{REPLICATE_URL}/_changes?since=1&limit={FEED_PAGE_LIMIT}", {"results": []})
    request = IngestRequest(
        as_of=datetime(2026, 10, 27, tzinfo=UTC), since=1, until=2, popularity=PopularityMode.NONE
    )
    return record_ingest(DataDir(tmp_path), NpmEcosystem, request, client=router.client()).run_id


def test_replay_reports_identical(tmp_path: Path, router: Router) -> None:
    run_id = recorded_run(tmp_path, router)
    result = runner.invoke(app, ["ingest", "replay", run_id, "--data-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert result.stdout.startswith("identical: ")


def test_replay_detects_mismatch(tmp_path: Path, router: Router) -> None:
    run_id = recorded_run(tmp_path, router)
    manifest_path = DataDir(tmp_path).run_dir(run_id) / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["changes_sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest))
    result = runner.invoke(app, ["ingest", "replay", run_id, "--data-dir", str(tmp_path)])
    assert result.exit_code == 1
    assert "MISMATCH" in result.output


def test_record_without_watchlist_explains_and_exits(tmp_path: Path) -> None:
    # Fails before any network access: the watchlist is resolved first.
    result = runner.invoke(app, ["ingest", "record", "--data-dir", str(tmp_path)])
    assert result.exit_code == 2
    assert "kitsunox watchlist build" in result.output


def test_schedule_plist_runs_collect(tmp_path: Path) -> None:
    result = runner.invoke(app, ["schedule", "plist", "--data-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    agent = plistlib.loads(result.stdout_bytes)
    assert agent["ProgramArguments"][-3:] == ["collect", "--data-dir", str(tmp_path.resolve())]
    assert agent["StartInterval"] == 3600


def test_prune_needs_labels(tmp_path: Path) -> None:
    result = runner.invoke(app, ["data", "prune", "--data-dir", str(tmp_path)])
    assert result.exit_code == 2


def test_collect_skips_when_locked(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    with data.lock():
        result = runner.invoke(app, ["collect", "--data-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert "skipped" in result.stdout
