"""End-to-end: recorded run -> labels -> dataset -> report, through the library and the CLI."""

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from conftest import Router, mal, osv_zip
from kitsunox.cli import app
from kitsunox.core.run import DataDir, IngestRequest, PopularityMode, record_ingest
from kitsunox.ecosystems.npm.registry import (
    FEED_PAGE_LIMIT,
    REGISTRY_URL,
    REPLICATE_URL,
    NpmEcosystem,
)
from kitsunox.evaluation.harness import make_dataset, run_eval, sync_labels
from kitsunox.evaluation.labels import OSV_EXPORT_URL
from kitsunox.evaluation.metrics import ForwardAll

runner = CliRunner()


@pytest.fixture
def data(tmp_path: Path, router: Router, load_fixture: Callable[[str], object]) -> DataDir:
    router.add_json(
        f"{REPLICATE_URL}/_changes?since=100&limit={FEED_PAGE_LIMIT}",
        {"results": [{"seq": 150, "id": "kx-fixture"}]},
    )
    router.add_json(f"{REPLICATE_URL}/_changes?since=150&limit={FEED_PAGE_LIMIT}", {"results": []})
    router.add_json(f"{REGISTRY_URL}/kx-fixture", load_fixture("npm/packument_basic.json"))
    router.add_bytes(
        OSV_EXPORT_URL.format(ecosystem="npm"),
        osv_zip({"MAL-2026-9.json": mal("MAL-2026-9", "kx-fixture", versions=["2.0.1"])}),
    )
    data = DataDir(tmp_path)
    request = IngestRequest(
        as_of=datetime(2026, 10, 27, 12, tzinfo=UTC),
        window_hours=12,
        since=100,
        until=200,
        popularity=PopularityMode.NONE,
    )
    record_ingest(data, NpmEcosystem, request, client=router.client())
    sync_labels(
        data,
        ecosystem="npm",
        fetched_at=datetime(2026, 12, 1, tzinfo=UTC),
        client=router.client(),
    )
    return data


def test_library_end_to_end(data: DataDir) -> None:
    dataset, _, _ = make_dataset(
        data, ecosystem="npm", name="smoke", built_at=datetime(2026, 12, 1, tzinfo=UTC)
    )
    assert dataset.counts() == {"benign/A": 3, "malicious/A": 1}
    (malicious,) = [s for s in dataset.samples if s.label == "malicious"]
    assert malicious.key == "npm:kx-fixture@2.0.1"
    assert malicious.label_ids == ("MAL-2026-9",)
    report = run_eval(data, ecosystem="npm", dataset_name="smoke", predictor=ForwardAll())
    assert report.cells["malicious/all"].rate == 1.0
    assert report.cells["benign/all"].total == 3


def test_cli_end_to_end(data: DataDir) -> None:
    args = ["--data-dir", str(data.root)]
    built = runner.invoke(app, ["eval", "build", "smoke", *args])
    assert built.exit_code == 0, built.output
    assert "malicious/A" in built.output
    ran = runner.invoke(app, ["eval", "run", "smoke", "--predictor", "popularity-only", *args])
    assert ran.exit_code == 0, ran.output
    assert "| malicious/all | 1 | 0 | 0.0% | recall |" in ran.output
    bad = runner.invoke(app, ["eval", "run", "smoke", "--predictor", "nope", *args])
    assert bad.exit_code == 2


def test_build_requires_labels_and_safe_name(tmp_path: Path) -> None:
    empty = DataDir(tmp_path)
    with pytest.raises(LookupError, match="labels sync"):
        make_dataset(empty, ecosystem="npm", name="x", built_at=datetime.now(UTC))
    with pytest.raises(ValueError, match="must match"):
        make_dataset(empty, ecosystem="npm", name="../escape", built_at=datetime.now(UTC))
    result = runner.invoke(app, ["eval", "build", "x", "--data-dir", str(tmp_path)])
    assert result.exit_code == 2
