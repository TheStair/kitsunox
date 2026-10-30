"""`kitsunox collect`: one unattended tick against a mocked registry."""

from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import NoReturn

import pytest

import kitsunox.collect
from conftest import AS_OF, Router, save_watchlist
from kitsunox.collect import REPORT_ONLY, _resume_from, collect, run_stages
from kitsunox.core.run import DataDir
from kitsunox.ecosystems.npm.registry import FEED_PAGE_LIMIT, REPLICATE_URL
from kitsunox.evaluation.labels import LabelSet, label_store


def save_labels(data: DataDir) -> None:
    labels = LabelSet(
        ecosystem="npm",
        source="test",
        fetched_at=AS_OF - timedelta(hours=1),
        source_sha256="0" * 64,
        labels={},
    )
    label_store(data).save("npm", labels.id, labels)


def feed_from(registry: Router, since: int) -> None:
    registry.add_json(
        f"{REPLICATE_URL}/_changes?since={since}&limit={FEED_PAGE_LIMIT}",
        {"results": [{"seq": 150, "id": "kx-fixture"}]} if since == 0 else {"results": []},
    )
    if since == 0:
        feed_from(registry, 150)


def test_ticks_chain_and_prune_once_a_day(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    save_watchlist(data, AS_OF - timedelta(hours=1))
    save_labels(data)
    feed_from(registry, 0)
    feed_from(registry, 200)
    log: list[str] = []

    tick = collect(data, now=AS_OF, log=log.append, clients=registry.client)
    first = tick.manifest
    assert first is not None
    assert first.chained_from is None and first.change_count == 4
    assert [r.run_id for r in tick.reports] == [first.run_id] and tick.failed == ()
    assert not any(line.startswith(("watchlist", "labels")) for line in log)  # both fresh
    assert any(line.startswith("prune: 0 runs pruned") for line in log)
    # Stages 1 and 2 ran on the new run; the mock serves no tarballs, so Stage 2 has no files.
    stages = next(line for line in log if line.startswith("stages: "))
    assert stages.startswith("stages: 4 triaged"), stages
    assert (data.run_dir(first.run_id) / "static.jsonl").exists()
    assert (data.run_dir(first.run_id) / "ast.jsonl").exists()
    assert (tmp_path / "queue" / "queue.json").exists()
    assert any(line.startswith("queue: 1 packages (1 versions) from 1 runs") for line in log), log

    log.clear()
    second = collect(
        data, now=AS_OF + timedelta(hours=1), log=log.append, clients=registry.client
    ).manifest
    assert second is not None
    assert second.chained_from == first.run_id
    assert not any(line.startswith("prune") for line in log)  # pruned an hour ago


def test_failed_refresh_is_logged_and_ingest_still_runs(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    save_watchlist(data, AS_OF - timedelta(hours=1))
    feed_from(registry, 0)
    log: list[str] = []
    tick = collect(data, now=AS_OF, log=log.append, clients=registry.client)
    assert tick.manifest is not None and tick.manifest.change_count == 4
    assert any(line.startswith("labels: FAILED") for line in log)  # OSV export is a 404 here
    assert tick.failed == ("labels",)
    assert "prune: skipped: no label set to decide which packuments to keep" in log


def test_offline_tick_writes_nothing(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    save_watchlist(data, AS_OF - timedelta(hours=1))
    save_labels(data)
    registry.offline.add(f"{REPLICATE_URL}/")
    log: list[str] = []
    tick = collect(data, now=AS_OF, log=log.append, clients=registry.client)
    assert tick.manifest is None and tick.reports == ()
    assert any(line.startswith("ingest: OFFLINE") for line in log)
    assert data.read_checkpoint("npm") is None


def test_unfinished_stages_are_caught_up(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    save_watchlist(data, AS_OF - timedelta(hours=1))
    save_labels(data)
    feed_from(registry, 0)
    feed_from(registry, 200)
    ignored: list[str] = []
    first = collect(data, now=AS_OF, log=ignored.append, clients=registry.client).manifest
    assert first is not None
    (data.run_dir(first.run_id) / "static.jsonl").unlink()  # as if Stage 2 had crashed

    log: list[str] = []
    tick = collect(data, now=AS_OF + timedelta(hours=1), log=log.append, clients=registry.client)
    assert tick.reports[0].run_id == first.run_id  # catch-ups first, then the new run
    assert any(
        line.startswith(f"stages (catch-up {first.run_id} from Stage 1): ") for line in log
    ), log
    assert (data.run_dir(first.run_id) / "static.jsonl").exists()
    assert (data.run_dir(first.run_id) / "correlate.jsonl").exists()

    (data.run_dir(first.run_id) / "correlate.jsonl").unlink()  # only Stage 4 is redone
    log.clear()
    collect(
        data, now=AS_OF + timedelta(hours=1, minutes=30), log=log.append, clients=registry.client
    )
    (line,) = [line for line in log if "catch-up" in line]
    assert "from Stage 4" in line and "triaged" not in line and "Stage 4" in line

    log.clear()  # nothing left to catch up
    collect(data, now=AS_OF + timedelta(hours=2), log=log.append, clients=registry.client)
    assert not any("catch-up" in line for line in log)


def test_a_missing_report_alone_is_redone(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    save_watchlist(data, AS_OF - timedelta(hours=1))
    save_labels(data)
    feed_from(registry, 0)
    feed_from(registry, 200)
    ignored: list[str] = []
    first = collect(data, now=AS_OF, log=ignored.append, clients=registry.client).manifest
    assert first is not None
    report = data.run_dir(first.run_id) / "report"
    damage: list[Callable[[], object]] = [
        (report / "report.json").unlink,  # as if writing the report had failed after Stage 4
        (report / "index.md").unlink,  # written last: report.json alone isn't a report
        lambda: (report / "report.json").write_bytes(  # another schema version
            (report / "report.json")
            .read_bytes()
            .replace(b'"schema_version": 1', b'"schema_version": 0')
        ),
    ]
    for hour, broken in enumerate(damage, start=1):
        broken()
        log: list[str] = []
        now = AS_OF + timedelta(hours=hour)
        tick = collect(data, now=now, log=log.append, clients=registry.client)
        (line,) = [line for line in log if "catch-up" in line]
        assert line.startswith(f"stages (catch-up {first.run_id} from the report): "), line
        assert "compared" not in line  # Stage 4 wasn't redone
        assert (report / "index.md").exists() and tick.reports[0].run_id == first.run_id


def test_an_interrupted_rerun_leaves_no_stale_report(
    tmp_path: Path, registry: Router, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = DataDir(tmp_path)
    save_watchlist(data, AS_OF - timedelta(hours=1))
    save_labels(data)
    feed_from(registry, 0)
    feed_from(registry, 200)
    first = collect(data, now=AS_OF, log=lambda _: None, clients=registry.client).manifest
    assert first is not None
    run_dir = data.run_dir(first.run_id)

    def killed(*_: object, **__: object) -> NoReturn:
        raise KeyboardInterrupt  # as if the tick were stopped during Stage 4

    monkeypatch.setattr(kitsunox.collect, "run_correlate_stage", killed)
    with pytest.raises(KeyboardInterrupt):
        run_stages(data, first.run_id, registry.client, start=1)
    # The old report would otherwise count as complete for the rewritten Stage 1-3 outputs.
    assert not (run_dir / "report" / "index.md").exists()
    assert _resume_from(run_dir) == REPORT_ONLY


def test_stage5_runs_only_with_a_results_root(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path / "data")
    save_watchlist(data, AS_OF - timedelta(hours=1))
    save_labels(data)
    feed_from(registry, 0)
    log: list[str] = []
    tick = collect(data, now=AS_OF, log=log.append, clients=registry.client)
    assert tick.manifest is not None
    assert not any(line.startswith("sandbox") for line in log)
    assert not (data.run_dir(tick.manifest.run_id) / "sandbox.jsonl").exists()

    results = tmp_path / "pa-results"
    results.mkdir()
    feed_from(registry, 200)
    log.clear()
    later = collect(
        data,
        now=AS_OF + timedelta(hours=1),
        log=log.append,
        clients=registry.client,
        sandbox_results=results,
    )
    assert later.manifest is not None and later.failed == ()
    (line,) = [line for line in log if line.startswith("sandbox")]
    # The mock serves no tarballs: the reported version can't be inspected, nothing exported.
    assert line.startswith(f"sandbox {later.manifest.run_id}: 0 of "), line
    assert "export: 0 jobs in " in line
    assert (data.run_dir(later.manifest.run_id) / "sandbox.jsonl").exists()
