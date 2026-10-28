"""`kitsunox collect`: one unattended tick against a mocked registry."""

from datetime import timedelta
from pathlib import Path

from conftest import AS_OF, Router, save_watchlist
from kitsunox.collect import collect
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

    first = collect(data, now=AS_OF, log=log.append, clients=registry.client)
    assert first is not None
    assert first.chained_from is None and first.change_count == 4
    assert not any(line.startswith(("watchlist", "labels")) for line in log)  # both fresh
    assert any(line.startswith("prune: 0 runs pruned") for line in log)
    # Stages 1 and 2 ran on the new run; the mock serves no tarballs, so Stage 2 has no files.
    stages = next(line for line in log if line.startswith("stages: "))
    assert stages.startswith("stages: 4 triaged"), stages
    assert (data.run_dir(first.run_id) / "static.jsonl").exists()
    assert (data.run_dir(first.run_id) / "ast.jsonl").exists()

    log.clear()
    second = collect(data, now=AS_OF + timedelta(hours=1), log=log.append, clients=registry.client)
    assert second is not None
    assert second.chained_from == first.run_id
    assert not any(line.startswith("prune") for line in log)  # pruned an hour ago


def test_failed_refresh_is_logged_and_ingest_still_runs(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    save_watchlist(data, AS_OF - timedelta(hours=1))
    feed_from(registry, 0)
    log: list[str] = []
    manifest = collect(data, now=AS_OF, log=log.append, clients=registry.client)
    assert manifest is not None and manifest.change_count == 4
    assert any(line.startswith("labels: FAILED") for line in log)  # OSV export is a 404 here
    assert "prune: skipped: no label set to decide which packuments to keep" in log


def test_offline_tick_writes_nothing(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    save_watchlist(data, AS_OF - timedelta(hours=1))
    save_labels(data)
    registry.offline.add(f"{REPLICATE_URL}/")
    log: list[str] = []
    assert collect(data, now=AS_OF, log=log.append, clients=registry.client) is None
    assert any(line.startswith("ingest: OFFLINE") for line in log)
    assert data.read_checkpoint("npm") is None


def test_unfinished_stages_are_caught_up(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    save_watchlist(data, AS_OF - timedelta(hours=1))
    save_labels(data)
    feed_from(registry, 0)
    feed_from(registry, 200)
    ignored: list[str] = []
    first = collect(data, now=AS_OF, log=ignored.append, clients=registry.client)
    assert first is not None
    (data.run_dir(first.run_id) / "static.jsonl").unlink()  # as if Stage 2 had crashed

    log: list[str] = []
    collect(data, now=AS_OF + timedelta(hours=1), log=log.append, clients=registry.client)
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
