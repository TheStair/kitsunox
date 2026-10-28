"""End-to-end Stage 0 record/replay against a mocked npm registry."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from conftest import AS_OF, Router, save_watchlist
from kitsunox.core.run import (
    CHAIN_OVERLAP,
    MAX_CHAIN_GAP,
    Checkpoint,
    DataDir,
    DataDirBusyError,
    IngestDegradedError,
    IngestRequest,
    PopularityMode,
    RunManifest,
    WatchlistMissingError,
    changes_digest,
    record_ingest,
    replay_ingest,
)
from kitsunox.ecosystems.npm.registry import (
    FEED_PAGE_LIMIT,
    REGISTRY_URL,
    REPLICATE_URL,
    NpmEcosystem,
)
from kitsunox.stages.ingest import RetryItem, read_changes

NONE = PopularityMode.NONE


def record(
    data: DataDir, registry: Router, popularity: PopularityMode = PopularityMode.WATCHLIST
) -> RunManifest:
    request = IngestRequest(
        as_of=AS_OF, window_hours=12, since=100, until=200, popularity=popularity
    )
    return record_ingest(data, NpmEcosystem, request, client=registry.client())


def test_record_then_replay_is_identical_api_mode(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    manifest = record(data, registry, PopularityMode.API)

    assert manifest.run_id == "20261027T120000Z-npm"
    assert manifest.packages_seen == 2
    assert manifest.change_count == 4  # kx-fixture versions in the window; "gone" is a 404
    # Fixture packument was last modified at 12:00, after the 00:00 window start.
    assert manifest.feed_start_estimate == datetime(2026, 10, 27, 12, tzinfo=UTC)
    assert manifest.window_covered is False
    run_dir = data.run_dir(manifest.run_id)
    changes = read_changes(run_dir / "changes.jsonl")
    assert {c.popularity.downloads for c in changes if c.popularity} == {1234}
    assert {p.name for p in run_dir.iterdir()} == {
        "manifest.json",
        "snapshot.json",
        "changes.jsonl",
        "skipped.jsonl",
    }

    requests_before = len(registry.requests)
    replayed = replay_ingest(data, NpmEcosystem, manifest.run_id)
    assert len(registry.requests) == requests_before  # replay never touches the network
    assert changes_digest(replayed) == manifest.changes_sha256


def test_watchlist_mode_records_provenance_and_replays(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    save_watchlist(data, datetime(2026, 10, 20, tzinfo=UTC))
    newest = save_watchlist(data, datetime(2026, 10, 26, tzinfo=UTC))
    save_watchlist(data, datetime(2026, 10, 28, tzinfo=UTC))  # after as_of: must not be used
    manifest = record(data, registry)

    assert manifest.popularity_mode is PopularityMode.WATCHLIST
    assert manifest.watchlist_id == newest
    assert manifest.watchlist_sha256 == data.watchlists.sha256("npm", newest)
    assert not any("api.npmjs.org" in r for r in registry.requests)
    changes = read_changes(data.run_dir(manifest.run_id) / "changes.jsonl")
    assert all(c.popularity and c.popularity.watched for c in changes if not c.is_new_package)
    assert changes_digest(replay_ingest(data, NpmEcosystem, manifest.run_id)) == (
        manifest.changes_sha256
    )

    data.watchlists.path("npm", newest).write_text("{}")  # tampered after the run
    with pytest.raises(ValueError, match="changed since it was recorded"):
        replay_ingest(data, NpmEcosystem, manifest.run_id)


def test_watchlist_mode_without_watchlist_fails_early(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    with pytest.raises(WatchlistMissingError):
        record(data, registry)
    assert not (tmp_path / "runs").exists()


def test_explicit_range_does_not_move_checkpoint(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    record(data, registry, NONE)
    assert data.read_checkpoint("npm") is None


def test_default_range_uses_lookback_then_checkpoint(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    first = record_ingest(
        data,
        NpmEcosystem,
        IngestRequest(as_of=AS_OF, lookback=100, popularity=NONE),
        client=registry.client(),
    )
    assert (first.cursor_since, first.cursor_until) == (100, 200)
    checkpoint = data.read_checkpoint("npm")
    assert checkpoint is not None and checkpoint.cursor == 200

    registry.add_json(
        f"{REPLICATE_URL}/_changes?since=200&limit={FEED_PAGE_LIMIT}", {"results": []}
    )
    second = record_ingest(
        data,
        NpmEcosystem,
        IngestRequest(as_of=AS_OF.replace(hour=13), popularity=NONE),
        client=registry.client(),
    )
    assert second.cursor_since == 200


def test_existing_run_is_not_overwritten(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    record(data, registry, NONE)
    with pytest.raises(FileExistsError):
        record(data, registry, NONE)


def default_run(
    data: DataDir, registry: Router, as_of: datetime, *, chain: bool = False
) -> RunManifest:
    request = IngestRequest(as_of=as_of, lookback=100, popularity=NONE, chain=chain)
    return record_ingest(data, NpmEcosystem, request, client=registry.client())


def test_chained_run_continues_where_the_previous_ended(tmp_path: Path, registry: Router) -> None:
    registry.add_json(
        f"{REPLICATE_URL}/_changes?since=200&limit={FEED_PAGE_LIMIT}", {"results": []}
    )
    data = DataDir(tmp_path)
    first = default_run(data, registry, AS_OF)
    assert first.chained_from is None  # no checkpoint yet: plain 24h window
    second = default_run(data, registry, AS_OF + timedelta(hours=1), chain=True)
    assert second.chained_from == first.run_id
    assert second.cursor_since == first.cursor_until
    assert second.window.start == AS_OF - CHAIN_OVERLAP
    assert second.window_covered is True
    checkpoint = data.read_checkpoint("npm")
    assert checkpoint == Checkpoint(cursor=200, run_id=second.run_id, as_of=second.as_of)


@pytest.mark.parametrize(
    "checkpoint",
    [
        Checkpoint(cursor=200),  # written before chaining existed
        Checkpoint(cursor=200, run_id="old", as_of=AS_OF - MAX_CHAIN_GAP - timedelta(hours=2)),
    ],
)
def test_chain_falls_back_without_a_usable_checkpoint(
    tmp_path: Path, registry: Router, checkpoint: Checkpoint
) -> None:
    registry.add_json(
        f"{REPLICATE_URL}/_changes?since=200&limit={FEED_PAGE_LIMIT}", {"results": []}
    )
    data = DataDir(tmp_path)
    data.write_checkpoint("npm", checkpoint)
    manifest = default_run(data, registry, AS_OF, chain=True)
    assert manifest.chained_from is None
    assert manifest.window.start == AS_OF - timedelta(hours=24)


def test_data_dir_lock_is_exclusive(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    with data.lock(), pytest.raises(DataDirBusyError), data.lock():
        pass
    with data.lock():  # released again
        pass


def test_network_skips_are_retried_by_the_next_run(tmp_path: Path, registry: Router) -> None:
    registry.add_json(
        f"{REPLICATE_URL}/_changes?since=200&limit={FEED_PAGE_LIMIT}", {"results": []}
    )
    data = DataDir(tmp_path)
    registry.offline.add(f"{REGISTRY_URL}/kx-fixture")
    first = default_run(data, registry, AS_OF)
    assert first.change_count == 0 and first.transient_skipped == 1
    checkpoint = data.read_checkpoint("npm")
    assert checkpoint is not None
    assert checkpoint.retry == (
        RetryItem(name="kx-fixture", cursor=150, window_start=first.window.start),
    )

    registry.offline.clear()  # back online; the feed has nothing new
    second = default_run(data, registry, AS_OF + timedelta(hours=1), chain=True)
    assert second.retried == checkpoint.retry
    assert second.change_count > 0  # found over the first run's window
    assert data.read_checkpoint("npm") == Checkpoint(
        cursor=200, run_id=second.run_id, as_of=second.as_of
    )
    replayed = replay_ingest(data, NpmEcosystem, second.run_id)
    assert changes_digest(replayed) == second.changes_sha256


def test_stale_retries_expire(tmp_path: Path, registry: Router) -> None:
    registry.add_json(
        f"{REPLICATE_URL}/_changes?since=200&limit={FEED_PAGE_LIMIT}", {"results": []}
    )
    data = DataDir(tmp_path)
    old = RetryItem(name="kx-fixture", cursor=150, window_start=AS_OF - MAX_CHAIN_GAP * 2)
    data.write_checkpoint("npm", Checkpoint(cursor=200, run_id="r", as_of=AS_OF, retry=(old,)))
    manifest = default_run(data, registry, AS_OF + timedelta(hours=1), chain=True)
    assert manifest.retried == ()


def test_an_outage_writes_nothing(
    tmp_path: Path, registry: Router, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("kitsunox.core.run.MIN_PACKAGES_FOR_DEGRADED", 1)
    data = DataDir(tmp_path)
    registry.offline.add(f"{REGISTRY_URL}/kx-fixture")  # 1 of 2 packages: over 20%
    with pytest.raises(IngestDegradedError, match="1 of 2 packages"):
        default_run(data, registry, AS_OF)
    assert data.read_checkpoint("npm") is None
    assert not (tmp_path / "runs").exists() or not any((tmp_path / "runs").iterdir())
