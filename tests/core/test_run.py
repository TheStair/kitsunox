"""End-to-end Stage 0 record/replay against a mocked npm registry."""

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

from conftest import Router
from kitsunox.core.run import (
    DataDir,
    IngestRequest,
    PopularityMode,
    RunManifest,
    WatchlistMissingError,
    changes_digest,
    record_ingest,
    replay_ingest,
)
from kitsunox.core.watchlist import WatchEntry, Watchlist
from kitsunox.ecosystems.npm.registry import (
    DOWNLOADS_URL,
    FEED_PAGE_LIMIT,
    REGISTRY_URL,
    REPLICATE_URL,
    NpmEcosystem,
)
from kitsunox.stages.ingest import read_changes

AS_OF = datetime(2026, 10, 27, 12, tzinfo=UTC)
NONE = PopularityMode.NONE


@pytest.fixture
def registry(router: Router, load_fixture: Callable[[str], object]) -> Router:
    router.add_json(f"{REPLICATE_URL}/", {"update_seq": 200})
    router.add_json(
        f"{REPLICATE_URL}/_changes?since=100&limit={FEED_PAGE_LIMIT}",
        {"results": [{"seq": 150, "id": "kx-fixture"}, {"seq": 160, "id": "gone"}]},
    )
    router.add_json(f"{REPLICATE_URL}/_changes?since=160&limit={FEED_PAGE_LIMIT}", {"results": []})
    router.add_json(f"{REGISTRY_URL}/kx-fixture", load_fixture("npm/packument_basic.json"))
    router.add_json(
        f"{DOWNLOADS_URL}/2026-10-19:2026-10-25/kx-fixture",
        {"downloads": 1234, "package": "kx-fixture"},
    )
    return router


def save_watchlist(data: DataDir, built_at: datetime) -> str:
    watchlist = Watchlist(
        ecosystem="npm",
        source="test",
        built_at=built_at,
        min_monthly_downloads=43_000,
        entries={"kx-fixture": WatchEntry(monthly_downloads=99_000)},
    )
    data.watchlists.save(watchlist.ecosystem, watchlist.id, watchlist)
    return watchlist.id


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
    assert data.read_checkpoint("npm") == 200

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
