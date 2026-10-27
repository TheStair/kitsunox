"""End-to-end Stage 0 record/replay against a mocked npm registry."""

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

from conftest import Router
from kitsunox.core.run import (
    DataDir,
    IngestRequest,
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

AS_OF = datetime(2026, 10, 27, 12, tzinfo=UTC)


@pytest.fixture
def registry(router: Router, load_fixture: Callable[[str], object]) -> Router:
    router.add_json(f"{REPLICATE_URL}/", {"update_seq": 200})
    router.add_json(
        f"{REPLICATE_URL}/_changes?since=100&limit={FEED_PAGE_LIMIT}",
        {"results": [{"seq": 150, "id": "kx-fixture"}, {"seq": 160, "id": "gone"}]},
    )
    router.add_json(f"{REPLICATE_URL}/_changes?since=160&limit={FEED_PAGE_LIMIT}", {"results": []})
    router.add_json(f"{REGISTRY_URL}/kx-fixture", load_fixture("npm/packument_basic.json"))
    return router


def test_record_then_replay_is_identical(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    request = IngestRequest(as_of=AS_OF, window_hours=12, since=100, until=200)
    manifest = record_ingest(data, NpmEcosystem, request, client=registry.client())

    assert manifest.run_id == "20261027T120000Z-npm"
    assert manifest.packages_seen == 2
    assert manifest.change_count == 4  # kx-fixture versions in the window; "gone" is a 404
    run_dir = data.run_dir(manifest.run_id)
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


def test_explicit_range_does_not_move_checkpoint(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    request = IngestRequest(as_of=AS_OF, since=100, until=200)
    record_ingest(data, NpmEcosystem, request, client=registry.client())
    assert data.read_checkpoint("npm") is None


def test_default_range_uses_lookback_then_checkpoint(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    first = record_ingest(
        data, NpmEcosystem, IngestRequest(as_of=AS_OF, lookback=100), client=registry.client()
    )
    assert (first.cursor_since, first.cursor_until) == (100, 200)
    assert data.read_checkpoint("npm") == 200

    registry.add_json(
        f"{REPLICATE_URL}/_changes?since=200&limit={FEED_PAGE_LIMIT}", {"results": []}
    )
    second = record_ingest(
        data,
        NpmEcosystem,
        IngestRequest(as_of=AS_OF.replace(hour=13)),
        client=registry.client(),
    )
    assert second.cursor_since == 200


def test_existing_run_is_not_overwritten(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    request = IngestRequest(as_of=AS_OF, since=100, until=200)
    record_ingest(data, NpmEcosystem, request, client=registry.client())
    with pytest.raises(FileExistsError):
        record_ingest(data, NpmEcosystem, request, client=registry.client())
