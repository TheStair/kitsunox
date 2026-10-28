"""Retention: prune old runs, pin packuments of labeled packages, collect unreferenced blobs."""

from datetime import timedelta
from pathlib import Path

import pytest

from conftest import AS_OF, Router
from kitsunox.core.retention import PruneReport, RetentionMarker, prune
from kitsunox.core.run import (
    STATIC_SNAPSHOT,
    DataDir,
    IngestRequest,
    PopularityMode,
    RunManifest,
    RunPrunedError,
    record_ingest,
    replay_ingest,
)
from kitsunox.ecosystems.npm.registry import REGISTRY_URL, NpmEcosystem, packument_url
from kitsunox.stages.ingest import changes_file, read_changes
from kitsunox.util.http import FetchMode, HttpFetcher, Snapshot, SnapshotEntry


def run(data: DataDir, registry: Router) -> RunManifest:
    request = IngestRequest(as_of=AS_OF, since=100, until=200, popularity=PopularityMode.NONE)
    return record_ingest(data, NpmEcosystem, request, client=registry.client())


def blob_count(data: DataDir) -> int:
    return len(list((data.root / "blobs").glob("??/*.zst")))


def prune_at(data: DataDir, days: int, pinned: set[str]) -> PruneReport:
    return prune(
        data,
        now=AS_OF + timedelta(days=days),
        keep_days=7,
        pinned_names=pinned,
        metadata_url=packument_url,
    )


def test_recent_runs_are_untouched(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    run(data, registry)
    before = blob_count(data)
    report = prune_at(data, 1, set())
    assert report.runs_pruned == () and report.blobs_deleted == 0
    assert blob_count(data) == before


def test_old_run_keeps_labeled_packuments_and_changes(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    manifest = run(data, registry)
    run_dir = data.run_dir(manifest.run_id)
    changes_before = read_changes(run_dir / "changes.jsonl")

    report = prune_at(data, 8, {"kx-fixture", "unrelated"})
    assert report.runs_pruned == (manifest.run_id,)
    assert report.blobs_pinned == 1
    assert report.blobs_deleted > 0

    marker = RetentionMarker.load_json((run_dir / "retention.json").read_bytes())
    (entry,) = marker.retained.values()
    assert entry.url == f"{REGISTRY_URL}/kx-fixture"
    assert data.blobs.get(entry.sha256)  # still readable and verified
    assert blob_count(data) == 1
    assert changes_file(run_dir).suffix == ".zst"
    assert read_changes(changes_file(run_dir)) == changes_before
    with pytest.raises(RunPrunedError):
        replay_ingest(data, NpmEcosystem, manifest.run_id)

    again = prune_at(data, 9, {"kx-fixture"})
    assert again.runs_pruned == () and again.blobs_deleted == 0


def test_unlabeled_run_keeps_no_blobs(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    run(data, registry)
    prune_at(data, 8, set())
    assert blob_count(data) == 0


def test_crash_after_compressing_still_pins(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    manifest = run(data, registry)
    run_dir = data.run_dir(manifest.run_id)
    prune_at(data, 8, {"kx-fixture"})
    (run_dir / "retention.json").unlink()  # as if the process died before writing it
    report = prune_at(data, 8, {"kx-fixture"})
    assert report.blobs_pinned == 1 and blob_count(data) == 1


def fetch_tarballs(data: DataDir, run_dir: Path, router: Router) -> list[str]:
    """What Stage 2 leaves behind: tarballs in the blob store and immutable index, recorded in
    the run's static snapshot."""
    urls = sorted(
        {
            snap.artifact.url
            for c in read_changes(changes_file(run_dir))
            for snap in (c.new, c.previous)
            if snap is not None and snap.artifact is not None
        }
    )
    snapshot = Snapshot()
    fetcher = HttpFetcher(
        store=data.blobs,
        snapshot=snapshot,
        mode=FetchMode.RECORD,
        immutable_index=data.immutable_index,
        client=router.client(),
    )
    for url in urls:
        router.add_bytes(url, f"tarball {url}".encode())
        fetcher.get(url, immutable=True)
    fetcher.close()
    snapshot.save(run_dir / STATIC_SNAPSHOT)
    return urls


def index_count(data: DataDir) -> int:
    return len(list(data.immutable_index.rglob("*.json")))


@pytest.mark.parametrize("labeled", [True, False])
def test_tarballs_follow_retention(tmp_path: Path, registry: Router, labeled: bool) -> None:
    data = DataDir(tmp_path)
    manifest = run(data, registry)
    urls = fetch_tarballs(data, data.run_dir(manifest.run_id), registry)
    assert urls and index_count(data) >= len(urls)

    prune_at(data, 1, set())  # recent: the immutable index entries stay
    assert index_count(data) >= len(urls)

    report = prune_at(data, 8, {"kx-fixture"} if labeled else set())
    marker = RetentionMarker.load_json(
        (data.run_dir(manifest.run_id) / "retention.json").read_bytes()
    )
    kept = {e.url for e in marker.retained.values()}
    if labeled:
        assert set(urls) <= kept and report.blobs_pinned == 1 + len(urls)
        assert all(data.blobs.get(e.sha256) for e in marker.retained.values())
    else:
        assert kept == set() and blob_count(data) == 0
    # The index is a fetch cache only: it keeps no blob alive by itself, and every entry left
    # points at a blob that still exists.
    assert index_count(data) == (len(urls) if labeled else 0)
    for path in data.immutable_index.rglob("*.json"):
        assert data.blobs.get(SnapshotEntry.model_validate_json(path.read_bytes()).sha256)
