"""Retention: prune old runs, pin packuments of labeled packages, collect unreferenced blobs."""

from compression import zstd
from datetime import timedelta
from pathlib import Path

import pytest

from conftest import AS_OF, Router
from kitsunox.core import retention
from kitsunox.core.retention import PruneReport, RetentionMarker, prune
from kitsunox.core.run import (
    CORRELATE_SNAPSHOT,
    SANDBOX_SNAPSHOT,
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
from kitsunox.githost.github import is_archive_url
from kitsunox.stages import ingest
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


def test_prune_streams_changes_and_the_compressed_file_round_trips(
    tmp_path: Path, registry: Router, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Pruning the 4-day catch-up (405k changes, 2.9 GB) with every Change in memory and a
    # one-shot compress would take ~16 GB: the prune reads changes one at a time and
    # compresses in chunks (two of them here, so chunk boundaries are crossed).
    data = DataDir(tmp_path)
    manifest = run(data, registry)
    run_dir = data.run_dir(manifest.run_id)
    plain = (run_dir / "changes.jsonl").read_bytes()
    assert len(plain) > 1

    def whole_run(path: Path) -> object:
        raise AssertionError(f"prune loaded the whole run {path}")

    monkeypatch.setattr(ingest, "read_changes", whole_run)
    monkeypatch.setattr(retention, "COMPRESS_CHUNK", len(plain) // 2 + 1)
    synced: list[Path] = []
    monkeypatch.setattr(retention, "sync_file", synced.append)

    report = prune_at(data, 8, {"kx-fixture"})
    assert report.runs_pruned == (manifest.run_id,) and report.blobs_pinned == 1
    packed = run_dir / "changes.jsonl.zst"
    assert not (run_dir / "changes.jsonl").exists()
    assert not packed.with_suffix(".zst.tmp").exists()
    assert synced == [packed.with_suffix(".zst.tmp")]  # synced before the rename
    assert zstd.decompress(packed.read_bytes()) == plain


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


def test_stage4_fetches_are_kept_with_the_run_and_damaged_index_entries_go(
    tmp_path: Path, registry: Router
) -> None:
    data = DataDir(tmp_path)
    manifest = run(data, registry)
    run_dir = data.run_dir(manifest.run_id)
    snapshot = Snapshot()
    fetcher = HttpFetcher(
        store=data.blobs,
        snapshot=snapshot,
        mode=FetchMode.RECORD,
        immutable_index=data.immutable_index,
        client=registry.client(),
    )
    archive = "https://codeload.github.com/o/r/tar.gz/" + "a" * 40
    registry.add_bytes(archive, b"repo archive")
    fetcher.get(archive, immutable=True)
    fetcher.close()
    snapshot.save(run_dir / CORRELATE_SNAPSHOT)
    damaged = data.immutable_index / "zz" / "damaged.json"
    damaged.parent.mkdir(parents=True)
    damaged.write_bytes(b"\x17\x03\x03 not json")
    prune_at(data, 1, set())
    assert snapshot.entries
    assert all(data.blobs.get(e.sha256) for e in snapshot.entries.values())
    assert not damaged.exists()


def test_stage5_bundle_fetches_are_kept_with_the_run(tmp_path: Path, registry: Router) -> None:
    # A bundle is rebuilt from these on replay: losing them makes the recorded key unreproducible.
    data = DataDir(tmp_path)
    manifest = run(data, registry)
    snapshot = Snapshot()
    fetcher = HttpFetcher(
        store=data.blobs, snapshot=snapshot, mode=FetchMode.RECORD, client=registry.client()
    )
    dependency = "https://registry.npmjs.org/dep/-/dep-1.0.0.tgz"
    registry.add_bytes(dependency, b"dependency tarball")
    fetcher.get(dependency)
    fetcher.close()
    snapshot.save(data.run_dir(manifest.run_id) / SANDBOX_SNAPSHOT)
    prune_at(data, 1, set())
    assert snapshot.entries
    assert all(data.blobs.get(e.sha256) for e in snapshot.entries.values())


def test_repository_archives_can_go_before_the_run(tmp_path: Path, registry: Router) -> None:
    data = DataDir(tmp_path)
    manifest = run(data, registry)
    snapshot = Snapshot()
    fetcher = HttpFetcher(
        store=data.blobs,
        snapshot=snapshot,
        mode=FetchMode.RECORD,
        immutable_index=data.immutable_index,
        client=registry.client(),
    )
    archive = "https://codeload.github.com/o/r/tar.gz/" + "a" * 40
    refs = "https://github.com/o/r.git/info/refs?service=git-upload-pack"
    registry.add_bytes(archive, b"repo archive")
    registry.add_bytes(refs, b"0000")
    fetcher.get(archive, immutable=True)
    fetcher.get(refs)
    fetcher.close()
    snapshot.save(data.run_dir(manifest.run_id) / CORRELATE_SNAPSHOT)
    entries = snapshot.entries.values()

    def prune_archives(days: int) -> None:
        prune(
            data,
            now=AS_OF + timedelta(days=days),
            keep_days=7,
            pinned_names=set(),
            metadata_url=packument_url,
            keep_archive_days=2,
            is_archive=is_archive_url,
        )

    prune_archives(1)
    assert all(data.blobs.exists(e.sha256) for e in entries)
    prune_archives(3)  # the run is kept; its archive isn't
    assert {e.url: data.blobs.exists(e.sha256) for e in entries} == {archive: False, refs: True}
    assert not list(data.immutable_index.rglob("*.json"))
    assert (data.run_dir(manifest.run_id) / "changes.jsonl").exists()  # not pruned
