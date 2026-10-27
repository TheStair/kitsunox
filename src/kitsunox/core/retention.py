"""Retention: keep what evaluation needs, drop what only replay needs.

A day of runs stores ~5.5 GB of packument bodies (zstd) and ~0.8 GB of `changes.jsonl`. Replay
needs the bodies; prospective labeling only needs the Change records, plus the raw packument of
anything that turns out to be malicious. So for each run older than `keep_days`:

1. **Pin** the packument blobs of packages that appear in the newest label set (any OSV record
   for that name). These are the bodies a later analysis of a malicious sample needs.
2. Write `retention.json` with the pinned snapshot entries. The run can no longer be replayed
   (`replay_ingest` refuses it with a clear message), but `snapshot.json` stays as a record of
   what was fetched.
3. **Compress** `changes.jsonl` to `changes.jsonl.zst` (about 10x smaller).

Then **collect garbage**: delete every blob that no unpruned run's snapshot, no pruned run's
pinned set, and no immutable-index entry references. Callers must hold `DataDir.lock()`: a run
that is still recording has blobs no snapshot references yet.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Collection
from compression import zstd
from datetime import datetime, timedelta
from pathlib import Path

from kitsunox.core.models import Persisted, Record
from kitsunox.core.run import DataDir, RunManifest
from kitsunox.stages.ingest import changes_file, read_changes
from kitsunox.util.http import Snapshot, SnapshotEntry


class RetentionMarker(Persisted):
    pruned_at: datetime
    keep_days: int
    retained: dict[str, SnapshotEntry]


class PruneReport(Record):
    runs_pruned: tuple[str, ...]
    blobs_pinned: int
    blobs_deleted: int
    bytes_freed: int


def prune(
    data: DataDir,
    *,
    now: datetime,
    keep_days: int,
    pinned_names: Collection[str],
    metadata_url: Callable[[str], str],
) -> PruneReport:
    """Prune runs older than `keep_days`, then delete unreferenced blobs. `metadata_url` maps a
    package name to the URL its metadata was fetched from (ecosystem-specific)."""
    cutoff = now - timedelta(days=keep_days)
    runs_root = data.root / "runs"
    run_dirs = sorted(p for p in runs_root.iterdir() if p.is_dir()) if runs_root.exists() else []
    pruned: list[str] = []
    pinned = 0
    for run_dir in run_dirs:
        manifest = RunManifest.load_json((run_dir / "manifest.json").read_bytes())
        if manifest.as_of >= cutoff or (run_dir / "retention.json").exists():
            continue
        pinned += _prune_run(run_dir, now, keep_days, pinned_names, metadata_url)
        pruned.append(manifest.run_id)
    deleted, freed = _collect_garbage(data, run_dirs)
    return PruneReport(
        runs_pruned=tuple(pruned), blobs_pinned=pinned, blobs_deleted=deleted, bytes_freed=freed
    )


def _prune_run(
    run_dir: Path,
    now: datetime,
    keep_days: int,
    pinned_names: Collection[str],
    metadata_url: Callable[[str], str],
) -> int:
    # changes_file, not changes.jsonl: after a crash between compressing and writing the
    # marker, only the .zst exists, and the retry must still pin from it.
    names = {c.new.ref.name for c in read_changes(changes_file(run_dir))}
    plain = run_dir / "changes.jsonl"
    urls = {metadata_url(name) for name in names if name in pinned_names}
    snapshot = Snapshot.load(run_dir / "snapshot.json")
    retained = {k: e for k, e in sorted(snapshot.entries.items()) if e.url in urls}
    marker = RetentionMarker(pruned_at=now, keep_days=keep_days, retained=retained)
    if plain.exists():
        packed = run_dir / "changes.jsonl.zst"
        tmp = packed.with_suffix(".zst.tmp")
        tmp.write_bytes(zstd.compress(plain.read_bytes(), level=9))
        os.replace(tmp, packed)
        plain.unlink()
    # Written last: a crash before this point leaves the run unpruned, so it is retried.
    (run_dir / "retention.json").write_text(marker.model_dump_json(indent=2) + "\n")
    return len(retained)


def _collect_garbage(data: DataDir, run_dirs: list[Path]) -> tuple[int, int]:
    referenced: set[str] = set()
    for run_dir in run_dirs:
        marker_path = run_dir / "retention.json"
        if marker_path.exists():
            marker = RetentionMarker.load_json(marker_path.read_bytes())
            referenced.update(e.sha256 for e in marker.retained.values())
        else:
            # A snapshot that fails to load raises here, before anything is deleted.
            snapshot = Snapshot.load(run_dir / "snapshot.json")
            referenced.update(e.sha256 for e in snapshot.entries.values())
    if data.immutable_index.exists():
        for path in data.immutable_index.rglob("*.json"):
            referenced.add(SnapshotEntry.model_validate_json(path.read_bytes()).sha256)

    deleted = freed = 0
    blob_root = data.root / "blobs"
    if not blob_root.exists():
        return 0, 0
    for path in blob_root.glob("??/*.zst"):
        if path.name.removesuffix(".zst") not in referenced:
            freed += path.stat().st_size
            path.unlink()
            deleted += 1
    return deleted, freed
