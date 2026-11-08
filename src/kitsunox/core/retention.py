"""Retention: keep what evaluation needs, drop what only replay needs.

A day of runs stores ~5.5 GB of packument bodies (zstd) and ~0.8 GB of `changes.jsonl`. Replay
needs the bodies; prospective labeling only needs the Change records, plus the raw packument of
anything that turns out to be malicious. So for each run older than `keep_days`:

1. **Pin** the packument blobs of packages that appear in the newest label set (any OSV record
   for that name), and the tarballs Stage 2 fetched for them (`static-snapshot.json`). These are
   what a later analysis of a malicious sample needs: npm deletes malicious tarballs.
2. Write `retention.json` with the pinned snapshot entries. The run can no longer be replayed
   (`replay_ingest` refuses it with a clear message), but `snapshot.json` stays as a record of
   what was fetched.
3. **Compress** `changes.jsonl` to `changes.jsonl.zst` (about 10x smaller).

Then **collect garbage**: delete every immutable-index entry and every blob that no unpruned
run's snapshots and no pruned run's pinned set reference. Repository archives (Stage 4, ~30 GB
a day) can have a shorter life: with `keep_archive_days`, a run older than that stops
referencing the snapshot entries `is_archive` picks, so Stage 4 of that run can't be replayed
from cache any more (its archives are fetched again if needed). The immutable index is only a
cross-run fetch cache (every hit is also recorded in the fetching run's snapshot), so it must not
keep tarballs alive by itself: at ~14 GB of tarballs a day it would fill the disk. Callers must
hold `DataDir.lock()`: a run that is still recording has blobs no snapshot references yet.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Callable, Collection
from compression import zstd
from datetime import datetime, timedelta
from pathlib import Path
from typing import Final

from kitsunox.core.models import Persisted, Record
from kitsunox.core.run import STAGE_SNAPSHOTS, DataDir, RunManifest
from kitsunox.stages.ingest import changes_file, iter_changes
from kitsunox.util.files import sync_file
from kitsunox.util.http import Snapshot, SnapshotEntry

COMPRESS_CHUNK: Final = 1 << 20


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
    keep_archive_days: int | None = None,
    is_archive: Callable[[str], bool] | None = None,
) -> PruneReport:
    """Prune runs older than `keep_days`, then delete unreferenced blobs. `metadata_url` maps a
    package name to the URL its metadata was fetched from (ecosystem-specific). Fetches that
    `is_archive` picks are kept only `keep_archive_days`."""
    cutoff = now - timedelta(days=keep_days)
    runs_root = data.root / "runs"
    run_dirs = sorted(p for p in runs_root.iterdir() if p.is_dir()) if runs_root.exists() else []
    archive_cutoff = now - timedelta(days=keep_archive_days or keep_days)
    pruned: list[str] = []
    expired: set[Path] = set()  # runs whose repository archives may go
    pinned = 0
    for run_dir in run_dirs:
        manifest = RunManifest.load_json((run_dir / "manifest.json").read_bytes())
        if is_archive is not None and manifest.as_of < archive_cutoff:
            expired.add(run_dir)
        if manifest.as_of >= cutoff or (run_dir / "retention.json").exists():
            continue
        pinned += _prune_run(run_dir, now, keep_days, pinned_names, metadata_url)
        pruned.append(manifest.run_id)
    deleted, freed = _collect_garbage(data, run_dirs, expired, is_archive)
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
    # marker, only the .zst exists, and the retry must still pin from it. One streamed pass:
    # a whole run as objects is ~32 KB a change (~13 GB for the 4-day catch-up of 405k).
    plain = run_dir / "changes.jsonl"
    urls: set[str] = set()
    for change in iter_changes(changes_file(run_dir)):
        if change.new.ref.name in pinned_names:
            urls.add(metadata_url(change.new.ref.name))
            urls.update(
                snap.artifact.url
                for snap in (change.new, change.previous)
                if snap is not None and snap.artifact is not None
            )
    entries = dict(Snapshot.load(run_dir / "snapshot.json").entries)
    for name in STAGE_SNAPSHOTS:
        if (run_dir / name).exists():
            entries |= Snapshot.load(run_dir / name).entries
    retained = {k: e for k, e in sorted(entries.items()) if e.url in urls}
    marker = RetentionMarker(pruned_at=now, keep_days=keep_days, retained=retained)
    if plain.exists():
        packed = run_dir / "changes.jsonl.zst"
        tmp = packed.with_suffix(".zst.tmp")
        _compress(plain, tmp)
        sync_file(tmp)  # before the rename, and before `plain` goes
        os.replace(tmp, packed)
        plain.unlink()
    # Written last: a crash before this point leaves the run unpruned, so it is retried.
    (run_dir / "retention.json").write_text(marker.model_dump_json(indent=2) + "\n")
    return len(retained)


def _compress(source: Path, target: Path) -> None:
    """zstd level 9, streamed in `COMPRESS_CHUNK` pieces. The frames can differ from a one-shot
    `zstd.compress`; nothing hashes them, and the decompressed bytes are the same."""
    with source.open("rb") as plain, zstd.open(target, "wb", level=9) as packed:
        shutil.copyfileobj(plain, packed, COMPRESS_CHUNK)


def _collect_garbage(
    data: DataDir,
    run_dirs: list[Path],
    expired: Collection[Path],
    is_archive: Callable[[str], bool] | None,
) -> tuple[int, int]:
    referenced: set[str] = set()
    for run_dir in run_dirs:
        marker_path = run_dir / "retention.json"
        if marker_path.exists():
            marker = RetentionMarker.load_json(marker_path.read_bytes())
            referenced.update(e.sha256 for e in marker.retained.values())
        else:
            # A snapshot that fails to load raises here, before anything is deleted.
            for name in ("snapshot.json", *STAGE_SNAPSHOTS):
                if name == "snapshot.json" or (run_dir / name).exists():
                    snapshot = Snapshot.load(run_dir / name)
                    referenced.update(
                        e.sha256
                        for e in snapshot.entries.values()
                        if not (run_dir in expired and is_archive and is_archive(e.url))
                    )
    if data.immutable_index.exists():
        # Index entries go first: a crash then leaves an orphan blob (collected next time),
        # never an index entry pointing at a deleted blob.
        for path in data.immutable_index.rglob("*.json"):
            try:
                sha = SnapshotEntry.model_validate_json(path.read_bytes()).sha256
            except ValueError:
                sha = None  # damaged: fetching treats it as a miss, so it can go
            if sha not in referenced:
                path.unlink()

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
