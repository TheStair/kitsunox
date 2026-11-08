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

**The label hold** (decision 0019). Pins are decided once, from the label set of prune time, so
a version labeled after its run was pruned had lost its tarball (51 of 139 in window A). The
hold, `data/eval/live/hold.json`, keeps blobs for `HOLD_DAYS` past their run whatever the
labels say: every captured tarball of at most `HOLD_SMALL_BYTES` (`small_tarballs`), and what
live evaluation asks for (reported versions and their diff bases, the review sample).
`_collect_garbage` treats held digests as referenced. A version that is later labeled is held
for good (`until` None). The hold is capped at `HOLD_CAP_BYTES`: past it, the lowest priority
and oldest go first (`small`, then `sample`, then `reported`; `labeled` never), and the
update reports what was dropped. Blobs no longer on disk leave the hold.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Callable, Collection, Iterable
from compression import zstd
from datetime import datetime, timedelta
from pathlib import Path
from typing import Final, Literal

from pydantic import Field

from kitsunox.core.models import Persisted, Record
from kitsunox.core.run import STAGE_SNAPSHOTS, DataDir, RunManifest
from kitsunox.stages.ingest import changes_file, iter_changes
from kitsunox.util.files import atomic_write, sync_file
from kitsunox.util.http import Snapshot, SnapshotEntry

COMPRESS_CHUNK: Final = 1 << 20
HOLD_FILE: Final = Path("eval") / "live" / "hold.json"  # under the data directory
HOLD_DAYS: Final = 30
HOLD_SMALL_BYTES: Final = 64 * 1024
# The owner approved ~10 GB (decision 0019): 0.59 GB of small tarballs in 2 days, so ~9 GB in 30.
HOLD_CAP_BYTES: Final = 15 * 10**9
HoldReason = Literal["labeled", "reported", "sample", "small"]
HOLD_PRIORITY: Final[tuple[HoldReason, ...]] = ("labeled", "reported", "sample", "small")


class RetentionMarker(Persisted):
    pruned_at: datetime
    keep_days: int
    retained: dict[str, SnapshotEntry]


class PruneReport(Record):
    runs_pruned: tuple[str, ...]
    blobs_pinned: int
    blobs_deleted: int
    bytes_freed: int
    blobs_held: int = 0


class HeldBlob(Record):
    until: datetime | None = Field(description="Held until then; None: for good (labeled).")
    size: int = Field(description="Bytes on disk (the compressed blob), set by `update_hold`.")
    reason: HoldReason
    ref: str = Field(description="`name@version` it was held for (untrusted package text).")
    run_id: str


class Hold(Persisted):
    updated_at: datetime
    cap_bytes: int
    blobs: dict[str, HeldBlob] = Field(default_factory=dict, description="SHA-256 -> why.")

    def digests(self, now: datetime) -> set[str]:
        return {sha for sha, b in self.blobs.items() if b.until is None or b.until > now}

    @property
    def held_bytes(self) -> int:
        return sum(b.size for b in self.blobs.values())


class HoldReport(Record):
    held: int
    held_bytes: int
    added: int
    expired: int
    missing: int = Field(description="Left the hold: the blob is no longer on disk.")
    dropped: int = Field(description="Left the hold over the cap.")
    dropped_bytes: int


def hold_path(data: DataDir) -> Path:
    return data.root / HOLD_FILE


def read_hold(data: DataDir) -> Hold | None:
    path = hold_path(data)
    return Hold.load_json(path.read_bytes()) if path.exists() else None


def held_digests(data: DataDir, now: datetime) -> set[str]:
    """What the hold keeps now (empty without a hold file)."""
    hold = read_hold(data)
    return hold.digests(now) if hold else set()


def small_tarballs(
    data: DataDir, *, is_artifact: Callable[[str], bool], max_bytes: int = HOLD_SMALL_BYTES
) -> list[tuple[str, HeldBlob]]:
    """Every artifact Stage 2 captured in an unpruned run at most `max_bytes` long, held
    `HOLD_DAYS` past its run (its blobs still exist; a pruned run's are decided already)."""
    found: list[tuple[str, HeldBlob]] = []
    runs_root = data.root / "runs"
    for run_dir in (
        sorted(p for p in runs_root.iterdir() if p.is_dir()) if runs_root.exists() else ()
    ):
        path = run_dir / STAGE_SNAPSHOTS[0]
        if (run_dir / "retention.json").exists() or not path.exists():
            continue
        as_of = RunManifest.load_json((run_dir / "manifest.json").read_bytes()).as_of
        for entry in Snapshot.load(path).entries.values():
            if entry.status == 200 and entry.size <= max_bytes and is_artifact(entry.url):
                found.append(
                    (
                        entry.sha256,
                        HeldBlob(
                            until=as_of + timedelta(days=HOLD_DAYS),
                            size=entry.size,
                            reason="small",
                            ref=entry.url.rsplit("/", 1)[-1],
                            run_id=run_dir.name,
                        ),
                    )
                )
    return found


def update_hold(
    data: DataDir,
    requests: Iterable[tuple[str, HeldBlob]],
    *,
    now: datetime,
    cap_bytes: int = HOLD_CAP_BYTES,
) -> tuple[Hold, HoldReport]:
    """Merge `requests` (SHA-256, why) into the hold: the later `until` and the higher
    priority win. Expired entries and blobs no longer on disk leave; then the cap is applied.
    Written atomically. The caller holds the lock."""
    old = read_hold(data)
    blobs = dict(old.blobs) if old else {}
    added = 0
    for sha, wanted in requests:
        current = blobs.get(sha)
        if current is None:
            added += 1
            blobs[sha] = wanted
        else:
            blobs[sha] = _merge(current, wanted)
    expired = [s for s, b in blobs.items() if b.until is not None and b.until <= now]
    for sha in expired:
        del blobs[sha]
    missing = []
    for sha in list(blobs):
        on_disk = _blob_size(data, sha)
        if on_disk is None:
            missing.append(sha)
            del blobs[sha]
        elif on_disk != blobs[sha].size:
            blobs[sha] = blobs[sha].model_copy(update={"size": on_disk})
    total = sum(b.size for b in blobs.values())
    dropped = dropped_bytes = 0
    order = sorted(
        (s for s, b in blobs.items() if b.reason != "labeled"),
        key=lambda s: (
            -HOLD_PRIORITY.index(blobs[s].reason),
            blobs[s].until or now,
            s,
        ),
    )
    for sha in order:
        if total <= cap_bytes:
            break
        total -= blobs[sha].size
        dropped_bytes += blobs[sha].size
        dropped += 1
        del blobs[sha]
    hold = Hold(updated_at=now, cap_bytes=cap_bytes, blobs=dict(sorted(blobs.items())))
    atomic_write(hold_path(data), hold.model_dump_json(indent=1).encode() + b"\n")
    return hold, HoldReport(
        held=len(blobs),
        held_bytes=hold.held_bytes,
        added=added,
        expired=len(expired),
        missing=len(missing),
        dropped=dropped,
        dropped_bytes=dropped_bytes,
    )


def _blob_size(data: DataDir, sha: str) -> int | None:
    """Bytes a blob takes on disk; None if absent (an empty blob, left by a crash, counts as
    absent, as in the blob store)."""
    try:
        size = (data.root / "blobs" / sha[:2] / f"{sha}.zst").stat().st_size
    except OSError:
        return None
    return size or None


def _merge(a: HeldBlob, b: HeldBlob) -> HeldBlob:
    reason = min(a.reason, b.reason, key=HOLD_PRIORITY.index)
    first = a if a.reason == reason else b
    until = None if a.until is None or b.until is None else max(a.until, b.until)
    return first.model_copy(update={"until": until})


def prune(
    data: DataDir,
    *,
    now: datetime,
    keep_days: int,
    pinned_names: Collection[str],
    metadata_url: Callable[[str], str],
    keep_archive_days: int | None = None,
    is_archive: Callable[[str], bool] | None = None,
    held: Collection[str] = (),
) -> PruneReport:
    """Prune runs older than `keep_days`, then delete unreferenced blobs. `metadata_url` maps a
    package name to the URL its metadata was fetched from (ecosystem-specific). Fetches that
    `is_archive` picks are kept only `keep_archive_days`. `held` digests (the label hold) are
    never deleted."""
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
    deleted, freed = _collect_garbage(data, run_dirs, expired, is_archive, held)
    return PruneReport(
        runs_pruned=tuple(pruned),
        blobs_pinned=pinned,
        blobs_deleted=deleted,
        bytes_freed=freed,
        blobs_held=len(held),
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
    # Atomic: a torn marker would make every later prune of this data dir fail to load it.
    atomic_write(run_dir / "retention.json", (marker.model_dump_json(indent=2) + "\n").encode())
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
    held: Collection[str] = (),
) -> tuple[int, int]:
    referenced: set[str] = set(held)
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
