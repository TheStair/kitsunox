"""Run bookkeeping: where a run's files live, its reproducibility manifest, and record/replay.

Layout under the data directory (gitignored):

    blobs/                      content-addressed HTTP response bodies, shared by all runs
    http-immutable/             cross-run index for immutable responses (e.g. tarballs)
    state/<ecosystem>.json      change-feed checkpoint for continuous mode
    .lock                       held by every command that writes runs or deletes blobs
    watchlists/<ecosystem>/     popularity watchlists, one JSON file per build
    runs/<run_id>/
        manifest.json           RunManifest
        snapshot.json           every HTTP response the run used
        changes.jsonl           Stage 0 output, one Change per line (`.jsonl.zst` once pruned)
        skipped.jsonl           packages Stage 0 could not process, with reasons
        retention.json          only on pruned runs: which blobs were kept (core/retention.py)

Chained runs (`IngestRequest.chain`, used by `kitsunox collect`) continue from the checkpoint the
previous run left. Their window starts `CHAIN_OVERLAP` before the previous run's `as_of`, so a
release that reached the feed a little after it was published is not lost between runs. Because
the feed ranges are contiguous, a chained run's window is covered by construction.

Catching up (decision 0006 addendum 2026-11-08): a chained run reads at most
`MAX_RUN_FEED_SPAN` of the feed. After a long gap (the machine was off for four days: 1.06M
sequence numbers, 405,710 changes, 27.6 GB peak in Stage 0 on a 30 GB VM) the gap is split over
several runs, one per tick, each the size the stages already handle. The feed lists each package
once, at its latest change, so the slices split the packages between the runs; each slice uses
the whole gap's window. Until a run reaches the feed head the checkpoint keeps the earlier
`as_of` (every package is covered up to then), so the next slice's window starts there too.

Network failures (decision 0009): a package skipped because of the network is kept in the
checkpoint's retry list and fetched again by the next run, over the window it was missed in. A run
in which more than `MAX_TRANSIENT_FRACTION` of packages failed that way is an outage, not bad
luck: it raises `IngestDegradedError` before anything is written, so the checkpoint stays put and
the next run covers the whole range again.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path

import httpx
from pydantic import Field

from kitsunox import __version__
from kitsunox.core.interfaces import DIFF_BASE, Ecosystem
from kitsunox.core.models import Persisted, Window
from kitsunox.core.store import RecordStore
from kitsunox.core.watchlist import Watchlist, build_watchlist
from kitsunox.stages.ingest import (
    DownloadsApiPopularity,
    IngestResult,
    PopularitySource,
    RetryItem,
    WatchlistPopularity,
    run_ingest,
    write_jsonl,
)
from kitsunox.util import disk
from kitsunox.util.files import atomic_write
from kitsunox.util.hashing import sha256_hex
from kitsunox.util.http import BlobStore, FetchMode, HttpFetcher, Snapshot

EcosystemFactory = Callable[[HttpFetcher], Ecosystem]


class PopularityMode(StrEnum):
    WATCHLIST = "watchlist"
    API = "api"
    NONE = "none"


class WatchlistMissingError(LookupError):
    """Watchlist mode was requested but no watchlist has been built yet."""


class RunPrunedError(LookupError):
    """The run's blobs were removed by retention, so it can no longer be replayed."""


class DataDirBusyError(RuntimeError):
    """Another Kitsunox process holds the data directory lock."""


class IngestDegradedError(RuntimeError):
    """Too many packages failed on the network; nothing was written."""


# Later stages' fetch records for a run (Stage 2: tarballs; Stage 4: repository refs and
# archives; Stage 5: the offline bundles' dependency packuments and tarballs). Retention keeps
# their blobs like those of `snapshot.json`.
STATIC_SNAPSHOT = "static-snapshot.json"
CORRELATE_SNAPSHOT = "correlate-snapshot.json"
SANDBOX_SNAPSHOT = "sandbox-snapshot.json"
STAGE_SNAPSHOTS = (STATIC_SNAPSHOT, CORRELATE_SNAPSHOT, SANDBOX_SNAPSHOT)
CHAIN_OVERLAP = timedelta(minutes=15)
# A run catches up on a gap this long (the machine was off or offline). Matches retention.
MAX_CHAIN_GAP = timedelta(days=7)
# The most of the feed one chained run reads (see "Catching up" above). The four-day gap of
# 2026-11-07 averaged 0.38 changes per sequence number, so a slice is ~95k changes (Stage 0
# ~68 KB each in memory: ~6.5 GB); an hourly tick reads ~11k. Measured, not tuned.
MAX_RUN_FEED_SPAN = 250_000
MAX_TRANSIENT_FRACTION = 0.2
MIN_PACKAGES_FOR_DEGRADED = 20


@dataclass(frozen=True)
class Checkpoint:
    """Where the last default-range run stopped reading the feed, and which run that was. Files
    written before chaining existed hold only the cursor."""

    cursor: int
    run_id: str | None = None
    as_of: datetime | None = None
    retry: tuple[RetryItem, ...] = ()


class RunManifest(Persisted):
    """Everything needed to identify, verify and replay one run."""

    run_id: str
    tool_version: str
    ecosystem: str
    as_of: datetime
    window: Window
    cursor_since: int
    cursor_until: int
    snapshot_sha256: str
    changes_sha256: str
    change_count: int
    skipped_count: int
    packages_seen: int
    popularity_mode: PopularityMode = PopularityMode.NONE
    watchlist_id: str | None = None
    watchlist_sha256: str | None = None
    popularity_failures: int = 0
    feed_start_estimate: datetime | None = None
    window_covered: bool | None = None
    chained_from: str | None = None
    feed_head: int | None = Field(
        default=None,
        description="The feed's head when a default-range run started; a chained run that "
        "stopped short of it (`cursor_until` < `feed_head`) is one slice of a catch-up.",
    )
    retried: tuple[RetryItem, ...] = Field(
        default=(), description="Packages carried over from earlier runs' network failures."
    )
    transient_skipped: int = 0
    diff_base: int = Field(
        default=1,
        description="How Stage 0 chose each release's diff base (`interfaces.DIFF_BASE`); "
        "runs recorded before it was recorded used rule 1.",
    )


@dataclass(frozen=True)
class DataDir:
    root: Path

    @property
    def blobs(self) -> BlobStore:
        return BlobStore(self.root / "blobs", min_free=disk.BLOB_FLOOR)

    @property
    def immutable_index(self) -> Path:
        return self.root / "http-immutable"

    @property
    def watchlists(self) -> RecordStore[Watchlist]:
        return RecordStore(self.root / "watchlists", Watchlist)

    def run_dir(self, run_id: str) -> Path:
        return self.root / "runs" / run_id

    def checkpoint_path(self, ecosystem: str) -> Path:
        return self.root / "state" / f"{ecosystem}.json"

    def read_checkpoint(self, ecosystem: str) -> Checkpoint | None:
        path = self.checkpoint_path(ecosystem)
        if not path.exists():
            return None
        raw = json.loads(path.read_text())
        cursor, run_id, as_of = raw.get("cursor"), raw.get("run_id"), raw.get("as_of")
        if not isinstance(cursor, int):
            return None
        return Checkpoint(
            cursor=cursor,
            run_id=run_id if isinstance(run_id, str) else None,
            as_of=datetime.fromisoformat(as_of) if isinstance(as_of, str) else None,
            retry=tuple(RetryItem.model_validate(item) for item in raw.get("retry") or ()),
        )

    def write_checkpoint(self, ecosystem: str, checkpoint: Checkpoint) -> None:
        path = self.checkpoint_path(ecosystem)
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = {
            "cursor": checkpoint.cursor,
            "run_id": checkpoint.run_id,
            "as_of": checkpoint.as_of.isoformat() if checkpoint.as_of else None,
            "retry": [item.model_dump(mode="json") for item in checkpoint.retry],
        }
        atomic_write(path, (json.dumps(raw) + "\n").encode())

    @contextmanager
    def lock(self) -> Iterator[None]:
        """Exclusive, non-blocking lock on the data directory. Pruning deletes blobs that no run
        references, so it must never overlap a run that is still writing them."""
        self.root.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.root / ".lock", os.O_RDWR | os.O_CREAT, 0o644)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise DataDirBusyError(
                    f"{self.root} is in use by another kitsunox process"
                ) from exc
            yield
        finally:
            os.close(fd)  # closing releases the lock


@dataclass(frozen=True)
class IngestRequest:
    as_of: datetime
    window_hours: float = 24.0
    since: int | None = None
    until: int | None = None
    lookback: int = 400_000
    workers: int = 8
    popularity: PopularityMode = PopularityMode.WATCHLIST
    watchlist_id: str | None = None
    chain: bool = False
    max_feed_span: int = MAX_RUN_FEED_SPAN


def make_run_id(ecosystem: str, as_of: datetime) -> str:
    return f"{as_of.astimezone(UTC):%Y%m%dT%H%M%SZ}-{ecosystem}"


def record_watchlist(
    data: DataDir,
    *,
    ecosystem: str,
    registry: str,
    built_at: datetime,
    min_monthly_downloads: int,
    client: httpx.Client | None = None,
) -> tuple[Watchlist, Path, str]:
    """Build and save a watchlist. The ~1 GB of raw ranking pages goes to a temporary blob
    store and is discarded; only the derived list is kept (and hashed into each run)."""
    with tempfile.TemporaryDirectory(prefix="kitsunox-watchlist-") as tmp:
        fetcher = HttpFetcher(
            store=BlobStore(Path(tmp)), snapshot=Snapshot(), mode=FetchMode.RECORD, client=client
        )
        try:
            watchlist = build_watchlist(
                fetcher,
                ecosystem=ecosystem,
                registry=registry,
                built_at=built_at,
                min_monthly_downloads=min_monthly_downloads,
            )
        finally:
            fetcher.close()
    path, sha = data.watchlists.save(watchlist.ecosystem, watchlist.id, watchlist)
    return watchlist, path, sha


def record_ingest(
    data: DataDir,
    factory: EcosystemFactory,
    request: IngestRequest,
    *,
    client: httpx.Client | None = None,
) -> RunManifest:
    """Fetch live data, run Stage 0, and persist everything needed to replay it."""
    snapshot = Snapshot()
    fetcher = HttpFetcher(
        store=data.blobs,
        snapshot=snapshot,
        mode=FetchMode.RECORD,
        immutable_index=data.immutable_index,
        client=client,
    )
    try:
        ecosystem = factory(fetcher)
        run_id = make_run_id(ecosystem.name, request.as_of)
        if data.run_dir(run_id).exists():
            raise FileExistsError(f"run {run_id} already exists")
        source, watchlist_id, watchlist_sha = _popularity_source(data, ecosystem, request)

        until = request.until if request.until is not None else ecosystem.feed_head()
        head = until if request.until is None else None
        explicit_since = request.since is not None
        checkpoint = data.read_checkpoint(ecosystem.name)
        if request.since is not None:
            since = request.since
        elif checkpoint is not None:
            since = checkpoint.cursor
        else:
            since = max(0, until - request.lookback)
        window = Window(
            start=request.as_of - timedelta(hours=request.window_hours), end=request.as_of
        )
        chained_from = _chain_parent(request, checkpoint)
        if chained_from is not None and checkpoint is not None and checkpoint.as_of is not None:
            window = Window(start=checkpoint.as_of - CHAIN_OVERLAP, end=request.as_of)
            until = min(until, since + request.max_feed_span)
        default_range = not explicit_since and request.until is None
        retry = tuple(
            item
            for item in (checkpoint.retry if checkpoint and default_range else ())
            if request.as_of - item.window_start <= MAX_CHAIN_GAP
        )
        result = run_ingest(
            ecosystem,
            window,
            since=since,
            until=until,
            workers=request.workers,
            popularity=source,
            retry=retry,
            diff_base=DIFF_BASE,
        )
    finally:
        fetcher.close()

    transient = [s for s in result.skipped if s.transient]
    if (
        result.packages_seen >= MIN_PACKAGES_FOR_DEGRADED
        and len(transient) > MAX_TRANSIENT_FRACTION * result.packages_seen
    ):
        raise IngestDegradedError(
            f"{len(transient)} of {result.packages_seen} packages failed on the network "
            f"(e.g. {transient[0].reason}); nothing written, the next run covers this range"
        )

    manifest = RunManifest(
        run_id=run_id,
        tool_version=__version__,
        ecosystem=ecosystem.name,
        as_of=request.as_of,
        window=window,
        cursor_since=since,
        cursor_until=until,
        snapshot_sha256="",  # filled in by _persist once the snapshot is written
        changes_sha256=changes_digest(result),
        change_count=len(result.changes),
        skipped_count=len(result.skipped),
        packages_seen=result.packages_seen,
        popularity_mode=request.popularity,
        watchlist_id=watchlist_id,
        watchlist_sha256=watchlist_sha,
        popularity_failures=len(result.popularity_failures),
        feed_start_estimate=result.feed_start_estimate,
        window_covered=True if chained_from is not None else result.window_covered,
        chained_from=chained_from,
        feed_head=head,
        retried=retry,
        transient_skipped=len(transient),
        diff_base=DIFF_BASE,
    )
    manifest = _persist(data, manifest, snapshot, result)
    if default_range:
        starts = {item.name: item.window_start for item in retry}
        carry = tuple(
            RetryItem(
                name=s.name,
                cursor=s.cursor,
                window_start=min(window.start, starts.get(s.name, window.start)),
            )
            for s in transient
        )
        # A catch-up slice covers the window only for the packages it read: the rest come in
        # the next slices, so the checkpoint keeps the time everything is covered up to.
        covered = request.as_of
        if head is not None and until < head and checkpoint is not None and checkpoint.as_of:
            covered = checkpoint.as_of
        data.write_checkpoint(
            ecosystem.name,
            Checkpoint(cursor=until, run_id=run_id, as_of=covered, retry=carry),
        )
    return manifest


def _chain_parent(request: IngestRequest, checkpoint: Checkpoint | None) -> str | None:
    """The run this one continues, if it can: chaining needs the default feed range and a
    checkpoint that says when the previous run ended, recently enough. Otherwise the run falls
    back to `window_hours` and the usual coverage estimate."""
    if not request.chain or request.since is not None or request.until is not None:
        return None
    if checkpoint is None or checkpoint.run_id is None or checkpoint.as_of is None:
        return None
    gap = request.as_of - checkpoint.as_of
    return checkpoint.run_id if timedelta(0) < gap <= MAX_CHAIN_GAP else None


def replay_ingest(data: DataDir, factory: EcosystemFactory, run_id: str) -> IngestResult:
    """Re-run Stage 0 for a recorded run using only its snapshot (and the exact watchlist it
    used, verified by hash). No network access."""
    run_dir = data.run_dir(run_id)
    manifest = RunManifest.load_json((run_dir / "manifest.json").read_bytes())
    if (run_dir / "retention.json").exists():
        raise RunPrunedError(f"run {run_id} was pruned; its HTTP bodies are no longer stored")
    fetcher = HttpFetcher(
        store=data.blobs,
        snapshot=Snapshot.load(run_dir / "snapshot.json"),
        mode=FetchMode.REPLAY,
        client=httpx.Client(transport=_OfflineTransport()),
    )
    try:
        ecosystem = factory(fetcher)
        source: PopularitySource | None = None
        if manifest.popularity_mode is PopularityMode.WATCHLIST and manifest.watchlist_id:
            watchlist = data.watchlists.load(
                manifest.ecosystem, manifest.watchlist_id, sha256=manifest.watchlist_sha256
            )
            source = WatchlistPopularity(watchlist)
        elif manifest.popularity_mode is PopularityMode.API:
            source = DownloadsApiPopularity(ecosystem)
        return run_ingest(
            ecosystem,
            manifest.window,
            since=manifest.cursor_since,
            until=manifest.cursor_until,
            workers=1,
            popularity=source,
            retry=manifest.retried,
            diff_base=manifest.diff_base,
        )
    finally:
        fetcher.close()


def changes_digest(result: IngestResult) -> str:
    """The manifest's `changes_sha256`: SHA-256 of every change's JSON line, then every skipped
    package's, joined by newlines (`sha256("\\n".join(lines).encode())`). Hashed a line at a
    time, so they are never held as one string: joining them touched ~6x the file's size,
    since the joined string takes 4 bytes a character once any line holds an emoji (an
    estimated ~18 GB for the 405k-change run of 2026-11-07; docs/proposals/streaming-stages.md).
    """
    digest = hashlib.sha256()
    for index, line in enumerate(_digest_lines(result)):
        if index:
            digest.update(b"\n")
        digest.update(line)
    return digest.hexdigest()


def _digest_lines(result: IngestResult) -> Iterator[bytes]:
    yield from (c.model_dump_json().encode() for c in result.changes)
    yield from (s.model_dump_json().encode() for s in result.skipped)


def _popularity_source(
    data: DataDir, ecosystem: Ecosystem, request: IngestRequest
) -> tuple[PopularitySource | None, str | None, str | None]:
    match request.popularity:
        case PopularityMode.NONE:
            return None, None, None
        case PopularityMode.API:
            return DownloadsApiPopularity(ecosystem), None, None
        case PopularityMode.WATCHLIST:
            watchlist_id = request.watchlist_id or data.watchlists.latest_id(
                ecosystem.name, not_after=request.as_of
            )
            if watchlist_id is None:
                raise WatchlistMissingError(
                    f"no {ecosystem.name} watchlist built before {request.as_of.isoformat()}"
                )
            sha = data.watchlists.sha256(ecosystem.name, watchlist_id)
            watchlist = data.watchlists.load(ecosystem.name, watchlist_id, sha256=sha)
            return WatchlistPopularity(watchlist), watchlist_id, sha


def _persist(
    data: DataDir, manifest: RunManifest, snapshot: Snapshot, result: IngestResult
) -> RunManifest:
    run_dir = data.run_dir(manifest.run_id)
    run_dir.mkdir(parents=True)
    snapshot.save(run_dir / "snapshot.json")
    write_jsonl(run_dir / "changes.jsonl", result.changes)
    write_jsonl(run_dir / "skipped.jsonl", result.skipped)
    manifest = manifest.model_copy(
        update={"snapshot_sha256": sha256_hex((run_dir / "snapshot.json").read_bytes())}
    )
    (run_dir / "manifest.json").write_text(manifest.model_dump_json(indent=2) + "\n")
    return manifest


class _OfflineTransport(httpx.BaseTransport):
    """Belt and braces for replay: any request that reaches the network layer fails."""

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"network disabled during replay: {request.url}")
