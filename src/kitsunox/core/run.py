"""Run bookkeeping: where a run's files live, its reproducibility manifest, and record/replay.

Layout under the data directory (gitignored):

    blobs/                      content-addressed HTTP response bodies, shared by all runs
    http-immutable/             cross-run index for immutable responses (e.g. tarballs)
    state/<ecosystem>.json      change-feed checkpoint for continuous mode
    runs/<run_id>/
        manifest.json           RunManifest
        snapshot.json           every HTTP response the run used
        changes.jsonl           Stage 0 output, one Change per line
        skipped.jsonl           packages Stage 0 could not process, with reasons
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from kitsunox import __version__
from kitsunox.core.interfaces import Ecosystem
from kitsunox.core.models import Record, Window
from kitsunox.stages.ingest import IngestResult, run_ingest, write_jsonl
from kitsunox.util.hashing import sha256_hex
from kitsunox.util.http import BlobStore, FetchMode, HttpFetcher, Snapshot

EcosystemFactory = Callable[[HttpFetcher], Ecosystem]


class RunManifest(Record):
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


@dataclass(frozen=True)
class DataDir:
    root: Path

    @property
    def blobs(self) -> BlobStore:
        return BlobStore(self.root / "blobs")

    @property
    def immutable_index(self) -> Path:
        return self.root / "http-immutable"

    def run_dir(self, run_id: str) -> Path:
        return self.root / "runs" / run_id

    def checkpoint_path(self, ecosystem: str) -> Path:
        return self.root / "state" / f"{ecosystem}.json"

    def read_checkpoint(self, ecosystem: str) -> int | None:
        path = self.checkpoint_path(ecosystem)
        if not path.exists():
            return None
        value = json.loads(path.read_text()).get("cursor")
        return value if isinstance(value, int) else None

    def write_checkpoint(self, ecosystem: str, cursor: int) -> None:
        path = self.checkpoint_path(ecosystem)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"cursor": cursor}) + "\n")


@dataclass(frozen=True)
class IngestRequest:
    as_of: datetime
    window_hours: float = 24.0
    since: int | None = None
    until: int | None = None
    lookback: int = 400_000
    workers: int = 8


def make_run_id(ecosystem: str, as_of: datetime) -> str:
    return f"{as_of.astimezone(UTC):%Y%m%dT%H%M%SZ}-{ecosystem}"


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
        run_dir = data.run_dir(run_id)
        if run_dir.exists():
            raise FileExistsError(f"run {run_id} already exists")

        until = request.until if request.until is not None else ecosystem.feed_head()
        explicit_since = request.since is not None
        checkpoint = data.read_checkpoint(ecosystem.name)
        if request.since is not None:
            since = request.since
        elif checkpoint is not None:
            since = checkpoint
        else:
            since = max(0, until - request.lookback)
        window = Window(
            start=request.as_of - timedelta(hours=request.window_hours), end=request.as_of
        )
        result = run_ingest(ecosystem, window, since=since, until=until, workers=request.workers)
    finally:
        fetcher.close()

    manifest = _persist(
        data, run_id, ecosystem.name, request.as_of, window, since, until, snapshot, result
    )
    if not explicit_since and request.until is None:
        data.write_checkpoint(ecosystem.name, until)
    return manifest


def replay_ingest(data: DataDir, factory: EcosystemFactory, run_id: str) -> IngestResult:
    """Re-run Stage 0 for a recorded run using only its snapshot. No network access."""
    run_dir = data.run_dir(run_id)
    manifest = RunManifest.model_validate_json((run_dir / "manifest.json").read_bytes())
    fetcher = HttpFetcher(
        store=data.blobs,
        snapshot=Snapshot.load(run_dir / "snapshot.json"),
        mode=FetchMode.REPLAY,
        client=httpx.Client(transport=_OfflineTransport()),
    )
    try:
        return run_ingest(
            factory(fetcher),
            manifest.window,
            since=manifest.cursor_since,
            until=manifest.cursor_until,
            workers=1,
        )
    finally:
        fetcher.close()


def changes_digest(result: IngestResult) -> str:
    lines = [c.model_dump_json() for c in result.changes]
    lines += [s.model_dump_json() for s in result.skipped]
    return sha256_hex("\n".join(lines).encode())


def _persist(
    data: DataDir,
    run_id: str,
    ecosystem: str,
    as_of: datetime,
    window: Window,
    since: int,
    until: int,
    snapshot: Snapshot,
    result: IngestResult,
) -> RunManifest:
    run_dir = data.run_dir(run_id)
    run_dir.mkdir(parents=True)
    snapshot.save(run_dir / "snapshot.json")
    write_jsonl(run_dir / "changes.jsonl", result.changes)
    write_jsonl(run_dir / "skipped.jsonl", result.skipped)
    manifest = RunManifest(
        run_id=run_id,
        tool_version=__version__,
        ecosystem=ecosystem,
        as_of=as_of,
        window=window,
        cursor_since=since,
        cursor_until=until,
        snapshot_sha256=sha256_hex((run_dir / "snapshot.json").read_bytes()),
        changes_sha256=changes_digest(result),
        change_count=len(result.changes),
        skipped_count=len(result.skipped),
        packages_seen=result.packages_seen,
    )
    (run_dir / "manifest.json").write_text(manifest.model_dump_json(indent=2) + "\n")
    return manifest


class _OfflineTransport(httpx.BaseTransport):
    """Belt and braces for replay: any request that reaches the network layer fails."""

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"network disabled during replay: {request.url}")
