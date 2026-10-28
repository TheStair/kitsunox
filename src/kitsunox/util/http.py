"""Caching HTTP fetcher that makes runs replayable.

Every response a run uses is stored content-addressed in a `BlobStore` and indexed in the run's
`Snapshot`. In RECORD mode requests go to the network (once per run per request); in REPLAY mode
they're answered only from the snapshot, and a missing entry is an error. Analysis code therefore
sees byte-identical inputs on replay.

Responses marked `immutable` (e.g. integrity-pinned tarballs) are also indexed across runs, so a
later RECORD run reuses them instead of downloading again.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Mapping
from compression import zstd
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Final

import httpx
from pydantic import BaseModel, ConfigDict

from kitsunox import __version__
from kitsunox.util.files import atomic_write
from kitsunox.util.hashing import sha256_hex
from kitsunox.util.schema import require_schema_version

USER_AGENT: Final = f"kitsunox/{__version__} (+https://github.com/TheStair/kitsunox)"
RETRYABLE_STATUS: Final = frozenset({429, 500, 502, 503, 504})


class FetchMode(StrEnum):
    RECORD = "record"
    REPLAY = "replay"


class FetchError(RuntimeError):
    """A request could not be satisfied (network failure after retries, size limit, or a
    replay miss)."""


class TransientFetchError(FetchError):
    """Retries ran out on network errors or retryable statuses (429, 5xx): the resource may well
    exist, the network or server just wasn't answering. Worth trying again later."""


SNAPSHOT_SCHEMA_VERSION: Final = 1


class SnapshotEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = SNAPSHOT_SCHEMA_VERSION
    url: str
    status: int
    content_type: str | None
    sha256: str
    size: int
    fetched_at: datetime


class Snapshot(BaseModel):
    """Request key -> response record for one run. Persisted with sorted keys."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = SNAPSHOT_SCHEMA_VERSION
    entries: dict[str, SnapshotEntry] = {}

    def save(self, path: Path) -> None:
        ordered = dict(sorted(self.entries.items()))
        data = Snapshot(entries=ordered).model_dump_json(indent=2)
        atomic_write(path, data.encode())

    @classmethod
    def load(cls, path: Path) -> Snapshot:
        data = path.read_bytes()
        require_schema_version(data, SNAPSHOT_SCHEMA_VERSION, "Snapshot")
        return cls.model_validate_json(data)


@dataclass(frozen=True)
class FetchedResponse:
    url: str
    status: int
    content_type: str | None
    body: bytes
    fetched_at: datetime

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def json(self) -> object:
        return json.loads(self.body)


class BlobStore:
    """Content-addressed store: `<root>/<sha[:2]>/<sha>.zst`, keyed by the SHA-256 of the
    *uncompressed* bytes. zstd keeps packuments (JSON, often megabytes) about 6x smaller. Reads
    re-verify the digest."""

    def __init__(self, root: Path, *, level: int = 3) -> None:
        self.root = root
        self.level = level

    def _path(self, sha: str) -> Path:
        return self.root / sha[:2] / f"{sha}.zst"

    def put(self, data: bytes) -> str:
        sha = sha256_hex(data)
        path = self._path(sha)
        if not path.exists():
            atomic_write(path, zstd.compress(data, level=self.level))
        return sha

    def get(self, sha: str) -> bytes:
        data = zstd.decompress(self._path(sha).read_bytes())
        if sha256_hex(data) != sha:
            raise FetchError(f"blob {sha} is corrupt")
        return data


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 5
    base_delay: float = 1.0
    max_delay: float = 60.0


DEFAULT_RETRY = RetryPolicy()


class HttpFetcher:
    """Thread-safe GET-only fetcher backed by a BlobStore and a per-run Snapshot."""

    def __init__(
        self,
        *,
        store: BlobStore,
        snapshot: Snapshot,
        mode: FetchMode,
        immutable_index: Path | None = None,
        client: httpx.Client | None = None,
        retry: RetryPolicy = DEFAULT_RETRY,
        max_bytes: int = 256 * 1024 * 1024,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.store = store
        self.snapshot = snapshot
        self.mode = mode
        self.immutable_index = immutable_index
        self.retry = retry
        self.max_bytes = max_bytes
        self._sleep = sleep
        self._clock = clock
        self._monotonic = monotonic
        self._lock = threading.Lock()
        self._pace_lock = threading.Lock()
        self._min_interval: dict[str, float] = {}
        self._next_slot: dict[str, float] = {}
        self._client = client or httpx.Client(
            headers={"User-Agent": USER_AGENT},
            timeout=httpx.Timeout(30.0, connect=10.0),
            follow_redirects=True,
        )

    def set_min_interval(self, host: str, seconds: float) -> None:
        """Space network requests to `host` at least `seconds` apart, across all threads. For
        APIs that throttle bursts. Replays and cache hits are never paced."""
        with self._pace_lock:
            self._min_interval[host] = seconds

    def _pace(self, url: str) -> None:
        host = httpx.URL(url).host
        with self._pace_lock:
            interval = self._min_interval.get(host)
            if interval is None:
                return
            now = self._monotonic()
            slot = max(now, self._next_slot.get(host, now))
            self._next_slot[host] = slot + interval
        if slot > now:
            self._sleep(slot - now)

    def close(self) -> None:
        self._client.close()

    def get(
        self, url: str, *, headers: Mapping[str, str] | None = None, immutable: bool = False
    ) -> FetchedResponse:
        key = request_key(url, headers)
        with self._lock:
            entry = self.snapshot.entries.get(key)
        if entry is None and self.mode is FetchMode.RECORD and immutable:
            entry = self._immutable_lookup(key)
            if entry is not None:
                with self._lock:
                    self.snapshot.entries[key] = entry
        if entry is not None:
            body = self.store.get(entry.sha256)
            return FetchedResponse(
                entry.url, entry.status, entry.content_type, body, entry.fetched_at
            )
        if self.mode is FetchMode.REPLAY:
            raise FetchError(f"replay miss: {key}")

        response = self._fetch_with_retry(url, headers)
        sha = self.store.put(response.body)
        entry = SnapshotEntry(
            url=url,
            status=response.status,
            content_type=response.content_type,
            sha256=sha,
            size=len(response.body),
            fetched_at=response.fetched_at,
        )
        with self._lock:
            self.snapshot.entries[key] = entry
        if immutable and response.ok:
            self._immutable_store(key, entry)
        return response

    def _fetch_with_retry(self, url: str, headers: Mapping[str, str] | None) -> FetchedResponse:
        last_error = "no attempts made"
        for attempt in range(1, self.retry.max_attempts + 1):
            retry_after: float | None = None
            self._pace(url)
            try:
                with self._client.stream("GET", url, headers=dict(headers or {})) as resp:
                    if resp.url.scheme != "https":
                        raise FetchError(f"GET {url}: refusing non-HTTPS response from {resp.url}")
                    if resp.status_code not in RETRYABLE_STATUS:
                        body = self._read_limited(resp)
                        content_type = resp.headers.get("content-type")
                        return FetchedResponse(
                            url, resp.status_code, content_type, body, self._clock()
                        )
                    last_error = f"HTTP {resp.status_code}"
                    retry_after = _parse_retry_after(resp.headers.get("retry-after"))
            except httpx.TransportError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
            except httpx.HTTPError as exc:  # decoding errors, redirect loops: not retryable
                raise FetchError(f"GET {url}: {type(exc).__name__}: {exc}") from exc
            if attempt < self.retry.max_attempts:
                delay = min(self.retry.max_delay, self.retry.base_delay * 2 ** (attempt - 1))
                self._sleep(max(delay, retry_after or 0.0))
        raise TransientFetchError(
            f"GET {url} failed after {self.retry.max_attempts} attempts: {last_error}"
        )

    def _read_limited(self, resp: httpx.Response) -> bytes:
        chunks: list[bytes] = []
        total = 0
        for chunk in resp.iter_bytes():
            total += len(chunk)
            if total > self.max_bytes:
                raise FetchError(f"response from {resp.url} exceeds {self.max_bytes} bytes")
            chunks.append(chunk)
        return b"".join(chunks)

    def _immutable_path(self, key: str) -> Path | None:
        if self.immutable_index is None:
            return None
        digest = sha256_hex(key.encode())
        return self.immutable_index / digest[:2] / f"{digest}.json"

    def _immutable_lookup(self, key: str) -> SnapshotEntry | None:
        path = self._immutable_path(key)
        if path is None or not path.exists():
            return None
        data = path.read_bytes()
        require_schema_version(data, SNAPSHOT_SCHEMA_VERSION, "SnapshotEntry")
        return SnapshotEntry.model_validate_json(data)

    def _immutable_store(self, key: str, entry: SnapshotEntry) -> None:
        path = self._immutable_path(key)
        if path is not None:
            atomic_write(path, entry.model_dump_json().encode())


def request_key(url: str, headers: Mapping[str, str] | None) -> str:
    """Stable identity for a request: URL plus the headers that change the response body."""
    accept = {k.lower(): v for k, v in (headers or {}).items()}.get("accept")
    return f"GET {url}" + (f" accept={accept}" if accept else "")


def _parse_retry_after(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None
