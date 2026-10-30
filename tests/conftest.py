"""Shared test helpers. Everything here is offline and inert."""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
import tarfile
import zipfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from hypothesis import settings

from kitsunox.core.models import Severity, Window
from kitsunox.core.run import DataDir, RunManifest
from kitsunox.core.watchlist import WatchEntry, Watchlist
from kitsunox.ecosystems.npm.registry import (
    DOWNLOADS_URL,
    FEED_PAGE_LIMIT,
    REGISTRY_URL,
    REPLICATE_URL,
)
from kitsunox.reporting.report import Links, Report, ReportEntry, ScoreTerm
from kitsunox.util.http import HttpFetcher

# Fuzz tests are deterministic by default (fixed seed derivation), matching the project's
# reproducibility rule. `HYPOTHESIS_PROFILE=deep` runs many more examples for a validation pass.
settings.register_profile("default", derandomize=True, max_examples=300, deadline=None)
settings.register_profile("deep", derandomize=True, max_examples=20_000, deadline=None)
# Random seeds, for searching beyond the fixed examples during a validation pass.
settings.register_profile("explore", derandomize=False, max_examples=20_000, deadline=None)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))

FIXTURES = Path(__file__).parent / "fixtures"


@dataclass
class TarEntry:
    name: str
    data: bytes = b""
    type: bytes = tarfile.REGTYPE
    linkname: str = ""


def make_tar_gz(entries: Iterable[TarEntry]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for entry in entries:
            info = tarfile.TarInfo(entry.name)
            info.type = entry.type
            info.linkname = entry.linkname
            info.size = len(entry.data) if entry.type == tarfile.REGTYPE else 0
            tar.addfile(info, io.BytesIO(entry.data) if info.size else None)
    return gzip.compress(buffer.getvalue(), mtime=0)


def sri_sha512(data: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


@dataclass
class Router:
    """Mock HTTP server: exact URL -> (status, body). Records every request it sees."""

    routes: dict[str, tuple[int, bytes]] = field(default_factory=dict)
    requests: list[str] = field(default_factory=list)
    offline: set[str] = field(default_factory=set)  # URLs whose connection fails

    def add_json(self, url: str, payload: object, status: int = 200) -> None:
        self.routes[url] = (status, json.dumps(payload).encode())

    def add_bytes(self, url: str, body: bytes, status: int = 200) -> None:
        self.routes[url] = (status, body)

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.requests.append(url)
        if url in self.offline:
            raise httpx.ConnectError("network is unreachable", request=request)
        status, body = self.routes.get(url, (404, b'{"error":"not found"}'))
        return httpx.Response(status, content=body)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))


@pytest.fixture(autouse=True)
def no_retry_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fetchers built inside the code under test retry with real back-off; don't wait."""
    original = HttpFetcher.__init__

    def init(self: HttpFetcher, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("sleep", lambda seconds: None)
        original(self, *args, **kwargs)

    monkeypatch.setattr(HttpFetcher, "__init__", init)


@pytest.fixture
def router() -> Router:
    return Router()


@pytest.fixture
def load_fixture() -> Callable[[str], object]:
    def load(relative: str) -> object:
        return json.loads((FIXTURES / relative).read_text())

    return load


# OSV export helpers (inert JSON records shaped like malicious-packages entries).
PUBLISHED = "2026-10-26T01:34:10Z"


def osv_zip(records: dict[str, object]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, record in records.items():
            archive.writestr(name, record if isinstance(record, str) else json.dumps(record))
    return buffer.getvalue()


def mal(record_id: str, name: str, **affected: object) -> dict[str, object]:
    return {
        "id": record_id,
        "published": PUBLISHED,
        "affected": [{"package": {"name": name, "ecosystem": "npm"}, **affected}],
    }


# Mock npm registry for Stage 0 runs: feed (100, 200] holds kx-fixture and a deleted package.
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


REPORT_AS_OF = datetime(2026, 10, 29, 21, 5, tzinfo=UTC)


def report_entry(
    rank: int,
    name: str,
    version: str,
    score: float,
    severity: Severity,
    *rules: str,
    published_at: datetime | None = REPORT_AS_OF,
    watched: bool = False,
) -> ReportEntry:
    """A minimal report entry; `rules` become its score terms."""
    return ReportEntry(
        rank=rank,
        ref=f"npm:{name}@{version}",
        name=name,
        version=version,
        previous_version=None,
        published_at=published_at,
        publisher=None,
        watched=watched,
        downloads=None,
        downloads_period_days=None,
        score=score,
        reason="r",
        severity=severity,
        score_terms=tuple(
            ScoreTerm(rule_id=r, severity=severity, weight=1, count=1) for r in rules
        ),
        findings=(),
        stages=(),
        links=Links(registry="https://www.npmjs.com/", files="https://www.npmjs.com/"),
    )


def make_report(
    run_id: str,
    *entries: ReportEntry,
    as_of: datetime = REPORT_AS_OF,
    ecosystem: str = "npm",
    correlation: dict[str, object] | None = None,
) -> Report:
    by_severity: dict[str, int] = {}
    for e in entries:
        by_severity[e.severity.value] = by_severity.get(e.severity.value, 0) + 1
    return Report(
        run_id=run_id,
        ecosystem=ecosystem,
        as_of=as_of,
        window_start=as_of - timedelta(hours=1),
        window_end=as_of,
        versions=4812,
        reported=len(entries),
        by_severity=dict(sorted(by_severity.items())),
        correlation=correlation or {},
        entries=entries,
    )


def run_manifest(
    run_id: str = "20261029T210500Z-npm", *, as_of: datetime = REPORT_AS_OF, **extra: object
) -> RunManifest:
    fields: dict[str, object] = {
        "run_id": run_id,
        "tool_version": "0",
        "ecosystem": "npm",
        "as_of": as_of,
        "window": Window(start=as_of - timedelta(hours=1), end=as_of),
        "cursor_since": 0,
        "cursor_until": 1,
        "snapshot_sha256": "0",
        "changes_sha256": "0",
        "change_count": 4812,
        "skipped_count": 0,
        "packages_seen": 4000,
        "chained_from": "20261029T200500Z-npm",
    }
    fields.update(extra)
    return RunManifest.model_validate(fields)
