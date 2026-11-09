"""Shared test helpers. Everything here is offline and inert."""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
import re
import tarfile
import zipfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import httpx
import pytest
from hypothesis import settings

import kitsunox.collect
from kitsunox.core.models import (
    ArtifactRef,
    Candidate,
    Change,
    Finding,
    PackageVersionRef,
    Popularity,
    PublishInfo,
    Severity,
    StageDecision,
    VersionSnapshot,
    Window,
)
from kitsunox.core.run import DataDir, RunManifest
from kitsunox.core.watchlist import WatchEntry, Watchlist
from kitsunox.ecosystems.npm.registry import (
    DOWNLOADS_URL,
    FEED_PAGE_LIMIT,
    REGISTRY_URL,
    REPLICATE_URL,
)
from kitsunox.reporting.report import Links, Report, ReportEntry, ScoreTerm
from kitsunox.util import disk
from kitsunox.util.http import HttpFetcher, Snapshot, SnapshotEntry
from kitsunox.util.text import safe_url, strip_hidden

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


class Disk:
    """Free space as the code under test sees it: plenty, unless a test lowers it. Tests must
    not depend on the host's actual free space."""

    def __init__(self) -> None:
        self.free = 500 * disk.GIB
        self.readings: list[int] = []  # what each check returns, in order; then `free`

    def __call__(self, path: Path) -> int:
        return self.readings.pop(0) if self.readings else self.free


@pytest.fixture(autouse=True)
def free_disk(monkeypatch: pytest.MonkeyPatch) -> Disk:
    fake = Disk()
    monkeypatch.setattr(disk, "free_bytes", fake)
    monkeypatch.setattr(kitsunox.collect, "free_bytes", fake)
    return fake


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


@dataclass
class LiveVersion:
    """One version of a finished fake run, as Stages 1-4 and the report left it (live eval)."""

    name: str
    version: str = "1.0.1"
    published: datetime = REPORT_AS_OF - timedelta(minutes=30)
    previous: str | None = "1.0.0"
    watched: bool = False
    publisher: str = "alice"
    triage: str = "no signal"  # Stage 1's reason; forwarded unless "no signal"
    static: str | None = None  # Stage 2's reason (None: not read); flagged if "rules: ..."
    ast: str | None = None
    score: float = 0.0
    reported: bool = False
    rules: tuple[tuple[str, Severity], ...] = ()
    tarball_size: int | None = None  # captured by Stage 2 with this size
    base_size: int | None = None
    hook: bool = False

    @property
    def tarball_url(self) -> str:
        return f"https://registry.npmjs.org/{self.name}/-/{self.name}-{self.version}.tgz"

    @property
    def base_url(self) -> str:
        return f"https://registry.npmjs.org/{self.name}/-/{self.name}-{self.previous}.tgz"


def live_candidate(v: LiveVersion) -> Candidate:
    def snap(version: str, url: str) -> VersionSnapshot:
        return VersionSnapshot(
            ref=PackageVersionRef(ecosystem="npm", name=v.name, version=version),
            publish=PublishInfo(published_at=v.published, publisher=v.publisher),
            manifest={"scripts": {"postinstall": "node x.js"}} if v.hook else {},
            artifact=ArtifactRef(url=url, unpacked_size=1000),
        )

    history = [StageDecision(stage="triage", forwarded=v.triage != "no signal", reason=v.triage)]
    for stage, reason in (("static", v.static), ("ast", v.ast)):
        if reason is not None:
            history.append(
                StageDecision(stage=stage, forwarded=reason.startswith("rules:"), reason=reason)
            )
    history.append(
        StageDecision(stage="correlate", forwarded=v.reported, reason=f"score {v.score:g}")
    )
    findings = tuple(
        Finding(
            rule_id=rule, rule_version=1, severity=severity, weight=1.0, title="t", explanation="e"
        )
        for rule, severity in v.rules
    )
    change = Change(
        new=snap(v.version, v.tarball_url),
        previous=snap(v.previous, v.base_url) if v.previous else None,
        popularity=Popularity(source="t", downloads=None, period_days=30, watched=v.watched),
    )
    return Candidate(change=change, findings=findings, history=tuple(history))


def write_live_run(
    runs_root: Path,
    run_id: str,
    versions: Iterable[LiveVersion],
    *,
    as_of: datetime = REPORT_AS_OF,
    window: timedelta = timedelta(hours=1),
    rules_hash: str = "r1",
    stage_version: int = 8,
    finished: bool = True,
) -> Path:
    """A run directory with what a finished tick leaves: manifest, `correlate.jsonl`,
    `correlate.json`, the report and Stage 2's snapshot."""
    run_dir = runs_root / run_id
    (run_dir / "report").mkdir(parents=True, exist_ok=True)
    manifest = run_manifest(run_id, as_of=as_of, window=Window(start=as_of - window, end=as_of))
    (run_dir / "manifest.json").write_text(manifest.model_dump_json())
    listed = list(versions)
    with (run_dir / "correlate.jsonl").open("w") as handle:
        for v in listed:
            handle.write(live_candidate(v).model_dump_json() + "\n")
    info = {"stage_version": stage_version, "rules": rules_hash, "report_score": 6.0}
    (run_dir / "correlate.json").write_text(json.dumps(info))
    reported = sorted((v for v in listed if v.reported), key=lambda v: (-v.score, v.name))
    entries = [
        report_entry(rank, v.name, v.version, v.score, Severity.MEDIUM, published_at=v.published)
        for rank, v in enumerate(reported, start=1)
    ]
    report = make_report(run_id, *entries, as_of=as_of)
    (run_dir / "report" / "report.json").write_text(report.model_dump_json())
    if finished:
        (run_dir / "report" / "index.md").write_text("# report\n")
    entries_snap = {}
    for v in listed:
        for url, size in ((v.tarball_url, v.tarball_size), (v.base_url, v.base_size)):
            if size is not None:
                entries_snap[url] = SnapshotEntry(
                    url=url,
                    status=200,
                    content_type=None,
                    sha256=hashlib.sha256(url.encode()).hexdigest(),
                    size=size,
                    fetched_at=as_of,
                )
    Snapshot(entries=entries_snap).save(run_dir / "static-snapshot.json")
    return run_dir


# ----------------------------------------------------------------- viewer pages
# Shared by tests/web: a page is only the viewer's own markup.

ALLOWED_TAGS = frozenset(
    {
        *("html", "head", "meta", "title", "link", "body", "header", "nav", "main", "footer"),
        *("a", "p", "h1", "h2", "h3", "h4", "code", "strong", "span", "pre", "div"),
        *("table", "caption", "thead", "tbody", "tfoot", "tr", "th", "td", "ul", "ol", "li"),
        *("section", "details", "summary"),
        # the results page's trend chart (inline SVG, coloured by the stylesheet)
        *("svg", "g", "line", "polyline", "circle", "rect", "text"),
    }
)
ALLOWED_ATTRS = frozenset(
    {"lang", "charset", "name", "content", "rel", "href", "class", "aria-label", "role"}
    | {"scope", "colspan"}
    | {"viewbox", "x", "y", "x1", "y1", "x2", "y2", "cx", "cy", "r", "width", "height"}
    | {"points", "text-anchor"}
)
INTERNAL_HREF = re.compile(
    r"/(?:runs(?:/[0-9]{8}T[0-9]{6}Z-[a-z0-9]+(?:/entries/[0-9]+)?)?"
    r"|runs/page/[0-9]+|static/style\.css|queue"
    r"|verdicts(?:/(?:malicious|unwanted|benign|unverified))?"
    r"|results(?:/live-[0-9]{8}T[0-9]{6}Z|/sample(?:/[0-9]{4}-[0-9]{2}-[0-9]{2})?)?)?"
)


class _Tags(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, list[tuple[str, str | None]]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, attrs))


def assert_inert(document: str) -> None:
    """The document is only our own markup: known tags and attributes, no script, no style,
    no event handlers, links only to the viewer or to safe https URLs, no hidden characters."""
    assert document.startswith("<!DOCTYPE html>\n")
    assert strip_hidden(document) == (document, 0)
    parser = _Tags()
    parser.feed(document)
    parser.close()
    for tag, attrs in parser.tags:
        assert tag in ALLOWED_TAGS, tag
        names = {name for name, _ in attrs}
        assert names <= ALLOWED_ATTRS, (tag, names)
        values = dict(attrs)
        if tag == "a":
            href = values["href"] or ""
            if href.startswith("/"):
                assert INTERNAL_HREF.fullmatch(href), href
                assert "rel" not in values
            else:
                assert safe_url(href) == href, href
                assert values["rel"] == "noopener noreferrer nofollow"
        if tag == "link":
            assert values == {"rel": "stylesheet", "href": "/static/style.css"}
