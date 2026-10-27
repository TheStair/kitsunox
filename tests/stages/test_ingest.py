from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from kitsunox.core.interfaces import ChangeStub, DownloadCounts
from kitsunox.core.models import (
    ArtifactRef,
    Change,
    PackageVersionRef,
    PublishInfo,
    VersionSnapshot,
    Window,
)
from kitsunox.core.watchlist import WatchEntry, Watchlist
from kitsunox.stages.ingest import (
    DownloadsApiPopularity,
    WatchlistPopularity,
    read_changes,
    run_ingest,
    write_jsonl,
)
from kitsunox.util.archive import ArtifactTree
from kitsunox.util.http import FetchError

WINDOW = Window(start=datetime(2026, 1, 1, tzinfo=UTC), end=datetime(2026, 1, 2, tzinfo=UTC))


def snapshot(name: str, version: str) -> VersionSnapshot:
    return VersionSnapshot(
        ref=PackageVersionRef(ecosystem="fake", name=name, version=version),
        publish=PublishInfo(),
        manifest={"name": name, "version": version},
    )


def change(name: str, version: str, previous: str | None = None) -> Change:
    return Change(
        new=snapshot(name, version),
        previous=snapshot(name, previous) if previous is not None else None,
    )


class FakeEcosystem:
    name = "fake"

    def __init__(
        self,
        behavior: dict[str, list[Change] | Exception],
        downloads: Mapping[str, int | None] | None = None,
    ) -> None:
        self.behavior = behavior
        self.downloads = downloads or {}
        self.popularity_requests: list[tuple[str, ...]] = []

    def feed_head(self) -> int:
        return 0

    def list_changes(self, since: int, until: int) -> list[ChangeStub]:
        return [ChangeStub(name=n, cursor=i) for i, n in enumerate(sorted(self.behavior))]

    def build_changes(self, stub: ChangeStub, window: Window) -> list[Change]:
        outcome = self.behavior[stub.name]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def download_counts(self, names: Sequence[str], as_of: datetime) -> DownloadCounts:
        self.popularity_requests.append(tuple(names))
        counts = {n: d for n, d in self.downloads.items() if n in names}
        return DownloadCounts(source="fake-downloads", period_days=7, counts=counts)

    def fetch_artifact(self, artifact: ArtifactRef) -> ArtifactTree:
        raise NotImplementedError


def test_failures_are_recorded_not_dropped() -> None:
    eco = FakeEcosystem(
        {
            "ok": [change("ok", "1.0.0")],
            "net": FetchError("timeout"),
            "bad": ValueError("malformed\nsecond line"),
            "quiet": [],
        }
    )
    result = run_ingest(eco, WINDOW, since=0, until=10)
    assert [str(c.new.ref) for c in result.changes] == ["fake:ok@1.0.0"]
    assert [(s.name, s.reason) for s in result.skipped] == [
        ("bad", "ValueError: malformed"),
        ("net", "FetchError: timeout"),
    ]
    assert result.packages_seen == 4


@pytest.mark.parametrize("workers", [1, 8])
def test_output_order_is_independent_of_workers(workers: int) -> None:
    eco = FakeEcosystem({n: [change(n, "2.0.0"), change(n, "1.0.0")] for n in "zyxwvu"})
    result = run_ingest(eco, WINDOW, since=0, until=10, workers=workers)
    keys = [c.sort_key for c in result.changes]
    assert keys == sorted(keys)


def test_jsonl_round_trip(tmp_path: Path) -> None:
    changes = [change("a", "1.0.0"), change("b", "1.0.0")]
    write_jsonl(tmp_path / "c.jsonl", changes)
    assert list(read_changes(tmp_path / "c.jsonl")) == changes


def popular_fixture() -> FakeEcosystem:
    return FakeEcosystem(
        {
            "old": [change("old", "2.0.0", previous="1.0.0")],
            "fresh": [change("fresh", "1.0.0")],
            "flaky": [change("flaky", "1.1.0", previous="1.0.0")],
            "niche": [change("niche", "1.1.0", previous="1.0.0")],
        },
        downloads={"old": 50_000, "niche": 9_999},
    )


def test_api_popularity_existing_packages_only_with_cutoff() -> None:
    eco = popular_fixture()
    result = run_ingest(eco, WINDOW, since=0, until=10, popularity=DownloadsApiPopularity(eco))
    assert eco.popularity_requests == [("flaky", "niche", "old")]  # brand-new "fresh" skipped
    by_name = {c.new.ref.name: c.popularity for c in result.changes}
    assert by_name["old"] is not None and by_name["old"].watched
    assert by_name["old"].downloads == 50_000 and by_name["old"].source == "fake-downloads"
    assert by_name["niche"] is not None and not by_name["niche"].watched  # below 10k/week
    assert by_name["fresh"] is None
    assert by_name["flaky"] is None
    assert result.popularity_failures == ("flaky",)


def test_watchlist_popularity_answers_every_existing_package() -> None:
    watchlist = Watchlist(
        ecosystem="fake",
        source="test",
        built_at=datetime(2026, 1, 1, tzinfo=UTC),
        min_monthly_downloads=43_000,
        entries={"old": WatchEntry(monthly_downloads=200_000, dependents=12)},
    )
    eco = popular_fixture()
    result = run_ingest(eco, WINDOW, since=0, until=10, popularity=WatchlistPopularity(watchlist))
    assert eco.popularity_requests == []  # no per-package network lookups
    by_name = {c.new.ref.name: c.popularity for c in result.changes}
    assert by_name["old"] is not None and by_name["old"].watched
    assert by_name["old"].source == "watchlist:20260101T000000Z"
    assert by_name["niche"] is not None and not by_name["niche"].watched
    assert by_name["fresh"] is None
    assert result.popularity_failures == ()


def test_no_popularity_source() -> None:
    result = run_ingest(popular_fixture(), WINDOW, since=0, until=10)
    assert all(c.popularity is None for c in result.changes)
