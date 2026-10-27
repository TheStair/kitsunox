from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from conftest import Router
from kitsunox.core.run import DataDir, record_watchlist
from kitsunox.core.store import RecordStore
from kitsunox.core.watchlist import ECOSYSTEMS_URL, Watchlist, build_watchlist
from kitsunox.util.http import BlobStore, FetchError, FetchMode, HttpFetcher, Snapshot

BASE = ECOSYSTEMS_URL.format(registry="npmjs.org")
BUILT = datetime(2026, 10, 27, 6, tzinfo=UTC)


def page_url(page: int, size: int = 3) -> str:
    return f"{BASE}?sort=downloads&order=desc&per_page={size}&page={page}"


def fetcher(tmp_path: Path, client: httpx.Client) -> HttpFetcher:
    return HttpFetcher(
        store=BlobStore(tmp_path), snapshot=Snapshot(), mode=FetchMode.RECORD, client=client
    )


def test_build_stops_at_cutoff_and_skips_malformed(tmp_path: Path, router: Router) -> None:
    router.add_json(
        page_url(1),
        [
            {"name": "big", "downloads": 900, "dependent_packages_count": 5},
            {"name": "@s/mid", "downloads": 500, "dependent_packages_count": "many"},
            {"name": 7, "downloads": 400},
        ],
    )
    router.add_json(
        page_url(2),
        [{"name": "edge", "downloads": 100}, {"name": "small", "downloads": 99}, {"x": 1}],
    )
    watchlist = build_watchlist(
        fetcher(tmp_path, router.client()),
        ecosystem="npm",
        registry="npmjs.org",
        built_at=BUILT,
        min_monthly_downloads=100,
        page_size=3,
    )
    assert list(watchlist.entries) == ["@s/mid", "big", "edge"]
    assert watchlist.entries["big"].dependents == 5
    assert watchlist.entries["@s/mid"].dependents is None
    assert len(router.requests) == 2
    lookup = watchlist.lookup(["big", "small"])
    assert lookup["big"].watched and lookup["big"].downloads == 900
    assert not lookup["small"].watched and lookup["small"].downloads is None


def test_build_stops_on_short_page(tmp_path: Path, router: Router) -> None:
    router.add_json(page_url(1), [{"name": "only", "downloads": 10**6}])
    watchlist = build_watchlist(
        fetcher(tmp_path, router.client()),
        ecosystem="npm",
        registry="npmjs.org",
        built_at=BUILT,
        page_size=3,
    )
    assert list(watchlist.entries) == ["only"]


def test_build_fails_if_cutoff_never_reached(tmp_path: Path, router: Router) -> None:
    for page in (1, 2):
        router.add_json(
            page_url(page), [{"name": f"p{page}{i}", "downloads": 10**6} for i in range(3)]
        )
    with pytest.raises(FetchError, match="within 2 pages"):
        build_watchlist(
            fetcher(tmp_path, router.client()),
            ecosystem="npm",
            registry="npmjs.org",
            built_at=BUILT,
            page_size=3,
            max_pages=2,
        )


def test_build_rejects_error_and_non_list_responses(tmp_path: Path, router: Router) -> None:
    router.add_json(page_url(1), {"error": "nope"})
    with pytest.raises(FetchError, match="JSON list"):
        build_watchlist(
            fetcher(tmp_path, router.client()),
            ecosystem="npm",
            registry="npmjs.org",
            built_at=BUILT,
            page_size=3,
        )


def test_store_latest_respects_not_after(tmp_path: Path) -> None:
    store = RecordStore(tmp_path, Watchlist)
    assert store.latest_id("npm") is None
    for day in (1, 5, 9):
        (tmp_path / "npm").mkdir(exist_ok=True)
        (tmp_path / "npm" / f"202610{day:02d}T000000Z.json").write_text("{}")
    assert store.latest_id("npm") == "20261009T000000Z"
    assert store.latest_id("npm", not_after=datetime(2026, 10, 6, tzinfo=UTC)) == (
        "20261005T000000Z"
    )


def test_record_watchlist_keeps_only_the_derived_list(tmp_path: Path, router: Router) -> None:
    router.add_json(
        f"{BASE}?sort=downloads&order=desc&per_page=500&page=1",
        [{"name": "a", "downloads": 50_000}, {"name": "b", "downloads": 1}],
    )
    data = DataDir(tmp_path)
    watchlist, path, sha = record_watchlist(
        data,
        ecosystem="npm",
        registry="npmjs.org",
        built_at=BUILT,
        min_monthly_downloads=43_000,
        client=router.client(),
    )
    assert list(watchlist.entries) == ["a"]
    assert path == tmp_path / "watchlists" / "npm" / "20261027T060000Z.json"
    assert data.watchlists.load("npm", watchlist.id, sha256=sha) == watchlist
    assert not (tmp_path / "blobs").exists()  # raw pages not persisted
