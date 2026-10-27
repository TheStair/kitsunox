"""Watchlist: the set of packages popular enough that tarball stages always look at their changes.

Built weekly from packages.ecosyste.ms, which ranks a registry's packages by last-month
downloads. One build is ~60k npm packages in ~125 paged requests, against ~100k paced requests a
day for per-change lookups (see docs/decisions/0003-popularity-watchlist.md). Raw pages aren't
kept; the derived list is saved under `data/watchlists/<ecosystem>/<id>.json`, and every run
records which list (id + SHA-256) it used, so replays see the same popularity.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from kitsunox.core.models import Popularity, Record
from kitsunox.util.hashing import sha256_hex
from kitsunox.util.http import FetchError, HttpFetcher

ECOSYSTEMS_URL: Final = "https://packages.ecosyste.ms/api/v1/registries/{registry}/packages"
WEEKLY_CUTOFF: Final = 10_000  # roadmap decision 3, revised 2026-10-27
MONTHLY_CUTOFF: Final = 43_000  # ~WEEKLY_CUTOFF * 30 / 7; ecosyste.ms reports last-month counts
PAGE_SIZE: Final = 500
MAX_PAGES: Final = 1_000


class WatchEntry(Record):
    monthly_downloads: int
    dependents: int | None = None


class Watchlist(Record):
    ecosystem: str
    source: str
    built_at: datetime
    min_monthly_downloads: int
    entries: dict[str, WatchEntry]

    @property
    def id(self) -> str:
        return f"{self.built_at.astimezone(UTC):%Y%m%dT%H%M%SZ}"

    def lookup(self, names: Sequence[str]) -> Mapping[str, Popularity]:
        """Every name gets an answer: listed packages are watched; anything else is below the
        cutoff (or unknown to the source), so it isn't."""
        result = {}
        for name in names:
            entry = self.entries.get(name)
            result[name] = Popularity(
                source=f"watchlist:{self.id}",
                downloads=entry.monthly_downloads if entry else None,
                period_days=30,
                watched=entry is not None,
            )
        return result


def build_watchlist(
    fetcher: HttpFetcher,
    *,
    ecosystem: str,
    registry: str,
    built_at: datetime,
    min_monthly_downloads: int = MONTHLY_CUTOFF,
    page_size: int = PAGE_SIZE,
    max_pages: int = MAX_PAGES,
) -> Watchlist:
    """Page through the registry's packages by descending downloads until counts drop below the
    cutoff. Items with wrong field types are skipped (the source is third-party data)."""
    base = ECOSYSTEMS_URL.format(registry=registry)
    entries: dict[str, WatchEntry] = {}
    for page in range(1, max_pages + 1):
        url = f"{base}?sort=downloads&order=desc&per_page={page_size}&page={page}"
        response = fetcher.get(url, headers={"Accept": "application/json"})
        if not response.ok:
            raise FetchError(f"GET {url}: HTTP {response.status}")
        items = response.json()
        if not isinstance(items, list):
            raise FetchError(f"GET {url}: expected a JSON list")
        below_cutoff = False
        for item in items:
            name = item.get("name") if isinstance(item, dict) else None
            downloads = item.get("downloads") if isinstance(item, dict) else None
            if not isinstance(name, str) or not isinstance(downloads, int):
                continue
            if downloads < min_monthly_downloads:
                below_cutoff = True
                break
            dependents = item.get("dependent_packages_count")
            entries[name] = WatchEntry(
                monthly_downloads=downloads,
                dependents=dependents if isinstance(dependents, int) else None,
            )
        if below_cutoff or len(items) < page_size:
            break
    else:
        raise FetchError(f"watchlist did not reach the cutoff within {max_pages} pages")
    return Watchlist(
        ecosystem=ecosystem,
        source=f"{base}?sort=downloads",
        built_at=built_at,
        min_monthly_downloads=min_monthly_downloads,
        entries=dict(sorted(entries.items())),
    )


class WatchlistStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def path(self, ecosystem: str, watchlist_id: str) -> Path:
        return self.root / ecosystem / f"{watchlist_id}.json"

    def save(self, watchlist: Watchlist) -> tuple[Path, str]:
        path = self.path(watchlist.ecosystem, watchlist.id)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = watchlist.model_dump_json().encode()
        path.write_bytes(data)
        return path, sha256_hex(data)

    def load(self, ecosystem: str, watchlist_id: str, *, sha256: str | None = None) -> Watchlist:
        data = self.path(ecosystem, watchlist_id).read_bytes()
        if sha256 is not None and sha256_hex(data) != sha256:
            raise ValueError(f"watchlist {watchlist_id} changed since it was recorded")
        return Watchlist.model_validate_json(data)

    def sha256(self, ecosystem: str, watchlist_id: str) -> str:
        return sha256_hex(self.path(ecosystem, watchlist_id).read_bytes())

    def latest_id(self, ecosystem: str, *, not_after: datetime | None = None) -> str | None:
        """Newest watchlist built no later than `not_after` (ids sort chronologically)."""
        directory = self.root / ecosystem
        ids = sorted(p.stem for p in directory.glob("*.json")) if directory.exists() else []
        if not_after is not None:
            cutoff = f"{not_after.astimezone(UTC):%Y%m%dT%H%M%SZ}"
            ids = [i for i in ids if i <= cutoff]
        return ids[-1] if ids else None
