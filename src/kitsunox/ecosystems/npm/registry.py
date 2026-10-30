"""npm implementation of the Ecosystem contract.

Discovery uses the replication `_changes` feed, metadata comes from full packuments, and artifacts
are registry tarballs. See docs/decisions/0002-data-sources.md.
"""

from __future__ import annotations

from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, date, datetime, timedelta
from typing import Final
from urllib.parse import quote

from kitsunox.core.interfaces import DIFF_BASE, ChangeStub, DownloadCounts, PackageChanges
from kitsunox.core.models import ArtifactRef, Window
from kitsunox.ecosystems.npm.packument import ECOSYSTEM, Packument
from kitsunox.util.archive import ArtifactTree, extract_tar_gz
from kitsunox.util.hashing import verify_integrity
from kitsunox.util.http import FetchError, HttpFetcher

REPLICATE_URL: Final = "https://replicate.npmjs.com/registry"
REGISTRY_URL: Final = "https://registry.npmjs.org"
DOWNLOADS_URL: Final = "https://api.npmjs.org/downloads/point"
ECOSYSTEMS_REGISTRY: Final = "npmjs.org"  # registry id on packages.ecosyste.ms
FEED_PAGE_LIMIT: Final = 10_000  # documented maximum for `_changes`
DOWNLOADS_BULK_LIMIT: Final = 128  # documented maximum; bulk lookups reject scoped names
# Download stats for a day can lag; end the 7-day period two days before as_of to be safe.
DOWNLOADS_LAG_DAYS: Final = 2
# Measured 2026-10-27: sequential requests (~2.4/s) never hit HTTP 429; two in parallel did
# almost immediately. Space requests to the downloads API accordingly.
DOWNLOADS_MIN_INTERVAL: Final = 0.5
_JSON: Final = {"Accept": "application/json"}


class NpmEcosystem:
    name = ECOSYSTEM

    def __init__(self, fetcher: HttpFetcher, *, workers: int = 8) -> None:
        self.fetcher = fetcher
        self.workers = workers
        fetcher.set_min_interval("api.npmjs.org", DOWNLOADS_MIN_INTERVAL)

    def feed_head(self) -> int:
        doc = self._json(f"{REPLICATE_URL}/")
        seq = doc.get("update_seq") if isinstance(doc, dict) else None
        if not isinstance(seq, int):
            raise FetchError("replicate root has no integer update_seq")
        return seq

    def list_changes(self, since: int, until: int) -> list[ChangeStub]:
        latest: dict[str, int] = {}
        cursor = since
        while cursor < until:
            url = f"{REPLICATE_URL}/_changes?since={cursor}&limit={FEED_PAGE_LIMIT}"
            doc = self._json(url)
            results = doc.get("results") if isinstance(doc, dict) else None
            if not isinstance(results, list) or not results:
                break
            next_cursor = cursor
            for row in results:
                if not isinstance(row, dict):
                    continue
                seq, name = row.get("seq"), row.get("id")
                if not isinstance(seq, int) or not isinstance(name, str):
                    continue
                next_cursor = max(next_cursor, seq)
                if since < seq <= until and not name.startswith("_design/"):
                    latest[name] = max(seq, latest.get(name, seq))
            if next_cursor <= cursor:
                break  # the feed did not advance; stop rather than loop forever
            cursor = next_cursor
        return [ChangeStub(name=n, cursor=s) for n, s in sorted(latest.items())]

    def packument(self, name: str) -> Packument | None:
        """Full packument, or None if the package no longer exists (404)."""
        response = self.fetcher.get(packument_url(name), headers=_JSON)
        if response.status == 404:
            return None
        if not response.ok:
            raise FetchError(f"packument {name}: HTTP {response.status}")
        return Packument(response.json(), expected_name=name)

    def build_changes(
        self, stub: ChangeStub, window: Window, *, diff_base: int = DIFF_BASE
    ) -> PackageChanges:
        packument = self.packument(stub.name)
        if packument is None:
            return PackageChanges()
        return PackageChanges(
            changes=tuple(packument.changes_in(window, feed_seq=stub.cursor, diff_base=diff_base)),
            modified_at=packument.modified_at,
        )

    def download_counts(self, names: Sequence[str], as_of: datetime) -> DownloadCounts:
        """Weekly downloads from the npm downloads API. Slow for scoped names (one paced
        request each); the default popularity source is the watchlist instead."""
        start, end = downloads_period(as_of)
        unscoped = sorted({n for n in names if not n.startswith("@")})
        scoped = sorted({n for n in names if n.startswith("@")})
        batches = [
            unscoped[i : i + DOWNLOADS_BULK_LIMIT]
            for i in range(0, len(unscoped), DOWNLOADS_BULK_LIMIT)
        ] + [[n] for n in scoped]

        def lookup(batch: list[str]) -> dict[str, int | None]:
            try:
                return self._downloads(batch, f"{start.isoformat()}:{end.isoformat()}")
            except FetchError, ValueError:
                return {}  # absent names are reported as failed lookups by the caller

        result: dict[str, int | None] = {}
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            for counts in pool.map(lookup, batches):
                result.update(counts)
        return DownloadCounts(
            source=f"npm-downloads:{start.isoformat()}..{end.isoformat()}",
            period_days=7,
            counts=dict(sorted(result.items())),
        )

    def _downloads(self, batch: list[str], period: str) -> dict[str, int | None]:
        joined = ",".join(quote(n, safe="@") for n in batch)
        # Counts for a period that has already ended are final, so successful responses are
        # reused across runs (each package is looked up at most once per period).
        response = self.fetcher.get(
            f"{DOWNLOADS_URL}/{period}/{joined}", headers=_JSON, immutable=True
        )
        if response.status == 404:
            return dict.fromkeys(batch)  # no stats for any of these names
        if not response.ok:
            raise FetchError(f"downloads {period}: HTTP {response.status}")
        return parse_downloads(response.json(), batch)

    def fetch_artifact(self, artifact: ArtifactRef) -> ArtifactTree:
        if not (artifact.integrity or artifact.shasum):
            raise FetchError(f"{artifact.url}: no digest to verify against")
        response = self.fetcher.get(artifact.url, immutable=True)
        if not response.ok:
            raise FetchError(f"{artifact.url}: HTTP {response.status}")
        verify_integrity(response.body, integrity=artifact.integrity, shasum=artifact.shasum)
        return extract_tar_gz(response.body, strip_components=1)

    def _json(self, url: str) -> object:
        response = self.fetcher.get(url, headers=_JSON)
        if not response.ok:
            raise FetchError(f"GET {url}: HTTP {response.status}")
        return response.json()


def downloads_period(as_of: datetime) -> tuple[date, date]:
    """The 7 whole UTC days ending DOWNLOADS_LAG_DAYS before `as_of`."""
    end = as_of.astimezone(UTC).date() - timedelta(days=DOWNLOADS_LAG_DAYS)
    return end - timedelta(days=6), end


def parse_downloads(doc: object, batch: Sequence[str]) -> dict[str, int | None]:
    """Parse either response shape: a single `{"package", "downloads"}` object, or a bulk
    `{name: {...} | null}` mapping. Names in the batch but missing from the response map to
    None (no stats); values of the wrong type are rejected."""
    if not isinstance(doc, dict):
        raise ValueError("downloads response is not an object")
    if "downloads" in doc and "package" in doc:
        doc = {doc["package"]: doc}
    counts: dict[str, int | None] = {}
    for name in batch:
        entry = doc.get(name)
        downloads = entry.get("downloads") if isinstance(entry, dict) else None
        if downloads is not None and (not isinstance(downloads, int) or downloads < 0):
            raise ValueError(f"bad download count for {name}")
        counts[name] = downloads
    return counts


def packument_url(name: str) -> str:
    return f"{REGISTRY_URL}/{quote(name, safe='@')}"
