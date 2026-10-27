"""npm implementation of the Ecosystem contract.

Discovery uses the replication `_changes` feed, metadata comes from full packuments, and artifacts
are registry tarballs. See docs/decisions/0002-data-sources.md.
"""

from __future__ import annotations

from typing import Final
from urllib.parse import quote

from kitsunox.core.interfaces import ChangeStub
from kitsunox.core.models import ArtifactRef, Change, Window
from kitsunox.ecosystems.npm.packument import ECOSYSTEM, Packument
from kitsunox.util.archive import ArtifactTree, extract_tar_gz
from kitsunox.util.hashing import verify_integrity
from kitsunox.util.http import FetchError, HttpFetcher

REPLICATE_URL: Final = "https://replicate.npmjs.com/registry"
REGISTRY_URL: Final = "https://registry.npmjs.org"
FEED_PAGE_LIMIT: Final = 10_000  # documented maximum for `_changes`
_JSON: Final = {"Accept": "application/json"}


class NpmEcosystem:
    name = ECOSYSTEM

    def __init__(self, fetcher: HttpFetcher) -> None:
        self.fetcher = fetcher

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
        response = self.fetcher.get(f"{REGISTRY_URL}/{quote(name, safe='@')}", headers=_JSON)
        if response.status == 404:
            return None
        if not response.ok:
            raise FetchError(f"packument {name}: HTTP {response.status}")
        return Packument(response.json(), expected_name=name)

    def build_changes(self, stub: ChangeStub, window: Window) -> list[Change]:
        packument = self.packument(stub.name)
        if packument is None:
            return []
        return packument.changes_in(window, feed_seq=stub.cursor)

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
