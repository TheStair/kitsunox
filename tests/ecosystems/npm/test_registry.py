from pathlib import Path

import pytest

from conftest import Router, TarEntry, make_tar_gz, sri_sha512
from kitsunox.core.models import ArtifactRef
from kitsunox.ecosystems.npm.registry import (
    FEED_PAGE_LIMIT,
    REGISTRY_URL,
    REPLICATE_URL,
    NpmEcosystem,
)
from kitsunox.util.hashing import IntegrityError
from kitsunox.util.http import BlobStore, FetchError, FetchMode, HttpFetcher, Snapshot


def feed_url(since: int) -> str:
    return f"{REPLICATE_URL}/_changes?since={since}&limit={FEED_PAGE_LIMIT}"


@pytest.fixture
def npm(tmp_path: Path, router: Router) -> NpmEcosystem:
    fetcher = HttpFetcher(
        store=BlobStore(tmp_path / "blobs"),
        snapshot=Snapshot(),
        mode=FetchMode.RECORD,
        client=router.client(),
        sleep=lambda _: None,
    )
    return NpmEcosystem(fetcher)


def test_feed_head(npm: NpmEcosystem, router: Router) -> None:
    router.add_json(f"{REPLICATE_URL}/", {"db_name": "registry", "update_seq": 140})
    assert npm.feed_head() == 140


def test_list_changes_pages_dedupes_and_bounds(npm: NpmEcosystem, router: Router) -> None:
    router.add_json(
        feed_url(100),
        {
            "results": [
                {"seq": 101, "id": "a", "changes": []},
                {"seq": 103, "id": "b", "changes": []},
                {"seq": 104, "id": "_design/app", "changes": []},
                {"seq": "bad", "id": "c"},
            ]
        },
    )
    router.add_json(
        feed_url(104),
        {"results": [{"seq": 106, "id": "a"}, {"seq": 120, "id": "late"}]},
    )
    stubs = npm.list_changes(100, 110)
    assert [(s.name, s.cursor) for s in stubs] == [("a", 106), ("b", 103)]


def test_list_changes_stops_when_feed_does_not_advance(npm: NpmEcosystem, router: Router) -> None:
    router.add_json(feed_url(5), {"results": [{"seq": 5, "id": "stuck"}]})
    assert npm.list_changes(5, 50) == []


def test_scoped_packument_url_and_404(npm: NpmEcosystem, router: Router) -> None:
    assert npm.packument("@scope/missing") is None
    assert router.requests == [f"{REGISTRY_URL}/@scope%2Fmissing"]


def test_packument_server_error_raises(npm: NpmEcosystem, router: Router) -> None:
    router.add_json(f"{REGISTRY_URL}/x", {}, status=403)
    with pytest.raises(FetchError, match="HTTP 403"):
        npm.packument("x")


def test_fetch_artifact_verifies_and_extracts(npm: NpmEcosystem, router: Router) -> None:
    tarball = make_tar_gz([TarEntry("package/index.js", b"module.exports = 1")])
    url = "https://registry.npmjs.org/x/-/x-1.0.0.tgz"
    router.add_bytes(url, tarball)
    tree = npm.fetch_artifact(ArtifactRef(url=url, integrity=sri_sha512(tarball)))
    assert list(tree) == ["index.js"]

    with pytest.raises(IntegrityError):
        npm.fetch_artifact(ArtifactRef(url=url, integrity=sri_sha512(b"something else")))
    with pytest.raises(FetchError, match="no digest"):
        npm.fetch_artifact(ArtifactRef(url=url))
