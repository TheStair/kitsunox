import hashlib
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from conftest import Router, TarEntry, make_tar_gz, sri_sha512
from kitsunox.core.models import ArtifactRef
from kitsunox.ecosystems.npm.registry import (
    DOWNLOADS_BULK_LIMIT,
    DOWNLOADS_URL,
    FEED_PAGE_LIMIT,
    REGISTRY_URL,
    REPLICATE_URL,
    NpmEcosystem,
    downloads_period,
    parse_downloads,
)
from kitsunox.stages.static import PARTIAL_POLICY
from kitsunox.util.hashing import IntegrityError
from kitsunox.util.http import BlobStore, FetchError, FetchMode, HttpFetcher, Snapshot
from kitsunox.util.partial import PARTIAL_CONTENT_TYPE


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


AS_OF = datetime(2026, 10, 27, 3, tzinfo=UTC)
PERIOD = "2026-10-19:2026-10-25"


def test_downloads_period_is_fixed_by_as_of() -> None:
    assert downloads_period(AS_OF) == (date(2026, 10, 19), date(2026, 10, 25))


def test_download_counts_bulk_scoped_and_missing(npm: NpmEcosystem, router: Router) -> None:
    router.add_json(
        f"{DOWNLOADS_URL}/{PERIOD}/a,b,c",
        {"a": {"downloads": 10, "package": "a"}, "b": None, "c": {"downloads": 0}},
    )
    router.add_json(f"{DOWNLOADS_URL}/{PERIOD}/@s%2Fone", {"downloads": 7, "package": "@s/one"})
    # "@s/two" has no route -> 404 -> "no stats"; "@s/err" -> 500 -> failed lookup
    router.add_json(f"{DOWNLOADS_URL}/{PERIOD}/@s%2Ferr", {}, status=500)
    result = npm.download_counts(["c", "@s/one", "a", "b", "@s/two", "@s/err"], AS_OF)
    assert result.counts == {"@s/one": 7, "@s/two": None, "a": 10, "b": None, "c": 0}
    assert result.source == "npm-downloads:2026-10-19..2026-10-25"
    assert result.period_days == 7


def test_download_counts_bulk_requests_are_chunked(npm: NpmEcosystem, router: Router) -> None:
    names = [f"p{i:03d}" for i in range(DOWNLOADS_BULK_LIMIT + 5)]
    npm.download_counts(names, AS_OF)
    assert len(router.requests) == 2
    assert router.requests[1].endswith("/p128,p129,p130,p131,p132")


@pytest.mark.parametrize(
    "doc", [[], {"x": {"downloads": -1}}, {"x": {"downloads": "many"}}, {"x": {"downloads": 1.5}}]
)
def test_parse_downloads_rejects_hostile_values(doc: object) -> None:
    with pytest.raises(ValueError):
        parse_downloads(doc, ["x"])


ELF = b"\x7fELF\x02\x01\x01\x00" + bytes(range(256)) * 64


def test_partial_reads_verify_the_whole_stream_and_store_only_the_re_pack(
    npm: NpmEcosystem, router: Router
) -> None:
    tarball = make_tar_gz(
        [
            TarEntry("package/package.json", b'{"scripts":{"postinstall":"node i.js"}}'),
            TarEntry("package/i.js", b"require('https')"),
            TarEntry("package/bin/x.node", ELF),
        ]
    )
    url = "https://registry.npmjs.org/x/-/x-1.0.0.tgz"
    router.add_bytes(url, tarball)
    artifact = ArtifactRef(url=url, integrity=sri_sha512(tarball))
    tree = npm.fetch_artifact_partial(artifact, PARTIAL_POLICY)
    assert sorted(tree) == ["i.js", "package.json"]
    assert [(o.path, o.reason, o.size) for o in tree.omitted] == [
        ("bin/x.node", "binary", len(ELF))
    ]
    (entry,) = npm.fetcher.snapshot.entries.values()
    assert entry.url == url and entry.content_type == PARTIAL_CONTENT_TYPE
    assert not npm.fetcher.store.exists(hashlib.sha256(tarball).hexdigest())

    router.add_bytes(url + "?other", tarball)
    with pytest.raises(IntegrityError, match="mismatch"):
        npm.fetch_artifact_partial(
            ArtifactRef(url=url + "?other", integrity=sri_sha512(b"else")), PARTIAL_POLICY
        )
    with pytest.raises(FetchError, match="no digest"):
        npm.fetch_artifact_partial(ArtifactRef(url=url), PARTIAL_POLICY)
    with pytest.raises(FetchError, match="HTTP 404"):
        npm.fetch_artifact_partial(
            ArtifactRef(url=url + "-gone", integrity=sri_sha512(tarball)), PARTIAL_POLICY
        )
