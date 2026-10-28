"""GitHub client: repo URLs, the smart-HTTP ref advertisement, and archives by commit."""

from pathlib import Path

import pytest

from conftest import Router, TarEntry, make_tar_gz
from kitsunox.githost.github import GitHub, GitHubRepo, parse_ref_advertisement
from kitsunox.util.http import BlobStore, FetchError, FetchMode, HttpFetcher, Snapshot

A, B, C = "a" * 40, "b" * 40, "c" * 40
REPO = GitHubRepo(owner="o", name="r")


def pkt(text: str) -> bytes:
    data = text.encode()
    return f"{len(data) + 4:04x}".encode() + data


ADVERTISEMENT = (
    pkt("# service=git-upload-pack\n")
    + b"0000"
    + pkt(f"{A} HEAD\0multi_ack symref=HEAD:refs/heads/main\n")
    + pkt(f"{A} refs/heads/main\n")
    + pkt(f"{B} refs/tags/v1.0.0\n")  # annotated: the tag object...
    + pkt(f"{C} refs/tags/v1.0.0^{{}}\n")  # ...peels to this commit
    + pkt(f"{A} refs/tags/v0.9.0\n")
    + b"0000"
)


def test_repo_from_url() -> None:
    assert GitHubRepo.from_url("https://github.com/o/r") == REPO
    assert GitHubRepo.from_url("https://gitlab.com/o/r") is None
    assert GitHubRepo.from_url("https://github.com/o/..") is None
    assert GitHubRepo.from_url(None) is None


def test_ref_advertisement_peels_annotated_tags() -> None:
    refs = parse_ref_advertisement(ADVERTISEMENT)
    assert refs == {"refs/heads/main": A, "refs/tags/v1.0.0": C, "refs/tags/v0.9.0": A}


def test_truncated_advertisement_is_an_error() -> None:
    with pytest.raises(FetchError, match="truncated"):
        parse_ref_advertisement(pkt(f"{A} refs/heads/main\n")[:-3])


def github(tmp_path: Path, router: Router) -> GitHub:
    return GitHub(
        HttpFetcher(
            store=BlobStore(tmp_path / "blobs"),
            snapshot=Snapshot(),
            mode=FetchMode.RECORD,
            immutable_index=tmp_path / "immutable",
            client=router.client(),
        )
    )


def test_refs_and_a_missing_repo(tmp_path: Path, router: Router) -> None:
    url = "https://github.com/o/r.git/info/refs?service=git-upload-pack"
    router.add_bytes(url, ADVERTISEMENT)
    assert github(tmp_path, router).refs(REPO) == parse_ref_advertisement(ADVERTISEMENT)
    router.add_bytes(url, b"", status=404)
    assert github(tmp_path, router).refs(REPO) is None


def test_archive_of_a_monorepo_directory(tmp_path: Path, router: Router) -> None:
    archive = make_tar_gz(
        [
            TarEntry(f"r-{A}/package.json", b"{}"),
            TarEntry(f"r-{A}/packages/kx/index.js", b"1"),
            TarEntry(f"r-{A}/packages/kx-extra/index.js", b"2"),  # same prefix, other package
        ]
    )
    router.add_bytes(f"https://codeload.github.com/o/r/tar.gz/{A}", archive)
    client = github(tmp_path, router)
    assert dict(client.archive(REPO, A, directory="packages/kx/")) == {"index.js": b"1"}
    assert set(client.archive(REPO, A)) == {
        "package.json",
        "packages/kx/index.js",
        "packages/kx-extra/index.js",
    }
    assert len(router.requests) == 1  # a commit's archive is immutable: fetched once
    with pytest.raises(ValueError, match="commit"):
        client.archive(REPO, "v1.0.0")
