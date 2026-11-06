"""GitHub client: repo URLs, the smart-HTTP ref advertisement, and archives by commit."""

from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from conftest import Router, TarEntry, make_tar_gz
from kitsunox.githost.github import CompareStatus, GitHub, GitHubRepo, parse_ref_advertisement
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


# The REST API (repository facts, default-branch ancestry), with a token.

TOKEN = "test-token-not-a-secret"  # noqa: S105
FACTS_URL = "https://api.github.com/repos/o/r"
FACTS = {
    "full_name": "o/r",
    "fork": False,
    "archived": False,
    "created_at": "2020-01-02T03:04:05Z",
    "stargazers_count": 42,
    "default_branch": "main",
    "owner": {"login": "o"},
}


def compare_url(base: str, head: str) -> str:
    return f"https://api.github.com/repos/o/r/compare/{base}...{head}?per_page=1&page=2"


def api(tmp_path: Path, router: Router, token: str | None = TOKEN) -> GitHub:
    return GitHub(
        HttpFetcher(
            store=BlobStore(tmp_path / "blobs"),
            snapshot=Snapshot(),
            mode=FetchMode.RECORD,
            client=router.client(),
        ),
        token=token,
    )


def test_facts_from_the_api(tmp_path: Path, router: Router) -> None:
    router.add_json(FACTS_URL, FACTS)
    facts = api(tmp_path, router).facts(REPO)
    assert facts is not None
    assert (facts.full_name, facts.fork, facts.stars, facts.default_branch) == (
        "o/r",
        False,
        42,
        "main",
    )
    assert facts.created_at.year == 2020


def test_a_repository_the_api_doesnt_show_has_no_facts(tmp_path: Path, router: Router) -> None:
    assert api(tmp_path, router).facts(REPO) is None  # 404
    router.add_json(FACTS_URL, {"message": "blocked"}, status=451)
    assert api(tmp_path / "2", router).facts(REPO) is None


def test_rate_limits_and_malformed_answers_are_errors(tmp_path: Path, router: Router) -> None:
    router.add_json(FACTS_URL, {"message": "API rate limit exceeded"}, status=403)
    with pytest.raises(FetchError, match="HTTP 403"):
        api(tmp_path, router).facts(REPO)
    router.add_json(FACTS_URL, {"full_name": "o/r", "fork": "maybe"})
    with pytest.raises(FetchError, match="malformed"):
        api(tmp_path / "2", router).facts(REPO)
    router.add_bytes(FACTS_URL, b"<html>")
    with pytest.raises(FetchError, match="malformed"):
        api(tmp_path / "3", router).facts(REPO)


def test_without_a_token_no_api_request_is_sent(tmp_path: Path, router: Router) -> None:
    github = api(tmp_path, router, token=None)
    assert not github.has_api
    with pytest.raises(FetchError, match="no token"):
        github.facts(REPO)
    assert router.requests == []


def test_the_token_is_sent_but_never_recorded(tmp_path: Path) -> None:
    seen: list[httpx.Headers] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers)
        return httpx.Response(200, json=FACTS)

    snapshot = Snapshot()
    fetcher = HttpFetcher(
        store=BlobStore(tmp_path / "blobs"),
        snapshot=snapshot,
        mode=FetchMode.RECORD,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    GitHub(fetcher, token=TOKEN).facts(REPO)
    assert seen[0]["authorization"] == f"Bearer {TOKEN}"
    snapshot.save(tmp_path / "snap.json")
    assert TOKEN not in (tmp_path / "snap.json").read_text()
    for blob in (tmp_path / "blobs").rglob("*"):
        if blob.is_file():
            assert TOKEN.encode() not in blob.read_bytes()


def test_the_token_goes_only_to_the_api(tmp_path: Path, router: Router) -> None:
    with pytest.raises(ValueError, match="not a GitHub API URL"):
        api(tmp_path, router)._api("https://evil.example/repos/o/r")
    assert router.requests == []


@pytest.mark.parametrize(
    ("status", "on"),
    [("ahead", True), ("identical", True), ("behind", False), ("diverged", False)],
)
def test_on_branch_reads_the_compare_status(
    tmp_path: Path, router: Router, status: str, on: bool
) -> None:
    router.add_json(compare_url(A, B), {"status": status, "ahead_by": 1, "behind_by": 0})
    assert api(tmp_path, router).on_branch(REPO, A, B) is on


def test_a_commit_github_doesnt_know_is_not_on_the_branch(tmp_path: Path, router: Router) -> None:
    assert api(tmp_path, router).on_branch(REPO, A, B) is False  # 404
    with pytest.raises(ValueError, match="full commit"):
        api(tmp_path, router).on_branch(REPO, "main", B)


def test_a_redirect_to_another_host_does_not_carry_the_token(tmp_path: Path) -> None:
    seen: dict[str, str | None] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen[request.url.host] = request.headers.get("authorization")
        if request.url.host == "api.github.com":
            return httpx.Response(301, headers={"Location": "https://elsewhere.example/x"})
        return httpx.Response(200, json=FACTS)

    fetcher = HttpFetcher(
        store=BlobStore(tmp_path / "blobs"),
        snapshot=Snapshot(),
        mode=FetchMode.RECORD,
        client=httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True),
    )
    GitHub(fetcher, token=TOKEN).facts(REPO)
    assert seen == {"api.github.com": f"Bearer {TOKEN}", "elsewhere.example": None}


def test_compare_status_reads_the_counts(tmp_path: Path, router: Router) -> None:
    router.add_json(compare_url(A, B), {"status": "behind", "ahead_by": 0, "behind_by": 3})
    status = api(tmp_path, router).compare_status(REPO, A, B)
    assert status == CompareStatus(status="behind", ahead_by=0, behind_by=3)
    assert api(tmp_path / "2", router).compare_status(REPO, B, A) is None  # 404
    router.add_json(compare_url(B, A), {"status": "ahead"})
    with pytest.raises(FetchError, match="malformed comparison"):
        api(tmp_path / "3", router).compare_status(REPO, B, A)


def test_commit_date_is_the_committer_date(tmp_path: Path, router: Router) -> None:
    url = f"https://api.github.com/repos/{REPO}/git/commits/{A}"
    router.add_json(
        url,
        {"author": {"date": "2020-01-01T00:00:00Z"}, "committer": {"date": "2026-11-03T12:00:00Z"}},
    )
    assert api(tmp_path, router).commit_date(REPO, A) == datetime(2026, 11, 3, 12, tzinfo=UTC)
    assert api(tmp_path / "2", router).commit_date(REPO, B) is None  # 404
    for body in (
        {"committer": None},
        {"committer": {"date": "yesterday"}},
        {"committer": {"date": "2026-11-03T12:00:00"}},
    ):
        router.add_json(url, body)
        with pytest.raises(FetchError, match=r"malformed commit|time zone"):
            api(tmp_path / str(len(router.requests)), router).commit_date(REPO, A)
    with pytest.raises(ValueError, match="full commit"):
        api(tmp_path, router).commit_date(REPO, "main")
