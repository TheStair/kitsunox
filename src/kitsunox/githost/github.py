"""GitHub repositories as data.

- **Refs** come from git's smart-HTTP ref advertisement,
  `https://github.com/<owner>/<repo>.git/info/refs?service=git-upload-pack`: one response
  lists every branch and tag with its commit, which is what `git ls-remote` reads.
- **Contents** come from `https://codeload.github.com/<owner>/<repo>/tar.gz/<commit>`. A commit's
  tree never changes, so the archive is fetched through the immutable index: once per commit,
  across runs and across the packages of a monorepo.

- **Facts** (`RepoFacts`: fork, age, stars, default branch) and whether a commit is on the
  default branch come from the REST API (`api.github.com`), only with a token
  (`GITHUB_TOKEN`; 5,000 requests an hour). The token goes in a request header, which
  `request_key` and the snapshot never record, and only to `API_PREFIX` URLs.

Everything goes through `HttpFetcher`, so a run that used a repository can be replayed. Archive
contents and API answers are untrusted data: archives are extracted with `extract_tar_gz`,
never checked out or run.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from pydantic import ValidationError

from kitsunox.core.models import Record
from kitsunox.util.archive import ArtifactTree, ExtractLimits, extract_tar_gz
from kitsunox.util.http import FetchError, HttpFetcher

# Larger than a package's limits: a repository holds sources, tests and fixtures, and a
# monorepo holds many packages. Only the package's directory is kept in memory.
REPO_LIMITS: Final = ExtractLimits(
    max_compressed_bytes=128 * 1024 * 1024,
    max_total_bytes=1024 * 1024 * 1024,
    max_file_bytes=64 * 1024 * 1024,
    max_files=300_000,
)
ARCHIVE_PREFIX: Final = "https://codeload.github.com/"
_REPO_URL: Final = re.compile(r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)$")
_SHA: Final = re.compile(r"^[0-9a-f]{40}$")
API_PREFIX: Final = "https://api.github.com/repos/"
TOKEN_ENV: Final = "GITHUB_TOKEN"  # noqa: S105  (a variable name; the token is in `.env`)
# `Accept` is part of the request key; the version header pins the response format.
API_HEADERS: Final = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
# Repository metadata is a few KB. A compare page with one commit and no file list (page 2,
# see `on_branch`) was 18 KB for `npm/node-semver`; a commit with a huge message stays below.
API_MAX_BYTES: Final = 2 * 1024 * 1024


class RepoFacts(Record):
    """What the REST API said about a repository when it was fetched (stars change; the
    fetch is recorded, so a replay reads the same)."""

    full_name: str
    fork: bool
    archived: bool
    created_at: datetime
    stars: int
    default_branch: str


@dataclass(frozen=True)
class GitHubRepo:
    owner: str
    name: str

    @classmethod
    def from_url(cls, url: str | None) -> GitHubRepo | None:
        """From a normalised `https://github.com/<owner>/<repo>` (see
        `normalize_repository_url`); None for anything else."""
        match = _REPO_URL.match(url or "")
        if match is None or match.group(2) in (".", ".."):
            return None
        return cls(owner=match.group(1), name=match.group(2))

    def __str__(self) -> str:
        return f"{self.owner}/{self.name}"


def parse_ref_advertisement(body: bytes) -> dict[str, str]:
    """`{ref name: commit}` from a smart-HTTP ref advertisement (pkt-lines). Annotated tags are
    peeled: `refs/tags/v1` maps to the commit, not the tag object."""
    refs: dict[str, str] = {}
    peeled: dict[str, str] = {}
    pos = 0
    while pos + 4 <= len(body):
        try:
            length = int(body[pos : pos + 4], 16)
        except ValueError as exc:
            raise FetchError("ref advertisement: malformed pkt-line") from exc
        if length == 0:  # flush-pkt
            pos += 4
            continue
        if length < 4 or pos + length > len(body):
            raise FetchError("ref advertisement: truncated pkt-line")
        line = body[pos + 4 : pos + length].split(b"\0", 1)[0].rstrip(b"\n")
        pos += length
        sha, _, name = line.decode("utf-8", errors="replace").partition(" ")
        if not _SHA.match(sha) or not name.startswith("refs/"):
            continue  # the `# service=` header, capabilities-only lines
        if name.endswith("^{}"):
            peeled[name.removesuffix("^{}")] = sha
        else:
            refs[name] = sha
    return refs | peeled


def is_archive_url(url: str) -> bool:
    """A repository archive (what `GitHub.archive` fetches): the bulk of Stage 4's downloads,
    which retention may keep for less time than the rest of a run."""
    return url.startswith(ARCHIVE_PREFIX)


class GitHub:
    def __init__(
        self,
        fetcher: HttpFetcher,
        *,
        limits: ExtractLimits = REPO_LIMITS,
        token: str | None = None,
    ) -> None:
        self.fetcher = fetcher
        self.limits = limits
        self._token = token

    @property
    def has_api(self) -> bool:
        """Whether REST API calls can be made (a token was given). Without one GitHub allows
        60 an hour, too few to be worth spending."""
        return self._token is not None

    def facts(self, repo: GitHubRepo) -> RepoFacts | None:
        """The repository's metadata, or None if the API doesn't show it (404: gone or
        private; 451: blocked)."""
        body = self._api(f"{API_PREFIX}{repo}")
        if body is None:
            return None
        try:
            raw = json.loads(body)
            return RepoFacts(
                full_name=raw["full_name"],
                fork=raw["fork"],
                archived=raw["archived"],
                created_at=raw["created_at"],
                stars=raw["stargazers_count"],
                default_branch=raw["default_branch"],
            )
        except (ValueError, TypeError, KeyError, ValidationError) as exc:
            raise FetchError(f"{repo}: malformed repository metadata") from exc

    def on_branch(self, repo: GitHubRepo, commit: str, head: str) -> bool:
        """Whether `commit` is `head` or one of its ancestors (`head`: a branch's commit, from
        `refs`), by the compare API: `head` is then "ahead" of `commit` or "identical". A
        commit only a fork has, or one GitHub doesn't know, is not. Page 2 with one commit a
        page: the status and counts without the file list, which page 1 carries (up to 300
        files with patches)."""
        if not (_SHA.match(commit) and _SHA.match(head)):
            raise ValueError(f"not full commit ids: {commit!r}, {head!r}")
        body = self._api(f"{API_PREFIX}{repo}/compare/{commit}...{head}?per_page=1&page=2")
        if body is None:
            return False
        try:
            status = json.loads(body)["status"]
        except (ValueError, TypeError, KeyError) as exc:
            raise FetchError(f"{repo}: malformed comparison") from exc
        return status in ("ahead", "identical")

    def _api(self, url: str) -> bytes | None:
        """A REST API response body, or None for 404 and 451. Anything else that isn't 200
        (401 bad token, 403 rate limit, 422) is a `FetchError`; 429 and 5xx are retried by the
        fetcher first. The token is sent only here, only to `API_PREFIX`."""
        if self._token is None:
            raise FetchError("GitHub API: no token")
        if not url.startswith(API_PREFIX):
            raise ValueError(f"not a GitHub API URL: {url!r}")
        headers = {**API_HEADERS, "Authorization": f"Bearer {self._token}"}
        response = self.fetcher.get(url, headers=headers)
        if response.status in (404, 451):
            return None
        if response.status != 200:
            raise FetchError(f"GitHub API {url.removeprefix(API_PREFIX)}: HTTP {response.status}")
        if len(response.body) > API_MAX_BYTES:
            raise FetchError(f"GitHub API {url.removeprefix(API_PREFIX)}: response too large")
        return response.body

    def refs(self, repo: GitHubRepo) -> Mapping[str, str] | None:
        """Every branch and tag, or None if the repository doesn't exist (or is private)."""
        url = f"https://github.com/{repo}.git/info/refs?service=git-upload-pack"
        response = self.fetcher.get(url)
        if response.status in (401, 403, 404):
            return None
        if not response.ok:
            raise FetchError(f"{url}: HTTP {response.status}")
        return parse_ref_advertisement(response.body)

    def archive(self, repo: GitHubRepo, commit: str, *, directory: str = "") -> ArtifactTree:
        """The files at `commit`, or only those under `directory` (paths relative to it)."""
        return self.extract(self.archive_body(repo, commit), directory=directory)

    def archive_body(self, repo: GitHubRepo, commit: str) -> bytes:
        """The archive at `commit`, compressed (at most `limits.max_compressed_bytes` once
        extracted): fetching and extracting are separate so a caller can bound how many
        archives are extracted at once (`stages/repo.py`)."""
        if not _SHA.match(commit):
            raise ValueError(f"not a full commit id: {commit!r}")
        url = f"{ARCHIVE_PREFIX}{repo}/tar.gz/{commit}"
        response = self.fetcher.get(url, immutable=True)
        if not response.ok:
            raise FetchError(f"{url}: HTTP {response.status}")
        return response.body

    def extract(self, body: bytes, *, directory: str = "") -> ArtifactTree:
        """An archive's files, or only those under `directory` (paths relative to it)."""
        return extract_archive(body, limits=self.limits, directory=directory)


def extract_archive(
    body: bytes, *, limits: ExtractLimits = REPO_LIMITS, directory: str = ""
) -> ArtifactTree:
    """A GitHub archive's files, or only those under `directory` (paths relative to it). A
    plain function, so a process pool can run it (`stages/repo.py`)."""
    prefix = f"{directory.strip('/')}/" if directory.strip("/") else ""
    tree = extract_tar_gz(
        body,
        strip_components=1,  # `<repo>-<commit>/`
        limits=limits,
        include=lambda path: path.startswith(prefix),
        hidden_entries=False,  # GitHub writes these archives; nothing is hidden in them
    )
    if not prefix:
        return tree
    return ArtifactTree(
        files={path.removeprefix(prefix): content for path, content in tree.files.items()},
        skipped=tree.skipped,
    )
