"""GitHub repositories as data, without the REST API (no token, no API quota).

- **Refs** come from git's smart-HTTP ref advertisement,
  `https://github.com/<owner>/<repo>.git/info/refs?service=git-upload-pack`: one response
  lists every branch and tag with its commit, which is what `git ls-remote` reads.
- **Contents** come from `https://codeload.github.com/<owner>/<repo>/tar.gz/<commit>`. A commit's
  tree never changes, so the archive is fetched through the immutable index: once per commit,
  across runs and across the packages of a monorepo.

Everything goes through `HttpFetcher`, so a run that used a repository can be replayed. Archive
contents are untrusted data: extracted with `extract_tar_gz`, never checked out or run.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

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
    def __init__(self, fetcher: HttpFetcher, *, limits: ExtractLimits = REPO_LIMITS) -> None:
        self.fetcher = fetcher
        self.limits = limits

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
        if not _SHA.match(commit):
            raise ValueError(f"not a full commit id: {commit!r}")
        url = f"{ARCHIVE_PREFIX}{repo}/tar.gz/{commit}"
        response = self.fetcher.get(url, immutable=True)
        if not response.ok:
            raise FetchError(f"{url}: HTTP {response.status}")
        prefix = f"{directory.strip('/')}/" if directory.strip("/") else ""
        tree = extract_tar_gz(
            response.body,
            strip_components=1,  # `<repo>-<commit>/`
            limits=self.limits,
            include=lambda path: path.startswith(prefix),
        )
        if not prefix:
            return tree
        return ArtifactTree(
            files={path.removeprefix(prefix): content for path, content in tree.files.items()},
            skipped=tree.skipped,
        )
