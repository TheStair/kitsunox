"""Stage 4's tarball-vs-repo comparison: what a release ships against its source repository at
the commit it was built from.

Many attacks publish straight to the registry with a stolen token, so the code never passes
through git. Comparing the two finds it without knowing what the code does. Measured on
`day1` benign updates (40 sampled, 2026-10-28):

- 30% can't be compared: the recorded commit was never pushed (HTTP 404), or the repository
  is a monorepo over `REPO_LIMITS`.
- 57% ship only build output (`dist/`, `lib/`, `es/`) that isn't in git, so "a file the repo
  doesn't have" means little by itself. It counts when the file's directory is in the repo
  and nothing there could have compiled to it (`compare_trees`): the Shai-Hulud 2.0 payload
  (`setup_bun.js`, `bun_environment.js` at the package root) has exactly that shape.
- A shipped file that *is* in the repo at the same path, with different content, was rare
  (1 of 28). That is where a payload injected into an existing source file shows.

Which commit a release came from, and where its package lives in the repository, are ecosystem
questions (`ReleaseSource`); the comparison itself is not.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from typing import Final, Protocol

from kitsunox.core.models import Change, Record
from kitsunox.githost.github import ARCHIVE_PREFIX, GitHub, GitHubRepo
from kitsunox.lang.javascript import language_for
from kitsunox.util.hashing import sha256_hex
from kitsunox.util.http import FetchError, TransientFetchError

Tree = Mapping[str, bytes]
MAX_LISTED: Final = 20


class ReleaseSource(Record):
    """Where a release's code should come from."""

    repo: str  # `owner/name`
    directory: str = ""  # the package's directory in a monorepo
    commit: str
    how: str  # e.g. `gitHead`, `tag refs/tags/v1.2.3`


class ManifestDifference(Record):
    """One way the release's manifest differs from the repository's at the same commit, e.g.
    `scripts.postinstall` present only in the release. Values are untrusted snippets."""

    field: str
    package: str | None
    repo: str | None
    # For an install hook: a repository file that writes it into the release's manifest (a
    # build script), when the files the hook runs are in the repository byte for byte.
    built_by: str | None = None


class RepoComparison(Record):
    """A release's code files against the repository at its commit. `unavailable` says why no
    comparison was made (no repository, no commit for this version, archive too large); the
    lists are then empty. `transient`: a repository request failed on the network
    (`TransientFetchError`), so trying again may work; Stage 4 retries those (`correlate_run`).
    `files_transient`: the release's own files failed on the network instead; Stage 2 owns
    those and redoes the run on the next tick, so Stage 4 doesn't retry them. Paths are sorted
    and capped at `MAX_LISTED`; counts are not."""

    source: ReleaseSource | None = None
    unavailable: str | None = None
    transient: bool = False
    files_transient: bool = False
    code_files: int = 0
    identical: int = 0
    differing: tuple[str, ...] = ()
    differing_count: int = 0
    not_in_repo_count: int = 0
    unexplained: tuple[str, ...] = ()  # not in the repo, and not build output (`compare_trees`)
    unexplained_count: int = 0
    manifest: tuple[ManifestDifference, ...] = ()


class Locator(Protocol):
    """Ecosystem knowledge: which repository and commit a change's release came from."""

    def repository(self, change: Change) -> tuple[GitHubRepo, str] | None: ...

    def commit(self, change: Change, refs: Mapping[str, str]) -> tuple[str, str] | None: ...

    def package_directory(self, change: Change, repo: Tree) -> str | None:
        """Where the release's package is in a repository whose release didn't say: the
        directory of its manifest, or None if the repository has none for it."""
        ...

    def manifest_differences(
        self, package: Tree, repo: Tree, whole: Tree | None = None
    ) -> tuple[ManifestDifference, ...]:
        """What the release's manifest declares that the repository's doesn't. `repo` is the
        package's directory; `whole` the repository (a monorepo's build scripts sit outside the
        package's directory)."""
        ...


@dataclass(frozen=True)
class TreeComparison:
    code_files: int
    identical: int
    differing: list[str]
    missing: list[str]
    unexplained: list[str]


def compare_trees(package: Tree, repo: Tree, whole: Tree | None = None) -> TreeComparison:
    """The package's JavaScript/TypeScript files against the repository (line endings
    normalised). A missing file is *unexplained* when its directory is in the repository (the
    root always is) and no file there shares its stem: `lib/x.js` next to `lib/x.ts` is compiled
    output, and `dist/` that git ignores is build output, but a new `setup_bun.js` at the root
    is neither. A missing file whose content is somewhere in the repository (`whole`, else
    `repo`), byte for byte, is explained: a build copied it there (`nutui-react` ships its
    `scripts/postinstall.js` as `postinstall.js`)."""
    contents: set[str] | None = None  # every repository file's hash, once a file needs it
    directories: dict[str, set[str]] = {}
    for path in repo:
        directory, _, name = path.rpartition("/")
        directories.setdefault(directory, set()).add(_stem(name))
    code = sorted(p for p in package if language_for(p) is not None)
    identical, differing, missing, unexplained = 0, [], [], []
    for path in code:
        if path in repo:
            if _normalised(package[path]) == _normalised(repo[path]):
                identical += 1
            else:
                differing.append(path)
            continue
        missing.append(path)
        directory, _, name = path.rpartition("/")
        stems = directories.get(directory)
        if stems is None or _stem(name) in stems:
            continue
        if contents is None:
            searched = whole if whole is not None else repo
            contents = {_normalised(content) for content in searched.values()}
        if _normalised(package[path]) not in contents:
            unexplained.append(path)
    return TreeComparison(len(code), identical, differing, missing, unexplained)


def _stem(name: str) -> str:
    return name.split(".", 1)[0]


def _normalised(content: bytes) -> str:
    return sha256_hex(content.replace(b"\r\n", b"\n"))


@dataclass(frozen=True)
class NetworkRequests:
    """What one pass of repository lookups asked of the network: how many distinct requests it
    sent, and the label and error of each that failed there (`TransientFetchError`), sorted.
    Requests the fetcher answered from its snapshot or immutable index, and requests refused
    because they had already failed in the pass, are not counted."""

    sent: int = 0
    errors: tuple[tuple[str, str], ...] = ()

    @property
    def failed(self) -> int:
        return len(self.errors)


@dataclass(frozen=True)
class _Request:
    """One repository request: its refs (`commit` None) or its archive at a commit."""

    repo: GitHubRepo
    commit: str | None = None

    @property
    def label(self) -> str:
        if self.commit is None:
            return f"{self.repo} refs"
        return f"{self.repo}@{self.commit[:12]} archive"


class RepoNetworkError(TransientFetchError):
    """A repository request failed on the network, now or earlier in the pass. The message
    names the request, not the error, so every version that needed it reads the same whichever
    worker thread asked first; the error itself is in `RepoMemory.requests()`."""

    def __init__(self, request: _Request) -> None:
        super().__init__(f"{request.label} unavailable")


# The URLs `GitHub.refs` and `GitHub.archive` request, to ask the fetcher whether it already
# holds them. If they drift from `githost/github.py`, cached requests just fail fast again;
# `test_a_cached_archive_is_never_refused` notices.
def _refs_url(repo: GitHubRepo) -> str:
    return f"https://github.com/{repo}.git/info/refs?service=git-upload-pack"


def _archive_url(repo: GitHubRepo, commit: str) -> str:
    return f"{ARCHIVE_PREFIX}{repo}/tar.gz/{commit}"


ARCHIVES_IN_MEMORY: Final = 3


class RepoMemory:
    """What the lookups of one Stage 4 run share about repositories, across worker threads.
    Each request (a repository's refs, or its archive at one commit) goes to the network at
    most once per pass, whatever the number of workers or versions that need it:

    - **One thread at a time per request:** versions needing a request another worker is
      sending wait for it, then use its response (refs are kept for the run, archives come
      from the fetcher's snapshot) or its failure.
    - **Failures, kept for one pass, per request:** once a request raised
      `TransientFetchError`, the versions that need it fail at once with the same
      `RepoNetworkError`, instead of each paying `HttpFetcher`'s back-off again during an
      outage. Other commits of the same repository are unaffected, and a response the fetcher
      already holds is always served. `new_pass()` forgets the failures, so a retry pass goes
      back to the network.
    - **Rejections, kept for the run:** a request the fetcher rejects without recording a
      response (a body over its size limit, a bad redirect) or whose archive can't be read
      raises the same `FetchError` or `ValueError` text for every version that needs it, instead
      of each downloading or extracting it again. Those are permanent, so a retry pass doesn't
      repeat them.
    - **At most `ARCHIVES_IN_MEMORY` archives extracted at once**, across threads: an
      extracted repository can hold up to 1 GB (`REPO_LIMITS`), and eight workers each
      holding one, with allocator fragmentation on top, took Stage 4 on a 110k-version run to
      18 GB on 2026-10-30. Downloads stay parallel; `archive` holds a slot from extraction
      until the caller is done with the tree.
    """

    def __init__(self, refs: dict[GitHubRepo, Mapping[str, str] | None] | None = None) -> None:
        self._lock = threading.Lock()
        self._refs = refs if refs is not None else {}
        self._request_locks: dict[_Request, threading.Lock] = {}
        self._sent: set[_Request] = set()
        self._failed: dict[_Request, str] = {}
        self._rejected: dict[_Request, FetchError | ValueError] = {}
        self._unreadable: dict[tuple[_Request, str], ValueError] = {}
        self._slots = threading.BoundedSemaphore(ARCHIVES_IN_MEMORY)

    def new_pass(self) -> None:
        with self._lock:
            self._sent.clear()
            self._failed.clear()

    def requests(self) -> NetworkRequests:
        """The current pass's network requests (since `new_pass`, or the start)."""
        with self._lock:
            errors = sorted((request.label, error) for request, error in self._failed.items())
            return NetworkRequests(sent=len(self._sent), errors=tuple(errors))

    def refs(self, github: GitHub, repo: GitHubRepo) -> Mapping[str, str] | None:
        request = _Request(repo)
        with self._request_lock(request):
            with self._lock:
                if repo in self._refs:
                    return self._refs[repo]
            if github.fetcher.needs_network(_refs_url(repo)):
                refs = self._send(request, lambda: github.refs(repo))
            else:
                refs = github.refs(repo)
            with self._lock:
                self._refs[repo] = refs
            return refs

    @contextmanager
    def archive(
        self, github: GitHub, repo: GitHubRepo, commit: str, directory: str
    ) -> Iterator[Tree]:
        """The tree at `commit` (under `directory`), held in one of the extraction slots
        until the `with` block ends."""
        url = _archive_url(repo, commit)
        request = _Request(repo, commit)
        body = self._archive_body(github, url, request)
        with self._lock:
            unreadable = self._unreadable.get((request, directory))
        if unreadable is not None:
            raise ValueError(str(unreadable))  # the same text for every version
        with self._slots:
            try:
                tree = github.extract(body, directory=directory)
            except ValueError as exc:
                with self._lock:
                    self._unreadable[(request, directory)] = exc
                raise
            del body
            yield tree

    def _archive_body(self, github: GitHub, url: str, request: _Request) -> bytes:
        def fetch() -> bytes:
            return github.archive_body(request.repo, request.commit or "")

        if github.fetcher.needs_network(url, immutable=True):
            with self._request_lock(request):
                if github.fetcher.needs_network(url, immutable=True):  # nobody fetched it since
                    return self._send(request, fetch)
        return fetch()  # from the fetcher's snapshot or immutable index, in parallel

    def _request_lock(self, request: _Request) -> threading.Lock:
        with self._lock:
            return self._request_locks.setdefault(request, threading.Lock())

    def _send[T](self, request: _Request, fetch: Callable[[], T]) -> T:
        """`fetch` goes to the network for `request`; the caller holds its lock."""
        with self._lock:
            refused = request in self._failed
            rejected = self._rejected.get(request)
            if not refused and rejected is None:
                self._sent.add(request)
        if refused:
            raise RepoNetworkError(request)
        if rejected is not None:
            raise type(rejected)(str(rejected))  # the same text for every version
        try:
            return fetch()
        except TransientFetchError as exc:
            with self._lock:
                self._failed[request] = str(exc)[:300]
            raise RepoNetworkError(request) from exc
        except (FetchError, ValueError) as exc:
            with self._lock:
                self._rejected[request] = exc
            raise


def compare(
    change: Change,
    package: Tree,
    locator: Locator,
    github: GitHub,
    *,
    refs_cache: dict[GitHubRepo, Mapping[str, str] | None] | None = None,
    memory: RepoMemory | None = None,
) -> RepoComparison:
    """Compare one release with its repository. Network failures (`RepoNetworkError`, a
    `TransientFetchError`) propagate, so the caller decides what they mean; everything else
    becomes `unavailable`. `memory` is shared across calls (Stage 4); `refs_cache` alone just
    reuses refs."""
    memory = memory if memory is not None else RepoMemory(refs_cache)
    located = locator.repository(change)
    if located is None:
        return RepoComparison(unavailable="no GitHub repository")
    repo, directory = located
    refs = memory.refs(github, repo)
    if refs is None:
        return RepoComparison(unavailable=f"repository {repo} not found")
    found = locator.commit(change, refs)
    if found is None:
        return RepoComparison(unavailable="no commit or tag for this version")
    commit, how = found
    source = ReleaseSource(repo=str(repo), directory=directory, commit=commit, how=how)
    with ExitStack() as held:  # the extraction slot, until the comparison is done
        try:
            tree = held.enter_context(memory.archive(github, repo, commit, directory))
        except TransientFetchError:
            raise
        except (FetchError, ValueError) as exc:  # e.g. HTTP 404 (never pushed), size limits
            return RepoComparison(source=source, unavailable=f"archive: {exc}"[:300])
        return _compare_tree(change, package, locator, source, directory, tree)


def _compare_tree(
    change: Change,
    package: Tree,
    locator: Locator,
    source: ReleaseSource,
    directory: str,
    tree: Tree,
) -> RepoComparison:
    whole = tree
    if not directory:
        found_in = locator.package_directory(change, tree)
        if found_in is None:
            return RepoComparison(
                source=source, unavailable="the repository has no manifest for this package"
            )
        if found_in:
            prefix = f"{found_in}/"
            tree = {p.removeprefix(prefix): c for p, c in tree.items() if p.startswith(prefix)}
            source = source.model_copy(update={"directory": found_in})
    if not tree:
        return RepoComparison(source=source, unavailable=f"directory {directory!r} is empty")
    trees = compare_trees(package, tree, whole)
    return RepoComparison(
        source=source,
        code_files=trees.code_files,
        identical=trees.identical,
        differing=tuple(trees.differing[:MAX_LISTED]),
        differing_count=len(trees.differing),
        not_in_repo_count=len(trees.missing),
        unexplained=tuple(trees.unexplained[:MAX_LISTED]),
        unexplained_count=len(trees.unexplained),
        manifest=locator.manifest_differences(package, tree, whole),
    )


RepoCompare = Callable[[Change, Tree], RepoComparison]
