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

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Final, Protocol

from kitsunox.core.models import Change, Record
from kitsunox.githost.github import GitHub, GitHubRepo
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


class RepoComparison(Record):
    """A release's code files against the repository at its commit. `unavailable` says why no
    comparison was made (no repository, no commit for this version, archive too large); the
    lists are then empty. Paths are sorted and capped at `MAX_LISTED`; counts are not."""

    source: ReleaseSource | None = None
    unavailable: str | None = None
    code_files: int = 0
    identical: int = 0
    differing: tuple[str, ...] = ()
    differing_count: int = 0
    not_in_repo_count: int = 0
    unexplained: tuple[str, ...] = ()  # not in the repo, and not build output (`compare_trees`)
    unexplained_count: int = 0


class Locator(Protocol):
    """Ecosystem knowledge: which repository and commit a change's release came from."""

    def repository(self, change: Change) -> tuple[GitHubRepo, str] | None: ...

    def commit(self, change: Change, refs: Mapping[str, str]) -> tuple[str, str] | None: ...


@dataclass(frozen=True)
class TreeComparison:
    code_files: int
    identical: int
    differing: list[str]
    missing: list[str]
    unexplained: list[str]


def compare_trees(package: Tree, repo: Tree) -> TreeComparison:
    """The package's JavaScript/TypeScript files against the repository (line endings
    normalised). A missing file is *unexplained* when its directory is in the repository (the
    root always is) and no file there shares its stem: `lib/x.js` next to `lib/x.ts` is compiled
    output, and `dist/` that git ignores is build output, but a new `setup_bun.js` at the root
    is neither."""
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
        if stems is not None and _stem(name) not in stems:
            unexplained.append(path)
    return TreeComparison(len(code), identical, differing, missing, unexplained)


def _stem(name: str) -> str:
    return name.split(".", 1)[0]


def _normalised(content: bytes) -> str:
    return sha256_hex(content.replace(b"\r\n", b"\n"))


def compare(
    change: Change,
    package: Tree,
    locator: Locator,
    github: GitHub,
    *,
    refs_cache: dict[GitHubRepo, Mapping[str, str] | None] | None = None,
) -> RepoComparison:
    """Compare one release with its repository. Network failures (`TransientFetchError`)
    propagate, so the caller decides what they mean; everything else becomes `unavailable`."""
    located = locator.repository(change)
    if located is None:
        return RepoComparison(unavailable="no GitHub repository")
    repo, directory = located
    if refs_cache is not None and repo in refs_cache:
        refs = refs_cache[repo]
    else:
        refs = github.refs(repo)
        if refs_cache is not None:
            refs_cache[repo] = refs
    if refs is None:
        return RepoComparison(unavailable=f"repository {repo} not found")
    found = locator.commit(change, refs)
    if found is None:
        return RepoComparison(unavailable="no commit or tag for this version")
    commit, how = found
    source = ReleaseSource(repo=str(repo), directory=directory, commit=commit, how=how)
    try:
        tree = github.archive(repo, commit, directory=directory)
    except TransientFetchError:
        raise
    except (FetchError, ValueError) as exc:  # e.g. HTTP 404 (commit never pushed), size limits
        return RepoComparison(source=source, unavailable=f"archive: {exc}"[:300])
    if not tree:
        return RepoComparison(source=source, unavailable=f"directory {directory!r} is empty")
    trees = compare_trees(package, tree)
    return RepoComparison(
        source=source,
        code_files=trees.code_files,
        identical=trees.identical,
        differing=tuple(trees.differing[:MAX_LISTED]),
        differing_count=len(trees.differing),
        not_in_repo_count=len(trees.missing),
        unexplained=tuple(trees.unexplained[:MAX_LISTED]),
        unexplained_count=len(trees.unexplained),
    )


RepoCompare = Callable[[Change, Tree], RepoComparison]
