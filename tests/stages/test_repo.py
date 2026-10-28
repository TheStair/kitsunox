"""Tarball-vs-repo comparison: locating the commit, comparing trees, and the rules over it."""

from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from conftest import Router, TarEntry, make_tar_gz
from kitsunox.core.models import (
    Candidate,
    Change,
    PackageVersionRef,
    PublishInfo,
    Severity,
    VersionSnapshot,
)
from kitsunox.ecosystems.npm.repo import NpmLocator, release_tags
from kitsunox.ecosystems.npm.rules.correlate import DependencyNotInRepo, InstallScriptNotInRepo
from kitsunox.githost.github import GitHub, GitHubRepo
from kitsunox.rules.repo import CodeDiffersFromRepo, CodeNotInRepo, RepoCompared
from kitsunox.stages.correlate import CorrelationContext
from kitsunox.stages.repo import RepoComparison, compare, compare_trees
from kitsunox.util.http import BlobStore, FetchMode, HttpFetcher, Snapshot

A, T = "a" * 40, "c" * 40
REFS_URL = "https://github.com/o/r.git/info/refs?service=git-upload-pack"


def change(version: str = "1.2.3", *, git_head: str | None = None, **manifest: Any) -> Change:
    snap = VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="@s/kx", version=version),
        publish=PublishInfo(git_head=git_head),
        manifest=manifest,
    )
    return Change(new=snap, previous=snap, repository_url="https://github.com/o/r")


def test_locator_prefers_githead_then_tags() -> None:
    locator = NpmLocator()
    tags = {"refs/tags/kx@1.2.3": T}
    assert locator.commit(change(git_head=A), tags) == (A, "gitHead")
    assert locator.commit(change(), tags) == (T, "tag kx@1.2.3")
    assert locator.commit(change("9.9.9"), tags) is None
    assert release_tags("@s/kx", "1.0.0")[:3] == ("v1.0.0", "1.0.0", "@s/kx@1.0.0")


def test_locator_directory_is_a_plain_relative_path() -> None:
    locator = NpmLocator()
    repo = GitHubRepo("o", "r")
    assert locator.repository(change(repository={"directory": "./packages/kx/"})) == (
        repo,
        "packages/kx",
    )
    assert locator.repository(change(repository={"directory": "../../etc"})) == (repo, "")
    assert locator.repository(change().model_copy(update={"repository_url": None})) is None


def test_compare_trees() -> None:
    package = {
        "a.js": b"x\r\n",  # same once line endings are normalised
        "b.js": b"evil",
        "setup_bun.js": b"payload",  # root is in the repo; nothing compiles to it
        "lib/x.js": b"compiled",  # lib/x.ts is in the repo
        "dist/y.js": b"built",  # dist/ isn't in the repo at all
        "README.md": b"not code",
    }
    repo = {"a.js": b"x\n", "b.js": b"good", "lib/x.ts": b"src", "README.md": b"other"}
    found = compare_trees(package, repo)
    assert (found.code_files, found.identical, found.differing) == (5, 1, ["b.js"])
    assert found.missing == ["dist/y.js", "lib/x.js", "setup_bun.js"]
    assert found.unexplained == ["setup_bun.js"]


def github(tmp_path: Path, router: Router) -> GitHub:
    fetcher = HttpFetcher(
        store=BlobStore(tmp_path / "b"),
        snapshot=Snapshot(),
        mode=FetchMode.RECORD,
        immutable_index=tmp_path / "i",
        client=router.client(),
    )
    return GitHub(fetcher)


def pkt(text: str) -> bytes:
    return f"{len(text) + 4:04x}".encode() + text.encode()


def test_compare_end_to_end(tmp_path: Path, router: Router) -> None:
    router.add_bytes(REFS_URL, pkt(f"{T} refs/tags/v1.2.3\n") + b"0000")
    router.add_bytes(
        f"https://codeload.github.com/o/r/tar.gz/{T}",
        make_tar_gz([TarEntry(f"r-{T}/index.js", b"good"), TarEntry(f"r-{T}/util.js", b"u")]),
    )
    package: Mapping[str, bytes] = {"index.js": b"evil", "util.js": b"u"}
    result = compare(change(), package, NpmLocator(), github(tmp_path, router))
    assert result.source is not None and result.source.how == "tag v1.2.3"
    assert (result.code_files, result.identical, result.differing) == (2, 1, ("index.js",))
    missing = compare(change("2.0.0"), package, NpmLocator(), github(tmp_path, router))
    assert missing.unavailable == "no commit or tag for this version"


def ctx(comparison: RepoComparison) -> CorrelationContext:
    return CorrelationContext(as_of=datetime(2026, 10, 28, tzinfo=UTC), repo=comparison)


def test_repo_rules() -> None:
    cand = Candidate(change=change())
    sources = RepoComparison(code_files=10, unexplained=("x.js",), unexplained_count=1)
    built = RepoComparison(code_files=10, not_in_repo_count=10)  # build output only
    differs = RepoComparison(code_files=2, identical=1, differing=("index.js",), differing_count=1)
    assert CodeNotInRepo().evaluate_candidate(cand, ctx(sources))
    assert not CodeNotInRepo().evaluate_candidate(cand, ctx(built))  # ships build output
    (found,) = CodeDiffersFromRepo().evaluate_candidate(cand, ctx(differs))
    assert found.evidence[0].path == "index.js"
    (info,) = RepoCompared().evaluate_candidate(cand, ctx(RepoComparison(unavailable="gone")))
    assert info.explanation == "No comparison: gone." and info.weight == 0


def test_manifest_differences_and_rules() -> None:
    package = {
        "package.json": b'{"scripts": {"preinstall": "node setup_bun.js", "build": "tsc"},'
        b' "dependencies": {"left-pad": "1", "evil": "1"}}'
    }
    repo = {"package.json": b'{"scripts": {"build": "tsc"}, "devDependencies": {"left-pad": "1"}}'}
    differences = NpmLocator().manifest_differences(package, repo)
    assert [(d.field, d.package, d.repo) for d in differences] == [
        ("scripts.preinstall", "node setup_bun.js", None),
        ("dependencies.evil", "1", None),
    ]
    assert NpmLocator().manifest_differences(package, {}) == ()  # no manifest in the repo
    comparison = RepoComparison(manifest=differences)
    cand = Candidate(change=change())
    (hook,) = InstallScriptNotInRepo().evaluate_candidate(cand, ctx(comparison))
    assert hook.severity == Severity.HIGH and hook.evidence[0].after == "node setup_bun.js"
    (dep,) = DependencyNotInRepo().evaluate_candidate(cand, ctx(comparison))
    assert dep.severity == Severity.LOW and "evil" in dep.explanation
