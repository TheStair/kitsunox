"""Stage 3 core: per-version capability profiles, deltas and the on-disk cache."""

import json
from pathlib import Path

from kitsunox.core.models import (
    Candidate,
    Change,
    Finding,
    PackageBatch,
    PackageVersionRef,
    PublishInfo,
    Severity,
    VersionSnapshot,
)
from kitsunox.ecosystems.npm.install import gyp_commands, install_sources
from kitsunox.lang.javascript import EXTRACTOR_VERSION, Capability
from kitsunox.stages.ast import (
    CapabilityCache,
    CodeChange,
    added,
    analyse_batch,
    ast_run,
    code_change,
    profile,
)
from kitsunox.stages.ingest import write_jsonl
from kitsunox.stages.static import Unavailable

BASE = {"index.js": b'const fs = require("fs")', "README.md": b'require("https")'}
NEW = BASE | {"lib/x.js": b'require("https").get(u); send(JSON.stringify(process.env))'}


def test_delta_is_what_the_new_version_gained(tmp_path: Path) -> None:
    cache = CapabilityCache(tmp_path)
    base, new = profile(BASE, cache), profile(NEW, cache)
    assert base.capabilities == {Capability.FILESYSTEM}  # README is not code
    assert added(base, new) == {Capability.NETWORK, Capability.ENV_ALL}
    assert added(None, new) == new.capabilities  # new package: everything is new
    (where,) = new.where(Capability.ENV_ALL)
    assert where.path == "lib/x.js" and where.use.line == 1


def test_profile_of_selected_paths(tmp_path: Path) -> None:
    only = profile(NEW, CapabilityCache(None), paths=frozenset({"index.js"}))
    assert only.capabilities == {Capability.FILESYSTEM} and only.files_parsed == 1


def test_cache_serves_repeat_contents(tmp_path: Path) -> None:
    cache = CapabilityCache(tmp_path)
    first = cache.get(b"fetch(u)", "javascript")
    (path,) = tmp_path.rglob("*.json")
    assert path.name.endswith("-javascript.json")
    assert path.parent.parent.name == f"v{EXTRACTOR_VERSION}"  # a new extractor: a new cache
    assert cache.get(b"fetch(u)", "javascript") == first
    assert cache.get(b"fetch(u)", "typescript") == first.model_copy(
        update={"language": "typescript"}
    )


class GainedNetwork:
    """A stand-in rule: flags a version that gained network access."""

    id = "test.gained-network"
    version = 1

    def evaluate_code(self, change: CodeChange) -> list[Finding]:
        if Capability.NETWORK not in change.added:
            return []
        return [
            Finding(
                rule_id=self.id,
                rule_version=1,
                severity=Severity.MEDIUM,
                weight=1.0,
                title="t",
                explanation="gained network",
            )
        ]


def snap(version: str) -> VersionSnapshot:
    return VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="kx", version=version),
        publish=PublishInfo(),
        manifest={},
    )


def test_batch_attributes_gains_to_the_version_that_made_them(tmp_path: Path) -> None:
    trees: dict[str, dict[str, bytes] | Unavailable] = {
        "1.0.0": BASE,
        "1.0.1": NEW,  # gains network and env-all
        "1.0.2": BASE,  # reverts
        "1.0.3": Unavailable(reason="gone"),
    }
    batch = PackageBatch(
        ecosystem="npm",
        name="kx",
        base=snap("1.0.0"),
        versions=tuple(
            Candidate(change=Change(new=snap(v), previous=snap(p)))
            for v, p in (("1.0.1", "1.0.0"), ("1.0.2", "1.0.1"), ("1.0.3", "1.0.2"))
        ),
    )
    write_jsonl(tmp_path / "static.jsonl", [batch])
    (result,) = ast_run(
        tmp_path, lambda s: trees[s.ref.version], CapabilityCache(None), [GainedNetwork()]
    )
    gained, reverted, gone = result.versions
    assert (
        gained.history[-1].forwarded and gained.history[-1].reason == "rules: test.gained-network"
    )
    assert not reverted.history[-1].forwarded
    assert gone.history[-1].reason == "files unavailable: gone"
    assert (tmp_path / "ast.jsonl").exists()


def test_version_without_previous_is_new_even_after_a_placeholder() -> None:
    """npm placeholders (`0.0.0-stage`) come before a package's first real release; that
    release has no previous, so it is a new package, not an update of the placeholder."""
    trees = {"0.0.0-stage": {"index.js": b""}, "1.4.0": NEW}
    seen: list[CodeChange] = []

    class Spy:
        id = "test.spy"
        version = 1

        def evaluate_code(self, change: CodeChange) -> list[Finding]:
            seen.append(change)
            return []

    batch = PackageBatch(
        ecosystem="npm",
        name="kx",
        base=None,
        versions=(
            Candidate(change=Change(new=snap("0.0.0-stage"))),
            Candidate(change=Change(new=snap("1.4.0"))),
        ),
    )
    analyse_batch(batch, lambda s: trees[s.ref.version], CapabilityCache(None), [Spy()])
    assert [c.before for c in seen] == [None, None]


def test_install_profile_covers_only_entry_files() -> None:
    files = NEW | {"package.json": b'{"scripts": {"postinstall": "node lib/x.js"}}'}
    seen: list[CodeChange] = []

    class Spy:
        id = "test.spy"
        version = 1

        def evaluate_code(self, change: CodeChange) -> list[Finding]:
            seen.append(change)
            return []

    batch = PackageBatch(
        ecosystem="npm", name="kx", base=None, versions=(Candidate(change=Change(new=snap("1"))),)
    )
    analyse_batch(
        batch, lambda s: files, CapabilityCache(None), [Spy()], install_entries=install_sources
    )
    (change,) = seen
    assert change.before is None
    assert change.install is not None
    assert change.install.capabilities == {Capability.NETWORK, Capability.ENV_ALL}


def test_build_commands_reach_the_rules() -> None:
    """npm passes `binding.gyp`'s commands (`gyp_commands`) for `npm.install-build-tool`."""
    gyp = b"{'targets': [{'actions': [{'action': ['node', 'x.js']}]}]}"
    files = NEW | {"binding.gyp": gyp}
    seen: list[CodeChange] = []

    class Spy:
        id = "test.spy"
        version = 1

        def evaluate_code(self, change: CodeChange) -> list[Finding]:
            seen.append(change)
            return []

    batch = PackageBatch(
        ecosystem="npm", name="kx", base=None, versions=(Candidate(change=Change(new=snap("1"))),)
    )
    analyse_batch(
        batch, lambda s: files, CapabilityCache(None), [Spy()], build_commands=gyp_commands
    )
    analyse_batch(batch, lambda s: files, CapabilityCache(None), [Spy()])
    assert [c.build_commands for c in seen] == [("node x.js",), ()]


def test_agent_files_reach_the_rules() -> None:
    """Install code that names an agent directory gets the agent files it may copy
    (`agent_config.agent_files`); other install code gets none."""
    manifest = json.dumps({"scripts": {"postinstall": "node setup.js"}}).encode()
    copier = {
        "package.json": manifest,
        "setup.js": b'copy("skills", path.join(home, ".claude"))',
        "skills/x/SKILL.md": b"# x",
    }
    other = copier | {"setup.js": b'copy("skills", "dist")'}
    seen: list[CodeChange] = []

    class Spy:
        id = "test.spy"
        version = 1

        def evaluate_code(self, change: CodeChange) -> list[Finding]:
            seen.append(change)
            return []

    batch = PackageBatch(
        ecosystem="npm", name="kx", base=None, versions=(Candidate(change=Change(new=snap("1"))),)
    )
    for tree in (copier, other):

        def files(_: VersionSnapshot, tree: dict[str, bytes] = tree) -> dict[str, bytes]:
            return tree

        analyse_batch(
            batch,
            files,
            CapabilityCache(None),
            [Spy()],
            install_entries=install_sources,
        )
    assert [sorted(c.agent_files) for c in seen] == [["skills/x/SKILL.md"], []]
    direct = code_change(snap("1"), copier, None, CapabilityCache(None), install_sources)
    assert sorted(direct.agent_files) == ["skills/x/SKILL.md"]


def test_a_previous_outside_the_batch_is_fetched() -> None:
    """`@bike4mind/cli`: branch snapshots, each following its own branch's last snapshot. The
    previous was neither the base nor in the batch, so its install code counted as new."""
    trees = {"base": BASE, "branch-a.1": NEW, "branch-b.2": NEW, "branch-b.1": NEW}
    fetched: list[str] = []
    seen: list[CodeChange] = []

    def tree_of(s: VersionSnapshot) -> dict[str, bytes]:
        fetched.append(s.ref.version)
        return trees[s.ref.version]

    class Spy:
        id = "test.spy"
        version = 1

        def evaluate_code(self, change: CodeChange) -> list[Finding]:
            seen.append(change)
            return []

    batch = PackageBatch(
        ecosystem="npm",
        name="kx",
        base=snap("base"),
        versions=(
            Candidate(change=Change(new=snap("branch-a.1"), previous=snap("base"))),
            Candidate(change=Change(new=snap("branch-b.2"), previous=snap("branch-b.1"))),
        ),
    )
    analyse_batch(batch, tree_of, CapabilityCache(None), [Spy()])
    assert fetched == ["base", "branch-a.1", "branch-b.1", "branch-b.2"]
    assert seen[1].before is not None and seen[1].added == frozenset()


def test_bundled_package() -> None:
    from kitsunox.stages.ast import bundled_package

    assert bundled_package("node_modules/a/index.js") == "a"
    assert bundled_package("dist/node_modules/@s/b/lib/x.js") == "@s/b"
    assert bundled_package("node_modules/a/node_modules/c/x.js") == "a"
    assert bundled_package("node_modules/@s") is None
    assert bundled_package("lib/node_modules") is None
    assert bundled_package("lib/x.js") is None
