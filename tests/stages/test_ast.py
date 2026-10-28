"""Stage 3 core: per-version capability profiles, deltas and the on-disk cache."""

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
from kitsunox.ecosystems.npm.install import install_entry_files
from kitsunox.lang.javascript import Capability
from kitsunox.stages.ast import (
    CapabilityCache,
    CodeChange,
    added,
    analyse_batch,
    ast_run,
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
    assert path.name.endswith("-javascript.json") and path.parent.parent.name == "v1"
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
        versions=tuple(Candidate(change=Change(new=snap(v))) for v in ("1.0.1", "1.0.2", "1.0.3")),
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
        batch, lambda s: files, CapabilityCache(None), [Spy()], install_entries=install_entry_files
    )
    (change,) = seen
    assert change.before is None
    assert change.install is not None
    assert change.install.capabilities == {Capability.NETWORK, Capability.ENV_ALL}
