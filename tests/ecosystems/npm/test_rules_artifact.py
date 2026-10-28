"""npm artifact rules: registry metadata vs the tarball's own files (inert fixtures)."""

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
from kitsunox.ecosystems.npm.rules.artifact import DeclaredSizeMismatch, HiddenInstallScript


def snap(scripts: dict[str, str] | None = None, size: int | None = None) -> VersionSnapshot:
    return VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="kx", version="1.0.0"),
        publish=PublishInfo(),
        manifest={"scripts": scripts} if scripts is not None else {},
        artifact=ArtifactRef(url="https://r.test/kx.tgz", unpacked_size=size),
    )


def package(**fields: Any) -> dict[str, bytes]:
    return {"package.json": json.dumps({"name": "kx", **fields}).encode()}


def test_hook_only_in_the_tarball_is_flagged() -> None:
    files = package(scripts={"postinstall": "node x.js", "test": "jest"})
    (finding,) = HiddenInstallScript().evaluate_artifact(snap({"test": "jest"}), files)
    assert finding.severity is Severity.HIGH
    assert finding.evidence[0].path == "package.json:scripts.postinstall"
    assert finding.evidence[0].before is None and finding.evidence[0].after == "node x.js"


def test_hook_changed_between_metadata_and_tarball_is_flagged() -> None:
    files = package(scripts={"install": "node evil.js"})
    (finding,) = HiddenInstallScript().evaluate_artifact(snap({"install": "node ok.js"}), files)
    assert finding.evidence[0].before == "node ok.js"


@pytest.mark.parametrize(
    ("shown", "packed"),
    [
        ({"postinstall": "node x.js"}, {"postinstall": "node x.js"}),
        ({"postinstall": "tsc"}, {"postinstall": "node_modules/.bin/tsc"}),  # npm normalises
        ({"install": "node-gyp rebuild"}, {}),  # registry adds it for binding.gyp
        ({}, {"build": "tsc", "prepare": "npm run build"}),  # not install hooks
    ],
)
def test_npm_normalisation_and_other_scripts_are_not_flagged(
    shown: dict[str, str], packed: dict[str, str]
) -> None:
    assert HiddenInstallScript().evaluate_artifact(snap(shown), package(scripts=packed)) == []


@pytest.mark.parametrize(
    "files",
    [{}, {"package.json": b"not json"}, {"package.json": b"[1]"}, package(scripts="x")],
)
def test_missing_or_hostile_package_json_never_crashes(files: dict[str, bytes]) -> None:
    assert list(HiddenInstallScript().evaluate_artifact(snap(), files)) == []


def test_size_mismatch_needs_a_real_gap() -> None:
    files = {"a.js": b"x" * 200_000}
    rule = DeclaredSizeMismatch()
    assert rule.evaluate_artifact(snap(size=200_000), files) == ()
    assert rule.evaluate_artifact(snap(size=199_000), files) == ()  # within 1 KiB
    assert rule.evaluate_artifact(snap(size=None), files) == ()
    (finding,) = rule.evaluate_artifact(snap(size=1_000), files)
    assert finding.severity is Severity.MEDIUM
    assert "understated by 199,000" in finding.explanation
    assert rule.evaluate_artifact(snap(size=900_000), files) == ()  # overstating gains nothing
