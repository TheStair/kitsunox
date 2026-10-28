"""Stage 3 rules on hand-written profiles built from inert snippets."""

import json

from kitsunox.core.models import PackageVersionRef, PublishInfo, Severity, VersionSnapshot
from kitsunox.ecosystems.npm.install import install_entry_files
from kitsunox.ecosystems.npm.rules.install_code import InstallScriptCode
from kitsunox.rules.capabilities import CapabilityGained
from kitsunox.stages.ast import CapabilityCache, CodeChange, code_change

CACHE = CapabilityCache(None)
SNAP = VersionSnapshot(
    ref=PackageVersionRef(ecosystem="npm", name="kx", version="1.0.1"),
    publish=PublishInfo(),
    manifest={},
)
PLAIN = {"index.js": b'const fs = require("fs")'}


def pkg(hook: str | None = None, files: dict[str, bytes] | None = None) -> dict[str, bytes]:
    tree = dict(PLAIN) | (files or {})
    if hook is not None:
        tree["package.json"] = json.dumps({"scripts": {"postinstall": hook}}).encode()
    return tree


def change(new: dict[str, bytes], base: dict[str, bytes] | None) -> CodeChange:
    return code_change(SNAP, new, base, CACHE, install_entry_files)


def test_gaining_network_with_env_is_medium() -> None:
    new = pkg(files={"lib/x.js": b"fetch(u, {body: JSON.stringify(process.env)})"})
    (finding,) = CapabilityGained().evaluate_code(change(new, PLAIN))
    assert finding.severity is Severity.MEDIUM
    assert "env-all, network" in finding.explanation
    assert {e.path for e in finding.evidence} == {"lib/x.js"}


def test_gaining_only_network_is_low_and_nothing_for_new_packages() -> None:
    new = pkg(files={"lib/x.js": b"fetch(u)"})
    (finding,) = CapabilityGained().evaluate_code(change(new, PLAIN))
    assert finding.severity is Severity.LOW
    assert CapabilityGained().evaluate_code(change(new, None)) == ()  # new package
    assert CapabilityGained().evaluate_code(change(PLAIN, PLAIN)) == ()


def test_install_script_code_for_new_packages() -> None:
    new = pkg("node setup.js", {"setup.js": b'require("child_process").exec(x)'})
    (finding,) = InstallScriptCode().evaluate_code(change(new, None))
    assert finding.severity is Severity.MEDIUM
    assert "runs setup.js, which uses process." in finding.explanation


def test_install_script_code_counts_only_new_capabilities_on_updates() -> None:
    old = {"setup.js": b'require("https").get(u)'} | pkg("node setup.js")
    same = {"setup.js": b'require("https").get(v)'} | pkg("node setup.js")
    worse = {"setup.js": b'require("https").get(u); eval(x)'} | pkg("node setup.js")
    assert InstallScriptCode().evaluate_code(change(same, old)) == ()
    (finding,) = InstallScriptCode().evaluate_code(change(worse, old))
    assert "dynamic-code (new to the install code)" in finding.explanation
    assert InstallScriptCode().evaluate_code(change(PLAIN, None)) == ()  # no install script
