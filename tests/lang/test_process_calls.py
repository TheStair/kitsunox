"""`lang.process_calls`: every `child_process` command a file can run (inert snippets, parsed
only)."""

import pytest

from kitsunox.lang.process_calls import ProcessCall, process_calls


def calls(source: bytes, language: str = "javascript") -> list[tuple[str, str]] | None:
    found = process_calls(source, language)
    return None if found is None else [(c.runner, c.command) for c in found]


def test_bindings_and_commands() -> None:
    source = b"""const { execFileSync, spawn: run } = require("child_process");
const cp = require("node:child_process");
const TAR = "tar";
execFileSync(TAR, ["-xzf", archive, "-C", dir]);
run(binary, ["serve"]);
cp.execSync(`cd ${dir} && unzip -o x.zip`);
require("child_process").spawnSync("chmod", ["+x", bin]);
const m = /v(\\d+)/.exec(text);  // a RegExp's exec is not child_process's
"""
    assert calls(source) == [
        ("execFileSync", "tar -xzf … -C …"),
        ("spawn", ""),
        ("execSync", "cd ${dir} && unzip -o x.zip"),
        ("spawnSync", "chmod +x …"),
    ]
    found = process_calls(source, "javascript")
    assert found is not None
    assert [c.line for c in found] == [4, 5, 6, 7]
    assert [c.shell for c in found] == [False, False, True, False]


def test_imports() -> None:
    source = b"""import { spawnSync, execFile as ef } from "node:child_process";
import * as cp from "child_process";
import other from "child_process";
spawnSync("tar", args);
ef("unzip", ["-q", a]);
cp.fork("./worker.js");
other.exec("ls");
"""
    assert calls(source, "typescript") == [
        ("spawnSync", "tar"),
        ("execFile", "unzip -q …"),
        ("fork", "./worker.js"),
        ("exec", "ls"),
    ]
    assert calls(b'import "child_process";') == []
    assert calls(b"const x = await import('child_process');\nx.exec('ls');") == [("exec", "ls")]
    assert calls(b"const fs = require('fs');\nfs.readFileSync('a');") == []


@pytest.mark.parametrize(
    "source",
    [
        b"const { exec } = require('child_process');\nconst run = promisify(exec);",
        b"const cp = require('child_process');\nconst f = cp.spawn;",  # not called
        b"const cp = require('child_process');\ncp['spawn']('x');",  # computed member
        b"const cp = require('child_process');\nhelper(cp);",  # passed on
        b"const { spawnSync } = require('child_process');\nrun({ spawnSync });",
        b"const { ChildProcess } = require('child_process');",  # not a runner
        b"const { spawn = other } = require('child_process');",  # a default value
        b"const { ...all } = require('child_process');",
        b"const name = 'child_process';\nrequire(name).exec('x');",  # the name in a string
        b"const e = require('child_process').exec;\nconst f = e;",
        b"import { ChildProcess } from 'child_process';",
        b"export { exec } from 'child_process';",
        b"const s = require('child_process').spawn.bind(null);",
        b"require('child_process', 'x');",
        b"module.exports = require('child_process');",
    ],
)
def test_unreadable(source: bytes) -> None:
    assert process_calls(source, "javascript") is None


def test_limits() -> None:
    assert process_calls(b"x" * (16 * 1024 * 1024 + 1), "javascript") is None
    assert calls(b"const { exec } = require('child_process');\nexec();") == [("exec", "")]
    assert ProcessCall(runner="spawn", command="tar", line=1).shell is False
