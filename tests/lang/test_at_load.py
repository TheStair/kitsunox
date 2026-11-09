"""`lang.at_load`: which identity reads run when a file is loaded (inert snippets, parsed only)."""

import pytest

from kitsunox.lang.javascript import analyse_source


def at_load(source: bytes, language: str = "javascript") -> list[tuple[str, int]]:
    return [(u.detail, u.line) for u in analyse_source(source, language).identity_at_load]


def test_top_level_reads_run_at_load() -> None:
    """The dependency-confusion probe moved from `preinstall` to `index.js`."""
    source = b"""const os = require("os");
const data = JSON.stringify({ h: os.hostname(), u: os.userInfo().username, d: os.homedir() });
"""
    assert at_load(source) == [("hostname", 2), ("userInfo", 2), ("homedir", 2)]


@pytest.mark.parametrize(
    "source",
    [
        b"function f() { return os.hostname(); }\nf();",  # a declaration called by name
        b"const f = () => os.hostname();\nf.call(null);",
        b"let f; f = function () { return os.hostname(); };\nf.apply(null, []);",
        b"(function () { os.hostname(); })();",  # called in place
        b"!function () { os.hostname(); }.call(this);",
        b"async function main() { await go(); }\nasync function go() { os.hostname(); }\n"
        b"main().catch(() => {});",  # through two named functions
        b"setTimeout(() => { os.hostname(); }, 5000);",  # a timer started at load
        b"collect('host', () => os.hostname());",  # passed to a call that runs
        b"new Promise((resolve) => resolve(os.hostname()));",  # an executor runs at once
        b"import { hostname } from 'node:os';\nconst h = hostname();",
    ],
)
def test_what_runs_at_load(source: bytes) -> None:
    assert [name for name, _ in at_load(source)] == ["hostname"]


@pytest.mark.parametrize(
    "source",
    [
        b"function f() { return os.hostname(); }\nmodule.exports = f;",  # exported, not called
        b"export function f() { return os.hostname(); }",
        b"exports.f = () => os.hostname();",
        b"class K { m() { return os.hostname(); } }\nnew K().m();",  # methods never count
        b"const o = { m() { return os.hostname(); } };\no.m();",
        b"function a() { b(); }\nfunction b() { a(); os.hostname(); }",  # a cycle, never called
        b"new Thing(() => os.hostname());",  # only a Promise executor runs at once
        b'const k = "host" + "name";\nos[k]();',  # a computed name is not followed
        b"const h = os.hostname;",  # not a call
    ],
)
def test_what_does_not_run_at_load(source: bytes) -> None:
    assert at_load(source) == []


def test_typescript_and_evidence_limits() -> None:
    source = b"import os from 'os';\nconst n: string = os.hostname();\n" + b"os.hostname();\n" * 5
    reads = analyse_source(source, "typescript").identity_at_load
    assert [u.line for u in reads] == [2, 3, 4]  # MAX_EVIDENCE per name
    assert reads[0].snippet == "os.hostname()"


def test_a_file_without_identity_reads_skips_the_walk() -> None:
    assert at_load(b"function f() { g(); }\nf();") == []


def commands(source: bytes, language: str = "javascript") -> list[tuple[str, int]]:
    return [(u.detail, u.line) for u in analyse_source(source, language).commands_at_load]


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (b'exec("npm publish --access public");', "npm publish --access public"),
        (b"execSync(`cd ${dir} && npm publish`);", "cd ${dir} && npm publish"),
        (b'cp.execSync("npm " + "publish");', "npm publish"),
        (b'cp.execSync("npm publish --tag " + tag);', "npm publish --tag …"),
        (b'spawn("npm", ["publish", "--access", "public"]);', "npm publish --access public"),
        (b'const CMD = "npm publish";\nfunction go() { execSync(CMD); }\ngo();', "npm publish"),
        (b"(async () => { await execa('npm publish'); })();", "npm publish"),
        (b"setTimeout(() => exec('npm publish'), 1000);", "npm publish"),
        (b'execSync(("npm publish"));', "npm publish"),
        (b"execSync(cmd);", ""),  # a value the parse can't read
        (b"execSync();", ""),
    ],
)
def test_commands_that_run_at_load(source: bytes, expected: str) -> None:
    assert [text for text, _ in commands(source)] == [expected]


def test_a_wrapper_of_a_runner_counts_once_its_caller_runs() -> None:
    """`@emilgroup/*`: `function run(cmd) { return execSync(cmd, ...); }`, then `run("...")`."""
    source = b"""function run(cmd) { return execSync(cmd, { stdio: "inherit" }); }
run("npm publish --access public");
"""
    assert commands(source) == [("", 1), ("npm publish --access public", 2)]
    assert commands(source.replace(b'run("npm', b'exports.go = () => run("npm')) == []
    for wrapper, language in (
        (b"const run = cmd => execSync(cmd);", "javascript"),
        (b"const run = (cmd = 'ls') => execSync(cmd);", "javascript"),
        (b"function run(cmd: string, o = {}) { return execSync(cmd, o); }", "typescript"),
    ):
        found = commands(wrapper + b'\nrun("npm publish");', language)
        assert found[-1] == ("npm publish", 2)
    # a function that runs its own command is not a wrapper: calls to it run nothing more
    assert commands(b'function go() { execSync("ls"); }\ngo(1);') == [("ls", 1)]
    assert commands(b"function go(a) { execSync(b); }\ngo(1);") == [("", 1)]


@pytest.mark.parametrize(
    "source",
    [
        b'function release() { execSync("npm publish"); }\nmodule.exports = release;',
        b'class R { publish() { execSync("npm publish"); } }\nnew R().publish();',
        b'const o = { go() { execSync("npm publish"); } };\no.go();',
        b'exports.release = () => execSync("npm publish");',
        b'console.log("npm publish");',  # printed, not run
    ],
)
def test_commands_that_do_not_run_at_load(source: bytes) -> None:
    assert commands(source) == []


def test_command_texts_are_kept_once_and_cut() -> None:
    source = b'exec("npm publish");\nexec("npm publish");\nexec("' + b"x" * 300 + b'");'
    found = commands(source)
    assert found[0] == ("npm publish", 1)
    assert len(found) == 2 and len(found[1][0]) == 200
    many = b"\n".join(b'exec("echo %d");' % i for i in range(60))
    assert len(commands(many)) == 50
