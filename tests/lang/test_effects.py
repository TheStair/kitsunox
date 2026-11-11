"""`lang.effects`: JSON-only requires, named environment reads, install guards
(small, inert JavaScript; nothing here runs)."""

import pytest

from kitsunox.lang.effects import (
    env_read_by_name,
    guard_only,
    requires_only_json,
)


def js(code: str) -> bytes:
    return code.encode()


@pytest.mark.parametrize(
    ("code", "ok"),
    [
        ("const p = require.resolve(`${pkg}/package.json`); require(p).version;", True),
        ('require(path.join(here, "package.json"))', True),
        ('require(dir + "/manifest.json")', True),
        ("require(`${root}/data/${name}.json`)", True),
        (
            "let m; try { m = require.resolve(`${t}/package.json`, { paths: [d] }); } catch {}\n"
            "require(m).version;",
            True,
        ),
        ('require("fs"); require("./lib/x.js");', True),  # constants: the profile reads them
        # Anything that may load code.
        ("require(path.join(dir, name))", False),
        ("const p = join(d, 'x.json'); p = other; require(p);", False),  # reassigned
        ("let p = a; let p2 = 'x.json'; require(p)", False),
        ("let p = 'x.json'; p += '.js'; require(p)", False),
        ("import(path.join(here, 'x.json'))", False),
        ("require(`${root}/${name}`)", False),
        ("require.extensions['.json'] = require.extensions['.js']; require(d + '/x.json')", False),
        ("require()", False),
    ],
)
def test_requires_only_json(code: str, ok: bool) -> None:
    assert requires_only_json(js(code), "javascript") is ok


@pytest.mark.parametrize(
    ("code", "ok"),
    [
        ("if (process.env.CI) process.exit(0);", True),
        ("const env = process.env; if (env.CI || env['NO_COLOR']) process.exit(0);", True),
        (
            "function isCI(env) { return Boolean(env.CI && env.CI.toLowerCase()); }\n"
            "isCI(process.env);",
            True,
        ),
        ("const f = (e) => e.CI === '1'; f(process.env);", True),
        ("if (process.env === undefined) {}", True),
        # Whole-environment uses stay whole.
        ("const env = process.env; send(JSON.stringify(env));", False),
        ("const env = process.env; Object.keys(env);", False),
        ("spawn('x', [], { env: process.env });", False),
        ("spawn('x', [], { env: { ...process.env } });", False),
        ("send(process.env);", False),  # not a function the file declares
        ("function f(a, env) { return env.CI; } f(process.env);", True),  # never used
        ("function f(a) { return arguments[0]; } f(process.env);", False),
        ("function f(env) { return env; } send(f(process.env));", False),
        ("function f(env) { return Object.entries(env); } f(process.env);", False),
        ("function f() { return arguments[0]; } f(process.env);", False),
        ("const env = process.env; env.FORCE_COLOR = '0';", True),  # sets one variable
        ("const env = process.env || {}; env.CI;", True),
        ("const env = opts.env ?? process.env; send(env);", False),
        ("send(process.env || {});", False),
        ("const e = ci ? {} : process.env; Object.keys(e);", False),
        ("if (process.env) process.exit(0); const n = process.env.CI ? 1 : 0;", True),
        ("const { CI, ...rest } = process.env;", False),
        ("const env = Reflect.get(process, 'env'); env.CI;", False),
        ("const env = process['env']; env.CI;", False),
        ("const env = process.env; const { CI } = env;", False),
    ],
)
def test_env_read_by_name(code: str, ok: bool) -> None:
    assert env_read_by_name(js(code), "javascript") is ok


@pytest.mark.parametrize(
    ("code", "ok"),
    [
        ("", True),
        ("process.exit(0)", True),
        (
            "if (process.versions.bun) process.exit(0); const [major, minor] = "
            "process.versions.node.split('.').map(Number); if (major < 22 || (major === 22 && "
            "minor < 13)) { console.error('Node 22.13 or newer is required'); process.exit(1); }",
            True,
        ),
        (
            "if(process.env.npm_config_global==='true'){console.error('global install refused');"
            "process.exit(1)}",
            True,
        ),
        (
            "const v = parseInt(process.version.slice(1), 10); if (v < 18) { "
            "console.log(`needs Node 18, found ${process.version}`); process.exit(1); } "
            "else if (process.platform === 'win32') { process.exit(0); }",
            True,
        ),
        # A banner, or a message on success, is not a guard (`shoal-cli@0.4.5`).
        ("console.log('Thanks for installing!')", False),
        ("if (process.env.CI) process.exit(0); console.log('Run kx init')", False),
        ("if (process.platform === 'darwin') { console.log('hi'); process.exit(0); }", False),
        # Anything that does more.
        ("require('fs').writeFileSync('x', '1')", False),
        ("if (major < 22) { require('child_process').execSync('id'); process.exit(1); }", False),
        ("const h = require('os').homedir();", False),
        ("const k = process.env; process.exit(0);", False),
        ("const s = process.env['A' + 'B'];", False),
        ("const v = process.versions.node.split('.').map(eval);", False),
        ("const v = process.version.constructor.constructor('return 1')();", False),
        ("process.exit(code)", False),
        ("for (;;) {}", False),
        ("x = 1;", False),
        ("const f = () => { fetch('https://x.invalid'); };", False),
        (
            "if (process.version < 'v18') { console.error(fetch('https://x')); process.exit(1); }",
            False,
        ),
        ("process.exit(0", False),
    ],
)
def test_guard_only(code: str, ok: bool) -> None:
    assert guard_only(js(code), "javascript") is ok
