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
