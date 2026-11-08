"""Capability extraction on inert, hand-written JS/TS snippets (parsed, never run)."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from kitsunox.lang.javascript import (
    FUNCTION_ALIASES,
    GIVEN_LOADER,
    MAX_EVIDENCE,
    Capability,
    analyse_source,
    fold_string,
    language_for,
    module_capability,
    package_name,
)

C = Capability


def caps(source: str, language: str = "javascript") -> set[tuple[Capability, str]]:
    return {(u.capability, u.detail) for u in analyse_source(source.encode(), language).uses}


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ('require("https")', (C.NETWORK, "https")),
        ('require("node:child_process")', (C.PROCESS, "node:child_process")),
        ('require("child_" + "process")', (C.PROCESS, "child_process")),
        ("require(`fs`)", (C.FILESYSTEM, "fs")),
        ('import fs from "fs/promises"', (C.FILESYSTEM, "fs/promises")),
        ('export * from "os"', (C.OS_INFO, "os")),
        ('await import("dns")', (C.NETWORK, "dns")),
        ("require(name)", (C.DYNAMIC_REQUIRE, "require(<computed>)")),
        ('require("./build/addon.node")', (C.NATIVE, "./build/addon.node")),
        ('process.binding("fs")', (C.NATIVE, "process.binding")),
        ("fetch(url)", (C.NETWORK, "fetch")),
        ("new WebSocket(u)", (C.NETWORK, "new WebSocket")),
        ("eval(code)", (C.DYNAMIC_CODE, "eval")),
        ('global["ev" + "al"](code)', (C.DYNAMIC_CODE, "global[eval]")),
        ('new Function("a", body)', (C.DYNAMIC_CODE, "new Function")),
        ("send(JSON.stringify(process.env))", (C.ENV_ALL, "process.env")),
        ("const {A, ...rest} = process.env", (C.ENV_ALL, "process.env")),
        ('process["env"]', (C.ENV_ALL, "process.env")),
        # v4, `@atedone/workspace-bootstrap`: the same capabilities without the usual tells
        ('process.getBuiltinModule("node:https")', (C.NETWORK, "node:https")),
        ("process.getBuiltinModule('child_' + 'process')", (C.PROCESS, "child_process")),
        (
            "process.getBuiltinModule(name)",
            (C.DYNAMIC_REQUIRE, "process.getBuiltinModule(<computed>)"),
        ),
        ("send(Reflect.get(process, 'env'))", (C.ENV_ALL, "Reflect.get(process, 'env')")),
    ],
)
def test_capabilities_found(source: str, expected: tuple[Capability, str]) -> None:
    assert expected in caps(source)


@pytest.mark.parametrize(
    "source",
    [
        '// require("https") and https://hooks.slack.com in a comment',
        'const s = "require(\\"child_process\\")"',  # a string, not a call
        "x.require('fs'); obj.eval(x); my.fetch(u)",  # methods, not the globals
        "const home = process.env.HOME; if (process.env.CI) {}",
        'const {HOME, USER} = process.env; process.env["X"]',
        'process.env.X = "1"',
        'require("lodash"); import React from "react"',
        "Reflect.get(process, 'env').HOME; Reflect.get(obj, 'env')",  # one variable; not process
        'process.getBuiltinModule("path")',  # a module with no capability
    ],
)
def test_lookalikes_are_not_capabilities(source: str) -> None:
    assert caps(source) == set()


def test_typescript_and_tsx() -> None:
    assert (C.NETWORK, "fetch") in caps(
        "const r: Response = await fetch(u as string);", "typescript"
    )
    assert (C.PROCESS, "child_process") in caps(
        'import { exec } from "child_process"; const A = () => <div/>;', "tsx"
    )


def test_language_for() -> None:
    assert language_for("lib/index.js") == "javascript"
    assert language_for("a.MJS") == "javascript"
    assert language_for("src/a.ts") == "typescript"
    assert language_for("src/a.tsx") == "tsx"
    assert language_for("types/index.d.ts") is None  # declarations: no code runs
    assert language_for("dist/index.d.cts") is None
    assert language_for("dist/index.d.mts") is None
    assert language_for("README.md") is None


def test_fold_string_only_folds_constants() -> None:
    assert fold_string(None) is None
    assert module_capability("@scope/pkg") is None
    assert module_capability("fs-extra/lib") == C.FILESYSTEM


def test_evidence_is_bounded_and_located() -> None:
    result = analyse_source(b"\n".join([b"fetch(a)"] * 10), "javascript")
    assert [u.line for u in result.uses] == [1, 2, 3]
    assert not result.parse_errors


def test_broken_source_is_reported_not_raised() -> None:
    result = analyse_source(b'require("https"); function (', "javascript")
    assert result.parse_errors
    assert {u.capability for u in result.uses} == {C.NETWORK}


def test_parsers_are_safe_across_threads() -> None:
    sources = [f'require("https"); fetch(x{i})'.encode() for i in range(200)]
    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(lambda s: analyse_source(s, "javascript"), sources))
    assert all(r.capabilities == {C.NETWORK} for r in results)


@pytest.mark.parametrize(
    ("code", "dynamic"),
    [
        (b'var g = Function("return this")();', False),  # bundlers' route to the global object
        (b"new Function('return this;')", False),
        (b'eval("a" + "b")', False),
        (b"Function()", False),
        (b"eval(atob(x))", True),
        (b"new Function(`return ${arg}`)", True),
        (b'new Function("a", body)', True),
        (b'Function("p", "' + b"x" * 200 + b'")', True),  # a long constant can be a payload
    ],
)
def test_constant_code_is_not_dynamic(code: bytes, dynamic: bool) -> None:
    uses = analyse_source(code, "javascript").uses
    assert any(u.capability is Capability.DYNAMIC_CODE for u in uses) is dynamic


def test_evidence_is_capped_per_detail_so_a_later_eval_is_kept() -> None:
    """v3: three `new Function(x)` calls used to fill the file's `dynamic-code` evidence."""
    code = b"new Function(a); new Function(b); new Function(c); new Function(d);\neval(y)"
    uses = [u for u in analyse_source(code, "javascript").uses if u.capability is C.DYNAMIC_CODE]
    assert [u.detail for u in uses] == ["new Function"] * MAX_EVIDENCE + ["eval"]


CHAIN, LITERAL = "constructor.constructor", "function.constructor"


@pytest.mark.parametrize(
    ("code", "detail"),
    [
        # v5: the Function constructor without naming it (`txnforge`'s shape, split over two
        # variables declared in the same function and returned)
        (
            "const get = () => { const g = (() => this)() || globalThis;"
            " const c = g.constructor; const f = c.constructor; return f; }",
            CHAIN,
        ),
        ("x.constructor.constructor(code)()", CHAIN),
        ("x['constructor']['constructor'](code)", CHAIN),
        ("x['constr' + 'uctor'].constructor.call(null, code)", CHAIN),
        ("const F = a.constructor.constructor || Function; F(code)", CHAIN),
        ("const F = ok ? [].constructor.constructor : null; run(F)", CHAIN),
        ("const AF = (async () => {}).constructor; new AF('a', body)", LITERAL),
        ("const G = (function* () {}).constructor; module.exports = {G}", LITERAL),
        ("const AF = Object.getPrototypeOf(async function () {}).constructor; f(AF)", LITERAL),
        ("run(Reflect.getPrototypeOf((() => {})).constructor)", LITERAL),
        ("new (class {}).constructor(body)", LITERAL),
    ],
)
def test_function_constructor_through_constructor(code: str, detail: str) -> None:
    assert (C.DYNAMIC_CODE, detail) in caps(code)


@pytest.mark.parametrize(
    "code",
    [
        "[].constructor.constructor('return this')()",  # short constant code, as `Function(...)`
        "if (f instanceof (async () => {}).constructor) {}",  # a type check
        "if ((async () => {}).constructor) {}",
        "typeof x.constructor.constructor",
        "x.constructor.constructor;",
        "const n = x.constructor.constructor.name",  # read, not used as a function
        "var P = function () {}.constructor, proto = P ? P.prototype : null",  # echarts
        "const AF = (async () => {}).constructor; if (fn instanceof AF) {}",
        'const AF = (async () => {}).constructor; log("AF", x.AF) // AF',  # not references
        "this.constructor.name; a.constructor === Object; const C = this.constructor; new C()",
        # a variable from another function, or assigned rather than declared, is not followed
        "function a() { const t = e.constructor } function b(t) { return t.constructor }",
        "t = e.constructor; run(t.constructor)",
        "const c = g.constructor; function b() { return c.constructor }",
        "run(Object.getPrototypeOf(fn).constructor); run(Object.getPrototypeOf().constructor)",
        "run(Object.keys(() => {}).constructor)",
    ],
)
def test_constructor_uses_that_are_not_dynamic_code(code: str) -> None:
    assert not {d for c, d in caps(code) if c is C.DYNAMIC_CODE} & FUNCTION_ALIASES


@pytest.mark.parametrize(
    ("code", "detail"),
    [
        # `smfos-bskdz-util`'s shape (inert): Node's loader as a parameter of the built function
        ("var F = (function () {}).constructor; F('require', '__dirname', s)(require, d)", LITERAL),
        ("new ((async () => {}).constructor)('module', body)", LITERAL),
        # `txnforge`'s: the built function is called with them, elsewhere in the file
        (
            "const F = g.constructor.constructor; const f = F(a, b); f(Buffer, require, process)",
            CHAIN,
        ),
    ],
)
def test_function_constructor_given_the_loader(code: str, detail: str) -> None:
    assert (C.DYNAMIC_CODE, detail + GIVEN_LOADER) in caps(code)
    assert (C.DYNAMIC_CODE, detail) not in caps(code)


def test_references_examined_are_capped() -> None:
    """A minified bundle can name thousands of things `t`: only the first MAX_REFERENCES are
    looked at."""
    from kitsunox.lang.javascript import MAX_REFERENCES

    reads = b"f(t.x);" * MAX_REFERENCES
    late = b"var t = function () {}.constructor;" + reads + b"g(t);"
    assert not {d for c, d in caps(late.decode()) if c is C.DYNAMIC_CODE} & FUNCTION_ALIASES
    early = b"var t = function () {}.constructor; g(t);" + reads
    assert (C.DYNAMIC_CODE, "function.constructor") in caps(early.decode())


def test_a_file_that_is_not_utf8() -> None:
    """A regular-expression predicate raised SystemError on such a file (`llm-oracle@1.0.2`)."""
    code = b"\xff\xfe x['constructor']['constructor'](c); q['\xc3\x28'] /* \xc3\x28 */"
    uses = analyse_source(code, "javascript").uses
    assert [u.detail for u in uses] == ["constructor.constructor"]


def test_packages_loaded_by_name() -> None:
    """v6: what `npm.undeclared-package` compares with the manifest."""
    code = b"""const a = require("@scope/payload/lib/x");
import b from "lodash/fp";
import t from "node:test";
const fs = require("fs/promises");
try { require("optional-a") } catch {}
try { require("optional-b") } catch {}
require("optional-b");
require("./local"); require("/abs"); require("#internal"); require("~/alias");
import("dynamic-pkg"); require(name); require("BAD NAME");
export * from "re-exported";
eval("not-a-package"); fetch("also-not");
"""
    result = analyse_source(code, "javascript")
    assert [(p.name, p.line, p.guarded) for p in result.packages] == [
        ("@scope/payload", 1, False),
        ("lodash", 2, False),
        ("optional-a", 5, True),
        ("optional-b", 7, False),  # loaded outside a `try` too
        ("dynamic-pkg", 9, False),
        ("re-exported", 10, False),
    ]
    typed = analyse_source(
        b'import type {A} from "types-only"; import {B} from "real"', "typescript"
    )
    assert [p.name for p in typed.packages] == ["real"]


@pytest.mark.parametrize(
    ("specifier", "name"),
    [
        ("x", "x"),
        ("x/sub/path.js", "x"),
        ("@s/x/sub", "@s/x"),
        ("JSONStream", None),  # uppercase: not a name npm accepts now (an AMD global)
        ("fs", None),
        ("node:sqlite", None),
        ("bun:test", None),
        ("https://esm.sh/x", None),
        ("./x", None),
        ("@s", None),
        ("{x}", None),
    ],
)
def test_package_name(specifier: str, name: str | None) -> None:
    assert package_name(specifier) == name
