"""Capability extraction on inert, hand-written JS/TS snippets (parsed, never run)."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from kitsunox.lang.javascript import (
    Capability,
    analyse_source,
    fold_string,
    language_for,
    module_capability,
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
