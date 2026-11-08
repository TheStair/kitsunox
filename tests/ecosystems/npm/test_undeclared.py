"""`npm.undeclared-package` on hand-written, inert trees."""

import json

from kitsunox.core.models import (
    Evidence,
    EvidenceKind,
    Finding,
    PackageVersionRef,
    PublishInfo,
    Severity,
    VersionSnapshot,
)
from kitsunox.ecosystems.npm.entry import load_sources
from kitsunox.ecosystems.npm.rules.undeclared import (
    UndeclaredPackage,
    declared_packages,
    undeclared_names,
)
from kitsunox.stages.ast import CapabilityCache, CodeChange, code_change

CACHE = CapabilityCache(None)
MANIFEST = {
    "name": "kx",
    "main": "plugin.js",
    "dependencies": {"postcss": "^8"},
    "peerDependencies": {"tailwindcss": "^3"},
    "optionalDependencies": {"fsevents": "^2"},
    "bundleDependencies": ["vendored-a"],
    "devDependencies": {"eslint": "^8"},
}


def change(
    files: dict[str, bytes], before: dict[str, bytes] | None = None, manifest: object = None
) -> CodeChange:
    snapshot = VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="kx", version="1.0.1"),
        publish=PublishInfo(),
        manifest=MANIFEST if manifest is None else manifest,
    )
    tree = {"package.json": json.dumps(snapshot.manifest).encode(), **files}
    base = None if before is None else {"package.json": b"{}", **before}
    return code_change(
        snapshot,
        tree,
        base,
        CACHE,
        None,
        "1.0.0" if before else None,
        load_entries=load_sources,
    )


def test_declared_packages() -> None:
    assert declared_packages(MANIFEST) == {"kx", "postcss", "tailwindcss", "fsevents", "vendored-a"}
    assert declared_packages({"dependencies": ["x"], "bundledDependencies": ["y", 1]}) == {"x", "y"}
    assert declared_packages({"dependencies": "x", "name": 3}) == frozenset()


def test_an_undeclared_package_is_named() -> None:
    """`tailwind-animate-engine@1.0.6`: `plugin.js` -> `src/styles.js` -> `src/motion.js`,
    whose fifth line required `@unipswap/postcss-animate-units` (an inert stand-in name here)
    without declaring it."""
    files = {
        "plugin.js": b'require("tailwindcss/plugin"); require("kx/package.json"); '
        b'require("./src/styles")',
        "src/styles.js": b'module.exports = require("./motion.js");',
        "src/motion.js": b'const p = require("postcss"); const u = require("@s/postcss-units");',
    }
    (finding,) = UndeclaredPackage().evaluate_code(change(files))
    assert (finding.severity, finding.weight) == (Severity.INFO, 0.0)  # scores nothing itself
    assert "@s/postcss-units" in finding.explanation
    assert [(e.path, e.line_start) for e in finding.evidence] == [("src/motion.js", 1)]
    assert undeclared_names(finding) == ("@s/postcss-units",)


def test_only_what_loading_the_package_runs_counts() -> None:
    """Files no entry point reaches, deferred loads and `try` don't count (version 1 counted
    every file and deferred loads); a devDependency does: npm doesn't install it for users."""
    files = {
        "plugin.js": b"""require("./lib/a");
function later() { return require("deferred-pkg"); }
class K { m() { return import("in-a-method"); } }
(function () { require("iife-pkg"); })();
try { require("maybe-there") } catch (e) {}
require("eslint");
""",
        "lib/a.js": b'import x from "imported-pkg";',
        "test/a.test.js": b'require("test-only-pkg")',
        "src/plugin.ts": b'import y from "@shared/alias"',
        "bin/cli.js": b'require("bin-only-pkg")',
    }
    (finding,) = UndeclaredPackage().evaluate_code(change(files))
    assert undeclared_names(finding) == ("imported-pkg", "iife-pkg", "eslint")  # by path


def test_without_an_entry_file_nothing_counts() -> None:
    assert UndeclaredPackage().evaluate_code(change({"lib/x.js": b'require("y")'})) == ()
    manifest = {"name": "kx"}  # no main and no exports: Node loads index.js
    (finding,) = UndeclaredPackage().evaluate_code(
        change({"index.js": b'require("y")'}, manifest=manifest)
    )
    assert undeclared_names(finding) == ("y",)


def test_what_does_not_count() -> None:
    files = {
        "plugin.js": b'require("./a"); require("./b"); require("./c.mjs")',
        "a.js": b'require("fs"); require("node:fs"); require("fsevents"); require("vendored-a")',
        "b.js": b'try { require("maybe-there") } catch (e) {}',
        "c.mjs": b'import x from "vendored-b/lib"; import("./local.js")',
        "node_modules/vendored-b/index.js": b'require("its-own-dependency")',
        "node_modules/@s/v/index.js": b'require("another")',
    }
    assert UndeclaredPackage().evaluate_code(change(files)) == ()


def test_on_updates_only_new_names_count() -> None:
    old = {"plugin.js": b'require("left-pad")'}
    assert UndeclaredPackage().evaluate_code(change(old, before=old)) == ()
    new = {"plugin.js": b'require("left-pad"); require("right-pad")'}
    (finding,) = UndeclaredPackage().evaluate_code(change(new, before=old))
    assert "right-pad" in finding.explanation and "left-pad" not in finding.explanation


def test_undeclared_names_reads_only_its_own_form() -> None:
    def evidence(snippet: str | None) -> Evidence:
        return Evidence(kind=EvidenceKind.FILE_SPAN, path="a.js", snippet=snippet)

    finding = Finding(
        rule_id=UndeclaredPackage.id,
        rule_version=2,
        severity=Severity.INFO,
        weight=0.0,
        title="t",
        explanation="e",
        evidence=(
            evidence("[a] require('a')"),
            evidence("[a] require('a/x')"),
            evidence("[Not A Name] x"),
            evidence("[fs] require('fs')"),  # Node's own: never a package we'd name
            evidence("no brackets"),
            evidence(None),
            evidence("[@s/b] import b from '@s/b'"),
        ),
    )
    assert undeclared_names(finding) == ("a", "@s/b")
