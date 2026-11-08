"""`npm.undeclared-package` on hand-written, inert trees."""

import json

from kitsunox.core.models import PackageVersionRef, PublishInfo, Severity, VersionSnapshot
from kitsunox.ecosystems.npm.rules.undeclared import UndeclaredPackage, declared_packages
from kitsunox.stages.ast import CapabilityCache, CodeChange, code_change

CACHE = CapabilityCache(None)
MANIFEST = {
    "name": "kx",
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
    return code_change(snapshot, tree, base, CACHE, None, "1.0.0" if before else None)


def test_declared_packages() -> None:
    assert declared_packages(MANIFEST) == {"kx", "postcss", "tailwindcss", "fsevents", "vendored-a"}
    assert declared_packages({"dependencies": ["x"], "bundledDependencies": ["y", 1]}) == {"x", "y"}
    assert declared_packages({"dependencies": "x", "name": 3}) == frozenset()


def test_an_undeclared_package_is_named() -> None:
    """`tailwind-animate-engine@1.0.6` required `@unipswap/postcss-animate-units` (an inert
    stand-in name here) without declaring it."""
    files = {
        "src/motion.js": b'const p = require("postcss"); const u = require("@s/postcss-units");',
        "plugin.js": b'require("tailwindcss/plugin"); require("kx/package.json"); require("./m")',
    }
    (finding,) = UndeclaredPackage().evaluate_code(change(files))
    assert (finding.severity, finding.weight) == (Severity.INFO, 0.0)  # far too noisy to score
    assert "@s/postcss-units" in finding.explanation
    assert [(e.path, e.line_start) for e in finding.evidence] == [("src/motion.js", 1)]


def test_what_does_not_count() -> None:
    files = {
        "a.js": b'require("fs"); require("node:fs"); require("fsevents"); require("vendored-a")',
        "b.js": b'try { require("maybe-there") } catch (e) {}',
        "c.mjs": b'import x from "vendored-b/lib"; import("./local.js")',
        "node_modules/vendored-b/index.js": b'require("its-own-dependency")',
        "node_modules/@s/v/index.js": b'require("another")',
    }
    assert UndeclaredPackage().evaluate_code(change(files)) == ()


def test_on_updates_only_new_names_count() -> None:
    old = {"a.js": b'require("left-pad")'}
    assert UndeclaredPackage().evaluate_code(change(old, before=old)) == ()
    new = {"a.js": b'require("left-pad"); require("right-pad")'}
    (finding,) = UndeclaredPackage().evaluate_code(change(new, before=old))
    assert "right-pad" in finding.explanation and "left-pad" not in finding.explanation
