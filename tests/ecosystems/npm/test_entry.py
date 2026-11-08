"""Which files loading an npm package runs (`ecosystems.npm.entry`), on inert trees."""

import json

import pytest

from kitsunox.ecosystems.npm.entry import entry_files, load_sources


def tree(manifest: object, **files: bytes) -> dict[str, bytes]:
    return {"package.json": json.dumps(manifest).encode(), **{k: v for k, v in files.items()}}


JS = b"module.exports = 1"


@pytest.mark.parametrize(
    ("manifest", "expected"),
    [
        ({}, {"index.js"}),  # Node's default
        ({"main": "lib"}, {"lib/index.js"}),
        ({"main": "./lib/main"}, {"lib/main.js"}),
        ({"main": "missing.js"}, set()),
        ({"exports": "./lib/main.js"}, {"lib/main.js"}),  # no `index.js` default with exports
        (
            {
                "exports": {
                    ".": {"types": "./index.d.ts", "import": "./esm.mjs", "require": "./cjs.cjs"},
                    "./sub": ["./lib/main.js"],
                    "./features/*": "./lib/*.js",
                    "./package.json": "./package.json",
                    "./none": None,
                }
            },
            {"esm.mjs", "cjs.cjs", "lib/main.js"},
        ),
        (
            {"module": "esm.mjs", "browser": "lib/main.js", "main": 3},
            {"esm.mjs", "lib/main.js", "index.js"},  # a `main` that is not a string: index.js
        ),
        ({"browser": {"./a": False}}, {"index.js"}),
    ],
)
def test_entry_files(manifest: object, expected: set[str]) -> None:
    files = tree(manifest)
    for path in ("index.js", "lib/index.js", "lib/main.js", "esm.mjs", "cjs.cjs", "index.d.ts"):
        files[path] = JS
    assert entry_files(files) == expected


def test_a_broken_manifest_falls_back_to_index_js() -> None:
    assert entry_files({"package.json": b"{not json", "index.js": JS}) == {"index.js"}
    assert entry_files({"package.json": b"[1]", "index.js": JS}) == {"index.js"}
    assert entry_files({"index.js": JS}) == {"index.js"}


def test_load_sources_follow_what_entries_load() -> None:
    files = tree(
        {"main": "plugin.js", "bin": "bin/cli.js"},
        **{
            "plugin.js": b'require("./src/styles")',
            "src/styles.js": b'const m = require("./motion"); import("../lib/x.mjs")',
            "src/motion.js": b'require("@s/payload")',
            "lib/x.mjs": JS,
            "bin/cli.js": b'require("./src/other")',
            "src/other.js": JS,
            "test/a.test.js": b'require("../plugin")',
        },
    )
    assert sorted(load_sources(files)) == [
        "lib/x.mjs",
        "plugin.js",
        "src/motion.js",
        "src/styles.js",
    ]
