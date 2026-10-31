"""Install-script entry points, from inert package.json fixtures."""

import json

from kitsunox.ecosystems.npm.install import install_commands, install_entry_files


def tree(scripts: object, *paths: str) -> dict[str, bytes]:
    files = {p: b"" for p in paths}
    files["package.json"] = json.dumps({"scripts": scripts}).encode()
    return files


def test_entry_files_from_hook_commands() -> None:
    files = tree(
        {"postinstall": "node ./scripts/setup.js && node 'x.cjs'", "test": "node t.js"},
        "scripts/setup.js",
        "x.cjs",
        "t.js",
    )
    assert install_entry_files(files) == {"scripts/setup.js", "x.cjs"}
    assert install_commands(files) == {"postinstall": "node ./scripts/setup.js && node 'x.cjs'"}


def test_missing_or_hostile_manifests() -> None:
    assert install_entry_files({}) == frozenset()
    assert install_entry_files({"package.json": b"[]"}) == frozenset()
    assert install_entry_files({"package.json": b"{"}) == frozenset()
    assert install_entry_files(tree({"install": "node-gyp rebuild"})) == frozenset()


def test_install_sources_include_inline_code() -> None:
    from kitsunox.ecosystems.npm.install import install_sources

    scripts = {
        "preinstall": 'node -e "require(\\"https\\").get(u)"',
        "install": "node setup.js && node --eval 'console.log(1)'",
        "postinstall": "echo done",
    }
    files = {"package.json": json.dumps({"scripts": scripts}).encode(), "setup.js": b"x()"}
    assert install_sources(files) == {
        "setup.js": b"x()",
        "package.json#scripts.install.js": b"console.log(1)",
        "package.json#scripts.preinstall.js": b'require("https").get(u)',
    }


def test_install_sources_follow_what_the_hook_loads() -> None:
    """`@next2012/aistudio-runtime`: the hook's file only imports `lib/postinstall.js`."""
    from kitsunox.ecosystems.npm import install
    from kitsunox.ecosystems.npm.install import install_sources

    files = {
        "package.json": json.dumps({"scripts": {"postinstall": "node install.cjs"}}).encode(),
        "install.cjs": b"import(pathToFileURL(join(__dirname, 'lib', 'postinstall.js')).href)",
        "lib/postinstall.js": b"const s = require('./steps'); require('../escape.js')",
        "lib/steps/index.js": b"require('./deep.cjs')",
        "lib/steps/deep.cjs": b"third level: not followed",
        "lib/big.js": b"x" * (install.MAX_FOLLOWED_BYTES + 1),
        "README.md": b"",
    }
    files["install.cjs"] += b"; require('./lib/big'); require('./README.md'); require('fs')"
    assert sorted(install_sources(files)) == [
        "install.cjs",
        "lib/postinstall.js",
        "lib/steps/index.js",
    ]
    inline = {
        "package.json": json.dumps({"scripts": {"install": "node -e \"require('./a')\""}}).encode(),
        "a.js": b"spawn(process.execPath, [path.resolve(__dirname, 'b.js')])",
        "b.js": b"payload",
    }
    assert sorted(install_sources(inline)) == ["a.js", "b.js", "package.json#scripts.install.js"]
