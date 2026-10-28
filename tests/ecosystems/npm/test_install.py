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
