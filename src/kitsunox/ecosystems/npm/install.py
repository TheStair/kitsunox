"""Which files an npm install script runs.

`npm install` runs `preinstall`, `install` and `postinstall` from the tarball's `package.json`.
Their commands are shell lines such as `node scripts/setup.js` or `node ./x.js && node y.cjs`;
any token that names a file in the package is an entry point. Stage 3 profiles those files on
their own, because code that runs at install time needs no import to do harm.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Final

from kitsunox.ecosystems.npm.rules.metadata import INSTALL_HOOKS, scripts

_TOKEN: Final = re.compile(r"[\s;&|()<>]+")


def install_commands(files: Mapping[str, bytes]) -> dict[str, str]:
    """The install hooks of the tarball's own `package.json` (what npm runs)."""
    raw = files.get("package.json")
    if raw is None:
        return {}
    try:
        manifest = json.loads(raw)
    except ValueError:
        return {}
    if not isinstance(manifest, dict):
        return {}
    return {k: v for k, v in scripts(manifest).items() if k in INSTALL_HOOKS}


def install_entry_files(files: Mapping[str, bytes]) -> frozenset[str]:
    """Package files named in an install hook's command line."""
    found = set()
    for command in install_commands(files).values():
        for token in _TOKEN.split(command):
            path = token.strip("'\"").removeprefix("./")
            if path in files:
                found.add(path)
    return frozenset(found)
