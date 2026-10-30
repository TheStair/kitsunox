"""Which files an npm install script runs.

`npm install` runs `preinstall`, `install` and `postinstall` from the tarball's `package.json`.
Their commands are shell lines such as `node scripts/setup.js` or `node ./x.js && node y.cjs`;
any token that names a file in the package is an entry point. Stage 3 profiles those files on
their own, because code that runs at install time needs no import to do harm.

Code passed inline (`node -e "..."`, `--eval`, `-p`, `--print`) is code too: `install_sources`
gives it as a virtual file, `package.json#scripts.<hook>.js`, so the install-code rules read it.
Before, an inline hook named no file and its code went unread (`dependencykfeg`, 2026-10-30:
`node -e "...dns.lookup(<cwd as hex>...)"`).
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Final

from kitsunox.ecosystems.npm.rules.metadata import INSTALL_HOOKS, scripts

_TOKEN: Final = re.compile(r"[\s;&|()<>]+")
INLINE_PREFIX: Final = "package.json#scripts."
# `node -e <quoted code>`: the code up to the matching unescaped quote (linear: no nesting).
_INLINE: Final = re.compile(
    r"""\bnode(?:\.exe)?\s++(?:-e|--eval|-p|--print)\s++"""
    r"""(?:"(?P<double>(?:[^"\\]|\\.)*+)"|'(?P<single>[^']*+)')""",
    re.DOTALL,
)


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


def install_sources(files: Mapping[str, bytes]) -> dict[str, bytes]:
    """What `npm install` runs: the package files its hooks name, and the code its hooks pass
    inline to `node`, as `package.json#scripts.<hook>.js`."""
    sources = {path: files[path] for path in install_entry_files(files)}
    for hook, command in sorted(install_commands(files).items()):
        inline = [
            m.group("double").replace('\\"', '"')
            if m.group("double") is not None
            else m.group("single")
            for m in _INLINE.finditer(command)
        ]
        if inline:
            sources[f"{INLINE_PREFIX}{hook}.js"] = "\n".join(inline).encode()
    return sources


def install_entry_files(files: Mapping[str, bytes]) -> frozenset[str]:
    """Package files named in an install hook's command line."""
    return frozenset().union(*(files_named(c, files) for c in install_commands(files).values()))


def files_named(command: str, files: Mapping[str, bytes]) -> frozenset[str]:
    """Files of `files` named on one command line."""
    found = set()
    for token in _TOKEN.split(command):
        path = token.strip("'\"").removeprefix("./")
        if path in files:
            found.add(path)
    return frozenset(found)
