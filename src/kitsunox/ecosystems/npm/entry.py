"""Which files loading an npm package runs: its entry points and the package files they load.

`require("pkg")` (or `import`) runs the file `package.json`'s `exports` or `main` names
(`index.js` when it names neither); bundlers also read `module` and a string `browser`.
Every file an entry loads by a constant relative path (`require("./lib/x")`, `import "./y.js"`)
runs too, and so on: `load_sources` follows them up to `LOAD_DEPTH` levels, at most
`MAX_LOAD_FILES` files of at most `MAX_LOAD_BYTES` each. A package the code of those files
loads at module load (`PackageLoad.at_load`) has to be installed the moment the package is
used. The Tailwind-wrapper template (`tailwind-animate-engine@1.0.6`, 2026-11-02) ran
`plugin.js` -> `src/styles.js` -> `src/motion.js`, whose fifth line required its payload.

`bin` scripts are not entries: they run when someone types the command, not when the package
is loaded. Files reached only from tests, examples or a shipped `src/` beside the build are
not reached at all, which is what keeps TypeScript sources, templates and test helpers out.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from typing import Final

from kitsunox.ecosystems.npm.install import followed_files, resolve

LOAD_DEPTH: Final = 8
MAX_LOAD_FILES: Final = 300
MAX_LOAD_BYTES: Final = 4 * 1024 * 1024
DEFAULT_ENTRY: Final = "./index.js"
ENTRY_FIELDS: Final = ("main", "module", "browser")
_TYPES_CONDITIONS: Final = frozenset({"types", "typings"})


def entry_files(files: Mapping[str, bytes]) -> frozenset[str]:
    """The package files the tarball's `package.json` names as what loading it runs."""
    raw = files.get("package.json")
    try:
        manifest = json.loads(raw) if raw is not None else None
    except ValueError:
        manifest = None
    if not isinstance(manifest, dict):
        manifest = {}
    targets = [manifest[f] for f in ENTRY_FIELDS if isinstance(manifest.get(f), str)]
    targets.extend(_export_targets(manifest.get("exports")))
    if not isinstance(manifest.get("main"), str) and "exports" not in manifest:
        targets.append(DEFAULT_ENTRY)
    found = set()
    for target in targets:
        specifier = target if target.startswith((".", "/")) else f"./{target}"
        if (path := resolve("", specifier, files)) is not None:
            found.add(path)
    return frozenset(found)


def _export_targets(exports: object) -> Iterator[str]:
    """Each file target of an `exports` value (a string, a list, or a map of subpaths and
    conditions), without type declarations' conditions and `*` patterns."""
    if isinstance(exports, str):
        if "*" not in exports:
            yield exports
    elif isinstance(exports, list):
        for item in exports:
            yield from _export_targets(item)
    elif isinstance(exports, Mapping):
        for key, value in exports.items():
            if key not in _TYPES_CONDITIONS and "*" not in str(key):
                yield from _export_targets(value)


def load_sources(files: Mapping[str, bytes]) -> dict[str, bytes]:
    """The entry files and the package files they load, up to `LOAD_DEPTH` levels (each
    followed file at most `MAX_LOAD_BYTES`; an entry is kept whatever its size)."""
    entries = {path: files[path] for path in sorted(entry_files(files))}
    followed = followed_files(
        entries, files, depth=LOAD_DEPTH, max_files=MAX_LOAD_FILES, max_bytes=MAX_LOAD_BYTES
    )
    return entries | followed
