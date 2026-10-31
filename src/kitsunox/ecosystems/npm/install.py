"""Which files an npm install script runs.

`npm install` runs `preinstall`, `install` and `postinstall` from the tarball's `package.json`.
Their commands are shell lines such as `node scripts/setup.js` or `node ./x.js && node y.cjs`;
any token that names a file in the package is an entry point. Stage 3 profiles those files on
their own, because code that runs at install time needs no import to do harm.

Code passed inline (`node -e "..."`, `--eval`, `-p`, `--print`) is code too: `install_sources`
gives it as a virtual file, `package.json#scripts.<hook>.js`, so the install-code rules read it.
Before, an inline hook named no file and its code went unread (`dependencykfeg`, 2026-10-30:
`node -e "...dns.lookup(<cwd as hex>...)"`).

The package files that code loads or runs by a constant path (`require("./lib/x")`,
`path.join(__dirname, "lib", "x.js")`) run at install time too, so they are followed
(`followed_files`): two levels deep, at most `MAX_FOLLOWED` files of at most
`MAX_FOLLOWED_BYTES` each, so a hook that loads the whole library doesn't make it all install
code. `@next2012/aistudio-runtime`'s hook only imports `lib/postinstall.js`.
"""

from __future__ import annotations

import json
import posixpath
import re
from collections.abc import Iterable, Mapping
from typing import Final

from kitsunox.ecosystems.npm.rules.metadata import INSTALL_HOOKS, scripts
from kitsunox.lang.javascript import language_for, local_paths

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


FOLLOW_DEPTH: Final = 2
MAX_FOLLOWED: Final = 20
MAX_FOLLOWED_BYTES: Final = 256 * 1024
_RESOLVED: Final = ("", ".js", ".cjs", ".mjs", ".ts", "/index.js", "/index.cjs", "/index.mjs")


def install_sources(files: Mapping[str, bytes]) -> dict[str, bytes]:
    """What `npm install` runs: the package files its hooks name, the code its hooks pass
    inline to `node` (as `package.json#scripts.<hook>.js`), and the package files those load
    (`followed_files`)."""
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
    return sources | followed_files(sources, files)


def followed_files(sources: Mapping[str, bytes], files: Mapping[str, bytes]) -> dict[str, bytes]:
    """Package files that `sources` load or run by a constant relative path, and those they
    load in turn, up to `FOLLOW_DEPTH` levels: at most `MAX_FOLLOWED` files, each at most
    `MAX_FOLLOWED_BYTES` (a larger one is skipped, not cut)."""
    seen = set(sources)
    found: dict[str, bytes] = {}
    level: Iterable[tuple[str, bytes]] = sorted(sources.items())
    for _ in range(FOLLOW_DEPTH):
        following: list[tuple[str, bytes]] = []
        for path, content in level:
            language = "javascript" if path.startswith(INLINE_PREFIX) else language_for(path)
            if language is None:
                continue
            for specifier in local_paths(content, language):
                target = _resolve(path, specifier, files)
                if target is None or target in seen:
                    continue
                seen.add(target)
                if len(files[target]) > MAX_FOLLOWED_BYTES:
                    continue
                found[target] = files[target]
                following.append((target, files[target]))
                if len(found) >= MAX_FOLLOWED:
                    return found
        level = following
    return found


def _resolve(importer: str, specifier: str, files: Mapping[str, bytes]) -> str | None:
    """The package file `specifier` names from `importer` (Node's extension and `index`
    lookup), if it is JavaScript or TypeScript in the package."""
    directory = "" if importer.startswith(INLINE_PREFIX) else posixpath.dirname(importer)
    joined = posixpath.normpath(posixpath.join(directory, specifier.split("?")[0]))
    if joined.startswith("..") or joined.startswith("/"):
        return None
    for suffix in _RESOLVED:
        candidate = joined + suffix
        if candidate in files and language_for(candidate) is not None:
            return candidate
    return None


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
