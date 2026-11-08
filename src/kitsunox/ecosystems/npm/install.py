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

A package with a `binding.gyp` is built with `node-gyp rebuild` on install (npm adds that hook
itself), and gyp runs commands while it builds: an `action`'s command, and a command expansion
`<!(...)` / `<!@(...)`. Those commands count as install commands (`gyp_commands`), and code they
pass inline is `binding.gyp#commands.js`. `@atedone/workspace-bootstrap` (2026-10-31) had no
install script at all; a gyp action ran `node scripts/write-state.js --install`.
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
GYP_FILE: Final = "binding.gyp"
GYP_INLINE: Final = f"{GYP_FILE}#commands.js"
# gyp's own syntax: an action's `'action': ['node', 'x.js']`, and a command expansion
# `<!(cmd)` or `<!@(cmd)` inside any string (the command may itself contain parentheses).
_GYP_ACTION: Final = re.compile(r"""["']action["']\s*:\s*\[([^\]]*)\]""")
_GYP_EXPANSION: Final = re.compile(r"""<!@?\((.*?)\)(?=\\?["'])""")
_GYP_STRING: Final = re.compile(r""""((?:[^"\\]|\\.)*)"|'([^']*)'""")
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


def gyp_commands(files: Mapping[str, bytes]) -> list[str]:
    """The commands `binding.gyp` makes `node-gyp rebuild` run: each action's, and each command
    expansion's (a larger file than `MAX_FOLLOWED_BYTES` is not read)."""
    raw = files.get(GYP_FILE)
    if raw is None or len(raw) > MAX_FOLLOWED_BYTES:
        return []
    text = raw.decode("utf-8", "replace")
    commands = []
    for match in _GYP_ACTION.finditer(text):
        words = [d or q for d, q in _GYP_STRING.findall(match.group(1))]
        commands.append(" ".join(words))
    commands.extend(m.group(1).replace('\\"', '"') for m in _GYP_EXPANSION.finditer(text))
    return commands


def _inline_code(command: str) -> list[str]:
    """Code a command passes inline to `node -e` / `--eval` / `-p` / `--print`."""
    return [
        m.group("double").replace('\\"', '"')
        if m.group("double") is not None
        else m.group("single")
        for m in _INLINE.finditer(command)
    ]


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
        if inline := _inline_code(command):
            sources[f"{INLINE_PREFIX}{hook}.js"] = "\n".join(inline).encode()
    if inline := [code for command in gyp_commands(files) for code in _inline_code(command)]:
        sources[GYP_INLINE] = "\n".join(inline).encode()
    return sources | followed_files(sources, files)


def followed_files(
    sources: Mapping[str, bytes],
    files: Mapping[str, bytes],
    *,
    depth: int = FOLLOW_DEPTH,
    max_files: int = MAX_FOLLOWED,
    max_bytes: int = MAX_FOLLOWED_BYTES,
) -> dict[str, bytes]:
    """Package files that `sources` load or run by a constant relative path, and those they
    load in turn, up to `depth` levels (default `FOLLOW_DEPTH`): at most `max_files` files,
    each at most `max_bytes` (a larger one is skipped, not cut)."""
    seen = set(sources)
    found: dict[str, bytes] = {}
    level: Iterable[tuple[str, bytes]] = sorted(sources.items())
    for _ in range(depth):
        following: list[tuple[str, bytes]] = []
        for path, content in level:
            language = "javascript" if _virtual(path) else language_for(path)
            if language is None:
                continue
            for specifier in local_paths(content, language):
                target = resolve(path, specifier, files)
                if target is None or target in seen:
                    continue
                seen.add(target)
                if len(files[target]) > max_bytes:
                    continue
                found[target] = files[target]
                following.append((target, files[target]))
                if len(found) >= max_files:
                    return found
        level = following
    return found


def loaded_files(sources: Mapping[str, bytes]) -> frozenset[str]:
    """The files of `sources` that another of them loads by a constant relative path: in
    `install_sources`' result, the followed files (and a named file another one imports)."""
    loaded = set()
    for path, content in sources.items():
        language = "javascript" if _virtual(path) else language_for(path)
        if language is None:
            continue
        for specifier in local_paths(content, language):
            target = resolve(path, specifier, sources)
            if target is not None and target != path:
                loaded.add(target)
    return frozenset(loaded)


def resolve(importer: str, specifier: str, files: Mapping[str, bytes]) -> str | None:
    """The package file `specifier` names from `importer` (Node's extension and `index`
    lookup), if it is JavaScript or TypeScript in the package."""
    directory = "" if _virtual(importer) else posixpath.dirname(importer)
    joined = posixpath.normpath(posixpath.join(directory, specifier.split("?")[0]))
    if joined.startswith("..") or joined.startswith("/"):
        return None
    for suffix in _RESOLVED:
        candidate = joined + suffix
        if candidate in files and language_for(candidate) is not None:
            return candidate
    return None


def install_entry_files(files: Mapping[str, bytes]) -> frozenset[str]:
    """Package files named in an install hook's command line, or in a command `binding.gyp`
    runs."""
    commands = [*install_commands(files).values(), *gyp_commands(files)]
    return frozenset().union(*(files_named(c, files) for c in commands))


def _virtual(path: str) -> bool:
    """Inline code given a path of its own (`package.json#scripts.<hook>.js`, `GYP_INLINE`)."""
    return path.startswith(INLINE_PREFIX) or path == GYP_INLINE


def files_named(command: str, files: Mapping[str, bytes]) -> frozenset[str]:
    """Files of `files` named on one command line."""
    found = set()
    for token in _TOKEN.split(command):
        path = token.strip("'\"").removeprefix("./")
        if path in files:
            found.add(path)
    return frozenset(found)
