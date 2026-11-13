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

Shell, PowerShell and batch scripts the install code starts by a constant name
(`spawned_scripts`, 2026-11-10) are install code too: what `install.sh` writes runs at install
as much as the JavaScript that spawns it. And what such a script starts in turn
(`script_started`, round 4 G): another package script (`sh ./stage2.sh`,
`& "$PSScriptRoot\\helper.ps1"`, `call %~dp0setup.bat`) up to `SCRIPT_DEPTH` levels, or a
package JavaScript file (`node ./lib/x.js`), which is then followed like any install file.
A hook path written Windows-style (`.\\scripts\\x.ps1`, `node lib\\index.js`) names the package
file too.

A package with a `binding.gyp` is built with `node-gyp rebuild` on install (npm adds that hook
itself), and gyp runs commands while it builds: an `action`'s command, and a command expansion
`<!(...)` / `<!@(...)`. Those commands count as install commands (`gyp_commands`), and code they
pass inline is `binding.gyp#commands.js`. `@atedone/workspace-bootstrap` (2026-10-31) had no
install script at all; a gyp action ran `node scripts/write-state.js --install`. How the gyp
files are read (every expansion however it is embedded, variables, included files) is
`ecosystems.npm.gyp`.
"""

from __future__ import annotations

import json
import posixpath
import re
from collections.abc import Iterable, Mapping
from typing import Final

from kitsunox.ecosystems.npm.gyp import GYP_FILE
from kitsunox.ecosystems.npm.gyp import gyp_commands as gyp_commands
from kitsunox.ecosystems.npm.rules.metadata import INSTALL_HOOKS, scripts
from kitsunox.lang.javascript import language_for, local_paths
from kitsunox.lang.shell import mask_script_messages

_TOKEN: Final = re.compile(r"[\s;&|()<>]+")
INLINE_PREFIX: Final = "package.json#scripts."
GYP_INLINE: Final = f"{GYP_FILE}#commands.js"
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


def _inline_code(command: str) -> list[str]:
    """Code a command passes inline to `node -e` / `--eval` / `-p` / `--print`."""
    return [
        m.group("double").replace('\\"', '"')
        if m.group("double") is not None
        else m.group("single")
        for m in _INLINE.finditer(command)
    ]


def inline_blanked(command: str, files: Mapping[str, bytes], hook: str) -> str:
    """The hook's command line with the code it passes inline to `node` blanked (each byte a
    space, newlines kept), when `install_sources` gave exactly that code its own file
    (`package.json#scripts.<hook>.js` in `files`) to be read as JavaScript; otherwise the
    command line as it is (a registry manifest whose hook differs from the tarball's)."""
    inline = files.get(f"{INLINE_PREFIX}{hook}.js")
    if inline is None or inline != "\n".join(_inline_code(command)).encode():
        return command

    def blank(m: re.Match[str]) -> str:
        group = "double" if m.group("double") is not None else "single"
        start, end = m.start(group) - m.start(), m.end(group) - m.start()
        text = m.group(0)
        return text[:start] + re.sub(r"[^\n]", " ", text[start:end]) + text[end:]

    return _INLINE.sub(blank, command)


FOLLOW_DEPTH: Final = 2
MAX_FOLLOWED: Final = 20
MAX_FOLLOWED_BYTES: Final = 256 * 1024
_RESOLVED: Final = ("", ".js", ".cjs", ".mjs", ".ts", "/index.js", "/index.cjs", "/index.mjs")


def install_sources(files: Mapping[str, bytes]) -> dict[str, bytes]:
    """What `npm install` runs: the package files its hooks name, the code its hooks pass
    inline to `node` (as `package.json#scripts.<hook>.js`), the package files those load
    (`followed_files`), the scripts install code starts (`spawned_scripts`), and what those
    scripts start (`script_started`, and the files that JavaScript loads)."""
    sources = {path: files[path] for path in install_entry_files(files)}
    for hook, command in sorted(install_commands(files).items()):
        if inline := _inline_code(command):
            sources[f"{INLINE_PREFIX}{hook}.js"] = "\n".join(inline).encode()
    if inline := [code for command in gyp_commands(files) for code in _inline_code(command)]:
        sources[GYP_INLINE] = "\n".join(inline).encode()
    sources |= followed_files(sources, files)
    sources |= spawned_scripts(sources, files)
    if chained := script_started(sources, files):
        sources |= chained
        sources |= followed_files(chained, files)  # the JavaScript a script runs loads more
    return sources


# Scripts install code starts with a shell (`spawnSync("sh", [path.join(__dirname,
# "setup.sh")])`, `execFileSync("bash", [join(dir, "scripts", "install.sh")])`): what they do
# runs at install as much as the JavaScript does (2026-11-10, round 4: four unwanted installers
# wrote user-wide agent configuration or PATH entries only from such a script).
SCRIPT_SUFFIXES: Final = (".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd")
MAX_SPAWNED: Final = 10
MAX_SAME_NAME: Final = 3  # a bare script name that matches more package files is ambiguous
_QUOTED: Final = re.compile(r"""["'`]([^"'`\s$]{1,200})["'`]""")
_JOIN: Final = re.compile(r"""\b(?:join|resolve)\s*\(([^()]{0,400})\)""")


def spawned_scripts(sources: Mapping[str, bytes], files: Mapping[str, bytes]) -> dict[str, bytes]:
    """Shell, PowerShell and batch scripts of the package that install code names, read as
    data: a constant relative path (`local_paths`, as `followed_files`), the trailing constant
    arguments of a `join`/`resolve` call (`join(adapterDir, "claude-code", "scripts",
    "install.sh")` names the package file ending in `claude-code/scripts/install.sh`), or a
    script's bare name used anywhere (`"setup-ziniao-cli.sh"`) when at most `MAX_SAME_NAME`
    package files have it. At most `MAX_SPAWNED` scripts of at most `MAX_FOLLOWED_BYTES` each;
    scripts are not followed further."""
    scripts_in = sorted(p for p in files if p.lower().endswith(SCRIPT_SUFFIXES))
    if not scripts_in:
        return {}
    found: dict[str, bytes] = {}

    def add(candidates: list[str]) -> None:
        for path in candidates:
            if path not in sources and len(files[path]) <= MAX_FOLLOWED_BYTES:
                found.setdefault(path, files[path])

    for path, content in sorted(sources.items()):
        language = "javascript" if _virtual(path) else language_for(path)
        if language is None:
            continue
        directory = "" if _virtual(path) else posixpath.dirname(path)
        for specifier in local_paths(content, language):
            joined = posixpath.normpath(posixpath.join(directory, specifier))
            if joined in files and joined.lower().endswith(SCRIPT_SUFFIXES):
                add([joined])
        text = content.decode("utf-8", "replace")
        for call in _JOIN.finditer(text):
            parts: list[str] = []
            for argument in reversed(call.group(1).split(",")):
                quoted = _QUOTED.fullmatch(argument.strip())
                if quoted is None:
                    break
                parts.insert(0, quoted.group(1))
            if parts and parts[-1].lower().endswith(SCRIPT_SUFFIXES):
                tail = posixpath.normpath("/".join(parts)).lstrip("./")
                if "/" in tail:
                    matches = [p for p in scripts_in if p == tail or p.endswith("/" + tail)]
                    add(matches[:MAX_SAME_NAME])
                else:  # a bare name joined to a directory: the importer's own, or the root
                    add([p for p in (posixpath.join(directory, tail), tail) if p in files])
        outside = _JOIN.sub(" ", text)  # a name inside a join was resolved above
        for literal in _QUOTED.findall(outside):
            if literal.lower().endswith(SCRIPT_SUFFIXES) and "/" not in literal:
                same = [p for p in scripts_in if posixpath.basename(p) == literal]
                if len(same) <= MAX_SAME_NAME:
                    add(same)
        if len(found) >= MAX_SPAWNED:
            break
    return dict(sorted(found.items())[:MAX_SPAWNED])


# What a script starts (2026-11-10, round 4 G): `sh ./stage2.sh`, `. "$DIR/lib/env.sh"`,
# `& "$PSScriptRoot\helper.ps1"`, `call %~dp0setup.bat`, `powershell -File .\x.ps1`,
# `node ./lib/x.js`. A path token ending in a script or JavaScript suffix, not part of a URL.
SCRIPT_DEPTH: Final = 2
_STARTED_SUFFIXES: Final = (*SCRIPT_SUFFIXES, ".js", ".cjs", ".mjs")
_PATH_TOKEN: Final = re.compile(
    r"(?<![\w.:-])((?:[\w$%{}~@.:-]+[/\\])*[\w@.%~-]+\.(?:sh|bash|zsh|ps1|psm1|bat|cmd|js|cjs|mjs))"
    r"(?![\w.])",
    re.IGNORECASE,
)
_VARIABLE_SEGMENT: Final = re.compile(r"[$%{}~]|^\.$|^[A-Za-z]:$")
_IN_URL: Final = re.compile(r"[a-z][a-z0-9+.-]*:/[^\s\"'`]*\Z", re.IGNORECASE)
_DP0: Final = re.compile(r"^%~dp0", re.IGNORECASE)  # batch: the script's own directory


def script_started(sources: Mapping[str, bytes], files: Mapping[str, bytes]) -> dict[str, bytes]:
    """Package files that the shell, PowerShell and batch scripts in `sources` start, read as
    data: scripts (and those they start, up to `SCRIPT_DEPTH` levels) and JavaScript files
    (which `followed_files` then follows). A path is resolved from the script's directory, then
    the package root, after dropping leading variable segments (`$DIR/`, `${SCRIPT_DIR}/`,
    `$PSScriptRoot\\`, `%~dp0`); a bare name matches when at most `MAX_SAME_NAME` package files
    have it. Comments and printed messages are not read (`lang.shell.mask_script_messages`).
    At most `MAX_SPAWNED` files of at most `MAX_FOLLOWED_BYTES` each."""
    by_name: dict[str, list[str]] = {}
    for path in sorted(files):
        if path.lower().endswith(_STARTED_SUFFIXES):
            by_name.setdefault(posixpath.basename(path), []).append(path)
    found: dict[str, bytes] = {}
    level = [p for p in sorted(sources) if p in files and p.lower().endswith(SCRIPT_SUFFIXES)]
    for _ in range(SCRIPT_DEPTH):
        following = []
        for script in level:
            text = mask_script_messages(files[script].decode("utf-8", "replace"))
            directory = posixpath.dirname(script)
            for match in _PATH_TOKEN.finditer(text):
                if _IN_URL.search(text, max(0, match.start() - 300), match.start()):
                    continue  # `https://get.example.dev/install.sh` is downloaded, not started
                for target in _started(match.group(1), directory, files, by_name):
                    if target in sources or target in found:
                        continue
                    if len(files[target]) > MAX_FOLLOWED_BYTES:
                        continue
                    found[target] = files[target]
                    if target.lower().endswith(SCRIPT_SUFFIXES):
                        following.append(target)
                    if len(found) >= MAX_SPAWNED:
                        return found
        level = following
    return found


def _started(
    token: str, directory: str, files: Mapping[str, bytes], by_name: Mapping[str, list[str]]
) -> list[str]:
    token = _DP0.sub("./", token)
    segments = [s for s in token.replace("\\", "/").split("/") if s]
    while segments and _VARIABLE_SEGMENT.search(segments[0]):
        segments = segments[1:]  # `$DIR`, `${SCRIPT_DIR}`, `%~dp0`, `.`, a drive letter
    if not segments:
        return []
    if _VARIABLE_SEGMENT.search(segments[-1]):
        return []
    rest = "/".join(segments)
    if len(segments) == 1 and token.replace("\\", "/") == rest:
        same = by_name.get(rest, [])  # a bare name: the script's own directory, or unique
        local = posixpath.join(directory, rest)
        if local in files:
            return [local]
        return same if len(same) <= MAX_SAME_NAME else []
    for base in (directory, ""):
        candidate = posixpath.normpath(posixpath.join(base, rest))
        if not candidate.startswith("..") and candidate in files:
            return [candidate]
    return []


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


def hook_paths(manifest: Mapping[str, object]) -> frozenset[str]:
    """Every token of `manifest`'s install hooks read as a package path, whether or not the
    package has such a file: before the files are read (a partial read keeps these first,
    decision 0021). The registry's manifest, so a hook only the tarball has isn't here."""
    commands = [c for hook, c in scripts(manifest).items() if hook in INSTALL_HOOKS]
    return frozenset(
        path
        for command in commands
        for token in _TOKEN.split(command)
        if (path := _package_path(token.strip("'\"")))
    )


def _virtual(path: str) -> bool:
    """Inline code given a path of its own (`package.json#scripts.<hook>.js`, `GYP_INLINE`)."""
    return path.startswith(INLINE_PREFIX) or path == GYP_INLINE


def files_named(command: str, files: Mapping[str, bytes]) -> frozenset[str]:
    """Files of `files` named on one command line."""
    found = set()
    for token in _TOKEN.split(command):
        path = _package_path(token.strip("'\""))
        if path in files:
            found.add(path)
    return frozenset(found)


def _package_path(token: str) -> str:
    """A command-line path as a package path: Windows separators as `/` (`.\\scripts\\x.ps1`,
    `lib\\index.js`; 2026-11-10, round 4 G: `company-ts@1.0.3`'s hook is `node lib\\index.js`),
    without a leading `./`."""
    path = token.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path
