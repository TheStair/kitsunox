"""The commands a package's gyp files make `node-gyp rebuild` run, read as data.

npm runs `node-gyp rebuild` for any package with a `binding.gyp` (it adds the `install` hook
itself), and gyp runs commands while it reads and builds the file:

- a **command expansion** in any string: `<!(cmd)` (its output, as a string) or `<!@(cmd)` (as
  a list), in each of gyp's three phases (`<`, `>`, `^`); `<!pymod_do_main(module args)`
  imports a Python module from the package's directory and calls it. The expansion is wherever
  the string has it: a key, a value, after or before other text (`"<!(node x.js):target"`),
  inside another expansion. gyp finds its end by bracket matching (`FindEnclosingBracketGroup`:
  every `(`, `[` and `{` counts, quotes don't), and so does `expansions`;
- an **action**: the `action` list of an `actions`, `rules` or `postbuilds` entry, run by the
  generated Makefile.

gyp reads the file as a Python literal (`eval` after an AST check). Here it is tokenized and
parsed by hand, never evaluated: strings with every Python escape decoded (`\\x3c!(` is `<!(`),
adjacent strings joined (`'<!(no' 'de x.js)'`), `#` comments dropped. A variable a command
uses (`<(cmd)`, `<@(cmd)`, defined in a `variables` dict of any file read) is replaced by its
definitions, so `'action': ['<@(cmd)']` names what it runs; node-gyp's `<(module_root_dir)` is
the package root. The `.gyp` and `.gypi` files a gyp file names (`includes`, a dependency's
`deps/x.gyp:x`) are read too, up to `MAX_GYP_FILES`. A file that doesn't parse is not skipped:
its expansions and actions are scanned in the raw text. A file over `MAX_GYP_BYTES` gives
`UNREAD`, a command no lookup test accepts.

Round 5 (I, 2026-11-10): before, a regular expression took an expansion only when its `)` was
followed by a quote, and an action only up to the first `]`; `"<!(node payload.js):x"` ran
unseen (round 4 B's owner question 4).
"""

from __future__ import annotations

import posixpath
import re
import unicodedata
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Final

GYP_FILE: Final = "binding.gyp"
MAX_GYP_FILES: Final = 20
MAX_GYP_BYTES: Final = 256 * 1024
MAX_DEPTH: Final = 100  # nesting of the literal; deeper parses fall back to the raw scan
MAX_SUBSTITUTIONS: Final = 3  # rounds of variable replacement (a variable may use another)
# Bounds on what one version's gyp files can make us build (hostile input: nested or unclosed
# expansions, self-referencing variables): commands, their total size, one command's size.
MAX_COMMANDS: Final = 1_000
MAX_TOTAL_BYTES: Final = 1024 * 1024
MAX_COMMAND_BYTES: Final = 64 * 1024
UNREAD: Final = "<gyp files not read whole: over a size limit>"

# A command expansion's start: phase, `!`, optional `@`, optional command name, `(`.
_EXPANSION: Final = re.compile(r"[<>^]!@?(?P<name>[-a-zA-Z0-9_.]+)?\(")
# A variable reference in a command (`<(name)`, `<@(name)`, the later phases too).
_VARIABLE: Final = re.compile(r"[<>^]@?\((?P<name>[-a-zA-Z0-9_.]+)\)")
_STRING_START: Final = re.compile(r"""(?P<prefix>[rRbBuU]{0,2})(?P<quote>'''|\"\"\"|'|")""")
_ATOM: Final = re.compile(r"[-+.\w]+")
_ESCAPE: Final = re.compile(
    r"""\\(\n|[\\'"abfnrtv]|x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|[0-7]{1,3}|N\{[^}]{1,100}\})"""
)
_SIMPLE_ESCAPES: Final = {
    "\n": "",
    "\\": "\\",
    "'": "'",
    '"': '"',
    "a": "\a",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
}
_OPEN: Final = {"(": ")", "[": "]", "{": "}"}
_CLOSE: Final = frozenset(_OPEN.values())
# The old regular expression for an action, kept for files that don't tokenize.
_RAW_ACTION: Final = re.compile(r"""["']action["']\s*:\s*\[([^\]]*)\]""")
_RAW_STRING: Final = re.compile(r""""((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'""")
# node-gyp's own variables, as package paths.
_BUILTIN: Final = {"module_root_dir": "."}


class _Syntax(ValueError):
    """Not a literal gyp accepts (or nested deeper than `MAX_DEPTH`)."""


@dataclass(frozen=True, slots=True)
class _Token:
    kind: str  # "s" string, "p" punctuation, "o" anything else (numbers, names)
    value: str


@dataclass(slots=True)
class _Dict:
    pairs: list[tuple[object, object]] = field(default_factory=list)


def _unescape(body: str) -> str:
    def one(match: re.Match[str]) -> str:
        code = match.group(1)
        if code in _SIMPLE_ESCAPES:
            return _SIMPLE_ESCAPES[code]
        if code[0] in "xuU":
            value = int(code[1:], 16)
            return chr(value) if value <= 0x10FFFF else match.group(0)
        if code[0] == "N":
            try:
                return unicodedata.lookup(code[2:-1])
            except KeyError:
                return match.group(0)
        return chr(int(code, 8))

    return _ESCAPE.sub(one, body)


def tokens(text: str) -> list[_Token] | None:
    """Python's tokens as far as a gyp literal needs them: strings (decoded, adjacent ones
    joined), brackets, `:` and `,`, other atoms; comments dropped. None when a string is not
    terminated."""
    out: list[_Token] = []
    pieces: list[str] = []  # adjacent strings, joined once (`'a' 'b'` is `'ab'`)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        continuation = c == "\\" and text.startswith("\n", i + 1)
        if (
            pieces
            and not (c.isspace() or c == "#" or continuation)
            and _STRING_START.match(text, i) is None
        ):
            out.append(_Token("s", "".join(pieces)))
            pieces = []
        if c.isspace():
            i += 1
        elif c == "#":
            end = text.find("\n", i)
            i = n if end < 0 else end
        elif continuation:
            i += 2
        elif (m := _STRING_START.match(text, i)) is not None:
            quote, raw = m.group("quote"), "r" in m.group("prefix").lower()
            j = m.end()
            while not text.startswith(quote, j):
                if j >= n or (len(quote) == 1 and text[j] == "\n"):
                    return None
                j += 2 if text[j] == "\\" else 1
            body = text[m.end() : j]
            pieces.append(body if raw else _unescape(body))
            i = j + len(quote)
        elif c in "[]{}(),:":
            out.append(_Token("p", c))
            i += 1
        elif (m := _ATOM.match(text, i)) is not None:
            out.append(_Token("o", m.group()))
            i = m.end()
        else:
            out.append(_Token("o", c))
            i += 1
    if pieces:
        out.append(_Token("s", "".join(pieces)))
    return out


def parse(items: list[_Token]) -> object:
    """The literal `items` spell: `_Dict`, list (a tuple too), str, None for other atoms."""
    value, end = _value(items, 0, 0)
    if end != len(items):
        raise _Syntax("trailing tokens")
    return value


def _value(items: list[_Token], i: int, depth: int) -> tuple[object, int]:
    if depth > MAX_DEPTH or i >= len(items):
        raise _Syntax("too deep or truncated")
    token = items[i]
    if token.kind == "s":
        return token.value, i + 1
    if token.kind == "o":
        return None, i + 1
    if token.value == "{":
        result = _Dict()
        i += 1
        while not _is(items, i, "}"):
            key, i = _value(items, i, depth + 1)
            if not _is(items, i, ":"):
                raise _Syntax("expected ':'")
            value, i = _value(items, i + 1, depth + 1)
            result.pairs.append((key, value))
            i = _separator(items, i, "}")
        return result, i + 1
    if token.value in "[(":
        close = _OPEN[token.value]
        values: list[object] = []
        i += 1
        while not _is(items, i, close):
            value, i = _value(items, i, depth + 1)
            values.append(value)
            i = _separator(items, i, close)
        return values, i + 1
    raise _Syntax(f"unexpected {token.value!r}")


def _is(items: list[_Token], i: int, punct: str) -> bool:
    if i >= len(items):
        raise _Syntax("truncated")
    return items[i] == _Token("p", punct)


def _separator(items: list[_Token], i: int, close: str) -> int:
    if _is(items, i, ","):
        return i + 1
    if _is(items, i, close):
        return i
    raise _Syntax("expected ',' or a closing bracket")


def _walk(node: object) -> Iterator[tuple[object, object, str | None]]:
    """Every (key, value, parent key) pair of every dict in `node`, in document order."""
    stack: list[tuple[object, str | None]] = [(node, None)]
    while stack:
        current, parent = stack.pop()
        if isinstance(current, _Dict):
            for key, value in current.pairs:
                yield key, value, parent
            stack.extend(
                (value, key if isinstance(key, str) else None)
                for key, value in reversed(current.pairs)
            )
            stack.extend((key, parent) for key, _ in reversed(current.pairs))
        elif isinstance(current, list):
            stack.extend((item, parent) for item in reversed(current))


def _strings(node: object) -> Iterator[str]:
    stack = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, str):
            yield current
        elif isinstance(current, _Dict):
            for key, value in reversed(current.pairs):
                stack.extend((value, key))
        elif isinstance(current, list):
            stack.extend(reversed(current))


def _closing(text: str) -> dict[int, int]:
    """Each opening bracket's closing one, as gyp's `FindEnclosingBracketGroup` matches them
    (every bracket kind counts, quotes don't), in one pass; an unclosed one is absent."""
    closing: dict[int, int] = {}
    stack: list[int] = []
    for index, char in enumerate(text):
        if char in _OPEN:
            stack.append(index)
        elif char in _CLOSE and stack:
            closing[stack.pop()] = index
    return closing


def expansions(text: str, limit: int = MAX_COMMANDS) -> list[str]:
    """Every command expansion's command in one string (at most `limit`), nested ones too:
    `<!(cmd)` -> `cmd`; an array form `<!(['node', 'x.js'])` -> `node x.js`;
    `<!pymod_do_main(m a)` -> `pymod_do_main m a`. An expansion that never closes runs to the
    end of the string."""
    found: list[str] = []
    if "!" not in text:
        return found
    closing = _closing(text)
    size = 0
    for match in _EXPANSION.finditer(text):
        if len(found) >= limit or size > MAX_TOTAL_BYTES:
            found.append(UNREAD)
            break
        start = match.end() - 1
        command = text[start + 1 : closing.get(start, len(text))].strip()
        if command.startswith("[") and (items := tokens(command)) is not None:
            command = " ".join(t.value for t in items if t.kind == "s")
        if match.group("name"):
            command = f"{match.group('name')} {command}"
        found.append(command)
        size += len(command)
    return found


@dataclass(slots=True)
class _Found:
    actions: list[str] = field(default_factory=list)
    expanded: list[str] = field(default_factory=list)
    variables: dict[str, list[str]] = field(default_factory=dict)
    named: list[str] = field(default_factory=list)  # gyp files this one names


def _read(text: str) -> _Found:
    found = _Found()
    items = tokens(text)
    tree: object = None
    if items is not None:
        try:
            tree = parse(items)
        except _Syntax:
            tree = None
    if tree is None:  # not a literal gyp reads: scan the raw text (and every string we have)
        for match in _RAW_ACTION.finditer(text):
            words = [d or q for d, q in _RAW_STRING.findall(match.group(1))]
            found.actions.append(_unescape(" ".join(words)))
        if items is None:  # an unterminated string: the raw text, escapes decoded per command
            found.expanded.extend(_unescape(c) for c in expansions(text))
            return found
        strings = [t.value for t in items if t.kind == "s"]
        _expand(strings, found)
        found.named.extend(strings)
        return found
    for key, value, parent in _walk(tree):
        if key == "action":
            found.actions.append(_joined(value))
        if parent == "variables" and isinstance(key, str):
            found.variables.setdefault(key.rstrip("%"), []).append(_joined(value))
    strings = list(_strings(tree))
    _expand(strings, found)
    found.named.extend(strings)
    return found


def _expand(strings: list[str], found: _Found) -> None:
    """The expansions of `strings` into `found`, within the file's share of the bounds."""
    size = 0
    for string in strings:
        left = MAX_COMMANDS - len(found.expanded)
        if left <= 0 or size > MAX_TOTAL_BYTES:
            found.expanded.append(UNREAD)
            return
        commands = expansions(string, left)
        found.expanded.extend(commands)
        size += sum(len(c) for c in commands)


def _joined(value: object) -> str:
    return " ".join(_strings(value))


def _gyp_path(directory: str, string: str) -> str | None:
    """The package path of a gyp file a string names (`includes`, `deps/x.gyp:target`)."""
    path = string.split(".gyp:", 1)[0] + ".gyp" if ".gyp:" in string else string
    path = path.replace("<(module_root_dir)/", "")
    if not path.endswith((".gyp", ".gypi")) or _VARIABLE.search(path):
        return None
    joined = posixpath.normpath(posixpath.join(directory, path))
    return None if joined.startswith(("..", "/")) else joined


def _substitute(command: str, variables: Mapping[str, str]) -> str:
    """`command` with its variables replaced, up to `MAX_SUBSTITUTIONS` rounds; a round that
    would make it longer than `MAX_COMMAND_BYTES` is not made."""
    for _ in range(MAX_SUBSTITUTIONS):
        pieces, size, end = [], 0, 0
        for match in _VARIABLE.finditer(command):
            name = match.group("name")
            value = _BUILTIN.get(name, variables.get(name, match.group(0)))
            pieces += [command[end : match.start()], value]
            size += match.start() - end + len(value)
            end = match.end()
            if size > MAX_COMMAND_BYTES:
                return command
        if not pieces:
            break
        replaced = "".join(pieces) + command[end:]
        if replaced == command or len(replaced) > MAX_COMMAND_BYTES:
            break
        command = replaced
    return command


def gyp_commands(files: Mapping[str, bytes]) -> list[str]:
    """The commands `binding.gyp` (and the gyp files it names) make `node-gyp rebuild` run:
    each action's, then each command expansion's, in file and document order, without
    repeats, variables replaced. `UNREAD` for a gyp file over `MAX_GYP_BYTES` and when the
    commands go over `MAX_COMMANDS` or `MAX_TOTAL_BYTES` (the rest is not listed)."""
    if GYP_FILE not in files:
        return []
    actions: list[str] = []
    expanded: list[str] = []
    variables: dict[str, list[str]] = {}
    queue, seen = [GYP_FILE], {GYP_FILE}
    while queue:
        path = queue.pop(0)
        raw = files[path]
        if len(raw) > MAX_GYP_BYTES:
            actions.append(UNREAD)
            continue
        found = _read(raw.decode("utf-8", "replace"))
        actions.extend(found.actions)
        expanded.extend(found.expanded)
        for name, values in found.variables.items():
            variables.setdefault(name, []).extend(values)
        for string in found.named:
            target = _gyp_path(posixpath.dirname(path), string)
            if target is None or target not in files or target in seen:
                continue
            if len(seen) < MAX_GYP_FILES:
                seen.add(target)
                queue.append(target)
    joined = {name: " ".join(values) for name, values in variables.items()}
    commands: dict[str, None] = {}
    total = 0
    for raw_command in [*actions, *expanded]:
        command = _substitute(raw_command, joined).strip()
        total += len(command)
        if len(commands) >= MAX_COMMANDS or total > MAX_TOTAL_BYTES:
            commands[UNREAD] = None
            break
        if command:
            commands[command] = None
    return list(commands)
