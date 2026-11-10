"""Every command a JavaScript file can run through `child_process` (Stage 3, explained installs).

`lang.at_load.commands` answers "what runs when the file is loaded", following calls within one
file. An explained install shape that downloads a binary needs a stronger answer: the install
code must never run anything but an archive tool, wherever the call sits (a function exported
to another install file runs at install too). This module lists **every** call of
`child_process`'s command runners in a file, reachable or not, with its command text, or says
the file can't be read that way.

A file can be read when each `child_process` load is one of

- `const cp = require("child_process")`, `import cp from ...`, `import * as cp from ...`:
  then every use of `cp` must be a call `cp.<runner>(...)`;
- `const { spawnSync, exec: run } = require(...)`, `import { spawn } from ...`,
  `const spawn = require(...).spawn`: then every use of the local name must be a call;
- `require("child_process").<runner>(...)`, called in place,

where a runner is one of `RUNNERS`. Anything else (the module or a runner passed to a function,
stored, aliased by an expression, `promisify(exec)`, a computed member, another export of the
module, the module's name in any other string) makes the file unreadable (`None`): the command
could be anything. Names are matched in the whole file, so a local variable that shadows a
runner's name counts as the runner (it can only make the answer stricter). Nothing runs:
tree-sitter parses the file.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Final

import tree_sitter as ts

from kitsunox.core.models import Record
from kitsunox.lang.javascript import MAX_SOURCE_BYTES, _parser, fold_string

MODULE_NAMES: Final = frozenset({"child_process", "node:child_process"})
RUNNERS: Final = frozenset(
    {"exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork"}
)
# Runners that hand their command line to a shell (`exec("tar -xf a && ./run")`).
SHELL_RUNNERS: Final = frozenset({"exec", "execSync"})
_REFERENCES: Final = frozenset({"identifier", "shorthand_property_identifier"})
_LOADERS: Final = frozenset({"require", "import"})


class ProcessCall(Record):
    """One `child_process` runner call: the runner's name, the command as written (the first
    argument's text, then the strings of an argument array; `…` for an element that isn't a
    string, `""` when the command itself can't be read) and its 1-based line."""

    runner: str
    command: str
    line: int

    @property
    def shell(self) -> bool:
        return self.runner in SHELL_RUNNERS


class _Unreadable(Exception):
    pass


def process_calls(content: bytes, language: str) -> tuple[ProcessCall, ...] | None:
    """Every `child_process` runner call in `content` (module docstring), in source order, or
    None when the file uses `child_process` in a way this reader doesn't follow."""
    if len(content) > MAX_SOURCE_BYTES:
        return None
    parser, _ = _parser(language)
    root = parser.parse(content).root_node
    try:
        return tuple(_calls(root))
    except _Unreadable:
        return None


def _nodes(root: ts.Node) -> Iterator[ts.Node]:
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def _text(node: ts.Node | None) -> str:
    if node is None or node.text is None:
        return ""
    return node.text.decode("utf-8", errors="replace")


def _key(node: ts.Node) -> tuple[int, int]:
    return node.start_byte, node.end_byte


def _calls(root: ts.Node) -> Iterator[ProcessCall]:
    modules: set[str] = set()
    functions: dict[str, str] = {}  # local name -> runner
    declared: set[tuple[int, int]] = set()  # identifier nodes that declare a binding
    direct: list[tuple[str, ts.Node]] = []  # (runner, call) of `require("cp").x(...)`
    bound: dict[str, ts.Node] = {}  # `const x = "..."` strings, for a command named by a variable
    nodes = list(_nodes(root))
    for node in nodes:
        if node.type == "variable_declarator":
            name, value = node.child_by_field_name("name"), node.child_by_field_name("value")
            if (
                name is not None
                and name.type == "identifier"
                and value is not None
                and value.type in ("string", "template_string", "binary_expression")
            ):
                bound.setdefault(_text(name), value)
        if node.type not in ("string", "template_string") or fold_string(node) not in MODULE_NAMES:
            continue
        parent = node.parent
        if parent is not None and parent.type == "import_statement":
            _import(parent, modules, functions, declared)
            continue
        if parent is None or parent.type != "arguments" or len(parent.named_children) != 1:
            raise _Unreadable
        load = parent.parent
        if (
            load is None
            or load.type != "call_expression"
            or _text(load.child_by_field_name("function")) not in _LOADERS
        ):
            raise _Unreadable
        _required(load, modules, functions, declared, direct)
    calls = list(direct)
    for node in nodes:
        if node.type not in _REFERENCES or _key(node) in declared:
            continue
        reference = _text(node)
        if reference in functions:
            calls.append((functions[reference], _called(node)))
        elif reference in modules:
            member = node.parent
            if (
                member is None
                or member.type != "member_expression"
                or member.child_by_field_name("object") != node
                or _text(member.child_by_field_name("property")) not in RUNNERS
            ):
                raise _Unreadable
            calls.append((_text(member.child_by_field_name("property")), _called(member)))
    for runner, call in sorted(calls, key=lambda c: c[1].start_byte):
        yield ProcessCall(
            runner=runner, command=_command(call, bound), line=call.start_point.row + 1
        )


def _called(node: ts.Node) -> ts.Node:
    """The call `node` is the callee of (`node(...)`), or unreadable."""
    parent = node.parent
    if parent is None or parent.type != "call_expression":
        raise _Unreadable
    if parent.child_by_field_name("function") != node:
        raise _Unreadable
    return parent


def _import(
    statement: ts.Node,
    modules: set[str],
    functions: dict[str, str],
    declared: set[tuple[int, int]],
) -> None:
    clause = next((c for c in statement.named_children if c.type == "import_clause"), None)
    if clause is None:
        return  # `import "child_process"`: loads it, binds nothing
    for part in clause.named_children:
        if part.type == "identifier":  # default import
            modules.add(_text(part))
            declared.add(_key(part))
        elif part.type == "namespace_import":
            for ident in part.named_children:
                modules.add(_text(ident))
                declared.add(_key(ident))
        elif part.type == "named_imports":
            for spec in part.named_children:
                if spec.type != "import_specifier":
                    continue
                name = spec.child_by_field_name("name")
                alias = spec.child_by_field_name("alias") or name
                if _text(name) not in RUNNERS:
                    raise _Unreadable
                functions[_text(alias)] = _text(name)
                declared.update({_key(n) for n in (name, alias) if n is not None})
        else:
            raise _Unreadable


def _required(
    load: ts.Node,
    modules: set[str],
    functions: dict[str, str],
    declared: set[tuple[int, int]],
    direct: list[tuple[str, ts.Node]],
) -> None:
    node = load
    if node.parent is not None and node.parent.type == "await_expression":
        node = node.parent  # `await import("node:child_process")`
    parent = node.parent
    if parent is None:
        raise _Unreadable
    if parent.type == "variable_declarator" and parent.child_by_field_name("value") == node:
        name = parent.child_by_field_name("name")
        if name is not None and name.type == "identifier":
            modules.add(_text(name))
            declared.add(_key(name))
            return
        if name is not None and name.type == "object_pattern":
            _pattern(name, functions, declared)
            return
        raise _Unreadable
    if parent.type == "member_expression" and parent.child_by_field_name("object") == node:
        runner = _text(parent.child_by_field_name("property"))
        if runner not in RUNNERS:
            raise _Unreadable
        holder = parent.parent
        if holder is not None and holder.type == "call_expression":
            direct.append((runner, _called(parent)))
            return
        if holder is not None and holder.type == "variable_declarator":
            name = holder.child_by_field_name("name")
            if name is not None and name.type == "identifier":
                functions[_text(name)] = runner
                declared.add(_key(name))
                return
    raise _Unreadable


def _pattern(pattern: ts.Node, functions: dict[str, str], declared: set[tuple[int, int]]) -> None:
    for part in pattern.named_children:
        if part.type == "shorthand_property_identifier_pattern":
            runner = local = _text(part)
        elif part.type == "pair_pattern":
            key, value = part.child_by_field_name("key"), part.child_by_field_name("value")
            if value is None or value.type != "identifier":
                raise _Unreadable
            runner, local = _text(key), _text(value)
            declared.add(_key(value))
        else:
            raise _Unreadable  # a default value, a rest element, a nested pattern
        if runner not in RUNNERS:
            raise _Unreadable
        functions[local] = runner


def _command(call: ts.Node, bound: dict[str, ts.Node]) -> str:
    arguments = call.child_by_field_name("arguments")
    values = arguments.named_children if arguments is not None else []
    if not values:
        return ""
    first = values[0]
    if first.type == "identifier" and _text(first) in bound:
        first = bound[_text(first)]
    words = [_literal(first)]
    if not words[0]:
        return ""
    if len(values) > 1 and values[1].type == "array":
        words.extend(_literal(v) or "…" for v in values[1].named_children)
    return " ".join(words)


def _literal(node: ts.Node) -> str:
    """A string's or template's text as written (substitutions kept as `${...}`), a `+` of
    those (other operands as `…`); `""` for anything else."""
    if node.type in ("string", "template_string"):
        return _text(node)[1:-1]
    if node.type == "parenthesized_expression" and node.named_child_count == 1:
        return _literal(node.named_children[0])
    if node.type == "binary_expression" and _text(node.child_by_field_name("operator")) == "+":
        parts = (node.child_by_field_name("left"), node.child_by_field_name("right"))
        return "".join(_literal(p) or "…" if p is not None else "" for p in parts)
    return ""
