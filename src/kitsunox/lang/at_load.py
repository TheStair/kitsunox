"""Which calls run when a JavaScript file is loaded (Stage 3, extractor v8).

`require("x")` runs x's top-level code. A payload that is loaded rather than installed
(`archetype-index-sdk@1.0.0`, 2026-11-08: `dist/index.js` imports `telemetry-info.mjs`, which
sends the host name, user name and home directory away and starts a dropper) does its work
there, or in functions that top-level code calls. A library's functions mostly run only when
the user calls them. This module tells the two apart for one kind of call, the reads of the
machine's identity (`os.hostname()`, `os.userInfo()`, `os.networkInterfaces()`,
`os.homedir()`), from the parse alone. A call **runs at load** when every function around it
runs at load, and a function does when it is

- called where it is written: `(function () { ... })()`, `(() => { ... }).call(this)`;
- passed to a call that runs at load (`main().then(() => ...)`, `setTimeout(() => ..., 5)`,
  `collect("host", () => os.hostname())`), or is a `new Promise(...)` executor there: the
  callee may only keep it for later (an event handler), so this over-approximates;
- named (`function f`, `const f = () => ...`, `f = function ...`) and called by that name,
  directly or with `.call`/`.apply`, from code that runs at load.

Class and object methods are never counted. Names are matched within the file, so a function
called from another file, or through an alias, is not seen; neither is a read through a
computed name (`os["host" + "name"]()`). Nothing runs: tree-sitter parses the file.

Since extractor v9 the same reach decides which **commands run at load** (`commands`): a call
to a command runner (`COMMAND_RUNNERS`: `child_process`'s `exec`, `execSync`, `spawn`, ...,
and `execa`), or to a function of the same file that calls one (`run(cmd)` wrapping
`execSync(cmd)`), with the command's text: the first argument as written (a string, a
template, a `+` of those, or a name the file binds to one with `const`/`let`/`var`), plus
the strings of a following argument list (`spawn("npm", ["publish"])` is `npm publish`).
The `*_z3n` spam family (DataDog, 2026-10) runs `npm publish --access public` this way from
its `main`, in a loop started at load.
"""

from __future__ import annotations

from collections.abc import Iterator
from functools import cache
from typing import Final

import tree_sitter as ts

IDENTITY_CALLS: Final = frozenset({"hostname", "userInfo", "networkInterfaces", "homedir"})
TIMERS: Final = frozenset({"setTimeout", "setImmediate", "setInterval", "queueMicrotask"})
COMMAND_RUNNERS: Final = frozenset(
    {
        "exec",
        "execSync",
        "execFile",
        "execFileSync",
        "spawn",
        "spawnSync",
        "execa",
        "execaSync",
        "execaCommand",
        "execaCommandSync",
    }
)
MAX_COMMAND_CHARS: Final = 200
_FUNCTIONS: Final = frozenset(
    {
        "function_declaration",
        "generator_function_declaration",
        "function_expression",
        "function",
        "generator_function",
        "arrow_function",
        "method_definition",
    }
)
_DECLARATIONS: Final = frozenset({"function_declaration", "generator_function_declaration"})
MAX_DEPTH: Final = 64  # functions followed from one call before giving up (counts as not run)
MAX_CALLERS: Final = 200  # calls of one name examined


def _names(names: frozenset[str]) -> str:
    return " ".join(f'"{n}"' for n in sorted(names))


_IDENTITY_QUERY: Final = f"""
((call_expression
  function: [(identifier) @name (member_expression property: (property_identifier) @name)]) @call
 (#any-of? @name {_names(IDENTITY_CALLS)}))
"""
_RUNNER_QUERY: Final = f"""
((call_expression
  function: [(identifier) @name (member_expression property: (property_identifier) @name)]) @call
 (#any-of? @name {_names(COMMAND_RUNNERS)}))
"""
_BINDINGS_QUERY: Final = """
(variable_declarator name: (identifier) @name value: [(string) (template_string)
  (binary_expression)] @value)
"""
_CALLS_QUERY: Final = """
(call_expression function: (identifier) @name) @call
((call_expression
  function: (member_expression object: (identifier) @name property: (property_identifier) @how))
 @call (#any-of? @how "call" "apply"))
"""


@cache
def _queries(language: ts.Language) -> tuple[ts.Query, ts.Query]:
    return ts.Query(language, _IDENTITY_QUERY), ts.Query(language, _CALLS_QUERY)


@cache
def _command_queries(language: ts.Language) -> tuple[ts.Query, ts.Query]:
    return ts.Query(language, _RUNNER_QUERY), ts.Query(language, _BINDINGS_QUERY)


def _text(node: ts.Node | None) -> str:
    if node is None or node.text is None:
        return ""
    return node.text.decode("utf-8", errors="replace")


def _key(node: ts.Node) -> tuple[int, int, str]:
    return node.start_byte, node.end_byte, node.type


def _enclosing_function(node: ts.Node) -> ts.Node | None:
    parent = node.parent
    while parent is not None and parent.type not in _FUNCTIONS:
        parent = parent.parent
    return parent


def _outer(function: ts.Node) -> ts.Node:
    """The function, or the parentheses around it."""
    node = function
    while node.parent is not None and node.parent.type == "parenthesized_expression":
        node = node.parent
    return node


def _site(function: ts.Node) -> bool:
    """Whether the function runs wherever it is written: called in place, passed to a call,
    or a `new Promise(...)` executor."""
    node = _outer(function)
    parent = node.parent
    if parent is None:
        return False
    if parent.type == "call_expression":
        return parent.child_by_field_name("function") == node
    if parent.type == "member_expression" and parent.child_by_field_name("object") == node:
        grand = parent.parent
        return (
            _text(parent.child_by_field_name("property")) in ("call", "apply")
            and grand is not None
            and grand.type == "call_expression"
            and grand.child_by_field_name("function") == parent
        )
    if parent.type == "arguments" and parent.parent is not None:
        call = parent.parent
        if call.type == "call_expression":
            return True
        if call.type == "new_expression":
            return _text(call.child_by_field_name("constructor")) == "Promise"
    return False


def _name(function: ts.Node) -> str | None:
    """The name code calls the function by: `function f`, `const f = ...`, `f = ...`."""
    if function.type in _DECLARATIONS:
        name = function.child_by_field_name("name")
        return _text(name) if name is not None else None
    parent = _outer(function).parent
    if parent is not None and parent.type == "variable_declarator":
        name = parent.child_by_field_name("name")
    elif parent is not None and parent.type == "assignment_expression":
        name = parent.child_by_field_name("left")
    else:
        return None
    return _text(name) if name is not None and name.type == "identifier" else None


class _Reach:
    """Whether nodes of one file run at load, memoised per function."""

    def __init__(self, root: ts.Node, calls_query: ts.Query) -> None:
        self.root = root
        self.calls_query = calls_query
        self.memo: dict[tuple[int, int, str], bool] = {}
        self.callers: dict[str, list[ts.Node]] | None = None

    def runs(self, node: ts.Node, depth: int = 0) -> bool:
        function = _enclosing_function(node)
        return function is None or self.function_runs(function, depth)

    def function_runs(self, function: ts.Node, depth: int) -> bool:
        key = _key(function)
        if key in self.memo:
            return self.memo[key]
        if depth >= MAX_DEPTH or function.type == "method_definition":
            return False
        self.memo[key] = False  # a cycle (recursion) doesn't make itself run
        result = (_site(function) and self.runs(function, depth + 1)) or any(
            self.runs(call, depth + 1) for call in self._calls_of(_name(function))
        )
        self.memo[key] = result
        return result

    def _calls_of(self, name: str | None) -> list[ts.Node]:
        if name is None:
            return []
        if self.callers is None:
            self.callers = {}
            for _, match in ts.QueryCursor(self.calls_query).matches(self.root):
                self.callers.setdefault(_text(match["name"][0]), []).append(match["call"][0])
        return self.callers.get(name, [])[:MAX_CALLERS]


def identity_reads(root: ts.Node, language: ts.Language) -> Iterator[tuple[str, ts.Node]]:
    """Each call reading the machine's identity (`IDENTITY_CALLS`) that runs at load, as
    (name, call node), in source order."""
    identity_query, calls_query = _queries(language)
    matches = ts.QueryCursor(identity_query).matches(root)
    if not matches:
        return
    reach = _Reach(root, calls_query)
    for _, match in sorted(matches, key=lambda m: m[1]["call"][0].start_byte):
        call = match["call"][0]
        if reach.runs(call):
            yield _text(match["name"][0]), call


def commands(root: ts.Node, language: ts.Language) -> Iterator[tuple[str, ts.Node]]:
    """Each call that runs a command at load, as (the command's text, call node), in source
    order: a `COMMAND_RUNNERS` call, or a call by name of a function of this file that makes
    one. A command whose text can't be read (a parameter, a computed value) is `""`."""
    runner_query, bindings_query = _command_queries(language)
    matches = ts.QueryCursor(runner_query).matches(root)
    if not matches:
        return
    reach = _Reach(root, _queries(language)[1])
    calls = {_key(m[1]["call"][0]): m[1]["call"][0] for m in matches}
    for call in list(calls.values()):  # one level of wrappers: `function run(cmd) {...}`
        function = _enclosing_function(call)
        if function is not None and _passes_first_parameter(function, call):
            for wrapper in reach._calls_of(_name(function)):
                calls.setdefault(_key(wrapper), wrapper)
    bound: dict[str, ts.Node] = {}
    for _, match in ts.QueryCursor(bindings_query).matches(root):
        bound.setdefault(_text(match["name"][0]), match["value"][0])
    for _, call in sorted(calls.items()):
        if reach.runs(call):
            yield _command_text(call, bound)[:MAX_COMMAND_CHARS], call


def _passes_first_parameter(function: ts.Node, call: ts.Node) -> bool:
    """Whether the runner call's command is the function's first parameter (`run(cmd)`)."""
    parameters = function.child_by_field_name("parameters")
    if parameters is None:
        parameter = function.child_by_field_name("parameter")  # `cmd => execSync(cmd)`
    else:
        parameter = parameters.named_children[0] if parameters.named_children else None
    if parameter is not None and parameter.type in ("assignment_pattern", "required_parameter"):
        parameter = parameter.child_by_field_name("left") or parameter.child_by_field_name(
            "pattern"
        )
    arguments = call.child_by_field_name("arguments")
    first = (
        arguments.named_children[0] if arguments is not None and arguments.named_children else None
    )
    return (
        parameter is not None
        and parameter.type == "identifier"
        and first is not None
        and first.type == "identifier"
        and _text(first) == _text(parameter)
    )


def _command_text(call: ts.Node, bound: dict[str, ts.Node]) -> str:
    arguments = call.child_by_field_name("arguments")
    values = arguments.named_children if arguments is not None else []
    if not values:
        return ""
    first = values[0]
    if first.type == "identifier" and _text(first) in bound:
        first = bound[_text(first)]
    words = [_literal(first)]
    if len(values) > 1 and values[1].type == "array":
        words.extend(_literal(v) for v in values[1].named_children)
    return " ".join(w for w in words if w)


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
