"""What install code does with things the capability profile counts coarsely.

Added 2026-11-11 for `npm.install-explained` v7 (`docs/proposals/precision-round7-V.md`).
The capability profile (`lang.javascript`) says *that* install code changes file modes, loads
through `createRequire` or a computed `require`, or takes the whole environment; these helpers
say *how*, so a shape can rest on it:

- `chmod_modes`: the mode of every `chmod` call (`fs.chmodSync(p, 0o755)`, `chmod(p, mode |
  0o111)`, `fs.promises.chmod`), when it is a constant (or a constant `|`-ed onto another
  value); S7 needs every one to add the owner's execute bit and set nothing beyond `0o777`.
- `requires_only_resolve`: every `createRequire(...)` result is only used to *locate* a file
  (`.resolve(...)`), never to load one (`req("x")` loads a package the profile's package list
  doesn't see).
- `requires_only_json`: every `require` of a computed path loads a `.json` file
  (`require(path.join(dir, "package.json"))`, `require(require.resolve(`${pkg}/package.json`))`
  through a `const`): Node parses JSON, it runs nothing, so it isn't `dynamic-require`.
- `env_read_by_name`: every place the code takes `process.env` whole (`const env =
  process.env`, `isCI(process.env)`) then only reads named variables from it (`env.CI`,
  `env["NO_COLOR"]`): what `env-all` means (harvesting the environment) can't happen.
- `guard_only`: inline install code that is only a Node-version, platform or environment check
  (S8).

Each returns the conservative answer (None, False) on a parse error or anything it doesn't
recognise.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Final

import tree_sitter as ts

from kitsunox.lang.javascript import MAX_SOURCE_BYTES, _parser, _text

CHMOD_CALLS: Final = frozenset({"chmod", "chmodSync", "lchmod", "lchmodSync"})
_FUNCTION_VALUES: Final = frozenset({"arrow_function", "function_expression", "function"})


def _root(content: bytes, language: str) -> ts.Node | None:
    if len(content) > MAX_SOURCE_BYTES:
        return None
    parser, _ = _parser(language)
    root = parser.parse(content).root_node
    return None if root.has_error else root


def _nodes(root: ts.Node) -> Iterator[ts.Node]:
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def _arguments(call: ts.Node) -> list[ts.Node]:
    arguments = call.child_by_field_name("arguments")
    if arguments is None:
        return []
    return [c for c in arguments.named_children if c.type != "comment"]


def _number(node: ts.Node | None) -> int | None:
    """An integer literal's value (`0o755`, `493`, `0x1ed`), or None."""
    if node is None or node.type != "number":
        return None
    text = _text(node).replace("_", "").lower()
    try:
        if text.startswith("0o"):
            return int(text[2:], 8)
        if text.startswith("0x"):
            return int(text[2:], 16)
        if text.startswith("0b"):
            return int(text[2:], 2)
        if len(text) > 1 and text.startswith("0") and text.isdigit():
            return int(text, 8)  # legacy octal `0755`
        return int(text)
    except ValueError:
        return None


def _mode(node: ts.Node | None) -> int | None:
    """A mode argument's constant bits: a number, an octal string (`"755"`), or `x | <number>`
    (the constant part; the other operand keeps bits the file already has)."""
    if node is None:
        return None
    if node.type == "parenthesized_expression" and node.named_child_count == 1:
        return _mode(node.named_children[0])
    if node.type == "string":
        text = "".join(_text(c) for c in node.named_children if c.type == "string_fragment")
        return int(text, 8) if text and len(text) <= 4 and set(text) <= set("01234567") else None
    if node.type == "binary_expression" and _text(node.child_by_field_name("operator")) == "|":
        right = _number(node.child_by_field_name("right"))
        left = _number(node.child_by_field_name("left"))
        return right if right is not None else left
    return _number(node)


def chmod_modes(content: bytes, language: str) -> tuple[int | None, ...] | None:
    """The mode of each `chmod`-like call (`CHMOD_CALLS`, as a bare call or a method) in source
    order, None for one whose mode isn't a constant; None if the file doesn't parse cleanly."""
    root = _root(content, language)
    if root is None:
        return None
    modes: list[int | None] = []
    for node in _nodes(root):
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        name = _text(function).rsplit(".", 1)[-1]
        if name in CHMOD_CALLS:
            arguments = _arguments(node)
            modes.append(_mode(arguments[1]) if len(arguments) >= 2 else None)
    return tuple(modes)


def requires_only_resolve(content: bytes, language: str) -> bool:
    """Every `createRequire(...)` call's result is used only to resolve a path: called as
    `createRequire(...).resolve(...)`, given to another `createRequire`, or bound to a name
    (`const require = createRequire(...)`) whose every other use in the file is
    `require.resolve(...)`. False if the file doesn't parse cleanly."""
    root = _root(content, language)
    if root is None:
        return False
    names: set[str] = set()
    for node in _nodes(root):
        if node.type != "call_expression" or _text(node.child_by_field_name("function")).rsplit(
            ".", 1
        )[-1] != ("createRequire"):
            continue
        parent = node.parent
        if parent is None:
            return False
        if parent.type == "member_expression" and _resolve_call(parent):
            continue
        if parent.type == "arguments" and parent.parent is not None:
            outer = _text(parent.parent.child_by_field_name("function")).rsplit(".", 1)[-1]
            if outer == "createRequire":
                continue
            return False
        if parent.type == "variable_declarator" and parent.child_by_field_name("value") == node:
            name = parent.child_by_field_name("name")
            if name is None or name.type != "identifier":
                return False
            names.add(_text(name))
            continue
        return False
    for node in _nodes(root):
        if node.type != "identifier" or _text(node) not in names:
            continue
        parent = node.parent
        if parent is None:
            return False
        if parent.type == "variable_declarator" and parent.child_by_field_name("name") == node:
            continue
        if (
            parent.type == "member_expression"
            and parent.child_by_field_name("object") == node
            and _resolve_call(parent)
        ):
            continue
        return False
    return True


def _resolve_call(member: ts.Node) -> bool:
    """`member` is `<x>.resolve` and is called."""
    call = member.parent
    return (
        _text(member.child_by_field_name("property")) == "resolve"
        and call is not None
        and call.type == "call_expression"
        and call.child_by_field_name("function") == member
    )


def requires_only_json(content: bytes, language: str) -> bool:
    """Every `require(...)` whose argument isn't a constant string loads a `.json` file: the
    argument is a path expression ending in a constant `.json` (`path.join(here,
    "package.json")`, `dir + "/manifest.json"`, `require.resolve(`${pkg}/package.json`)`), or a
    name given one value (declared, or `let p;` then assigned once) that is one.
    `import(...)` of a computed path never counts (it can load code). False if the file
    doesn't parse cleanly."""
    root = _root(content, language)
    if root is None or b"extensions" in content or b"getBuiltinModule" in content:
        return False  # `require.extensions[".json"] = ...` makes a `.json` file run as code
    declared: dict[str, list[ts.Node]] = {}
    for node in _nodes(root):
        if node.type == "variable_declarator":
            name = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if name is not None and name.type == "identifier" and value is not None:
                declared.setdefault(_text(name), []).append(value)
        elif node.type in ("assignment_expression", "augmented_assignment_expression"):
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and left.type == "identifier" and right is not None:
                if node.type == "augmented_assignment_expression":
                    right = node  # `p += x`: not one value
                declared.setdefault(_text(left), []).append(right)
    for node in _nodes(root):
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        if function is None or function.type not in ("identifier", "import"):
            continue
        loader = "import" if function.type == "import" else _text(function)
        if loader not in ("require", "import"):
            continue
        arguments = _arguments(node)
        if arguments and arguments[0].type == "string":
            continue  # a constant: the profile reads it
        if loader == "import" or not arguments:
            return False
        argument = arguments[0]
        if argument.type == "identifier":
            values = declared.get(_text(argument), [])
            if len(values) != 1:
                return False
            argument = values[0]
        if not _json_path(argument):
            return False
    return True


def _json_path(node: ts.Node) -> bool:
    """A path expression that ends in a constant `.json`: a string or template ending so, a `+`
    whose right side does, or a call (`join`, `resolve`, `require.resolve`) whose last argument
    does."""
    if node.type == "string":
        return "".join(
            _text(c) for c in node.named_children if c.type == "string_fragment"
        ).endswith(".json")
    if node.type == "template_string":
        parts = [c for c in node.named_children if c.type != "comment"]
        return (
            bool(parts)
            and parts[-1].type == "string_fragment"
            and _text(parts[-1]).endswith(".json")
        )
    if node.type == "binary_expression" and _text(node.child_by_field_name("operator")) == "+":
        right = node.child_by_field_name("right")
        return right is not None and _json_path(right)
    if node.type == "call_expression":
        callee = _text(node.child_by_field_name("function"))
        arguments = _arguments(node)
        if not arguments:
            return False
        if callee == "require.resolve":  # `require.resolve(path, { paths })`
            return _json_path(arguments[0])
        return callee.rsplit(".", 1)[-1] in ("join", "resolve") and _json_path(arguments[-1])
    return False


# The other ways to take the environment the capability profile counts (`Reflect.get(process,
# "env")`, `process["env"]`, `process.getBuiltinModule`): not followed, so never read by name.
_OTHER_ENV_FORMS: Final = re.compile(rb"\bReflect\b|\bprocess\s*\[|getBuiltinModule")
# Comparisons: `process.env === x` lets no variable out (`||`, `??` and `&&` would).
_COMPARISONS: Final = frozenset({"===", "!==", "==", "!="})


def env_read_by_name(content: bytes, language: str) -> bool:
    """Every use of `process.env` in the file only reads (or sets) named variables: a member
    (`process.env.X`, `process.env["X"]`), compared or negated, bound to a name (`const env =
    process.env`, also through `||`, `??` and ternaries) whose every use is a named access, or
    passed to a function the file declares (`function isCI(env)`, `const f = (env) => ...`)
    whose matching parameter is only accessed by name. A named access is `name.X` or
    `name["X"]` (also `name.X.toLowerCase()`). Anything else (a spread, `Object.keys(env)`,
    `JSON.stringify`, `{ env: process.env }` for a child process, a call of an imported
    function, `arguments`) is not. False if the file doesn't parse cleanly."""
    root = _root(content, language)
    if root is None or _OTHER_ENV_FORMS.search(content):
        return False
    functions = _declared_functions(root)
    for node in _nodes(root):
        if node.type != "member_expression":
            continue
        if _text(node.child_by_field_name("object")) != "process":
            continue
        if _text(node.child_by_field_name("property")) != "env":
            continue
        if not _env_value_ok(node, root, functions):
            return False
    return True


def _declared_functions(root: ts.Node) -> dict[str, list[ts.Node]]:
    """Functions the file declares by name: `function f(...)`, `const f = (...) => ...`."""
    found: dict[str, list[ts.Node]] = {}
    for node in _nodes(root):
        if node.type in ("function_declaration", "generator_function_declaration"):
            name = node.child_by_field_name("name")
            if name is not None:
                found.setdefault(_text(name), []).append(node)
        elif node.type == "variable_declarator":
            value = node.child_by_field_name("value")
            name = node.child_by_field_name("name")
            if value is not None and value.type in _FUNCTION_VALUES and name is not None:
                found.setdefault(_text(name), []).append(value)
    return found


def _named_access(node: ts.Node) -> bool:
    """`node` (an expression that is the environment) is accessed by a constant name here:
    `node.X` or `node["X"]`."""
    parent = node.parent
    if parent is None:
        return False
    if parent.type == "member_expression" and parent.child_by_field_name("object") == node:
        return True
    if parent.type == "subscript_expression" and parent.child_by_field_name("object") == node:
        index = parent.child_by_field_name("index")
        return index is not None and index.type == "string"
    return False


def _env_value_ok(node: ts.Node, root: ts.Node, functions: dict[str, list[ts.Node]]) -> bool:
    """The environment at `node` (`process.env`, or an expression that may be it) is only
    accessed by name (`env_read_by_name`)."""
    parent = node.parent
    if parent is None:
        return False
    if _named_access(node):
        return True
    if parent.type == "binary_expression":
        operator = _text(parent.child_by_field_name("operator"))
        if operator in _COMPARISONS:
            return True
        return operator in ("||", "??", "&&") and _env_value_ok(parent, root, functions)
    if parent.type == "unary_expression":
        return _text(parent.child_by_field_name("operator")) in ("!", "typeof")
    if parent.type == "ternary_expression":
        if parent.child_by_field_name("condition") == node:
            return True
        return _env_value_ok(parent, root, functions)
    if parent.type == "parenthesized_expression":
        above = parent.parent
        if above is not None and above.type in ("if_statement", "while_statement"):
            return above.child_by_field_name("condition") == parent  # only tested
        return _env_value_ok(parent, root, functions)
    if parent.type == "variable_declarator" and parent.child_by_field_name("value") == node:
        name = parent.child_by_field_name("name")
        if name is None or name.type != "identifier":
            return False  # destructuring: `{...rest}` takes it whole
        return _name_accessed_by_name(root, _text(name), declaration=name)
    if parent.type == "arguments" and parent.parent is not None:
        callee = parent.parent.child_by_field_name("function")
        if callee is None or callee.type != "identifier":
            return False
        declared = functions.get(_text(callee))
        if not declared:
            return False
        index = [c for c in parent.named_children if c.type != "comment"].index(node)
        return all(_parameter_accessed_by_name(f, index) for f in declared)
    return False


def _name_accessed_by_name(scope: ts.Node, name: str, *, declaration: ts.Node | None) -> bool:
    """Every identifier `name` in `scope` besides `declaration` is a named access."""
    for node in _nodes(scope):
        if node.type not in ("identifier", "shorthand_property_identifier") or node == declaration:
            continue
        if _text(node) != name:
            continue
        if node.type == "shorthand_property_identifier" or not _named_access(node):
            return False
    return True


def _parameter_accessed_by_name(function: ts.Node, index: int) -> bool:
    """The `index`-th parameter of `function` is a plain name only accessed by name in its
    body, and the body doesn't read `arguments`."""
    parameters = function.child_by_field_name("parameters")
    if parameters is None:
        single = function.child_by_field_name("parameter")  # `env => ...`
        listed = [single] if single is not None else []
    else:
        listed = [c for c in parameters.named_children if c.type != "comment"]
    body = function.child_by_field_name("body")
    if index >= len(listed) or body is None:
        return False
    parameter = listed[index]
    if parameter.type != "identifier" or any(
        n.type == "identifier" and _text(n) == "arguments" for n in _nodes(body)
    ):
        return False
    return _name_accessed_by_name(body, _text(parameter), declaration=None)


# `guard_only` (S8): what an install guard may read and call. Values: Node's version, the
# platform and CPU, named environment variables. Methods: the string, array and number helpers
# a version comparison uses.
GUARD_VALUES: Final = frozenset(
    {"process.version", "process.versions", "process.platform", "process.arch"}
)
GUARD_METHODS: Final = frozenset(
    {
        "split", "map", "filter", "trim", "includes", "startsWith", "endsWith", "toLowerCase",
        "toUpperCase", "slice", "replace", "test", "some", "every", "indexOf", "join",
    }
)  # fmt: skip
GUARD_FUNCTIONS: Final = frozenset({"Number", "parseInt", "parseFloat", "String", "Boolean"})
GUARD_PRINTS: Final = frozenset(
    {
        "console.log", "console.error", "console.warn", "console.info",
        "process.stdout.write", "process.stderr.write",
    }
)  # fmt: skip
_GUARD_LEAVES: Final = frozenset(
    {
        "number", "string", "string_fragment", "escape_sequence", "true", "false", "null",
        "undefined", "regex", "regex_pattern", "regex_flags", "comment",
    }
)  # fmt: skip
_GUARD_EXPRESSIONS: Final = frozenset(
    {
        "binary_expression", "unary_expression", "ternary_expression", "parenthesized_expression",
        "template_string", "template_substitution", "array",
    }
)  # fmt: skip


def guard_only(content: bytes, language: str) -> bool:
    """The code is an install guard and nothing else (S8, `npm.install-explained` v7): its
    statements are declarations of values computed from `GUARD_VALUES` and named environment
    variables (`process.env.X`) with `GUARD_METHODS` and `GUARD_FUNCTIONS`, `if` tests on them,
    and `process.exit(<number>)`; it prints (`GUARD_PRINTS`) only in a branch that then ends
    with `process.exit(<non-zero>)`, so it is silent unless it fails the install. Empty code is
    a guard too. A banner (`console.log(...)` on its own), any other call, assignment, loop or
    function is not. False if the code doesn't parse cleanly."""
    root = _root(content, language)
    if root is None:
        return False
    names: set[str] = set()
    return all(_guard_statement(s, names) for s in root.named_children)


def _guard_statement(node: ts.Node, names: set[str]) -> bool:
    if node.type in ("comment", "empty_statement"):
        return True
    if node.type in ("lexical_declaration", "variable_declaration"):
        for declarator in node.named_children:
            if declarator.type != "variable_declarator":
                return False
            value = declarator.child_by_field_name("value")
            pattern = declarator.child_by_field_name("name")
            if value is None or pattern is None or not _guard_expression(value, names):
                return False
            if pattern.type not in ("identifier", "array_pattern") or any(
                n.type not in ("identifier", ",") for n in pattern.named_children
            ):
                return False
            names.update(_text(n) for n in _nodes(pattern) if n.type == "identifier")
        return True
    if node.type == "if_statement":
        condition = node.child_by_field_name("condition")
        if condition is None or not _guard_expression(condition, names):
            return False
        branches = [node.child_by_field_name("consequence")]
        alternative = node.child_by_field_name("alternative")
        if alternative is not None:
            branches.extend(alternative.named_children)  # an `else_clause` holds one statement
        return all(b is not None and _guard_branch(b, names) for b in branches)
    if node.type == "statement_block":
        return _guard_branch(node, names)
    return _exit_code(node) is not None


def _guard_branch(node: ts.Node, names: set[str]) -> bool:
    """A branch of a guard's `if`: guard statements, and prints only when it ends in
    `process.exit(<non-zero>)`."""
    statements = node.named_children if node.type == "statement_block" else [node]
    statements = [s for s in statements if s.type != "comment"]
    prints = [s for s in statements if _print(s, names)]
    if not all(_guard_statement(s, set(names)) for s in statements if s not in prints):
        return False
    if not prints:
        return True
    last = _exit_code(statements[-1])
    return last is not None and last != 0


def _exit_code(node: ts.Node) -> int | None:
    """`process.exit(<n>)` (or `process.exit()`, 0) as a statement: its code; else None."""
    if node.type != "expression_statement" or node.named_child_count != 1:
        return None
    call = node.named_children[0]
    if call.type != "call_expression":
        return None
    if _text(call.child_by_field_name("function")) != "process.exit":
        return None
    arguments = _arguments(call)
    if not arguments:
        return 0
    return _number(arguments[0]) if len(arguments) == 1 else None


def _print(node: ts.Node, names: set[str]) -> bool:
    """A statement that only prints guard values and text."""
    if node.type != "expression_statement" or node.named_child_count != 1:
        return False
    call = node.named_children[0]
    return (
        call.type == "call_expression"
        and _text(call.child_by_field_name("function")) in GUARD_PRINTS
        and all(_guard_expression(a, names) for a in _arguments(call))
    )


def _guard_expression(node: ts.Node, names: set[str]) -> bool:
    """An expression over guard values (`guard_only`)."""
    if node.type in _GUARD_LEAVES:
        return True
    if node.type == "identifier":
        return _text(node) in names
    if node.type in _GUARD_EXPRESSIONS:
        return all(_guard_expression(c, names) for c in node.named_children)
    if node.type == "member_expression":
        obj = node.child_by_field_name("object")
        if _text(node) in GUARD_VALUES or (obj is not None and _text(obj) == "process.env"):
            return True  # `process.versions`, `process.env.X`
        return obj is not None and _guard_expression(obj, names)  # `x.length`, `v.node`
    if node.type == "subscript_expression":
        obj = node.child_by_field_name("object")
        index = node.child_by_field_name("index")
        if obj is None or index is None:
            return False
        if _text(obj) == "process.env":
            return index.type == "string"
        return _guard_expression(obj, names) and _guard_expression(index, names)
    if node.type == "arrow_function":  # `.map((s) => s.trim())`
        return _guard_arrow(node, names)
    if node.type == "call_expression":
        return _guard_call(node, names)
    return False


def _guard_arrow(node: ts.Node, names: set[str]) -> bool:
    """An arrow function whose parameters are plain names and whose body is a guard
    expression."""
    body = node.child_by_field_name("body")
    single = node.child_by_field_name("parameter")
    parameters = node.child_by_field_name("parameters")
    listed = [single] if single is not None else []
    if parameters is not None:
        listed = [c for c in parameters.named_children if c.type != "comment"]
    if body is None or body.type == "statement_block":
        return False
    if any(p.type != "identifier" for p in listed):
        return False
    return _guard_expression(body, names | {_text(p) for p in listed})


def _guard_call(node: ts.Node, names: set[str]) -> bool:
    """`Number(x)`, `parseInt(x, 10)`, `v.split(".")`: a `GUARD_FUNCTIONS` call or a
    `GUARD_METHODS` method of a guard value, with guard arguments."""
    function = node.child_by_field_name("function")
    if function is None:
        return False
    if function.type == "identifier":
        ok = _text(function) in GUARD_FUNCTIONS
    elif function.type == "member_expression":
        obj = function.child_by_field_name("object")
        ok = (
            _text(function.child_by_field_name("property")) in GUARD_METHODS
            and obj is not None
            and _guard_expression(obj, names)
        )
    else:
        ok = False
    return ok and all(
        _guard_expression(a, names) or (a.type == "identifier" and _text(a) in GUARD_FUNCTIONS)
        for a in _arguments(node)
    )
