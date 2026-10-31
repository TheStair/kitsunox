"""What a JavaScript or TypeScript file can do: capabilities found by parsing it (Stage 3).

A capability is a kind of access to the outside world (network, processes, files, the whole
environment) or a way to run code that static reading can't see (eval, dynamic require). The
parser is tree-sitter, so a file never runs; queries are matched in C, which keeps multi-MB
bundles affordable.

Compared with Stage 2's regular expressions, the parse:

- ignores comments and plain strings: a URL in a doc comment is not a `require("https")`;
- folds string concatenation, so `require("child_" + "process")` is still `child_process`;
- sees bracket access with literal keys (`global["eval"]`, `process["env"]`);
- tells reading one variable (`process.env.HOME`) from taking the whole environment
  (`JSON.stringify(process.env)`), which only the second is a harvesting capability.

Results are a pure function of the content and the file's language, so they are cached by content
hash like Stage 2's.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable, Iterator
from enum import StrEnum
from functools import cache
from typing import Final

import tree_sitter as ts
import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts

from kitsunox.core.models import Record

# Bump whenever extraction changes: it keys the on-disk cache (`stages/ast.py`).
# 2: `eval`, `Function(...)` and `new Function(...)` whose every argument is a short constant
#    string are not dynamic code (`_constant_code`).
# 3: MAX_EVIDENCE counts per capability and detail, so three `new Function(x)` calls no longer
#    hide a later `eval(x)` in the same file (`code.capability-gained` tells them apart).
EXTRACTOR_VERSION: Final = 3
MAX_CONSTANT_CODE: Final = 120  # characters of constant code `_constant_code` lets through
MAX_SOURCE_BYTES: Final = 16 * 1024 * 1024  # same as Stage 2's file limit
SNIPPET_CHARS: Final = 160
MAX_EVIDENCE: Final = 3  # per capability and detail, per file


class Capability(StrEnum):
    NETWORK = "network"
    PROCESS = "process"
    FILESYSTEM = "filesystem"
    ENV_ALL = "env-all"
    OS_INFO = "os-info"
    DYNAMIC_CODE = "dynamic-code"
    DYNAMIC_REQUIRE = "dynamic-require"
    NATIVE = "native"


class Use(Record):
    """One place a capability is used: 1-based line and a short source snippet."""

    capability: Capability
    detail: str  # e.g. the module name, or `eval`
    line: int
    snippet: str


class FileCapabilities(Record):
    language: str
    parse_errors: bool
    uses: tuple[Use, ...]

    @property
    def capabilities(self) -> frozenset[Capability]:
        return frozenset(u.capability for u in self.uses)


# Node built-ins and the common third-party clients that give the same power. Subpaths count
# (`fs/promises`), and so does the `node:` prefix.
MODULES: Final[dict[str, Capability]] = {
    **dict.fromkeys(
        (
            "http",
            "https",
            "http2",
            "net",
            "tls",
            "dns",
            "dgram",
            "undici",
            "axios",
            "node-fetch",
            "got",
            "request",
            "ws",
        ),
        Capability.NETWORK,
    ),
    **dict.fromkeys(("child_process",), Capability.PROCESS),
    **dict.fromkeys(("fs", "fs-extra", "graceful-fs"), Capability.FILESYSTEM),
    **dict.fromkeys(("os",), Capability.OS_INFO),
    **dict.fromkeys(("vm",), Capability.DYNAMIC_CODE),
}
GLOBAL_CALLS: Final[dict[str, Capability]] = {
    "fetch": Capability.NETWORK,
    "eval": Capability.DYNAMIC_CODE,
    "Function": Capability.DYNAMIC_CODE,
}
CONSTRUCTORS: Final[dict[str, Capability]] = {
    "WebSocket": Capability.NETWORK,
    "XMLHttpRequest": Capability.NETWORK,
    "Function": Capability.DYNAMIC_CODE,
}
PROCESS_NATIVE: Final = frozenset({"binding", "dlopen", "_linkedBinding"})

GLOBAL_OBJECTS: Final = ("global", "globalThis", "window", "self", "this")


def _any_of(names: Iterable[str]) -> str:
    return " ".join(f'"{n}"' for n in sorted(names))


# One pattern per kind of construct, filtered by name in the query itself (matched in C), so
# Python only sees relevant nodes. `@arg`, `@source` and `@key` are folded as strings.
_QUERY: Final = f"""
((call_expression
  function: (identifier) @callee
  arguments: (arguments . (_)? @arg)) @call
 (#any-of? @callee "require" {_any_of(GLOBAL_CALLS)}))
(call_expression function: (import) @callee arguments: (arguments . (_)? @arg)) @call
((new_expression constructor: (identifier) @ctor) @new (#any-of? @ctor {_any_of(CONSTRUCTORS)}))
(import_statement source: (string) @source) @import
(export_statement source: (string) @source) @import
((member_expression object: (identifier) @obj property: (property_identifier) @prop) @member
 (#any-of? @obj "process" {_any_of(GLOBAL_OBJECTS)}))
((subscript_expression object: (identifier) @obj index: (_) @key) @member
 (#any-of? @obj "process" {_any_of(GLOBAL_OBJECTS)}))
"""

# Where a file loads other files of its package from (`local_paths`): a relative `require`,
# `import` or `export ... from`, `path.join` or `path.resolve` from `__dirname`, or
# `new URL(rel, import.meta.url)`.
_LOCAL_QUERY: Final = """
((call_expression function: (identifier) @callee arguments: (arguments . (_) @arg))
 (#eq? @callee "require"))
(call_expression function: (import) arguments: (arguments . (_) @arg))
(import_statement source: (string) @arg)
(export_statement source: (string) @arg)
((call_expression
  function: [(identifier) @fn (member_expression property: (property_identifier) @fn)]
  arguments: (arguments . (identifier) @base)) @join
 (#any-of? @fn "join" "resolve")
 (#eq? @base "__dirname"))
((new_expression constructor: (identifier) @ctor arguments: (arguments . (_) @arg))
 (#eq? @ctor "URL"))
"""

_TS_SUFFIXES: Final = (".ts", ".mts", ".cts")


@cache
def _language(language: str) -> tuple[ts.Language, ts.Query]:
    lang = {
        "javascript": lambda: ts.Language(tsjs.language()),
        "typescript": lambda: ts.Language(tsts.language_typescript()),
        "tsx": lambda: ts.Language(tsts.language_tsx()),
    }[language]()
    return lang, ts.Query(lang, _QUERY)


@cache
def _local_query(language: str) -> ts.Query:
    return ts.Query(_language(language)[0], _LOCAL_QUERY)


def local_paths(content: bytes, language: str) -> tuple[str, ...]:
    """The package files `content` names to load or run, relative to its own directory
    (`./lib/x.js`, `../y`), in source order, each once. Only constant paths count; a
    `path.join(__dirname, "lib", "x.js")` is `./lib/x.js`."""
    if len(content) > MAX_SOURCE_BYTES:
        return ()
    parser, _ = _parser(language)
    found: dict[str, None] = {}
    matches = ts.QueryCursor(_local_query(language)).matches(parser.parse(content).root_node)
    for _, match in sorted(matches, key=lambda m: _first_byte(m[1])):
        if "join" in match:
            arguments = match["join"][0].child_by_field_name("arguments")
            rest = [fold_string(a) for a in (arguments.named_children[1:] if arguments else [])]
            if rest and all(r is not None for r in rest):
                found.setdefault("./" + "/".join(r or "" for r in rest), None)
        elif (value := fold_string(match["arg"][0])) is not None and value.startswith("."):
            found.setdefault(value, None)
    return tuple(found)


def _first_byte(match: dict[str, list[ts.Node]]) -> int:
    return min(node.start_byte for nodes in match.values() for node in nodes)


_local = threading.local()


def _parser(language: str) -> tuple[ts.Parser, ts.Query]:
    """A parser per thread: a tree-sitter `Parser` must not be used by two threads at once
    (sharing one crashed the process with a bus error)."""
    parsers: dict[str, ts.Parser] = _local.__dict__.setdefault("parsers", {})
    lang, query = _language(language)
    if language not in parsers:
        parsers[language] = ts.Parser(lang)
    return parsers[language], query


def language_for(path: str) -> str | None:
    """The grammar for a path, or None if it isn't JavaScript or TypeScript source."""
    lower = path.lower()
    if lower.endswith(".d.ts"):
        return None  # type declarations: no code runs
    if lower.endswith(".tsx"):
        return "tsx"
    if lower.endswith(_TS_SUFFIXES):
        return "typescript"
    if lower.endswith((".js", ".mjs", ".cjs", ".jsx")):
        return "javascript"
    return None


def fold_string(node: ts.Node | None) -> str | None:
    """The string value of a literal, a template without substitutions, or a `+` of those."""
    if node is None:
        return None
    if node.type == "string":
        return "".join(_text(c) for c in node.named_children if c.type == "string_fragment")
    if node.type == "template_string":
        if any(c.type == "template_substitution" for c in node.named_children):
            return None
        return "".join(_text(c) for c in node.named_children if c.type == "string_fragment")
    if node.type == "parenthesized_expression" and node.named_child_count == 1:
        return fold_string(node.named_children[0])
    if node.type == "binary_expression" and _text(node.child_by_field_name("operator")) == "+":
        left = fold_string(node.child_by_field_name("left"))
        right = fold_string(node.child_by_field_name("right"))
        return left + right if left is not None and right is not None else None
    return None


def module_capability(specifier: str) -> Capability | None:
    name = specifier.removeprefix("node:")
    if name.endswith(".node"):
        return Capability.NATIVE
    parts = name.split("/")
    root = "/".join(parts[:2]) if name.startswith("@") else parts[0]
    return MODULES.get(root)


def analyse_source(content: bytes, language: str) -> FileCapabilities:
    if len(content) > MAX_SOURCE_BYTES:
        return FileCapabilities(language=language, parse_errors=True, uses=())
    parser, query = _parser(language)
    tree = parser.parse(content)
    uses: dict[Capability, list[Use]] = {}
    kept: dict[tuple[Capability, str], int] = {}
    for capability, detail, node in _uses(query, tree.root_node):
        key = (capability, detail[:80])
        if kept.get(key, 0) < MAX_EVIDENCE:
            kept[key] = kept.get(key, 0) + 1
            uses.setdefault(capability, []).append(
                Use(
                    capability=capability,
                    detail=key[1],
                    line=node.start_point.row + 1,
                    snippet=_snippet(content, node),
                )
            )
    ordered = tuple(u for capability in Capability for u in uses.get(capability, ()))
    return FileCapabilities(language=language, parse_errors=tree.root_node.has_error, uses=ordered)


def _uses(query: ts.Query, root: ts.Node) -> Iterator[tuple[Capability, str, ts.Node]]:
    for _, match in ts.QueryCursor(query).matches(root):
        if "call" in match:
            yield from _call(match)
        elif "new" in match:
            name = _text(match["ctor"][0])
            if name == "Function" and _constant_code(match["new"][0]):
                continue
            if name in CONSTRUCTORS:
                yield CONSTRUCTORS[name], f"new {name}", match["new"][0]
        elif "import" in match:
            specifier = fold_string(match["source"][0])
            capability = module_capability(specifier) if specifier else None
            if capability is not None and specifier is not None:
                yield capability, specifier, match["import"][0]
        elif "member" in match:
            yield from _member(match)


def _call(match: dict[str, list[ts.Node]]) -> Iterator[tuple[Capability, str, ts.Node]]:
    callee, node = match["callee"][0], match["call"][0]
    name = "import" if callee.type == "import" else _text(callee)
    arg = match["arg"][0] if "arg" in match else None
    if name in ("require", "import"):
        specifier = fold_string(arg)
        if specifier is None:
            yield Capability.DYNAMIC_REQUIRE, f"{name}(<computed>)", node
            return
        capability = module_capability(specifier)
        if capability is not None:
            yield capability, specifier, node
    elif name in GLOBAL_CALLS:
        if GLOBAL_CALLS[name] is Capability.DYNAMIC_CODE and _constant_code(node):
            return
        yield GLOBAL_CALLS[name], name, node


def _constant_code(node: ts.Node) -> bool:
    """`eval` or `Function` given only short constant strings (or nothing): the code is in the
    file as written, so it hides nothing. `Function("return this")()`, bundlers' way to the global
    object, was the commonest `dynamic-code` on the first live days (66 of 216 reports that
    `code.capability-gained` made alone). A variable, a call or a template with a substitution
    still counts."""
    arguments = node.child_by_field_name("arguments")
    if arguments is None:
        return False
    values = [fold_string(c) for c in arguments.named_children if c.type != "comment"]
    if any(v is None for v in values):
        return False
    # A long constant can be a payload: obfuscator output is often passed to `Function` as one
    # literal (`calculatorscool346`), so only short code is let through.
    return sum(len(v or "") for v in values) <= MAX_CONSTANT_CODE


def _member(match: dict[str, list[ts.Node]]) -> Iterator[tuple[Capability, str, ts.Node]]:
    obj, node = _text(match["obj"][0]), match["member"][0]
    key = _text(match["prop"][0]) if "prop" in match else fold_string(match["key"][0])
    if key is None:
        return
    if obj in GLOBAL_OBJECTS and key in GLOBAL_CALLS:
        yield GLOBAL_CALLS[key], f"{obj}[{key}]", node  # e.g. global["eval"]
    elif obj == "process" and key in PROCESS_NATIVE:
        yield Capability.NATIVE, f"process.{key}", node
    elif obj == "process" and key == "env" and _whole_env(node):
        yield Capability.ENV_ALL, "process.env", node


def _whole_env(node: ts.Node) -> bool:
    """`process.env` used as a value, not just to read one variable (`process.env.X`,
    `process.env["X"]`) or to set one (`process.env.X = ...` also starts with a member)."""
    parent = node.parent
    if parent is None:
        return False
    if parent.type in ("member_expression", "subscript_expression"):
        return parent.child_by_field_name("object") != node
    if parent.type == "assignment_expression" and parent.child_by_field_name("left") == node:
        return False
    pattern = parent.child_by_field_name("name" if parent.type == "variable_declarator" else "left")
    if pattern is not None and pattern.type == "object_pattern":
        # `const {HOME} = process.env` reads named variables; `{...all}` takes the rest.
        return any(c.type == "rest_pattern" for c in pattern.named_children)
    return parent.type not in ("binary_expression", "unary_expression")


def _text(node: ts.Node | None) -> str:
    if node is None or node.text is None:
        return ""
    return node.text.decode("utf-8", errors="replace")


def _snippet(content: bytes, node: ts.Node) -> str:
    text = content[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
    text = " ".join(text.split())
    return text if len(text) <= SNIPPET_CHARS else text[:SNIPPET_CHARS] + "..."
