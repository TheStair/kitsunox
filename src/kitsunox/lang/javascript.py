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

import re
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
# 4: `process.getBuiltinModule("fs")` loads a module as `require` does, and
#    `Reflect.get(process, "env")` is `process.env` (`@atedone/workspace-bootstrap`, 2026-10-31,
#    used both to keep its install code clear of the usual tells).
# 5: the Function constructor reached through `constructor` (`_function_constructors`):
#    `x.constructor.constructor`, `(() => {}).constructor`, and a variable holding
#    `x.constructor` whose own `constructor` is taken (`txnforge`, `mock-datas-lib`, 2026-11-02).
# 6: the packages a file loads by name (`FileCapabilities.packages`), for
#    `npm.undeclared-package`; `.d.cts` and `.d.mts` are type declarations, like `.d.ts`.
EXTRACTOR_VERSION: Final = 6
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


class PackageLoad(Record):
    """A package loaded by name (`require("x")`, `import ... from "x"`, `import("x")`): the
    package (`@scope/x` for `@scope/x/sub`), 1-based line, a short snippet, and whether it is
    loaded inside a `try` (the usual way to load an optional package)."""

    name: str
    line: int
    snippet: str
    guarded: bool = False


class FileCapabilities(Record):
    language: str
    parse_errors: bool
    uses: tuple[Use, ...]
    packages: tuple[PackageLoad, ...] = ()  # each package once, unguarded first

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

# Node's own modules (`require("module").builtinModules`, Node 22), loaded without a package;
# subpaths count (`fs/promises`), and every `node:` specifier is Node's.
NODE_BUILTINS: Final = frozenset(
    {
        "_http_agent", "_http_client", "_http_common", "_http_incoming", "_http_outgoing",
        "_http_server", "_stream_duplex", "_stream_passthrough", "_stream_readable",
        "_stream_transform", "_stream_wrap", "_stream_writable", "_tls_common", "_tls_wrap",
        "assert", "async_hooks", "buffer", "child_process", "cluster", "console", "constants",
        "crypto", "dgram", "diagnostics_channel", "dns", "domain", "events", "fs", "http",
        "http2", "https", "inspector", "module", "net", "os", "path", "perf_hooks", "process",
        "punycode", "querystring", "readline", "repl", "stream", "string_decoder", "sys",
        "timers", "tls", "trace_events", "tty", "url", "util", "v8", "vm", "wasi",
        "worker_threads", "zlib",
    }
)  # fmt: skip
_LOADERS: Final = frozenset({"require", "import"})  # `import("x")`'s callee is `import` too
# npm has refused new names with capitals since 2017; a capitalised specifier is a bundler's
# external or an AMD global (`require("React")`), not a package to install.
_PACKAGE_NAME: Final = re.compile(r"(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*")

# `detail` of a `dynamic-code` use that reaches the Function constructor through `constructor`.
CONSTRUCTOR_CHAIN: Final = "constructor.constructor"  # also `c.constructor`, `c = x.constructor`
FUNCTION_CONSTRUCTOR: Final = "function.constructor"  # `(async () => {}).constructor`
# Either, in a file that hands Node's loader to code: a call passing `require`, `process` or
# `module` (`f(require, process)`), or the constructor given them as parameter names
# (`F("require", body)`).
GIVEN_LOADER: Final = "(require)"
FUNCTION_ALIASES: Final = frozenset(
    {
        CONSTRUCTOR_CHAIN,
        FUNCTION_CONSTRUCTOR,
        CONSTRUCTOR_CHAIN + GIVEN_LOADER,
        FUNCTION_CONSTRUCTOR + GIVEN_LOADER,
    }
)
LOADER_NAMES: Final = frozenset({"require", "process", "module"})
_FUNCTION_LITERALS: Final = frozenset(
    {"arrow_function", "function_expression", "function", "generator_function", "class"}
)


def _any_of(names: Iterable[str]) -> str:
    return " ".join(f'"{n}"' for n in sorted(names))


# `x["constructor"]` by the key's source text, quotes included. Not `#match?`: py-tree-sitter
# decodes the text for a regular expression and raised SystemError on a file that isn't UTF-8
# (`llm-oracle@1.0.2`). A concatenated key (`x["constr" + "uctor"]`) is captured whenever its
# left operand is a string, and folded in Python.
_CONSTRUCTOR_KEYS: Final = '"\\"constructor\\"" "\'constructor\'" "`constructor`"'

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
 (#any-of? @obj "process" "Reflect" {_any_of(GLOBAL_OBJECTS)}))
((subscript_expression object: (identifier) @obj index: (_) @key) @member
 (#any-of? @obj "process" {_any_of(GLOBAL_OBJECTS)}))
((member_expression property: (property_identifier) @ctor_prop) @ctor_access
 (#eq? @ctor_prop "constructor"))
((subscript_expression index: [(string) (template_string)] @ctor_key) @ctor_access
 (#any-of? @ctor_key {_CONSTRUCTOR_KEYS}))
(subscript_expression index: (binary_expression left: [(string) (binary_expression)])) @ctor_access
((arguments (identifier) @passed) (#any-of? @passed {_any_of(LOADER_NAMES)}))
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
    if lower.endswith((".d.ts", ".d.cts", ".d.mts")):
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
    loads: list[tuple[str, ts.Node]] = []
    for capability, detail, node in _uses(query, tree.root_node, content, loads):
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
    return FileCapabilities(
        language=language,
        parse_errors=tree.root_node.has_error,
        uses=ordered,
        packages=_packages(content, loads),
    )


def package_name(specifier: str) -> str | None:
    """The npm package a specifier loads (`@scope/x` for `@scope/x/sub`, `x` for `x/sub`), or
    None for Node's own modules, paths (`./x`, `/x`), URLs and other schemes (`node:`,
    `http:`), package-internal imports (`#x`) and anything that isn't a package name."""
    if ":" in specifier or specifier.startswith((".", "/", "#", "~")):
        return None
    parts = specifier.split("/")
    name = "/".join(parts[:2]) if specifier.startswith("@") else parts[0]
    if name in NODE_BUILTINS or not _PACKAGE_NAME.fullmatch(name):
        return None
    return name


def _packages(content: bytes, loads: list[tuple[str, ts.Node]]) -> tuple[PackageLoad, ...]:
    found: dict[str, PackageLoad] = {}
    for specifier, node in sorted(loads, key=lambda load: load[1].start_byte):
        name = package_name(specifier)
        if name is None or (name in found and not found[name].guarded):
            continue
        guarded = _in_try(node)
        if name not in found or not guarded:
            found[name] = PackageLoad(
                name=name,
                line=node.start_point.row + 1,
                snippet=_snippet(content, node),
                guarded=guarded,
            )
    return tuple(found.values())


def _in_try(node: ts.Node) -> bool:
    parent = node.parent
    while parent is not None:
        if parent.type == "try_statement":
            return True
        parent = parent.parent
    return False


def _type_only(node: ts.Node) -> bool:
    """`import type {X} from "y"` and `export type {X} from "y"` (TypeScript): no code loads."""
    return node.type in ("import_statement", "export_statement") and any(
        c.type == "type" for c in node.children
    )


def _uses(
    query: ts.Query, root: ts.Node, content: bytes, loads: list[tuple[str, ts.Node]]
) -> Iterator[tuple[Capability, str, ts.Node]]:
    """Capability uses; also appends each constant specifier loaded, with its node, to
    `loads`."""
    accesses: list[ts.Node] = []
    passes_loader = False
    for _, match in ts.QueryCursor(query).matches(root):
        if "passed" in match:
            passes_loader = True
            continue
        if "import" in match or ("call" in match and _text(match["callee"][0]) in _LOADERS):
            node = match["import" if "import" in match else "call"][0]
            source = match["source"][0] if "source" in match else match.get("arg", [None])[0]
            if (specifier := fold_string(source)) is not None and not _type_only(node):
                loads.append((specifier, node))
        if "ctor_access" in match:
            if _is_constructor_access(match["ctor_access"][0]):
                accesses.append(match["ctor_access"][0])
        elif "call" in match:
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
    yield from _function_constructors(accesses, content, passes_loader)


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


def _is_constructor_access(node: ts.Node) -> bool:
    """`x.constructor` or `x["constructor"]` (a folded key: `x["constr" + "uctor"]`)."""
    if node.type == "member_expression":
        return _text(node.child_by_field_name("property")) == "constructor"
    return node.type == "subscript_expression" and (
        fold_string(node.child_by_field_name("index")) == "constructor"
    )


def _unparenthesized(node: ts.Node | None) -> ts.Node | None:
    while node is not None and node.type == "parenthesized_expression":
        node = node.named_children[-1] if node.named_child_count else None
    return node


def _function_constructors(
    accesses: list[ts.Node], content: bytes, passes_loader: bool
) -> Iterator[tuple[Capability, str, ts.Node]]:
    """The Function constructor reached without naming it, a way to run built code that reads
    as neither `eval` nor `Function`: the `constructor` of a function (`(() => {}).constructor`,
    `Object.getPrototypeOf(async function () {}).constructor`) or of a constructor
    (`globalThis.constructor.constructor`, also split over a variable declared in the same
    function: `const c = g.constructor; c.constructor`). It counts only where it is used as a
    function (called, stored, passed, returned), not where it is read (`.name`), compared or
    tested (`instanceof`), and not when called directly with only short constant code
    (`_constant_code`). The detail says `GIVEN_LOADER` when the file passes `require`,
    `process` or `module` to a call, or the constructor is given one as a parameter name."""
    declared: dict[str, list[tuple[tuple[int, int], int]]] = {}
    for node in accesses:
        if (name := _declared_name(node)) is not None:
            declared.setdefault(name, []).append((_scope(node), node.start_byte))
    for node in accesses:
        obj = _unparenthesized(node.child_by_field_name("object"))
        if obj is None:
            continue
        if _is_constructor_access(obj) or (
            obj.type == "identifier"
            and any(
                scope == _scope(node) and start < node.start_byte
                for scope, start in declared.get(_text(obj), ())
            )
        ):
            detail = CONSTRUCTOR_CHAIN
        elif obj.type in _FUNCTION_LITERALS or _prototype_of_function(obj):
            detail = FUNCTION_CONSTRUCTOR
        else:
            continue
        sites = _function_uses(node, content)
        if sites and not _called_with_constant_code(node):
            if passes_loader or any(_given_loader_names(site) for site in sites):
                detail += GIVEN_LOADER
            yield Capability.DYNAMIC_CODE, detail, node


def _declared_name(node: ts.Node) -> str | None:
    """The variable `node` initialises: `const c = node` (not a later assignment, which in
    minified code reuses one-letter names for anything)."""
    parent = node.parent
    if parent is None or parent.type != "variable_declarator":
        return None
    name = parent.child_by_field_name("name")
    if parent.child_by_field_name("value") != node or name is None or name.type != "identifier":
        return None
    return _text(name)


_SCOPES: Final = frozenset(
    {
        "program",
        "function_declaration",
        "function_expression",
        "function",
        "arrow_function",
        "method_definition",
        "generator_function",
        "generator_function_declaration",
    }
)


def _scope_node(node: ts.Node) -> ts.Node | None:
    """The function (or file) `node` is in."""
    parent = node.parent
    while parent is not None and parent.type not in _SCOPES:
        parent = parent.parent
    return parent


def _scope(node: ts.Node) -> tuple[int, int]:
    scope = _scope_node(node)
    return (scope.start_byte, scope.end_byte) if scope is not None else (0, 0)


_FLOWS_ON: Final = frozenset({"||", "&&", "??"})
_INVOKERS: Final = frozenset({"call", "apply", "bind"})
_TESTS: Final = frozenset(
    {
        "if_statement",
        "while_statement",
        "do_statement",
        "for_statement",
        "expression_statement",
        "unary_expression",
        "binary_expression",
    }
)


def _used_as_function(node: ts.Node) -> bool:
    """`node` is called, stored, passed or returned; not read from (`c.name`, `c.prototype`),
    compared, tested (`f instanceof (async () => {}).constructor`, `typeof c`, `c ? ... :`) or
    left unused. Its value flows on through parentheses, `||`, `&&`, `??` and a ternary's
    branches."""
    child, parent = node, node.parent
    while parent is not None and (
        parent.type == "parenthesized_expression"
        or (
            parent.type == "binary_expression"
            and _text(parent.child_by_field_name("operator")) in _FLOWS_ON
        )
        or (
            parent.type == "ternary_expression" and parent.child_by_field_name("condition") != child
        )
    ):
        child, parent = parent, parent.parent
    if parent is None:
        return True
    if parent.type == "member_expression" and parent.child_by_field_name("object") == child:
        return _text(parent.child_by_field_name("property")) in _INVOKERS
    if parent.type == "subscript_expression" and parent.child_by_field_name("object") == child:
        return fold_string(parent.child_by_field_name("index")) in _INVOKERS
    return parent.type not in _TESTS and parent.type != "ternary_expression"


_IDENTIFIER: Final = re.compile(r"[\w$]+")
_REFERENCE_TYPES: Final = frozenset({"identifier", "shorthand_property_identifier"})


MAX_REFERENCES: Final = 1000  # references of one variable examined (`_function_uses`)


def _function_uses(node: ts.Node, content: bytes) -> list[ts.Node]:
    """Where `node` is used as a function (`_used_as_function`): `node` itself, or for
    `const c = <node>` the references to `c` in its scope that are (echarts keeps
    `function () {}.constructor` only to read its `.prototype`). References are found by
    searching the scope's text for the name (a query over every identifier of a 7 MB bundle
    took 0.4 s); at most MAX_REFERENCES are examined, and the search stops at a use that is
    given Node's loader (a minified bundle can name thousands of things `t`)."""
    name = _declared_name(node)
    scope = _scope_node(node)
    if name is None or scope is None:
        return [node] if _used_as_function(node) else []
    if not _IDENTIFIER.fullmatch(name):
        return [node]
    word = re.compile(rb"(?<![\w$])" + re.escape(name.encode()) + rb"(?![\w$])")
    declarator_name = node.parent.child_by_field_name("name") if node.parent else None
    sites = []
    for count, found in enumerate(word.finditer(content, scope.start_byte, scope.end_byte)):
        if count >= MAX_REFERENCES:
            break
        ref = scope.descendant_for_byte_range(found.start(), found.end())
        if (
            ref is not None
            and ref.type in _REFERENCE_TYPES
            and ref != declarator_name
            and _used_as_function(ref)
        ):
            sites.append(ref)
            if _given_loader_names(ref):
                break
    return sites


def _given_loader_names(site: ts.Node) -> bool:
    """`site` is called or `new`ed with `"require"`, `"process"` or `"module"` among its
    arguments: a function built with Node's loader as a parameter."""
    child, parent = site, site.parent
    while parent is not None and parent.type == "parenthesized_expression":
        child, parent = parent, parent.parent
    if parent is None or parent.type not in ("call_expression", "new_expression"):
        return False
    field = "function" if parent.type == "call_expression" else "constructor"
    arguments = parent.child_by_field_name("arguments")
    if parent.child_by_field_name(field) != child or arguments is None:
        return False
    return any(fold_string(a) in LOADER_NAMES for a in arguments.named_children)


def _prototype_of_function(node: ts.Node) -> bool:
    """`Object.getPrototypeOf(<function>)` or `Reflect.getPrototypeOf(<function>)`."""
    if node.type != "call_expression":
        return False
    callee = node.child_by_field_name("function")
    if callee is None or _text(callee) not in ("Object.getPrototypeOf", "Reflect.getPrototypeOf"):
        return False
    arguments = node.child_by_field_name("arguments")
    args = [c for c in arguments.named_children if c.type != "comment"] if arguments else []
    return bool(args) and (_unparenthesized(args[0]) or args[0]).type in _FUNCTION_LITERALS


def _called_with_constant_code(node: ts.Node) -> bool:
    parent = node.parent
    if parent is None or parent.type not in ("call_expression", "new_expression"):
        return False
    field = "function" if parent.type == "call_expression" else "constructor"
    return parent.child_by_field_name(field) == node and _constant_code(parent)


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
    elif (obj, key) in (("process", "getBuiltinModule"), ("Reflect", "get")):
        yield from _indirect(obj, key, node)


def _indirect(obj: str, key: str, member: ts.Node) -> Iterator[tuple[Capability, str, ts.Node]]:
    """`process.getBuiltinModule(x)`, which is `require(x)` for Node's own modules, and
    `Reflect.get(process, "env")`, which is `process.env`."""
    call = member.parent
    if (
        call is None
        or call.type != "call_expression"
        or call.child_by_field_name("function") != member
    ):
        return
    arguments = call.child_by_field_name("arguments")
    args = [c for c in arguments.named_children if c.type != "comment"] if arguments else []
    if key == "getBuiltinModule":
        specifier = fold_string(args[0]) if args else None
        if specifier is None:
            yield Capability.DYNAMIC_REQUIRE, "process.getBuiltinModule(<computed>)", call
        elif (capability := module_capability(specifier)) is not None:
            yield capability, specifier, call
    elif (
        len(args) >= 2
        and _text(args[0]) == "process"
        and fold_string(args[1]) == "env"
        and _whole_env(call)
    ):
        yield Capability.ENV_ALL, "Reflect.get(process, 'env')", call


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
