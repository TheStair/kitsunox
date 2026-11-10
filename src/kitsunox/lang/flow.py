"""Where a value goes in JavaScript install code: does a path reach a file write?

Added 2026-11-11 for `npm.install-persistence` v5 (`docs/proposals/precision-round6-S.md`).
Install code that only *reads* an AI agent's user-wide configuration (a usage meter reading
`~/.codex/sessions`, a native host checking whether `~/.codex/config.toml` exists) names the
same paths as code that installs skills there. `reaches_write` follows a value from the
expressions that name such a path to the calls it is handed to:

- through expressions (`||`, `??`, `+`, ternaries, templates, `await`, arrays, member access,
  calls of unknown functions such as `path.join`), variables (in the scope that declares
  them; a top-level name in every install file, as it may be exported), object properties
  (by name, in every file: `{home: x}` then `c.home`), a function's return value (calls of
  that function), the parameters of a function defined in the install files (by position),
  `for ... of`, and containers it is pushed into (`list.push(x)`, also through a parameter
  back to the caller's argument);
- to a **write**: Node's file writes at the destination argument (`writeFile`, `mkdir`,
  `copyFile`'s second argument, `rename`, `symlink`, ...; `open` with a write flag), a shell
  command that writes (`cp`, `mv`, `ln`, `mkdir`, `tee`, `>`, PowerShell's `Copy-Item`, ...)
  given the value, or a library function named for writing that the install files don't
  define (`installSkill`, `writeJsonFile`, `saveConfig`: words in `WRITE_WORDS`);
- and stops at reads (`existsSync`, `readFileSync`, `stat`, functions named for reading),
  comparisons, conditions, printing (`console`, `process.stdout`) and content arguments (the
  data `writeFile` writes is not where it writes).

A write only inside `if (process.env.X === "1")` (an opt-in switch the user sets, not npm's
own `npm_config_*`) doesn't count. It is a may-analysis: names are not resolved by scope
beyond the declaring function, so a name shared by unrelated code can only add a write.
Anything it can't finish (`MAX_STEPS`, `MAX_REFERENCES` uses of one name) counts as a write.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

import tree_sitter as ts

from kitsunox.lang.javascript import _FUNCTIONS, _function_name, _parser, _scope_node, _text

MAX_STEPS: Final = 4000  # values followed per call
MAX_REFERENCES: Final = 1000  # uses of one name examined per file

# Node's file writes (also `fs-extra`'s, `mkdirp`), by the argument that is the destination.
DESTINATION_FIRST: Final = frozenset(
    {
        "writeFile", "writeFileSync", "appendFile", "appendFileSync", "outputFile",
        "outputFileSync", "outputJson", "outputJsonSync", "outputJSON", "outputJSONSync",
        "writeJson", "writeJsonSync", "writeJSON", "writeJSONSync", "createWriteStream",
        "mkdir", "mkdirSync", "mkdirp", "mkdirpSync", "mkdirs", "mkdirsSync", "ensureDir",
        "ensureDirSync", "ensureFile", "ensureFileSync", "truncate", "truncateSync",
    }
)  # fmt: skip
DESTINATION_SECOND: Final = frozenset(
    {
        "copyFile", "copyFileSync", "cp", "cpSync", "copy", "copySync", "rename", "renameSync",
        "symlink", "symlinkSync", "link", "linkSync", "move", "moveSync",
    }
)  # fmt: skip
RUNNERS: Final = frozenset(
    {
        "exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork", "execa",
        "execaSync", "execaCommand", "execaCommandSync",
    }
)  # fmt: skip
SHELL_RUNNERS: Final = frozenset({"exec", "execSync", "execaCommand", "execaCommandSync"})
# The object a runner is called on: `child_process`, `cp`, an import alias; not a regex's
# `.exec(...)` (`PATTERN.exec(text)`).
_CHILD: Final = re.compile(r"(?i)child|^cp$|^proc|^execa$|^shell|^[\w$]{1,2}$")
# A command that writes the path it is given.
WRITER_COMMAND: Final = re.compile(
    r"(?:^|[\s;&|(\"'`])(?:cp|mv|ln|mkdir|rsync|tee|install|xcopy|robocopy|copy|move|mklink"
    r"|ditto)(?=[\s\"'`]|$)|>>?|\b(?:Copy-Item|Move-Item|New-Item|Set-Content|Add-Content"
    r"|Out-File)\b"
)
_OUTPUT_OBJECT: Final = re.compile(r"\b(?:stdout|stderr|console|process)\b")
# Words (camelCase parts) of a function name that writes; one-word collection and stream
# methods (`set.add(x)`, `stream.write(data)`) are not file writes.
WRITE_WORDS: Final = frozenset(
    {
        "write", "append", "copy", "mkdir", "symlink", "output", "save", "install", "persist",
        "merge", "upsert", "inject", "patch", "ensure", "register", "put", "cp", "rename",
        "link", "move", "mv", "store", "update", "add", "deploy", "configure", "setup",
    }
)  # fmt: skip
_ONE_WORD_NOT_WRITES: Final = frozenset(
    {"add", "put", "update", "store", "output", "ensure", "write"}
)
_CONTENT_WRITES: Final = frozenset({"writeSync", "write", "end"})
READ_WORDS: Final = frozenset(
    {
        "read", "exists", "stat", "access", "watch", "load", "parse", "scan", "list", "find",
        "detect", "collect", "glob", "is", "has", "get", "check", "log", "warn",
    }
)  # fmt: skip
_READ_NAMES: Final = frozenset(
    {"includes", "startsWith", "endsWith", "indexOf", "test", "match", "info", "error", "debug"}
)
_CONTAINER_METHODS: Final = frozenset({"push", "unshift", "add"})
_WRAPS: Final = frozenset(
    {
        "parenthesized_expression", "ternary_expression", "template_substitution",
        "template_string", "string", "await_expression", "array", "spread_element",
        "as_expression", "non_null_expression", "satisfies_expression", "type_assertion",
        "sequence_expression",
    }
)  # fmt: skip
_FLOW_OPERATORS: Final = frozenset({"||", "&&", "??", "+"})
_PARAMETER_PARENTS: Final = frozenset(
    {"formal_parameters", "required_parameter", "optional_parameter", "assignment_pattern"}
)
_NAME: Final = re.compile(r"[\w$]+")
_OPT_IN: Final = re.compile(
    r"^process\s*\.\s*env\s*(?:\.\s*(?P<a>\w+)|\[\s*[\"'`](?P<b>\w+)[\"'`]\s*\])\s*===?\s*"
    r"[\"'`](?:1|true|yes|on)[\"'`]$"
    r"|^[\"'`](?:1|true|yes|on)[\"'`]\s*===?\s*process\s*\.\s*env\s*"
    r"(?:\.\s*(?P<c>\w+)|\[\s*[\"'`](?P<d>\w+)[\"'`]\s*\])$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Write:
    """Where a followed value reaches a write: the file, the byte offset of the call, and its
    text (empty when the analysis gave up and counts that as a write)."""

    path: str
    offset: int
    text: str


Spans = Mapping[str, list[tuple[int, int]]]


def reaches_write(files: Mapping[str, tuple[bytes, str]], seeds: Spans) -> Write | None:
    """The first write that a value starting at one of `seeds` (byte spans per file) reaches,
    or None when every path it takes ends in a read. `files` is every JavaScript install
    file, as (content, language)."""
    return _Flow(files).run(seeds)


class _Flow:
    def __init__(self, files: Mapping[str, tuple[bytes, str]]) -> None:
        self.files = files
        self.roots: dict[str, ts.Node] = {}
        self.seen: set[tuple[str, int, int]] = set()
        self.bound: set[tuple[str, str, int, int]] = set()
        self.work: list[tuple[str, ts.Node]] = []
        self.functions: dict[str, list[tuple[str, ts.Node]]] | None = None
        self.gave_up = False

    def root(self, path: str) -> ts.Node:
        if path not in self.roots:
            content, language = self.files[path]
            parser, _ = _parser(language)
            self.roots[path] = parser.parse(content).root_node
        return self.roots[path]

    def push(self, path: str, node: ts.Node) -> None:
        key = (path, node.start_byte, node.end_byte)
        if key not in self.seen:
            self.seen.add(key)
            self.work.append((path, node))

    def run(self, seeds: Spans) -> Write | None:
        for path, spans in sorted(seeds.items()):
            if path not in self.files:
                continue
            root = self.root(path)
            for start, end in spans:
                node = root.descendant_for_byte_range(start, max(start, end - 1))
                if node is not None:
                    self.push(path, node)
        steps = 0
        while self.work:
            steps += 1
            path, node = self.work.pop()
            if steps > MAX_STEPS:
                return Write(path=path, offset=node.start_byte, text="")
            if (hit := self.climb(path, node)) is not None:
                return hit
            if self.gave_up:
                return Write(path=path, offset=node.start_byte, text="")
        return None

    def climb(self, path: str, node: ts.Node) -> Write | None:
        """Follow the value of `node` up its expression to where it ends: a write (returned),
        a binding (queued) or a read (dropped)."""
        while (parent := node.parent) is not None:
            kind = parent.type
            if kind in _WRAPS:
                if kind == "ternary_expression" and parent.child_by_field_name("condition") == node:
                    return None
            elif kind == "binary_expression":
                if _text(parent.child_by_field_name("operator")) not in _FLOW_OPERATORS:
                    return None
            elif kind in ("member_expression", "subscript_expression"):
                if parent.child_by_field_name("object") != node:
                    return None
            elif kind == "call_expression":
                if parent.child_by_field_name("function") != node:
                    return None  # an argument is under `arguments`, never here
            elif kind == "pair" or node.type == "shorthand_property_identifier":
                if kind == "pair" and parent.child_by_field_name("value") != node:
                    return None
                key = parent.child_by_field_name("key") if kind == "pair" else node
                self.bind_property(_text(key).strip("\"'`"))
                literal = parent.parent if kind == "pair" else parent
                if literal is None or literal.parent is None or literal.parent.type != "arguments":
                    return None
                parent = literal  # an options object handed to a call: `install({dir: x})`
            elif kind == "arguments":
                call = parent.parent
                if call is None:
                    return None
                given = [c for c in parent.named_children if c.type != "comment"]
                what = self.call(call, given.index(node) if node in given else -1)
                if what == "write":
                    if _opted_in(call):
                        return None
                    return Write(path=path, offset=call.start_byte, text=_text(call))
                if what == "container":
                    self.fill_container(path, call)
                if what != "flow":
                    return None
                parent = call
            elif kind == "variable_declarator":
                if parent.child_by_field_name("value") == node:
                    self.bind_pattern(path, parent.child_by_field_name("name"), _scope_node(parent))
                return None
            elif kind in ("assignment_expression", "augmented_assignment_expression"):
                if parent.child_by_field_name("right") == node:
                    self.assign(path, parent.child_by_field_name("left"))
                return None
            elif kind == "return_statement" or (
                kind == "arrow_function" and parent.child_by_field_name("body") == node
            ):
                function: ts.Node | None = parent
                while function is not None and function.type not in _FUNCTIONS:
                    function = function.parent
                if function is not None and (name := _function_name(function)):
                    self.bind_function(name)
                return None
            elif kind == "for_in_statement":
                if parent.child_by_field_name("right") == node:
                    self.bind_pattern(path, parent.child_by_field_name("left"), _scope_node(parent))
                return None
            else:
                return None
            node = parent
        return None

    def call(self, call: ts.Node, index: int) -> str:
        """What a call does with its argument at `index`: "write", "stop", "container" (it
        is put into the receiver) or "flow" (the call's result carries it)."""
        callee = call.child_by_field_name("function") or call.child_by_field_name("constructor")
        if callee is None:
            return "flow"
        if callee.type == "identifier":
            receiver, name = "", _text(callee)
        elif callee.type == "member_expression":
            receiver = _text(callee.child_by_field_name("object"))
            name = _text(callee.child_by_field_name("property"))
        else:
            return "flow"
        name = name.rstrip("0123456789")  # bundlers number imports: `renameSync2`
        if receiver and (name in _CONTAINER_METHODS or (name == "set" and index == 1)):
            return "container"
        if _OUTPUT_OBJECT.search(receiver) or name in _CONTENT_WRITES:
            return "stop"
        if name in DESTINATION_FIRST:
            return "write" if index == 0 else "stop"
        if name in DESTINATION_SECOND:
            return "write" if index == 1 else "stop"
        if name in ("open", "openSync"):
            flags = _argument_text(call, 1)
            return "write" if index == 0 and re.search(r"[\"'`][^\"'`]*[wa+]", flags) else "stop"
        if name in RUNNERS and (not receiver or _CHILD.search(receiver)):
            return "write" if _runs_writer(call, name, index) else "stop"
        if self.defined(name):
            self.bind_parameter(name, index)
            return "stop"
        words = [w.lower() for w in re.findall(r"[a-z]+|[A-Z][a-z]*", name)]
        if not words:
            return "flow"
        if name in _READ_NAMES or words[0] in READ_WORDS:
            return "stop"
        if len(words) == 1 and words[0] in _ONE_WORD_NOT_WRITES:
            return "stop"
        if set(words) & WRITE_WORDS:
            return "write"
        return "stop" if set(words) & READ_WORDS else "flow"

    # Bindings: a name the value is given, and every use of it.

    def assign(self, path: str, left: ts.Node | None) -> None:
        if left is None:
            return
        if left.type == "identifier":
            self.bind(path, _text(left), self.root(path))
        elif left.type in ("member_expression", "subscript_expression"):
            key = left.child_by_field_name("property") or left.child_by_field_name("index")
            self.bind_property(_text(key).strip("\"'`"))
        else:
            self.bind_pattern(path, left, self.root(path))

    def bind_pattern(self, path: str, pattern: ts.Node | None, scope: ts.Node | None) -> None:
        stack = [pattern] if pattern is not None else []
        while stack:
            node = stack.pop()
            if node.type in ("identifier", "shorthand_property_identifier_pattern"):
                self.bind(path, _text(node), scope)
            else:
                stack.extend(node.named_children)

    def bind(self, path: str, name: str, scope: ts.Node | None) -> None:
        """Every use of `name` in `scope`: a top-level name in every file."""
        scope = scope if scope is not None else self.root(path)
        top = scope.type == "program"
        key = (name, "" if top else path, scope.start_byte, scope.end_byte)
        if top:
            key = (name, "", 0, 0)
        if key in self.bound or not _NAME.fullmatch(name):
            return
        self.bound.add(key)
        where = [(p, self.root(p)) for p in sorted(self.files)] if top else [(path, scope)]
        for file, region in where:
            for ref in self.references(file, name, region):
                if ref.type in ("identifier", "shorthand_property_identifier") and not (
                    _declaration(ref)
                ):
                    self.push(file, ref)

    def bind_property(self, name: str) -> None:
        """Every read of the property `name` (`x.name`), in every file; a destructuring of
        it binds that variable."""
        key = ("." + name, "", 0, 0)
        if key in self.bound or not _NAME.fullmatch(name):
            return
        self.bound.add(key)
        for file in sorted(self.files):
            for ref in self.references(file, name, self.root(file)):
                parent = ref.parent
                if (
                    ref.type == "property_identifier"
                    and parent is not None
                    and parent.type == "member_expression"
                    and parent.child_by_field_name("property") == ref
                    and not _assigned_to(parent)
                ):
                    self.push(file, parent)
                elif ref.type == "shorthand_property_identifier_pattern":
                    self.bind(file, name, _scope_node(ref))

    def bind_function(self, name: str) -> None:
        """Every call of the function `name` returns the value; so does the function handed
        on as a value (`(options.dirs ?? defaultDirs)(name)`)."""
        key = (name + "()", "", 0, 0)
        if key in self.bound or not _NAME.fullmatch(name):
            return
        self.bound.add(key)
        for file in sorted(self.files):
            for ref in self.references(file, name, self.root(file)):
                node = ref
                if ref.type == "property_identifier" and ref.parent is not None:
                    node = ref.parent
                elif ref.type != "identifier" or _declaration(ref):
                    continue
                parent = node.parent
                if parent is not None and parent.type == "call_expression":
                    if parent.child_by_field_name("function") == node:
                        self.push(file, parent)
                elif node.type == "identifier":
                    self.push(file, node)

    def bind_parameter(self, name: str, index: int) -> None:
        if index < 0 or not self.defined(name) or self.functions is None:
            return
        for file, function in self.functions.get(name, []):
            parameter = _parameter(function, index)
            if parameter is not None:
                self.bind_pattern(file, parameter, function)

    def fill_container(self, path: str, call: ts.Node) -> None:
        """`list.push(x)`: `list` holds the value; when `list` is a parameter, so does the
        caller's argument."""
        callee = call.child_by_field_name("function")
        receiver = callee.child_by_field_name("object") if callee is not None else None
        while receiver is not None and receiver.type == "parenthesized_expression":
            receiver = receiver.named_children[0] if receiver.named_children else None
        if receiver is None:
            return
        if receiver.type == "member_expression":
            self.bind_property(_text(receiver.child_by_field_name("property")))
            return
        if receiver.type != "identifier":
            return
        name = _text(receiver)
        scope = _declaring_scope(receiver, name)
        self.bind(path, name, scope)
        if scope is None or scope.type not in _FUNCTIONS:
            return
        function = _function_name(scope)
        names = [_parameter_name(scope, i) for i in range(_parameter_count(scope))]
        if function and name in names:
            self.fill_arguments(function, names.index(name))

    def fill_arguments(self, function: str, index: int) -> None:
        for file in sorted(self.files):
            for ref in self.references(file, function, self.root(file)):
                node = ref.parent if ref.type == "property_identifier" else ref
                call = node.parent if node is not None else None
                if call is None or call.type != "call_expression":
                    continue
                if call.child_by_field_name("function") != node:
                    continue
                argument = _argument(call, index)
                if argument is not None and argument.type == "identifier":
                    name = _text(argument)
                    self.bind(file, name, _declaring_scope(argument, name))

    def references(self, path: str, name: str, region: ts.Node) -> list[ts.Node]:
        """The nodes `name` occurs as in `region` (searched in the text: a query over every
        identifier of a large bundle is slow); at most MAX_REFERENCES, else the analysis
        gives up."""
        content = self.files[path][0]
        word = re.compile(rb"(?<![\w$])" + re.escape(name.encode()) + rb"(?![\w$])")
        found = []
        for count, match in enumerate(word.finditer(content, region.start_byte, region.end_byte)):
            if count >= MAX_REFERENCES:
                self.gave_up = True
                break
            node = region.descendant_for_byte_range(match.start(), match.end())
            if node is not None:
                found.append(node)
        return found

    def defined(self, name: str) -> bool:
        """`name` is a function the install files define (its parameters can be followed)."""
        if self.functions is None:
            self.functions = {}
            for file in sorted(self.files):
                stack = [self.root(file)]
                while stack:
                    node = stack.pop()
                    if node.type in _FUNCTIONS and (own := _function_name(node)):
                        self.functions.setdefault(own, []).append((file, node))
                    stack.extend(node.named_children)
        return name in self.functions


def _runs_writer(call: ts.Node, name: str, index: int) -> bool:
    """A runner given the value runs a command that writes it: as part of a shell command
    string (`execSync(\\`cp -r x ${dest}\\`)`), or in the argument list of a writing program
    (`spawnSync("cp", ["-r", x, dest])`)."""
    if index == 0 and name in SHELL_RUNNERS:
        return bool(WRITER_COMMAND.search(_argument_text(call, 0)))
    if index == 1 and name not in SHELL_RUNNERS:
        command = _argument_text(call, 0).strip("\"'`")
        return bool(WRITER_COMMAND.search(command + " " + _argument_text(call, 1)))
    return False


def _opted_in(node: ts.Node) -> bool:
    """`node` runs only inside `if (process.env.X === "1") { ... }` in its function: a switch
    the user sets on purpose (npm's own `npm_config_*` and `npm_lifecycle_*` don't count)."""
    current: ts.Node | None = node
    while current is not None and (parent := current.parent) is not None:
        if (
            parent.type == "if_statement"
            and parent.child_by_field_name("consequence") == current
            and _env_opt_in(parent.child_by_field_name("condition"))
        ):
            return True
        if parent.type in _FUNCTIONS:
            return False
        current = parent
    return False


def _env_opt_in(condition: ts.Node | None) -> bool:
    while condition is not None and condition.type == "parenthesized_expression":
        condition = condition.named_children[0] if condition.named_children else None
    if condition is None or condition.type != "binary_expression":
        return False
    if _text(condition.child_by_field_name("operator")) == "&&":
        return _env_opt_in(condition.child_by_field_name("left")) or _env_opt_in(
            condition.child_by_field_name("right")
        )
    match = _OPT_IN.match(" ".join(_text(condition).split()))
    if match is None:
        return False
    variable = next(group for group in match.groups() if group)
    return not variable.lower().startswith("npm_")


def _declaration(ref: ts.Node) -> bool:
    """`ref` is where a name is declared (a variable, an assignment's target, a function's
    name, a parameter), not a use."""
    parent = ref.parent
    if parent is None:
        return False
    if parent.type == "variable_declarator":
        return parent.child_by_field_name("name") == ref
    if parent.type == "assignment_expression":
        return parent.child_by_field_name("left") == ref
    if parent.type in _FUNCTIONS:
        return parent.child_by_field_name("name") == ref
    return parent.type in _PARAMETER_PARENTS


def _assigned_to(member: ts.Node) -> bool:
    parent = member.parent
    return (
        parent is not None
        and parent.type == "assignment_expression"
        and parent.child_by_field_name("left") == member
    )


def _declaring_scope(ref: ts.Node, name: str) -> ts.Node | None:
    """The innermost function around `ref` that declares `name` (a parameter or a `const`,
    `let` or `var`), else the file."""
    scope = _scope_node(ref)
    word = re.escape(name) + r"(?![\w$])"
    while scope is not None and scope.type != "program":
        parameters = scope.child_by_field_name("parameters")
        if parameters is not None and re.search(r"(?<![\w$])" + word, _text(parameters)):
            return scope
        body = scope.child_by_field_name("body")
        if body is not None and re.search(r"\b(?:const|let|var)\s+" + word, _text(body)):
            return scope
        scope = _scope_node(scope)
    return scope


def _parameters(function: ts.Node) -> list[ts.Node]:
    parameters = function.child_by_field_name("parameters")
    if parameters is None:
        return []
    return [c for c in parameters.named_children if c.type != "comment"]


def _parameter_count(function: ts.Node) -> int:
    return len(_parameters(function))


def _parameter(function: ts.Node, index: int) -> ts.Node | None:
    given = _parameters(function)
    if index >= len(given):
        return None
    parameter = given[index]
    if parameter.type == "assignment_pattern":
        return parameter.child_by_field_name("left")
    if parameter.type in ("required_parameter", "optional_parameter"):
        return parameter.child_by_field_name("pattern")
    return parameter


def _parameter_name(function: ts.Node, index: int) -> str:
    parameter = _parameter(function, index)
    return _text(parameter) if parameter is not None else ""


def _argument(call: ts.Node, index: int) -> ts.Node | None:
    arguments = call.child_by_field_name("arguments")
    if arguments is None:
        return None
    given = [c for c in arguments.named_children if c.type != "comment"]
    return given[index] if 0 <= index < len(given) else None


def _argument_text(call: ts.Node, index: int) -> str:
    return _text(_argument(call, index))


# A program the install code runs with an installer subcommand, whose code the analysis
# doesn't have (`unfollowed_installer`).
_INSTALLER_ARGUMENT: Final = re.compile(
    r"^(?:--?)?(?:install|setup|configure(?:-[\w-]+)?|register)$"
)
_RUNS_PROGRAM: Final = re.compile(
    rb"\b(?:spawn|spawnSync|execFile|execFileSync|fork|execa)\w*\s*\("
)
_NODE: Final = re.compile(r"^(?:process\s*\.\s*execPath|[\"'`]node(?:\.exe)?[\"'`])$")
_SCRIPT_NAME: Final = re.compile(r"[\"'`]([^\"'`]*\.[cm]?js)[\"'`]")
_PROGRAM_RUNNERS: Final = frozenset(
    {"spawn", "spawnSync", "execFile", "execFileSync", "fork", "execa", "execaSync"}
)


def unfollowed_installer(files: Mapping[str, tuple[bytes, str]]) -> Write | None:
    """A call that runs a program with an installer subcommand in its argument list
    (`spawn(process.execPath, [cli, "install"])`, `spawnSync(bin, ["--configure-clients"])`)
    when that program's code is not among `files`: a native binary, or a package script the
    install files don't include. A literal program other than node (`npm`, `git`, `cmd.exe`)
    is a tool, not the package's installer; a package script that is in `files` is
    followed by `reaches_write` instead."""
    basenames = {path.rsplit("/", 1)[-1] for path in files}
    for path in sorted(files):
        content, language = files[path]
        if not _RUNS_PROGRAM.search(content):
            continue
        parser, _ = _parser(language)
        root = parser.parse(content).root_node
        stack = [root]
        while stack:
            node = stack.pop()
            stack.extend(node.named_children)
            if node.type == "call_expression" and (found := _installer(node, root, basenames)):
                return Write(path=path, offset=node.start_byte, text=found)
    return None


def _installer(call: ts.Node, root: ts.Node, basenames: set[str]) -> str | None:
    name = _text(call.child_by_field_name("function")).rsplit(".", 1)[-1]
    if name not in _PROGRAM_RUNNERS:
        return None
    program = _argument(call, 0)
    arguments = program if name == "fork" else _argument(call, 1)
    if program is None or arguments is None:
        return None
    node = _NODE.match(" ".join(_text(program).split())) is not None
    if program.type in ("string", "template_string") and not node:
        return None
    array = arguments if arguments.type == "array" else _declared_array(root, arguments)
    if array is None:
        return None
    words = [_text(e).strip("\"'`") for e in array.named_children if e.type == "string"]
    if not any(_INSTALLER_ARGUMENT.match(w) for w in words):
        return None
    if (node or name == "fork") and array.named_children:
        script = _named_script(root, array.named_children[0])
        if script is not None and script in basenames:
            return None
    return _text(call)


def _declared_array(root: ts.Node, ident: ts.Node) -> ts.Node | None:
    value = _declared_value(root, ident)
    return value if value is not None and value.type == "array" else None


def _declared_value(root: ts.Node, ident: ts.Node) -> ts.Node | None:
    if ident.type != "identifier":
        return None
    name = _text(ident)
    stack = [root]
    while stack:
        node = stack.pop()
        stack.extend(node.named_children)
        if node.type == "variable_declarator" and _text(node.child_by_field_name("name")) == name:
            return node.child_by_field_name("value")
    return None


def _named_script(root: ts.Node, node: ts.Node) -> str | None:
    """The basename of the script an expression names (its last string ending in `.js`,
    `.cjs` or `.mjs`), also through the variable it is declared from."""
    value = _declared_value(root, node) if node.type == "identifier" else node
    found = _SCRIPT_NAME.findall(_text(value))
    return found[-1].rsplit("/", 1)[-1] if found else None
