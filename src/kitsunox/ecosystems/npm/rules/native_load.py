"""Stage 2 npm artifact rule: a bundled native addon loaded where nothing may notice it fail
or what it does.

A `.node` file is a compiled shared library: `require("./x.node")` makes Node `dlopen` it,
which runs its initialiser with the user's rights. No JavaScript rule can read it. Packages
that ship addons legitimately build them (`binding.gyp`, which npm turns into
`node-gyp rebuild`) or ship prebuilt binaries in a known layout (`prebuilds/` for
`node-gyp-build`, `prebuild-install`, `node-pre-gyp`'s `binary` field), and their loaders use
what the addon exports and report when it is missing.

`strutil-helpers-core` 1.0.1 (OSV-labelled, 2026-11-01) was "string utility helpers" whose
`index.js` began with `try{ ...require('./native_win.node') ... require('./native.napi.node')
}catch(_){}`: two bundled addons (and a 3.7 MB opaque blob beside them), loaded at the top of
the entry file for their side effects alone, any failure swallowed, with no build files.
Stage 3's `code.capability-gained` (LOW) was all that fired (round 11,
`docs/proposals/gap-fixes-round11-N1.md`, P6).

The rule fires when a file that loading or installing the package runs (npm's
`load_sources`, `install_sources`) requires a `.node` file the package ships, by a relative
path, as a statement of its own (what the addon exports is not used: it is loaded for what
loading it does), inside a `try` block whose `catch` is empty (comments only), and the
package has no
build or prebuilt-binary files: no `binding.gyp`, no `prebuilds/` directory, no `gypfile` or
`binary` field and no dependency on a prebuilt-binary loader (`BINARY_LOADERS`). A plain
`.node` require with no build files is common (agent M counted 117 in a random 25,000 live
tarballs: platform packages and their loaders), and so is one in a `try` that handles the
failure (`catch (e) { loadError = e }`, napi-rs's loaders). An optional addon whose
failure is swallowed on purpose keeps what it loads (`dsh-needs-you-mac` 0.2.0: `const addon =
require('./native/dsh_notify.node')` in a `try` whose `catch` only has a comment, live); a
load whose exports nothing takes, with any failure swallowed, is the shape. MEDIUM, weight 3.
"""

from __future__ import annotations

import json
import posixpath
from collections.abc import Iterator, Mapping, Sequence
from typing import Final

import tree_sitter as ts

from kitsunox.core.models import Evidence, EvidenceKind, Finding, Severity, VersionSnapshot
from kitsunox.core.rules import BaseRule
from kitsunox.ecosystems.npm.entry import load_sources
from kitsunox.ecosystems.npm.install import install_sources
from kitsunox.lang.javascript import MAX_SOURCE_BYTES, _parser, fold_string, language_for

MAX_SHOWN: Final = 3
SNIPPET_CHARS: Final = 160
BINARY_LOADERS: Final = frozenset(
    {
        "node-gyp-build",
        "node-gyp-build-optional-packages",
        "prebuild-install",
        "node-pre-gyp",
        "@mapbox/node-pre-gyp",
        "@discordjs/node-pre-gyp",
        "bindings",
        "pkg-prebuilds",
        "cmake-js",
    }
)
_DEPENDENCY_FIELDS: Final = ("dependencies", "optionalDependencies", "peerDependencies")


def build_files(files: Mapping[str, bytes]) -> bool:
    """Whether the package builds its addons or ships them in a prebuilt-binary layout."""
    if any(
        p == "binding.gyp"
        or p.endswith("/binding.gyp")
        or p.startswith("prebuilds/")
        or "/prebuilds/" in p
        for p in files
    ):
        return True
    try:
        manifest = json.loads(files.get("package.json", b"{}"))
    except ValueError:
        return False
    if not isinstance(manifest, dict):
        return False
    if manifest.get("gypfile") or "binary" in manifest:
        return True
    for field in _DEPENDENCY_FIELDS:
        dependencies = manifest.get(field)
        if isinstance(dependencies, dict) and BINARY_LOADERS & set(dependencies):
            return True
    return False


def _swallowed(node: ts.Node) -> bool:
    """`node` is inside the `try` block of a `try` whose `catch` block is empty or only has
    comments (the nearest such `try`; a function between them does not count)."""
    child, parent = node, node.parent
    while parent is not None:
        if parent.type in ("function_declaration", "function_expression", "arrow_function"):
            return False
        if parent.type == "try_statement" and parent.child_by_field_name("body") == child:
            handler = parent.child_by_field_name("handler")
            body = handler.child_by_field_name("body") if handler is not None else None
            return body is not None and all(c.type == "comment" for c in body.named_children)
        child, parent = parent, parent.parent
    return False


def _discarded(node: ts.Node) -> bool:
    """`node`'s value is not used: the call is a statement of its own (`require(x);`, also
    as an `if`/`else` branch)."""
    parent = node.parent
    while parent is not None and parent.type == "parenthesized_expression":
        parent = parent.parent
    return parent is not None and parent.type == "expression_statement"


def swallowed_native_loads(
    path: str, content: bytes, files: Mapping[str, bytes]
) -> Iterator[tuple[int, str, str]]:
    """Each `require("./x.node")` in `path` of a shipped file, as a statement of its own
    inside a `try` with an empty `catch`: (line, the addon's package path, snippet)."""
    language = language_for(path)
    if language is None or b".node" not in content or len(content) > MAX_SOURCE_BYTES:
        return
    parser, _ = _parser(language)
    stack = [parser.parse(content).root_node]
    while stack:
        node = stack.pop()
        stack.extend(reversed(node.children))
        if node.type != "call_expression":
            continue
        callee = node.child_by_field_name("function")
        if callee is None or callee.type != "identifier" or callee.text != b"require":
            continue
        arguments = node.child_by_field_name("arguments")
        first = arguments.named_children[0] if arguments and arguments.named_children else None
        specifier = fold_string(first)
        if specifier is None or not specifier.endswith(".node"):
            continue
        if not specifier.startswith(("./", "../")):
            continue
        target = posixpath.normpath(posixpath.join(posixpath.dirname(path), specifier))
        if target not in files or not _discarded(node) or not _swallowed(node):
            continue
        text = content[node.start_byte : node.end_byte].decode("utf-8", "replace")
        yield node.start_point[0] + 1, target, " ".join(text.split())[:SNIPPET_CHARS]


class SilentNativeLoad(BaseRule):
    """Code the package runs loads a bundled `.node` addon with every failure swallowed, and
    nothing in the package builds or lays out prebuilt addons (module docstring)."""

    id = "static.silent-native-load"
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Loads a bundled native addon and swallows any failure"

    def evaluate_artifact(
        self, snapshot: VersionSnapshot, files: Mapping[str, bytes]
    ) -> Sequence[Finding]:
        if not any(p.endswith(".node") for p in files) or build_files(files):
            return ()
        sources = load_sources(files) | install_sources(files)
        evidence: list[Evidence] = []
        addons: list[str] = []
        for path in sorted(sources):
            if path not in files:  # inline hook code: never `require`s a package `.node`
                continue
            for line, addon, snippet in swallowed_native_loads(path, files[path], files):
                if addon not in addons:
                    addons.append(addon)
                evidence.append(
                    Evidence(
                        kind=EvidenceKind.FILE_SPAN,
                        path=path,
                        line_start=line,
                        line_end=line,
                        snippet=snippet,
                    )
                )
        if not evidence:
            return ()
        return (
            self.finding(
                "Code that loading or installing the package runs loads the bundled native "
                "addon"
                + ("s " if len(addons) > 1 else " ")
                + ", ".join(f"`{a}`" for a in addons[:MAX_SHOWN])
                + " for what loading does (its exports unused), inside a `try` whose `catch` "
                "is empty, and nothing in the package builds "
                "it or ships it as a prebuilt binary (no `binding.gyp`, `prebuilds/` or "
                "prebuilt-binary loader): compiled code no rule can read runs when the "
                "package loads, and nothing reports if it fails.",
                *evidence[:MAX_SHOWN],
            ),
        )


RULES: Final = (SilentNativeLoad(),)
