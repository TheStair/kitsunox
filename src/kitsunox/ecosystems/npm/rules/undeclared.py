"""Code that loading a package runs loads a package the release doesn't declare (Stage 3, npm).

A package a file loads by name (`require("x")`, `import ... from "x"`) must be installed with
it, so it has to be in `dependencies`, `peerDependencies`, `optionalDependencies` or
`bundleDependencies`, or be shipped under the tarball's own `node_modules/`. A name that is
none of those resolves only if something else installs it. The Tailwind-wrapper campaign
(2026-11-01/02: `tailwind-animate-engine@1.0.6`, `tailwind-animate-final`,
`tailwind-animate-test`) required its payload, `@unipswap/postcss-animate-units`, without
declaring it: the payload package was published later, so the wrapper reviewed clean while it
waited for it. Stage 4's `npm.dependency.missing` covers the declared case, and
`npm.undeclared.missing` asks the registry about the names this rule gives.

Version 2 counts only what loading the package runs: packages loaded at module load
(`PackageLoad.at_load`: not in a `try`, not deferred inside a function) by its entry points
or the package files they load (`CodeChange.load`, `ecosystems.npm.entry.load_sources`). A
name listed only in `devDependencies` still counts: npm doesn't install those for a user
either, and on the live runs measured (`docs/stages/ast.md`) leaving them out removed no
name the registry lacked. On updates only names the previous version's code didn't load
count.

INFO (weight 0): it scores nothing and reports nothing on its own; it names the packages for
the reviewer and for Stage 4's registry lookup, one evidence item per package (at most
`MAX_EVIDENCE`, in the form `undeclared_names` reads). Version 1 (every file, deferred loads
too) fired on 700-1,150 benign releases a day; measured numbers for version 2 are in
`docs/stages/ast.md`.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Final

from kitsunox.core.models import Evidence, EvidenceKind, Finding, Severity
from kitsunox.core.rules import BaseRule
from kitsunox.lang.javascript import package_name
from kitsunox.stages.ast import CodeChange, PathPackage

DECLARING_SECTIONS: Final = ("dependencies", "peerDependencies", "optionalDependencies")
BUNDLE_SECTIONS: Final = ("bundleDependencies", "bundledDependencies")
MAX_EVIDENCE: Final = 10  # packages named as evidence (and so looked up by Stage 4)
# The evidence snippet: `[<package>] <source>`. The package name is ours (`package_name`
# accepted it), the source is the package's.
_EVIDENCE: Final = re.compile(r"\[([^\]\s]+)\] ")


def declared_packages(manifest: Mapping[str, object]) -> frozenset[str]:
    """Every package the manifest installs or expects next to it, and its own name."""
    names: set[str] = set()
    for section in (*DECLARING_SECTIONS, *BUNDLE_SECTIONS):
        listed = manifest.get(section)
        if isinstance(listed, Mapping | list):  # bundleDependencies is a list
            names.update(name for name in listed if isinstance(name, str))
    if isinstance(own := manifest.get("name"), str):
        names.add(own)
    return frozenset(names)


def undeclared(change: CodeChange) -> tuple[PathPackage, ...]:
    """Packages that loading this version loads at module load (`CodeChange.load`), that it
    neither declares nor ships, and that the previous
    version's code didn't load already."""
    if change.load is None:
        return ()
    known = declared_packages(change.snapshot.manifest) | change.after.bundled
    before = {p.load.name for p in change.before.packages} if change.before else set()
    found: dict[str, PathPackage] = {}
    for package in change.load.packages:
        name = package.load.name
        if not package.load.at_load or name in known or name in before:
            continue
        found.setdefault(name, package)
    return tuple(found.values())


def undeclared_evidence(finding: Finding) -> tuple[tuple[str, Evidence], ...]:
    """Each package an `npm.undeclared-package` finding names, once, with its evidence."""
    found: dict[str, Evidence] = {}
    for evidence in finding.evidence:
        match = _EVIDENCE.match(evidence.snippet or "")
        if match is not None and package_name(name := match.group(1)) == name:
            found.setdefault(name, evidence)
    return tuple(found.items())


def undeclared_names(finding: Finding) -> tuple[str, ...]:
    """The packages an `npm.undeclared-package` finding names, from its evidence."""
    return tuple(name for name, _ in undeclared_evidence(finding))


class UndeclaredPackage(BaseRule):
    """Loading this version loads a package it doesn't declare."""

    id = "npm.undeclared-package"
    version = 2
    severity = Severity.INFO
    weight = 0.0
    title = "Loads a package it doesn't declare"

    def evaluate_code(self, change: CodeChange) -> Sequence[Finding]:
        packages = undeclared(change)
        if not packages:
            return ()
        names = ", ".join(sorted(p.load.name for p in packages))
        return (
            self.finding(
                f"Loading this version loads {names} (at module load, from its entry points or "
                "the files they load), which its package.json does not declare (dependencies, "
                "peerDependencies, optionalDependencies or bundleDependencies; devDependencies "
                "are not installed for users) and which it does not ship under node_modules/. "
                "Installed alone it fails; what that name runs depends on whatever gets "
                "published under it.",
                *(
                    Evidence(
                        kind=EvidenceKind.FILE_SPAN,
                        path=p.path,
                        line_start=p.load.line,
                        line_end=p.load.line,
                        snippet=f"[{p.load.name}] {p.load.snippet}",
                    )
                    for p in packages[:MAX_EVIDENCE]
                ),
            ),
        )


RULES: Final = (UndeclaredPackage(),)
