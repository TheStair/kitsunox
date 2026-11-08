"""Code that loads a package the release doesn't declare (Stage 3, npm).

A package a file loads by name (`require("x")`, `import ... from "x"`) must be installed with
it, so it has to be in `dependencies`, `peerDependencies`, `optionalDependencies` or
`bundleDependencies`, or be shipped under the tarball's own `node_modules/`. A name that is
none of those resolves only if something else installs it. The Tailwind-wrapper campaign
(2026-11-01/02: `tailwind-animate-engine@1.0.6`, `tailwind-animate-final`,
`tailwind-animate-test`) required its payload, `@unipswap/postcss-animate-units`, without
declaring it: the payload package was published later, so the wrapper reviewed clean while it
waited for it. Stage 4's `npm.dependency.missing` covers the declared case.

INFO (weight 0): it scores nothing and reports nothing on its own; it names the package for
the reviewer, and for a lookup that could tell whether the name exists. Measured 2026-11-08
on the live versions Stage 3 read (32,272: two full runs, 15.5 hours, and a 1-in-10 sample of
a 4-day run), it fires on far too many benign releases to be MEDIUM: 700-1,150 a day that
nothing else reports (React plugins whose host provides `react`, `vscode` extensions,
TypeScript sources and scaffolding templates shipped beside the build, path aliases such as
`@shared/x`). Leaving out devDependencies, test/example/template paths and declaration files
still leaves 450-560 a day; also requiring a scoped name of another scope, 60-130. In
`vm-day1` it fires on 64 of 1,500 benign samples. Only the names npm did not have when
measured (570 of 3,008) narrow it to about 8 a day in the full runs and 47 in the sample, and
that needs a registry lookup at the release's time: Stage 4's.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Final

from kitsunox.core.models import Evidence, EvidenceKind, Finding, Severity
from kitsunox.core.rules import BaseRule
from kitsunox.stages.ast import CodeChange, PathPackage

DECLARING_SECTIONS: Final = ("dependencies", "peerDependencies", "optionalDependencies")
BUNDLE_SECTIONS: Final = ("bundleDependencies", "bundledDependencies")
MAX_EVIDENCE: Final = 3


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
    """Packages this version's own files load outside a `try`, that it neither declares nor
    ships, and that the previous version's code didn't load already."""
    known = declared_packages(change.snapshot.manifest) | change.after.bundled
    before = {p.load.name for p in change.before.packages} if change.before else set()
    found: dict[str, PathPackage] = {}
    for package in change.after.packages:
        name = package.load.name
        if package.load.guarded or name in known or name in before:
            continue
        found.setdefault(name, package)
    return tuple(found.values())


class UndeclaredPackage(BaseRule):
    """This version's code loads a package it doesn't declare."""

    id = "npm.undeclared-package"
    version = 1
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
                f"This version's code loads {names}, which its package.json does not declare "
                "(dependencies, peerDependencies, optionalDependencies or bundleDependencies) "
                "and which it does not ship under node_modules/. Installed alone it fails; "
                "what that name runs depends on whatever gets published under it.",
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
