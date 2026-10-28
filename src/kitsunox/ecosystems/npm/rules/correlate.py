"""Stage 4 rules for npm: release provenance and known-malware dependencies.

Numbers are from `day1` (2026-10-28; "updates" are shape-A first releases, DataDog for
malicious). See `docs/stages/correlate.md`.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from kitsunox.core.models import Candidate, Change, Evidence, EvidenceKind, Finding, Severity
from kitsunox.core.rules import BaseRule
from kitsunox.ecosystems.npm import semver
from kitsunox.ecosystems.npm.rules.metadata import runtime_dependencies
from kitsunox.stages.correlate import CorrelationContext

DEFINITELY_TYPED: Final = "types"  # the npm account that publishes `@types/*`


class GitHeadDropped(BaseRule):
    """The previous release recorded the commit it was built from (`gitHead`) and this one
    doesn't: it was not published from a git checkout. npm records `gitHead` when `npm publish`
    runs in a git working tree, so its loss is typical of a stolen token used to publish a
    hand-edited tarball.

    | Updates | Benign | Malicious |
    |---|---|---|
    | previous had `gitHead`, this one lacks it | 0.4% | 46.5% |

    Most of those malicious releases are flagged anyway; on its own this is corroboration, so
    it is weighted below the report score.
    """

    id = "npm.provenance.githead-dropped"
    severity = Severity.LOW
    weight = 2.0
    title = "Published without the git commit the previous release recorded"

    def evaluate_candidate(
        self, candidate: Candidate, ctx: CorrelationContext
    ) -> Sequence[Finding]:
        change = candidate.change
        if change.previous is None:
            return ()
        before = change.previous.publish.git_head
        if before is None or change.new.publish.git_head is not None:
            return ()
        return (
            self.finding(
                f"{change.previous.ref.version} was published from commit {before[:12]}; this "
                "release records no commit, so it was not published from a git checkout.",
                Evidence(kind=EvidenceKind.METADATA, path="gitHead", before=before, after=None),
            ),
        )


def _dependency_name(name: str, spec: str) -> str:
    """The package npm installs: the alias target for `"x": "npm:evil@1.0.0"`."""
    if not spec.startswith("npm:"):
        return name
    target = spec.removeprefix("npm:")
    at = target.rfind("@")
    return target[:at] if at > 0 else target


class KnownMalwareDependency(BaseRule):
    """The release adds a dependency that an OSV `MAL-` record, published by the run's
    `as_of`, calls malware in every version. Only whole-package records count (see
    `LabelSet.known_malware`). On `day1`: 11 of 905 malicious new packages, no benign sample."""

    id = "npm.dependency.known-malware"
    severity = Severity.HIGH
    weight = 5.0
    title = "Depends on a known-malicious package"

    def evaluate_candidate(
        self, candidate: Candidate, ctx: CorrelationContext
    ) -> Sequence[Finding]:
        if ctx.known_bad is None:
            return ()
        change = candidate.change
        own = change.new.ref.name
        old = runtime_dependencies(change.previous.manifest) if change.previous else {}
        findings = []
        for name, spec in sorted(runtime_dependencies(change.new.manifest).items()):
            if old.get(name) == spec:
                continue
            target = _dependency_name(name, spec)
            records = ctx.known_bad.known_malware(target, ctx.as_of) if target != own else ()
            if records:
                findings.append(
                    self.finding(
                        f"Depends on `{target}`, which {', '.join(records[:3])} "
                        "lists as malware in every version.",
                        Evidence(
                            kind=EvidenceKind.MANIFEST_FIELD,
                            path=f"package.json:dependencies.{name}",
                            after=f"{name}: {spec}"[:300],
                        ),
                    )
                )
        return findings


def _definitely_typed(change: Change) -> bool:
    publishers = {change.new.publish.publisher}
    if change.previous is not None:
        publishers.add(change.previous.publish.publisher)
    return change.new.ref.name.startswith("@types/") and publishers == {DEFINITELY_TYPED}


class RevivedWithNewDependency(BaseRule):
    """A package dormant for a long time (`npm.dormant-revived`) comes back with a new runtime
    dependency (`npm.dependency.added`). Each is common alone; together they are the shape of
    a takeover that pulls its payload in through a dependency.

    Prereleases are skipped: a `canary`/`experimental`/`pr-` channel can sit unused for years,
    so its next build is "revived", and new builds add dependencies. On `day1` all 3 benign
    updates this reported end to end were such builds; the malicious ones were all releases.
    DefinitelyTyped's `@types/*` packages are skipped when the `types` account published both
    versions: its bot republishes long-idle type packages, and they add dependencies (4 in one
    live hour on 2026-10-28; none carry provenance to tell them apart otherwise). Abusing that
    takes DefinitelyTyped's own publishing token.
    Caveat: the malicious ones are two campaigns (`@antv/*` and `@mastra/*` in the Shai-Hulud
    wave), so the recall figure says more about them than about takeovers in general.
    """

    id = "npm.combination.revived-with-new-dependency"
    severity = Severity.MEDIUM
    weight = 2.0
    title = "Dormant package revived with a new dependency"

    def evaluate_candidate(
        self, candidate: Candidate, ctx: CorrelationContext
    ) -> Sequence[Finding]:
        change = candidate.change
        version = semver.parse(change.new.ref.version)
        if version is None or version.is_prerelease or _definitely_typed(change):
            return ()
        fired = {f.rule_id: f for f in candidate.findings}
        revived, added = fired.get("npm.dormant-revived"), fired.get("npm.dependency.added")
        if revived is None or added is None:
            return ()
        return (
            self.finding(
                f"{revived.explanation} {added.explanation}",
                *revived.evidence,
                *added.evidence,
            ),
        )


RULES: Final = (GitHeadDropped(), KnownMalwareDependency(), RevivedWithNewDependency())
