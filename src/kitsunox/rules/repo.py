"""Stage 4 rules over the tarball-vs-repo comparison (`stages/repo.py`), ecosystem-agnostic.

Severities and weights come from `day1` (2026-10-28; 965 malicious and 300 benign updates):

| | Malicious | Benign |
|---|---|---|
| comparable (repository + commit + archive) | 57 (5.9%) | 121 (40%) |
| `code-differs` or `code-not-in-repo` | 49 of 57 | 9 of 121 |
| ... and not already flagged by Stages 1-3 | 6, none watched | |

At 3% of all benign updates, MEDIUM would triple the pipeline's false positives, and the six
extra malicious updates aren't ones Stage 4 compares live (`wants_repo`). So both rules are
LOW: evidence in the report, and weight in the score that orders the review queue. Benign hits
were mostly generated files at the package root (`@girs/*` bindings, `index.cjs` bundles).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from kitsunox.core.models import Candidate, Evidence, EvidenceKind, Finding, Severity
from kitsunox.core.rules import BaseRule
from kitsunox.stages.correlate import CorrelationContext
from kitsunox.stages.repo import RepoComparison


def _where(comparison: RepoComparison) -> str:
    source = comparison.source
    if source is None:
        return "the repository"
    place = f"{source.repo}/{source.directory}" if source.directory else source.repo
    return f"{place} at {source.commit[:12]} ({source.how})"


class RepoCompared(BaseRule):
    """What the comparison found, or why there was none. Context for the reviewer; not scored."""

    id = "repo.compared"
    severity = Severity.INFO
    weight = 0.0
    title = "Compared with the source repository"

    def evaluate_candidate(
        self, candidate: Candidate, ctx: CorrelationContext
    ) -> Sequence[Finding]:
        comparison = ctx.repo
        if comparison is None:
            return ()
        if comparison.unavailable is not None:
            text = f"No comparison: {comparison.unavailable}."
        else:
            text = (
                f"{comparison.code_files} code files against {_where(comparison)}: "
                f"{comparison.identical} identical, {comparison.differing_count} different, "
                f"{comparison.not_in_repo_count} not in the repository."
            )
        return (
            self.finding(
                text,
                Evidence(
                    kind=EvidenceKind.METADATA,
                    path="repository",
                    after=comparison.source.model_dump_json() if comparison.source else None,
                ),
            ),
        )


class CodeDiffersFromRepo(BaseRule):
    """A code file the release ships is in the repository at the same path, at the release's
    commit, with different content. Build tools rarely rewrite a file in place, and a payload
    injected into a shipped source file shows here."""

    id = "repo.code-differs"
    severity = Severity.LOW
    weight = 2.0
    title = "Shipped code differs from the repository"

    def evaluate_candidate(
        self, candidate: Candidate, ctx: CorrelationContext
    ) -> Sequence[Finding]:
        comparison = ctx.repo
        if comparison is None or not comparison.differing_count:
            return ()
        return (
            self.finding(
                f"{comparison.differing_count} code files differ from {_where(comparison)}.",
                *(
                    Evidence(kind=EvidenceKind.FILE_SPAN, path=path)
                    for path in comparison.differing[:5]
                ),
            ),
        )


class CodeNotInRepo(BaseRule):
    """The release ships code files the repository doesn't have, in directories the repository
    does have, with nothing there they could have been compiled from (`compare_trees`). Build
    output in directories git ignores (`dist/`) doesn't count."""

    id = "repo.code-not-in-repo"
    severity = Severity.LOW
    weight = 2.0
    title = "Shipped code that the repository doesn't have"

    def evaluate_candidate(
        self, candidate: Candidate, ctx: CorrelationContext
    ) -> Sequence[Finding]:
        comparison = ctx.repo
        if comparison is None or not comparison.unexplained_count:
            return ()
        return (
            self.finding(
                f"{comparison.unexplained_count} code files are not in {_where(comparison)}, "
                "though their directories are, and no source file there could have been "
                "compiled to them.",
                *(
                    Evidence(kind=EvidenceKind.FILE_SPAN, path=path)
                    for path in comparison.unexplained[:5]
                ),
            ),
        )


RULES: Final = (RepoCompared(), CodeDiffersFromRepo(), CodeNotInRepo())
