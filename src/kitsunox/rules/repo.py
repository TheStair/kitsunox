"""Stage 4 rules over the tarball-vs-repo comparison (`stages/repo.py`), ecosystem-agnostic.

Severities and weights come from `day1` (2026-10-28; 965 malicious and 300 benign updates;
re-measured 2026-10-29 after `repo.compared` v2 found monorepo packages' own directories):

| | Malicious | Benign |
|---|---|---|
| comparable (repository + commit + archive) | 55 (5.7%) | 116 (39%) |
| `code-differs` or `code-not-in-repo` | 48 of 55 | 3 of 116 (v1: 9 of 121) |
| ... and not already flagged by Stages 1-3 (v1) | 6, none watched | |

At 3% of all benign updates (v1), MEDIUM would triple the pipeline's false positives, and the six
extra malicious updates aren't ones Stage 4 compares live (`wants_repo`). So both rules are
LOW: evidence in the report, and weight in the score that orders the review queue. Benign hits
were mostly generated files at the package root (`@girs/*` bindings, `index.cjs` bundles).
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import timedelta
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
    version = 2  # v2: a release without `repository.directory` is compared with its own manifest
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


# An established repository (measured 2026-11-04 on the live queue, 1,231 reported versions with
# a GitHub repository): clean matches to repositories that aren't forks and are at least 30 days
# old were 1 malicious and 90 benign verdicts; the malicious one (`@finzzcloud/baileys`) came
# from the attacker's own 1-star repository, and at 5 stars 34 of 34 reviewed were benign.
ESTABLISHED_AGE: Final = timedelta(days=30)
ESTABLISHED_STARS: Final = 5


class EstablishedMatch(BaseRule):
    """The release is exactly what an established repository holds at a commit on its default
    branch: every code file identical (`RepoComparison.clean`), and a repository that is not a
    fork or archived, was created at least `ESTABLISHED_AGE` before the release and has at
    least `ESTABLISHED_STARS` stars (when fetched). INFO and unscored: Stage 4's decision reads
    it (`stages/correlate.py`, `CLEARED_BY_REPO`) to not report install-code findings the
    repository explains.

    What this can't see: a malicious commit pushed into a real repository (a stolen maintainer
    account, a merged pull request) matches cleanly. That is the git path's job
    (`docs/proposals/git-path.md`, Phase B). Stars can be bought; 30 days of age and a commit
    on the default branch make that cost more than a throwaway account."""

    id = "repo.established-match"
    severity = Severity.INFO
    weight = 0.0
    title = "Matches an established repository"

    def evaluate_candidate(
        self, candidate: Candidate, ctx: CorrelationContext
    ) -> Sequence[Finding]:
        comparison = ctx.repo
        trust = comparison.trust if comparison is not None else None
        facts = trust.facts if trust is not None else None
        if comparison is None or trust is None or facts is None or not comparison.clean:
            return ()
        released = candidate.change.new.publish.published_at or ctx.as_of
        if (
            facts.fork
            or facts.archived
            or not trust.on_default_branch
            or facts.stars < ESTABLISHED_STARS
            or released - facts.created_at < ESTABLISHED_AGE
        ):
            return ()
        age = (released - facts.created_at).days
        return (
            self.finding(
                f"Every code file matches {_where(comparison)}, on its default branch "
                f"`{facts.default_branch}`; the repository is {age} days old at the release, "
                f"has {facts.stars} stars and is not a fork.",
                Evidence(
                    kind=EvidenceKind.METADATA,
                    path="repository",
                    after=facts.model_dump_json(),
                ),
            ),
        )


# How long after a release its tag's commit may have been made (measured 2026-11-06, decision
# 0018): of 815 live releases matched by a tag, the latest tag commit came 1.4 hours after the
# publish (release tools publish, then commit and tag); the malicious `vm-day1` updates whose
# tag commit postdates the publish came 7 hours to 255 days later.
COMMIT_AFTER_RELEASE: Final = timedelta(hours=6)


def _after_release(candidate: Candidate, comparison: RepoComparison) -> timedelta | None:
    """How long after the release its tag's commit was made, past `COMMIT_AFTER_RELEASE`. Not
    for a tag of the version alone (`v3.2.2`) on a package in a subdirectory: in a monorepo
    that may be another package's release (`@mongodb-js/mcp-atlas-telemetry@3.2.2` matched
    `mongodb-mcp-server`'s own `v3.2.2`, six days later)."""
    history = comparison.history
    source = comparison.source
    published = candidate.change.new.publish.published_at
    if source is None or history is None or history.commit_date is None or published is None:
        return None
    version = candidate.change.new.ref.version
    if source.directory and source.how.removeprefix("tag ") in (version, f"v{version}"):
        return None
    gap = history.commit_date - published
    return gap if gap > COMMIT_AFTER_RELEASE else None


class CommitAfterRelease(BaseRule):
    """The release's tag points to a commit made well after the release was published
    (`COMMIT_AFTER_RELEASE`): the release can't have been built from it, so whatever it
    shipped never went through git at that point, and the comparison was with the wrong
    commit. Seen when a stolen token published a release and the maintainers' own release of
    that version number came later (`@postman/tunnel-agent`, `zapier-platform-*`,
    `@asyncapi/*`).

    | | Malicious | Benign |
    |---|---|---|
    | `vm-day1` (`pipeline+4`, 2026-11-06) | 13 of 3,444 | 0 of 1,500 |
    | live tag-found releases (sample, 2026-11-06) | | 0 of 815 |

    All 13 are reported through other rules too. The monorepo exception cost two (`@posthog/
    rrweb-*`, bare `0.0.31` tags in `packages/`; reported anyway) and removed the one benign.
    """

    id = "repo.commit-after-release"
    severity = Severity.MEDIUM
    weight = 3.0
    title = "The release's tag points to a later commit"

    def evaluate_candidate(
        self, candidate: Candidate, ctx: CorrelationContext
    ) -> Sequence[Finding]:
        comparison = ctx.repo
        if comparison is None or comparison.source is None:
            return ()
        gap = _after_release(candidate, comparison)
        history = comparison.history
        if gap is None or history is None or history.commit_date is None:
            return ()
        hours = gap.total_seconds() / 3600
        when = f"{gap.days} days" if gap.days >= 2 else f"{hours:.0f} hours"
        return (
            self.finding(
                f"{comparison.source.how} is commit {comparison.source.commit[:12]}, made "
                f"{when} after this release was published: the release wasn't built from it.",
                Evidence(
                    kind=EvidenceKind.METADATA,
                    path="repository",
                    before=str(candidate.change.new.publish.published_at),
                    after=str(history.commit_date),
                ),
            ),
        )


class HistoryMatch(BaseRule):
    """The release is exactly what the repository holds at its commit
    (`RepoComparison.clean`), and that commit is ahead of the previous release's: the change
    between the two releases went through git, as commits. INFO and unscored: Stage 4's
    decision can read it (`CLEAR_HISTORY`, off) to not report install-code findings git
    explains, and the reviewer reads the commit count.

    What this can't see, as `repo.established-match`: a maintainer, or someone with their git
    access, committing the code (`gina@0.7.1`, 44 commits by its maintainer since 0.7.1-alpha.1).
    """

    id = "repo.history-match"
    severity = Severity.INFO
    weight = 0.0
    title = "The change since the previous release is in git"

    def evaluate_candidate(
        self, candidate: Candidate, ctx: CorrelationContext
    ) -> Sequence[Finding]:
        comparison = ctx.repo
        history = comparison.history if comparison is not None else None
        if (
            comparison is None
            or history is None
            or history.previous_commit is None
            or not comparison.clean
            or history.status != "ahead"
            or not history.ahead_by
            or _after_release(candidate, comparison) is not None
        ):
            return ()
        return (
            self.finding(
                f"Every code file matches {_where(comparison)}, {history.ahead_by} commits "
                f"after {history.previous_version}'s commit {history.previous_commit[:12]} "
                f"({history.previous_how}).",
                Evidence(
                    kind=EvidenceKind.METADATA,
                    path="repository",
                    before=history.previous_commit,
                    after=comparison.source.commit if comparison.source else None,
                ),
            ),
        )


RULES: Final = (
    RepoCompared(),
    CodeDiffersFromRepo(),
    CodeNotInRepo(),
    EstablishedMatch(),
    CommitAfterRelease(),
    HistoryMatch(),
)
