"""Stage 4 rule over follow-on releases (`CorrelationContext.follow_on`), ecosystem-agnostic.

Stages 1-3 judge what a release changes. A release that keeps a reported release's payload
unchanged therefore shows nothing: `pdf-html5-page-flip@2.0.2` was published 15 minutes after
2.0.1 with the same credential stealer, byte for byte, in `dist/lib/fonts/fa-solid-400.woff2`;
2.0.1 was reported (score 6), 2.0.2 scored 3. Decision 0007 kept such *follow-on* releases out
of the `vm-day1` recall cells for that reason. `correlate_run`'s follow-on pass gives a release
whose previous release the same run reported the evidence it still holds (`FollowOn`), and this
rule turns it into a finding: the earlier release named, every carried file or manifest field
listed. See `docs/stages/correlate.md` (Follow-on releases) and
`docs/proposals/precision-round6-U.md` for the measurements.
"""

from __future__ import annotations

from collections.abc import Sequence

from kitsunox.core.models import Candidate, Finding, Severity
from kitsunox.core.rules import BaseRule
from kitsunox.stages.correlate import (
    DECLARED_ONLY,
    FOLLOW_ON,
    FOLLOW_ON_EVIDENCE,
    NOT_EVALUATED,
    CorrelationContext,
)


class FollowOnRelease(BaseRule):
    """The previous release, reported by this run or an earlier one (within the window), had
    payload evidence (`payload_evidence`) that this release still holds unchanged: a file with
    the same bytes at the same path, or a manifest field with the same value. MEDIUM, so it
    reports the release on its own: the reviewer sees the same payload again, named as such.
    When the files couldn't be read, an INFO finding says the follow-on was not checked."""

    # v2 (2026-11-13, round 11 P9): a carried dependency the registry didn't have is listed as
    # "still declared" (`DECLARED_ONLY`: carried by name, its range may have changed).

    id = FOLLOW_ON
    version = 2
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Same flagged code as a reported earlier release"

    def evaluate_candidate(
        self, candidate: Candidate, ctx: CorrelationContext
    ) -> Sequence[Finding]:
        follow = ctx.follow_on
        if follow is None:
            return ()
        name = candidate.change.new.ref.name
        by = f"run {follow.previous_run}" if follow.previous_run else "this run"
        if not follow.carried:
            if follow.unavailable is None:
                return ()
            return (
                self.finding(
                    f"{NOT_EVALUATED}follow-on of {name}@{follow.previous}, which {by}"
                    f" reported ({follow.previous_reason}): {follow.unavailable}.",
                    severity=Severity.INFO,
                    weight=0.0,
                ),
            )
        shown = follow.carried[:FOLLOW_ON_EVIDENCE]
        listed = ", ".join(
            f"{item.evidence.path} ({item.rule_id}"
            + (", still declared)" if item.rule_id in DECLARED_ONLY else ")")
            for item in shown
        ) + (
            f", and {len(follow.carried) - len(shown)} more"
            if len(follow.carried) > len(shown)
            else ""
        )
        unchecked = f" Not all checked: {follow.unavailable}." if follow.unavailable else ""
        return (
            self.finding(
                f"Follow-on of {name}@{follow.previous}, published {follow.hours:g} hours"
                f" earlier and reported by {by} ({follow.previous_reason}). Unchanged"
                f" since: {listed}.{unchecked}",
                *(item.evidence for item in shown),
            ),
        )
