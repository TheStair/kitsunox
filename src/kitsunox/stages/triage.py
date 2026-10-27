"""Stage 1: metadata triage.

Runs the metadata rules on every change from Stage 0 and decides which ones go on to the
tarball stages. Forward policy (roadmap decision 3): a change is forwarded if any finding is at
least `threshold` severity, or the package is watched (popular enough to always look at). The
decision and its reason are recorded on the candidate, so per-stage metrics can be computed.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Final

from kitsunox.core.models import Candidate, Change, Severity, StageDecision
from kitsunox.core.rules import Rule, RuleContext, run_rules
from kitsunox.ecosystems.npm.rules.metadata import RULES as NPM_RULES
from kitsunox.stages.ingest import changes_file, read_changes, write_jsonl

STAGE_ID: Final = "triage"
SEVERITY_ORDER: Final = tuple(Severity)
DEFAULT_THRESHOLD: Final = Severity.MEDIUM
RULES_BY_ECOSYSTEM: Final[dict[str, Sequence[Rule]]] = {"npm": NPM_RULES}


def at_least(severity: Severity, threshold: Severity) -> bool:
    return SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index(threshold)


def triage(
    change: Change,
    ctx: RuleContext,
    *,
    threshold: Severity = DEFAULT_THRESHOLD,
    forward_watched: bool = True,
) -> Candidate:
    findings = run_rules(RULES_BY_ECOSYSTEM[change.new.ref.ecosystem], change, ctx)
    flagged = sorted({f.rule_id for f in findings if at_least(f.severity, threshold)})
    watched = bool(change.popularity and change.popularity.watched)
    if flagged:
        decision = StageDecision(
            stage=STAGE_ID, forwarded=True, reason=f"rules: {', '.join(flagged)}"
        )
    elif watched and forward_watched:
        decision = StageDecision(stage=STAGE_ID, forwarded=True, reason="watched package")
    else:
        decision = StageDecision(stage=STAGE_ID, forwarded=False, reason="no signal")
    return Candidate(change=change, findings=findings, history=(decision,))


def triage_run(run_dir: Path, ctx: RuleContext) -> tuple[Candidate, ...]:
    """Triage every change of a recorded run and write `triage.jsonl` (one Candidate per line,
    in the run's change order). `ctx.as_of` should be the run's `as_of`."""
    candidates = tuple(triage(c, ctx) for c in read_changes(changes_file(run_dir)))
    write_jsonl(run_dir / "triage.jsonl", candidates)
    return candidates
