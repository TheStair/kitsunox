"""Stage 1: metadata triage.

Runs the metadata rules on every change from Stage 0 and decides which ones go on to the
tarball stages. Forward policy (roadmap decision 3): a change is forwarded if any finding is at
least `threshold` severity, or the package is watched (popular enough to always look at). The
decision and its reason are recorded on the candidate, so per-stage metrics can be computed.

Forwarded work is handed to Stage 2 as `PackageBatch`es: one per package per run, holding every
version of that package in the run (also the unflagged ones: they are cheap once the package is
being looked at anyway). See `PackageBatch` for why the batch is not reduced to its newest
version.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Final

from kitsunox.core.models import Candidate, Change, PackageBatch, Severity, StageDecision
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


def batch_forwarded(candidates: Sequence[Candidate]) -> tuple[PackageBatch, ...]:
    """Group candidates by package; keep packages with at least one forwarded version. Versions
    are ordered by publish time (then version string); the base is the earliest version's
    previous version, so nothing published since the last batch is skipped."""
    by_package: dict[tuple[str, str], list[Candidate]] = {}
    for candidate in candidates:
        ref = candidate.change.new.ref
        by_package.setdefault((ref.ecosystem, ref.name), []).append(candidate)
    batches = []
    for (ecosystem, name), group in sorted(by_package.items()):
        group.sort(key=_publish_order)
        batch = PackageBatch(
            ecosystem=ecosystem, name=name, base=group[0].change.previous, versions=tuple(group)
        )
        if batch.forwarded:
            batches.append(batch)
    return tuple(batches)


def _publish_order(candidate: Candidate) -> tuple[str, str]:
    published = candidate.change.new.publish.published_at
    return (published.isoformat() if published else "", candidate.change.new.ref.version)


def triage_run(
    run_dir: Path, ctx: RuleContext
) -> tuple[tuple[Candidate, ...], tuple[PackageBatch, ...]]:
    """Triage every change of a recorded run. Writes `triage.jsonl` (one Candidate per change,
    in the run's change order) and `batches.jsonl` (the forwarded PackageBatches, by package).
    `ctx.as_of` should be the run's `as_of`."""
    candidates = tuple(triage(c, ctx) for c in read_changes(changes_file(run_dir)))
    batches = batch_forwarded(candidates)
    write_jsonl(run_dir / "triage.jsonl", candidates)
    write_jsonl(run_dir / "batches.jsonl", batches)
    return candidates, batches
