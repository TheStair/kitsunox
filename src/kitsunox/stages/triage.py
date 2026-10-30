"""Stage 1: metadata triage.

Runs the metadata rules on every change from Stage 0 and decides which ones go on to the
tarball stages. A change is forwarded, in this order of reasons, if:

1. any finding is at least `threshold` severity (it is *flagged*: Stage 1 alone would report it);
2. the package is watched (popular enough to always look at; roadmap decision 3);
3. it is a new package (no previous version: small, and no base tarball to fetch);
4. it has an install hook, so Stage 3 can compare the files the hook runs with the previous
   version's (`npm.install-script-changed`): a hook can stay word for word the same while the
   file it runs changes. 2.2% of updates on the first VM day, 1,440 of them not forwarded
   before;
5. its declared unpacked size grew by at least `MIN_GROWTH_BYTES`, or a size is unknown.

Reasons 3 to 5 route code to Stage 2 that has no metadata signal (the "hybrid" policy chosen
on 2026-10-27; numbers in `docs/stages/static.md`). The decision and its reason are recorded on
the candidate, so per-stage metrics can be computed.

Forwarded work is handed to Stage 2 as `PackageBatch`es: one per package per run, holding every
version of that package in the run (also the unflagged ones: they are cheap once the package is
being looked at anyway). See `PackageBatch` for why the batch is not reduced to its newest
version.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Final

from kitsunox.core.models import (
    Candidate,
    Change,
    PackageBatch,
    Severity,
    StageDecision,
    VersionSnapshot,
)
from kitsunox.core.rules import Rule, RuleContext, run_rules
from kitsunox.ecosystems.npm.rules.metadata import RULES as NPM_RULES
from kitsunox.ecosystems.npm.rules.metadata import has_install_hook
from kitsunox.stages.ingest import changes_file, read_changes, write_jsonl

STAGE_ID: Final = "triage"
SEVERITY_ORDER: Final = tuple(Severity)
DEFAULT_THRESHOLD: Final = Severity.MEDIUM
# Payloads are added code: 71% of malicious updates (DataDog, first releases) grew by at least
# 64 KiB of declared unpacked size, against 8% of benign ones (2026-10-27).
MIN_GROWTH_BYTES: Final = 64 * 1024
RULES_BY_ECOSYSTEM: Final[dict[str, Sequence[Rule]]] = {"npm": NPM_RULES}


def at_least(severity: Severity, threshold: Severity) -> bool:
    return SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index(threshold)


def triage(
    change: Change,
    ctx: RuleContext,
    *,
    threshold: Severity = DEFAULT_THRESHOLD,
    forward_watched: bool = True,
    route_code: bool = True,
) -> Candidate:
    """`route_code=False` turns off reasons 3 to 5 (Stage 1 measured on its own)."""
    findings = run_rules(RULES_BY_ECOSYSTEM[change.new.ref.ecosystem], change, ctx)
    flagged = sorted({f.rule_id for f in findings if at_least(f.severity, threshold)})
    watched = bool(change.popularity and change.popularity.watched)
    if flagged:
        reason: str | None = f"rules: {', '.join(flagged)}"
    elif watched and forward_watched:
        reason = "watched package"
    else:
        reason = code_route(change) if route_code else None
    decision = StageDecision(
        stage=STAGE_ID, forwarded=reason is not None, reason=reason or "no signal"
    )
    return Candidate(change=change, findings=findings, history=(decision,))


def code_route(change: Change) -> str | None:
    """Why a change with no metadata signal should still have its code read, if it should."""
    if change.previous is None:
        return "new package"
    if has_install_hook(change.new.manifest):
        return "install hook"
    new, old = _unpacked_size(change.new), _unpacked_size(change.previous)
    if new is None or old is None:
        return "unpacked size unknown"
    if new - old >= MIN_GROWTH_BYTES:
        return f"unpacked size grew by {new - old} bytes"
    return None


def _unpacked_size(snapshot: VersionSnapshot) -> int | None:
    return snapshot.artifact.unpacked_size if snapshot.artifact else None


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
