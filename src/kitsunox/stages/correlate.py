"""Stage 4: correlation and scoring. Puts every stage's findings for a version together, adds
the findings that need more than one stage's view or outside knowledge, and decides what a
human should review.

- **Input:** every version Stage 1 triaged (`triage.jsonl`), with Stages 2-3's findings for
  those routed to them (`ast.jsonl`). Versions never routed still carry Stage 1's weak
  signals, and two weak signals together can be worth a look: on `day1`, most malicious
  updates the pipeline missed were never routed, and many had the same two LOW findings.
- **Correlation rules** see the whole `Candidate`: the change and every finding so far. Some
  read outside data through the `CorrelationContext` (known-malware records, the comparison
  with the source repository); combination rules read only the findings.
- **Score:** each rule counts once, at its largest weight (Stage 2 reports one finding per
  file, and twenty matching files are not twenty signals); INFO counts nothing. Every term is a
  named rule, so the report can show how the number was reached. Reports are ordered by it.
- **Decision:** report a version when any finding is MEDIUM or above (each stage's own bar, so
  recall is never lower than Stages 1-3 together), or when LOW findings add up to
  `REPORT_SCORE`. See `docs/stages/correlate.md` for the numbers.

Like the other stages, nothing here reads the clock: "known by" means known by the run's
`as_of`, so a re-run with a later label set doesn't change an old run's answers.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Final, Protocol

from kitsunox.core.models import Candidate, Finding, PackageBatch, Severity, StageDecision
from kitsunox.core.rules import rules_fingerprint
from kitsunox.stages.ingest import write_jsonl
from kitsunox.stages.repo import RepoComparison
from kitsunox.stages.triage import at_least
from kitsunox.util.files import atomic_write

STAGE_ID: Final = "correlate"
REPORT_SEVERITY: Final = Severity.MEDIUM
# Measured on `day1`: LOW findings of Stages 1-3 summing to 3, 4 or 5 added 0.6, 0.2 and 0
# points of recall on malicious updates for 2.0, 0.8 and 0.4 points of benign updates reported;
# at 6 they add neither. Below 6, routine LOWs (process-exec + network + npm-publish) add up.
REPORT_SCORE: Final = 6.0
CORRELATE_INFO: Final = "correlate.json"


class KnownBad(Protocol):
    """Outside knowledge about packages (e.g. OSV malware records)."""

    @property
    def id(self) -> str: ...

    def known_malware(self, name: str, as_of: datetime) -> tuple[str, ...]: ...


@dataclass(frozen=True)
class CorrelationContext:
    """What correlation rules may know besides the candidate: the run's `as_of`, outside
    knowledge, and (per candidate) the comparison with its source repository."""

    as_of: datetime
    known_bad: KnownBad | None = None
    repo: RepoComparison | None = None


RepoLookup = Callable[[Candidate], RepoComparison | None]


def wants_repo(candidate: Candidate) -> bool:
    """Which versions get the repository comparison (chosen 2026-10-28): any version an earlier
    stage flagged, and every update of a watched package. About 500 versions an hour, most of
    them watched-package updates, which share archives when a burst or a monorepo shares a
    commit."""
    flagged = any(
        d.forwarded and (d.stage != "triage" or d.reason.startswith("rules:"))
        for d in candidate.history
    )
    change = candidate.change
    watched = bool(change.popularity and change.popularity.watched)
    return flagged or (watched and change.previous is not None)


class CorrelationRule(Protocol):
    @property
    def id(self) -> str: ...

    @property
    def version(self) -> int: ...

    def evaluate_candidate(
        self, candidate: Candidate, ctx: CorrelationContext
    ) -> Sequence[Finding]: ...


def score(findings: Sequence[Finding]) -> float:
    """Each rule once, at its largest weight; INFO findings count nothing."""
    best: dict[str, float] = {}
    for f in findings:
        if f.severity != Severity.INFO:
            best[f.rule_id] = max(best.get(f.rule_id, 0.0), f.weight)
    return sum(best.values())


def correlate(
    candidate: Candidate,
    ctx: CorrelationContext,
    rules: Sequence[CorrelationRule],
    *,
    report_score: float = REPORT_SCORE,
) -> Candidate:
    """Run the rules in order (each sees the findings of those before it) and decide."""
    for rule in rules:
        found = tuple(rule.evaluate_candidate(candidate, ctx))
        if found:
            candidate = candidate.model_copy(update={"findings": candidate.findings + found})
    decision = decide(candidate.findings, report_score=report_score)
    return candidate.model_copy(update={"history": (*candidate.history, decision)})


def decide(findings: Sequence[Finding], *, report_score: float = REPORT_SCORE) -> StageDecision:
    total = score(findings)
    severe = sorted({f.rule_id for f in findings if at_least(f.severity, REPORT_SEVERITY)})
    if severe:
        reason = f"score {total:g}; {REPORT_SEVERITY.value}: {', '.join(severe)}"
    else:
        reason = f"score {total:g}" + (f" >= {report_score:g}" if total >= report_score else "")
    return StageDecision(
        stage=STAGE_ID, forwarded=bool(severe) or total >= report_score, reason=reason
    )


def correlate_run(
    run_dir: Path,
    ctx: CorrelationContext,
    rules: Sequence[CorrelationRule],
    *,
    repo: RepoLookup | None = None,
    report_score: float = REPORT_SCORE,
    workers: int = 8,
) -> tuple[Candidate, ...]:
    """Stage 4 over a run Stage 3 has processed. Reads every triaged version
    (`triage.jsonl`), taking Stages 2-3's version of those routed to them (`ast.jsonl`); writes
    `correlate.jsonl` (one Candidate per line, in triage order) and `correlate.json` (which
    outside data and rules were used). `repo` compares a version with its repository
    (`wants_repo` decides which); it must be thread-safe."""
    analysed = {
        str(c.change.new.ref): c
        for line in (run_dir / "ast.jsonl").read_bytes().splitlines()
        if line.strip()
        for c in PackageBatch.load_json(line).versions
    }

    def one(line: bytes) -> Candidate:
        candidate = Candidate.model_validate_json(line)
        candidate = analysed.get(str(candidate.change.new.ref), candidate)
        comparison = repo(candidate) if repo is not None and wants_repo(candidate) else None
        return correlate(candidate, replace(ctx, repo=comparison), rules, report_score=report_score)

    lines = [line for line in (run_dir / "triage.jsonl").read_bytes().splitlines() if line.strip()]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        candidates = tuple(pool.map(one, lines, chunksize=64))
    write_jsonl(run_dir / "correlate.jsonl", candidates)
    info = {
        "as_of": ctx.as_of.isoformat(),
        "known_bad": ctx.known_bad.id if ctx.known_bad else None,
        "rules": rules_fingerprint(rules),
        "report_score": report_score,
    }
    atomic_write(run_dir / CORRELATE_INFO, json.dumps(info, indent=2).encode())
    return candidates
