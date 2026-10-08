"""Orchestrates an evaluation run and produces the report (docs/Plan.md §7).

This is the only module that decides whether a change is escalated to Tier 2. `rules.py`
scores, `llm.py` judges when asked, and the threshold connecting them lives here so it is
tunable in one place.

**Tier 2 is opt-in.** `tier2=False` by default: every Tier 2 call costs real money, and
an evaluation run that quietly spends is a bad default for a project whose whole thesis
is that the expensive tier should be rare. Tier 0 numbers are free and are what week 5's
tuning needs.

**Detection is reported against what actually ran.** With Tier 2 off, a change counts as
detected when Tier 0 escalated it. With Tier 2 on, the verdict decides, and a failed call
counts as neither — an API error must never be scored as a clean change.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from kitsunox import fetch, llm, rules
from kitsunox.incidents import INCIDENTS, load_incident
from kitsunox.model import Change, GroundTruth

# Held out from all tuning, across 10 languages. Rules keyed on `package.json`, `dist/`
# bundles and npm idioms had only ever met Python and JavaScript web libraries, so
# ecosystem-specific false positives surface here or nowhere.
CONTROL_REPOS = [
    "django/django", "pytest-dev/pytest", "scikit-learn/scikit-learn", "psf/black",
    "encode/httpx", "fastapi/fastapi", "vuejs/core", "webpack/webpack", "babel/babel",
    "prettier/prettier", "vitejs/vite", "sveltejs/svelte", "gin-gonic/gin", "spf13/cobra",
    "prometheus/prometheus", "tokio-rs/tokio", "serde-rs/serde", "clap-rs/clap",
    "google/guava", "square/retrofit", "rails/rails", "laravel/framework",
    "symfony/symfony", "curl/curl", "nlohmann/json",
]

# The original sample. Three rules were tuned against its false positives and two
# regression tests derive from it, so it is training data — useful for checking nothing
# regressed, never for reporting a false-positive rate. See Plan.md §6.
TUNING_REPOS = ["psf/requests", "pallets/flask", "expressjs/express", "axios/axios"]

DEFAULT_PRS_PER_REPO = 18
DEFAULT_PUSHES_PER_REPO = 12


@dataclass
class ChangeResult:
    """One change's journey through the pipeline."""

    key: str
    repo: str
    source: str
    ground_truth: GroundTruth | None
    evidence_score: int
    total_score: int
    escalated: bool
    rule_ids: list[str] = field(default_factory=list)
    verdict: str | None = None
    confidence: float | None = None
    rationale: str | None = None
    tier2_error: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0

    @property
    def detected(self) -> bool | None:
        """Whether the pipeline called this change dangerous.

        None when Tier 2 was asked and failed — unknowable, and counting it either way
        would corrupt the rate it feeds.
        """
        if self.tier2_error:
            return None
        if self.verdict is not None:
            return self.verdict in ("malicious", "suspicious")
        return self.escalated


@dataclass
class Report:
    incidents: list[ChangeResult] = field(default_factory=list)
    control: list[ChangeResult] = field(default_factory=list)
    tier2_ran: bool = False
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))

    @property
    def detection_rate(self) -> tuple[int, int]:
        judged = [r for r in self.incidents if r.detected is not None]
        return sum(1 for r in judged if r.detected), len(judged)

    @property
    def false_positives(self) -> tuple[int, int]:
        judged = [r for r in self.control if r.detected is not None]
        return sum(1 for r in judged if r.detected), len(judged)

    @property
    def escalated_count(self) -> int:
        return sum(1 for r in self.incidents + self.control if r.escalated)

    @property
    def total_cost_usd(self) -> float:
        return sum(r.cost_usd for r in self.incidents + self.control)

    @property
    def errors(self) -> list[ChangeResult]:
        return [r for r in self.incidents + self.control if r.tier2_error]


def _run_one(change: Change, *, threshold: int, tier2: bool, anonymize: bool = False) -> ChangeResult:
    findings = rules.scan(change)
    evidence = rules.evidence_score(findings)
    escalated = evidence >= threshold

    result = ChangeResult(
        key=f"{change.repo}@{change.sha[:10]}" if change.pr_number is None
        else f"{change.repo}#{change.pr_number}",
        repo=change.repo,
        source=change.source,
        ground_truth=change.ground_truth,
        evidence_score=evidence,
        total_score=rules.score(findings),
        escalated=escalated,
        rule_ids=sorted({f.rule_id for f in findings}),
    )

    if escalated and tier2:
        review = llm.review(change, findings, anonymize=anonymize)
        result.input_tokens = review.usage.input_tokens
        result.output_tokens = review.usage.output_tokens
        result.cost_usd = review.usage.cost_usd
        if review.ok:
            result.verdict = review.verdict.verdict
            result.confidence = review.verdict.confidence
            result.rationale = review.verdict.rationale
        else:
            result.tier2_error = review.error

    return result


def load_control(
    repos: list[str] | None = None,
    *,
    prs_per_repo: int = DEFAULT_PRS_PER_REPO,
    pushes_per_repo: int = DEFAULT_PUSHES_PER_REPO,
    progress=None,
) -> list[Change]:
    """Fetch the benign control sample: merged PRs and direct pushes.

    Both halves are needed. All five incidents are direct pushes, so a PR-only control
    measures false positives on a population that cannot trigger the push rules.
    """
    changes: list[Change] = []
    for full in repos or CONTROL_REPOS:
        owner, name = full.split("/", 1)
        for label, fn, count in (
            ("prs", fetch.fetch_merged_prs, prs_per_repo),
            ("pushes", fetch.fetch_direct_pushes, pushes_per_repo),
        ):
            if count <= 0:
                continue
            try:
                got = fn(owner, name, count)
            except fetch.FetchError as exc:
                if progress:
                    progress(f"  ! {full} {label}: {exc}")
                continue
            for change in got:
                change.ground_truth = "benign"
            changes += got
            if progress:
                progress(f"  {full} {label}: {len(got)} (total {len(changes)})")
    return changes


def evaluate(
    *,
    incidents: bool = True,
    control: bool = True,
    tier2: bool = False,
    anonymize: bool = False,
    threshold: int | None = None,
    repos: list[str] | None = None,
    prs_per_repo: int = DEFAULT_PRS_PER_REPO,
    pushes_per_repo: int = DEFAULT_PUSHES_PER_REPO,
    progress=None,
) -> Report:
    """Run the pipeline over the ground truth and/or the control sample."""
    threshold = rules.ESCALATION_THRESHOLD if threshold is None else threshold
    report = Report(tier2_ran=tier2)

    if incidents:
        if progress:
            progress("Loading ground-truth incidents...")
        for incident in INCIDENTS:
            change = load_incident(incident)
            result = _run_one(change, threshold=threshold, tier2=tier2, anonymize=anonymize)
            result.key = incident.key
            report.incidents.append(result)
            if progress:
                progress(f"  {incident.key}: evidence={result.evidence_score} detected={result.detected}")

    if control:
        if progress:
            progress("Fetching control sample...")
        for change in load_control(
            repos, prs_per_repo=prs_per_repo, pushes_per_repo=pushes_per_repo, progress=progress
        ):
            report.control.append(
                _run_one(change, threshold=threshold, tier2=tier2, anonymize=anonymize)
            )

    return report


def format_summary(report: Report) -> str:
    """Short human-readable summary for stdout."""
    lines = ["", "=" * 62, "KITSUNOX EVALUATION", "=" * 62]

    if report.incidents:
        hit, total = report.detection_rate
        lines.append(f"\nDetection      {hit}/{total} incidents")
        for r in report.incidents:
            mark = "HIT " if r.detected else ("ERR " if r.tier2_error else "MISS")
            verdict = f"  [{r.verdict}]" if r.verdict else ""
            lines.append(f"  {mark} {r.key:16} evidence={r.evidence_score:3}{verdict}")

    if report.control:
        fp, total = report.false_positives
        pct = 100 * fp / total if total else 0.0
        lines.append(f"\nFalse positives {fp}/{total} benign changes ({pct:.2f}%)")
        for r in report.control:
            if r.detected:
                evidence_rules = [x for x in r.rule_ids if not x.startswith("context.")]
                lines.append(f"  FP  {r.key:34} evidence={r.evidence_score:3} {evidence_rules}")

    seen = len(report.incidents) + len(report.control)
    lines.append(f"\nTier 2          {report.escalated_count}/{seen} changes escalated")
    if report.tier2_ran:
        lines.append(f"                ${report.total_cost_usd:.4f} spent")
        if report.errors:
            lines.append(f"                {len(report.errors)} call(s) failed — excluded from rates")
    else:
        lines.append("                not run (Tier 0 only; pass --tier2 to spend)")

    lines.append("=" * 62)
    return "\n".join(lines)


def write_report(report: Report, path: Path) -> Path:
    """Write the full report as JSON, for the write-up to draw numbers from."""
    hit, det_total = report.detection_rate
    fp, fp_total = report.false_positives
    payload = {
        "generated_at": report.generated_at,
        "tier2_ran": report.tier2_ran,
        "summary": {
            "detection": {"detected": hit, "of": det_total},
            "false_positives": {"flagged": fp, "of": fp_total},
            "escalated": report.escalated_count,
            "cost_usd": round(report.total_cost_usd, 6),
            "tier2_errors": len(report.errors),
        },
        "incidents": [asdict(r) for r in report.incidents],
        "control": [asdict(r) for r in report.control],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def scan_repo(owner: str, repo: str, limit: int, *, progress=None) -> list[ChangeResult]:
    """Rank a repository's recent direct pushes by score (Plan.md §7a).

    Ranked, not flagged. One malicious commit among thousands means even a 1% false
    positive rate buries it, so the useful output is an ordering, not a verdict.
    """
    results = []
    for change in fetch.fetch_direct_pushes(owner, repo, limit):
        results.append(_run_one(change, threshold=rules.ESCALATION_THRESHOLD, tier2=False))
        if progress and len(results) % 25 == 0:
            progress(f"  scanned {len(results)}...")
    return sorted(results, key=lambda r: (-r.total_score, r.key))
