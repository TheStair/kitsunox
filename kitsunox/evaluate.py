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

import csv
import json
import statistics
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from kitsunox import fetch, llm, rules
from kitsunox.incidents import INCIDENTS, load_incident
from kitsunox.model import Change, Finding, GroundTruth

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

# Hunting defaults. Briefs are capped per hunt because the binding cost is the
# investigator's time and the API bill both: a wide net can escalate many changes, and
# briefing the top 20 by Tier 0 score keeps a hunt under roughly $0.60.
DEFAULT_HUNT_LIMIT = 50
DEFAULT_MAX_BRIEFS = 20

DISPOSITIONS = ("unreviewed", "benign", "suspicious", "malicious", "unclear")
DISPOSITION_FIELDS = [
    "key", "url", "first_seen", "score", "verdict", "cost_usd",
    "disposition", "minutes", "notes",
]


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

    # Carried for the triage queue so the report needs no second fetch.
    url: str = ""
    message: str = ""
    author: str | None = None
    tenure_days: int | None = None
    prior_commits: int | None = None
    findings: list[dict] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    refused: bool = False

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


def _url_for(change: Change) -> str:
    if "/" not in change.repo:
        return ""
    if change.pr_number:
        return f"https://github.com/{change.repo}/pull/{change.pr_number}"
    return f"https://github.com/{change.repo}/commit/{change.sha}"


def _apply_review(result: ChangeResult, review: llm.Review) -> None:
    result.input_tokens += review.usage.input_tokens
    result.output_tokens += review.usage.output_tokens
    result.cost_usd += review.usage.cost_usd
    if review.ok:
        result.verdict = review.verdict.verdict
        result.confidence = review.verdict.confidence
        result.rationale = review.verdict.rationale
        result.next_steps = list(review.verdict.next_steps)
    else:
        result.tier2_error = review.error
        result.refused = review.refused


def _run_one(change: Change, *, threshold: int, tier2: bool, anonymize: bool = False,
             extra_findings: list[Finding] | None = None) -> ChangeResult:
    """Score one change, optionally brief it. `extra_findings` carries signals computed
    outside the diff -- tag integrity -- so they are scored alongside it."""
    findings = rules.scan(change) + list(extra_findings or [])
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
        url=_url_for(change),
        message=change.message,
        author=change.author,
        tenure_days=change.author_tenure_days,
        prior_commits=change.author_prior_commits,
        findings=[asdict(f) for f in findings],
    )

    if escalated and tier2:
        _apply_review(result, llm.review(change, findings, anonymize=anonymize))

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


# --------------------------------------------------------------------------- hunting
# The pipeline ends in a human investigator. A hunt scans target repositories, ranks what
# Tier 0 escalates, optionally briefs the top of the queue, and writes two artifacts: a
# Markdown queue to read, and a disposition log the investigator fills in. The log is
# what turns manual review into measured results.


_VERDICT_RANK = {"malicious": 0, "suspicious": 1, None: 2, "benign": 3}


def rank(results: list[ChangeResult]) -> list[ChangeResult]:
    """Queue order: refusals first, then by verdict, then by Tier 0 score.

    A refusal leads because in the wild it is a signal in its own right -- the model
    declining to analyse a diff is itself evidence the diff looks malicious.
    """
    return sorted(
        results,
        key=lambda r: (not r.refused, _VERDICT_RANK.get(r.verdict, 2), -r.total_score, r.key),
    )


def load_targets(path: Path) -> list[str]:
    """`owner/name` per line. Blank lines and `#` comments, whole-line or trailing, ignored."""
    targets = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.count("/") != 1 or line.startswith("/") or line.endswith("/"):
            raise ValueError(f"{path}: not an owner/name target: {raw!r}")
        targets.append(line)
    return targets


def _load_snapshots(path: Path | None) -> dict[str, dict[str, str]]:
    if path is None or not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _save_snapshots(path: Path | None, snapshots: dict[str, dict[str, str]]) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snapshots, indent=1, sort_keys=True), encoding="utf-8")


def hunt(
    repos: list[str],
    *,
    limit: int = DEFAULT_HUNT_LIMIT,
    prs: int = 0,
    tags: bool = False,
    brief: bool = False,
    max_briefs: int = DEFAULT_MAX_BRIEFS,
    snapshot_path: Path | None = None,
    progress=None,
) -> list[ChangeResult]:
    """Scan repositories in the wild and return every change, ranked.

    Listings are read fresh: a hunt has to see what changed since the last one. With
    `tags`, release tags are checked too -- an Actions consumer runs what its pinned tag
    points at, so a tag-rewrite attack never has to touch the default branch, and a
    default-branch scan alone could not see either Actions incident in the ground truth.

    Briefing is a second pass over only the top `max_briefs` escalated changes by Tier 0
    score, so a wide net cannot run up an unbounded bill.
    """
    snapshots = _load_snapshots(snapshot_path)
    scored: list[tuple[Change, list[Finding], ChangeResult]] = []

    for full in repos:
        owner, name = full.split("/", 1)
        by_sha: dict[str, tuple[Change, list[Finding]]] = {}
        try:
            for change in fetch.fetch_direct_pushes(owner, name, limit, fresh=True):
                by_sha[change.sha] = (change, [])
            if prs:
                for change in fetch.fetch_merged_prs(owner, name, prs, fresh=True):
                    by_sha[change.sha] = (change, [])
        except fetch.FetchError as exc:
            if progress:
                progress(f"  ! {full}: {exc}")
            continue

        if tags:
            current = fetch.list_tags(owner, name)
            previous = snapshots.get(full)
            reachable = {
                sha: fetch.on_default_branch(owner, name, sha)
                for sha in rules.tags_to_check(current, previous)
            }
            for sha, extra in rules.tag_findings(current, previous, reachable).items():
                if sha in by_sha:
                    by_sha[sha][1].extend(extra)
                    continue
                try:
                    target = fetch.fetch_commit(owner, name, sha)
                except fetch.FetchError:
                    # A release tag pointing at a commit that cannot even be fetched is
                    # worth an investigator's look on its own; report it bare.
                    target = Change(repo=full, source="push", sha=sha, author=None,
                                    committed_at=None, message="(commit could not be fetched)")
                by_sha[sha] = (target, extra)
            if current:
                snapshots[full] = dict(current)

        for change, extra in by_sha.values():
            result = _run_one(change, threshold=rules.ESCALATION_THRESHOLD, tier2=False,
                              extra_findings=extra)
            scored.append((change, extra, result))
        if progress:
            flagged = sum(1 for _, _, r in scored if r.repo == full and r.escalated)
            progress(f"  {full}: {len(by_sha)} changes, {flagged} escalated")

    if brief:
        chosen = {id(r) for r in rank([r for _, _, r in scored if r.escalated])[:max_briefs]}
        for change, extra, result in scored:
            if id(result) in chosen:
                findings = rules.scan(change) + extra
                _apply_review(result, llm.review(change, findings))

    _save_snapshots(snapshot_path, snapshots)
    return rank([r for _, _, r in scored])


def _block(text: str, limit: int = 1500) -> str:
    """Untrusted text as an indented code block.

    Commit messages, diff evidence and tag names are attacker-controlled, and so is the
    Tier 2 brief, which an attacker can steer by planting instructions in a commit. In a
    fenced block a stray triple backtick closes the fence and lets crafted text render
    as part of the report -- a forged "Disposition: benign", say. Indentation cannot be
    escaped from.
    """
    text = (text or "").strip() or "(empty)"
    if len(text) > limit:
        text = text[:limit] + "\n[...truncated]"
    return "\n".join("    " + line for line in text.splitlines())


def _inline(text: str) -> str:
    """A short untrusted value as inline code that cannot break out of its backticks."""
    return "`" + str(text).replace("`", "'").replace("\n", " ")[:200] + "`"


def write_triage(results: list[ChangeResult], path: Path, *, scanned: int,
                 repos: list[str] | None = None) -> Path:
    """Write the ranked Markdown queue of escalated changes for the investigator."""
    alerts = rank([r for r in results if r.escalated])
    briefed = [r for r in alerts if r.verdict or r.tier2_error]
    cost = sum(r.cost_usd for r in alerts)

    out = [
        "# Kitsunox triage queue",
        "",
        f"Generated {datetime.now().isoformat(timespec='minutes')}. "
        f"{scanned} changes scanned across {len(repos or [])} repositories; "
        f"**{len(alerts)} escalated**; {len(briefed)} briefed (${cost:.4f}).",
        "",
        "Record what you find in `dispositions.csv` alongside this file "
        "(`benign`, `suspicious`, `malicious` or `unclear`, plus minutes spent), then run "
        "`kitsunox tally`.",
        "",
        "Everything shown in an indented block is untrusted: it is written or influenced by "
        "the change's author, including the model's brief. Read the change itself before "
        "deciding.",
    ]
    if not alerts:
        out += ["", "_Nothing escalated._"]

    for n, r in enumerate(alerts, start=1):
        verdict = f" -- model: {r.verdict} ({r.confidence:.2f})" if r.verdict else ""
        out += ["", "---", "", f"## {n}. {_inline(r.key)} -- score {r.total_score}{verdict}", ""]
        if r.refused:
            out += ["**The model declined to analyse this change. Review it first.**", ""]
        out += [f"<{r.url}>" if r.url else "(no link)", ""]
        tenure = (f", {r.tenure_days} days in repo, {r.prior_commits} prior commits"
                  if r.tenure_days is not None else "")
        out += [f"Author: {_inline(r.author or 'unknown')}{tenure}. Source: {r.source}.", ""]
        out += ["**Commit message**", "", _block(r.message, limit=800), ""]

        out += ["**Why it was flagged**"]
        evidence_first = sorted(r.findings, key=lambda f: (f["rule_id"].startswith("context."),
                                                           f["rule_id"]))
        seen = set()
        for f in evidence_first:
            ident = (f["rule_id"], f.get("file_path"), f.get("line"))
            if ident in seen:
                continue
            seen.add(ident)
            where = ""
            if f.get("file_path"):
                where = " in " + _inline(f["file_path"] + (f":{f['line']}" if f.get("line") else ""))
            out += ["", f"- **{f['rule_id']}** ({f['severity']}){where} -- {f['rationale']}"]
            if f.get("precedent"):
                out += [f"  Precedent: {f['precedent']}."]
            if f.get("evidence"):
                out += ["", _block(f["evidence"], limit=300)]

        if r.rationale or r.next_steps:
            out += ["", f"**Model brief** (${r.cost_usd:.4f}; untrusted, steerable by the author)",
                    "", _block(r.rationale or "")]
            if r.next_steps:
                out += ["", "**Suggested next steps** (model output)", "",
                        _block("\n".join(f"{i}. {s}" for i, s in enumerate(r.next_steps, 1)))]
        elif r.tier2_error and not r.refused:
            out += ["", f"_Brief unavailable: {r.tier2_error}_"]

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    return path


def merge_dispositions(results: list[ChangeResult], path: Path) -> int:
    """Append newly escalated changes to the disposition log as `unreviewed`.

    Append-only by construction: existing rows are never rewritten, so a reviewed row
    cannot be clobbered by a later hunt. Returns the number of rows added.
    """
    existing: set[str] = set()
    if path.exists():
        with path.open(encoding="utf-8-sig", newline="") as fh:
            existing = {row.get("key", "") for row in csv.DictReader(fh)}

    new = [r for r in rank(results) if r.escalated and r.key not in existing]
    if not new:
        return 0

    path.parent.mkdir(parents=True, exist_ok=True)
    fresh_file = not path.exists() or path.stat().st_size == 0
    if not fresh_file:
        # A spreadsheet editor may save without a trailing newline; appending straight
        # onto the last row would corrupt it.
        with path.open("rb") as fh:
            fh.seek(-1, 2)
            needs_newline = fh.read(1) not in (b"\n", b"\r")
        if needs_newline:
            with path.open("a", encoding="utf-8", newline="") as fh:
                fh.write("\r\n")

    with path.open("a", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=DISPOSITION_FIELDS)
        if fresh_file:
            writer.writeheader()
        today = datetime.now().date().isoformat()
        for r in new:
            writer.writerow({
                "key": r.key, "url": r.url, "first_seen": today, "score": r.total_score,
                "verdict": r.verdict or "", "cost_usd": f"{r.cost_usd:.4f}",
                "disposition": "unreviewed", "minutes": "", "notes": "",
            })
    return len(new)


def tally(path: Path) -> dict:
    """Summarise the disposition log: the in-the-wild evaluation result."""
    if not path.exists():
        return {"alerts": 0, "reviewed": 0, "counts": {}, "unknown": []}
    with path.open(encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.DictReader(fh))

    def label(row):
        return (row.get("disposition") or "unreviewed").strip().lower()

    counts = Counter(label(r) for r in rows)
    unknown = sorted({d for d in counts if d not in DISPOSITIONS})
    reviewed = [r for r in rows if label(r) not in ("unreviewed", "")]

    def number(value):
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    minutes = [m for m in (number(r.get("minutes")) for r in reviewed) if m is not None]
    costs = [c for c in (number(r.get("cost_usd")) for r in rows) if c is not None]
    malicious, suspicious = counts.get("malicious", 0), counts.get("suspicious", 0)

    return {
        "alerts": len(rows),
        "reviewed": len(reviewed),
        "counts": dict(counts),
        "unknown": unknown,
        "precision": malicious / len(reviewed) if reviewed else None,
        "worth_a_look": (malicious + suspicious) / len(reviewed) if reviewed else None,
        "median_minutes": statistics.median(minutes) if minutes else None,
        "total_minutes": sum(minutes),
        "brief_cost_usd": sum(costs),
        "brief_cost_per_alert": sum(costs) / len(rows) if rows else None,
    }


def format_tally(t: dict) -> str:
    def pct(x):
        return "n/a" if x is None else f"{100 * x:.1f}%"

    lines = ["", "KITSUNOX -- IN THE WILD", "=" * 40,
             f"Alerts          {t['alerts']}",
             f"Reviewed        {t['reviewed']}"]
    for d in DISPOSITIONS:
        if t["counts"].get(d):
            lines.append(f"  {d:13} {t['counts'][d]}")
    if t.get("unknown"):
        lines.append(f"  unrecognised  {', '.join(t['unknown'])}  (use: {', '.join(DISPOSITIONS)})")
    if t["reviewed"]:
        lines += [
            f"Precision       {pct(t['precision'])}  (confirmed malicious / reviewed)",
            f"Worth a look    {pct(t['worth_a_look'])}  (malicious or suspicious / reviewed)",
            f"Minutes/alert   {t['median_minutes'] if t['median_minutes'] is not None else 'n/a'}"
            f"  (median; {t['total_minutes']:.0f} total)",
        ]
    if t.get("brief_cost_per_alert") is not None:
        lines.append(f"Brief cost      ${t['brief_cost_usd']:.4f}  (${t['brief_cost_per_alert']:.4f}/alert)")
    return "\n".join(lines + ["=" * 40])
