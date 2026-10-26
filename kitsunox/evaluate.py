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
import re
import json
import statistics
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

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
# investigator's time and the API bill both: a wide net can escalate many changes.
#
# Measured, not estimated: briefing the 17 holdout alerts cost $1.50 -- $0.016 to $0.238
# per brief, about $0.09 on average -- because commits in the wild carry far larger diffs
# than the ground-truth incidents ($0.017-0.030 each), which an earlier figure here was
# wrongly extrapolated from. At the measured average a 20-brief hunt is about $1.75; one
# full of large diffs can cost several dollars. The cap bounds the count, not the price.
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
    pr_number: int | None = None
    message: str = ""
    author: str | None = None
    tenure_days: int | None = None
    prior_commits: int | None = None
    findings: list[dict] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    refused: bool = False

    # What the reviewer's links and fact table need.
    sha: str = ""
    parent_sha: str | None = None
    committed_at: str | None = None
    file_roles: dict[str, int] = field(default_factory=dict)
    additions: int = 0
    deletions: int = 0

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


def _is_pr(change: Change) -> bool:
    """A change *is* a pull request only when it came from the PR listing.

    `fetch_commit` also sets `pr_number` when a pushed commit is merely associated with a
    PR, and keying on that collided: a tag-target commit and a squash commit that both
    traced back to PR #431 got the same key, and the disposition log -- which de-duplicates
    by key -- would have merged two escalated commits into one row. A commit is identified
    by its SHA, a pull request by its number.
    """
    return change.source == "pr" and change.pr_number is not None


def _key_for(change: Change) -> str:
    if _is_pr(change):
        return f"{change.repo}#{change.pr_number}"
    return f"{change.repo}@{change.sha[:10]}"


def _url_for(change: Change) -> str:
    if "/" not in change.repo:
        return ""
    if _is_pr(change):
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
        key=_key_for(change),
        repo=change.repo,
        source=change.source,
        ground_truth=change.ground_truth,
        evidence_score=evidence,
        total_score=rules.score(findings),
        escalated=escalated,
        rule_ids=sorted({f.rule_id for f in findings}),
        url=_url_for(change),
        pr_number=change.pr_number,
        message=change.message,
        author=change.author,
        tenure_days=change.author_tenure_days,
        prior_commits=change.author_prior_commits,
        findings=[asdict(f) for f in findings],
        sha=change.sha,
        parent_sha=change.parent_sha,
        committed_at=change.committed_at.date().isoformat() if change.committed_at else None,
        file_roles=dict(Counter(rules.file_role(f) for f in change.files)),
        additions=sum(f.additions for f in change.files),
        deletions=sum(f.deletions for f in change.files),
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
            for change in fetch.fetch_recent_commits(owner, name, limit, fresh=True):
                by_sha[change.sha] = (change, [])
            if prs:
                # Listed second so a PR's richer metadata -- reviews, approvals, who
                # merged it -- replaces the bare commit view of the same squash commit.
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
                sha: fetch.on_any_branch(owner, name, sha)
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
            for change, extra in by_sha.values():
                # An off-branch tag on a docs-only commit is harmless only if the commit
                # it was built on is on a branch; that costs one more reachability check.
                if any(f.rule_id == "tag.on_no_branch" for f in extra)                         and rules.only_docs(change) and change.parent_sha:
                    parent_ok = fetch.on_any_branch(owner, name, change.parent_sha)
                    extra[:] = rules.qualify_off_branch(extra, change, parent_ok)
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


def _cell(text: str) -> str:
    """An untrusted value inside a table cell. A pipe ends a cell even inside backticks,
    so a commit author named `a | Disposition | benign` could otherwise add columns."""
    return _inline(text).replace("|", "\\|")


def _inline(text: str) -> str:
    """A short untrusted value as inline code that cannot break out of its backticks."""
    return "`" + str(text).replace("`", "'").replace("\n", " ")[:200] + "`"


# What each rule means to a reviewer, in a few words: the alert's headline. Kept apart from
# the rules' rationales, which are written for the Tier 2 prompt.
RULE_TITLES = {
    "combo.encoded_payload_in_build_script": "Encoded payload in a build or install script",
    "combo.encoded_payload_in_artifact": "Encoded payload in a generated bundle",
    "combo.encoded_payload_in_ci": "Encoded payload in CI configuration",
    "combo.encoded_payload_executed": "Encoded payload next to code that executes it",
    "combo.credential_exfiltration": "Credentials read next to an exfiltration endpoint",
    "combo.new_maintainer_adds_dependency": "New maintainer pushed a new dependency",
    "tag.version_collapse": "Release tags from different versions share one commit",
    "tag.moved": "A release tag was moved",
    "tag.on_no_branch": "Release tag points at a commit on no branch",
    "content.install_hook_obfuscated": "Install hook carries an encoded payload",
    "content.install_hook_network": "Install hook reaches the network",
    "content.install_hook_exec": "Install hook executes code",
    "content.install_hook_silenced": "Install hook hides its output",
    "content.install_hook_recon": "Install hook collects host identity",
    "content.install_hook": "Install hook declared",
    "content.encoded_blob": "Long base64 literal added",
    "content.decode_call": "Decoding call added",
    "content.shell_exec": "Shell or eval added",
    "content.suspicious_host": "Paste, tunnel or bare-IP endpoint added",
    "content.network_in_build": "Network fetch added to build or CI",
    "content.secret_access": "Credential store, process memory or environment read",
    "content.unbounded_loop": "Loop that cannot terminate",
    "content.binary_added": "Binary file added",
    "content.dependency_added": "Dependency added",
}

# How much of each rule's hits a card shows: enough to locate the pattern, not every
# repetition of it.
MAX_PLACES_SHOWN = 3
MAX_EVIDENCE_SHOWN = 2

# Order of the file-role summary, most consequential first.
ROLE_ORDER = ("action", "CI", "build", "bundle", "binary", "manifest", "source", "tests",
              "docs", "vendored")


ENCODED_RULES = {
    "content.encoded_blob", "content.install_hook_obfuscated",
    "combo.encoded_payload_in_build_script", "combo.encoded_payload_in_artifact",
    "combo.encoded_payload_in_ci", "combo.encoded_payload_executed",
}


def _gh(repo: str, *parts: str) -> str:
    """A github.com URL. `repo` comes from the target list; every other part is quoted, so
    an attacker-chosen file name cannot break out of the link."""
    return f"https://github.com/{repo}/" + "/".join(quote(p, safe="/") for p in parts)


def _file_link(r: "ChangeResult", path: str, line: int | None = None) -> str:
    if not r.sha or "/" not in r.repo:
        return ""
    return _gh(r.repo, "blob", r.sha, path) + (f"#L{line}" if line else "")


def _group_findings(findings: list[dict]) -> dict[str, list[dict]]:
    """Findings by rule, each rule's hits strongest first, duplicates of one location
    dropped."""
    weight = rules.SEVERITY_WEIGHT
    by_rule: dict[str, list[dict]] = {}
    for f in findings:
        hits = by_rule.setdefault(f["rule_id"], [])
        if (f.get("file_path"), f.get("line")) not in {(h.get("file_path"), h.get("line"))
                                                       for h in hits}:
            hits.append(f)
    for hits in by_rule.values():
        hits.sort(key=lambda h: -weight[h["severity"]])
    return dict(sorted(by_rule.items(), key=lambda kv: (
        kv[0].startswith("context."), -weight[kv[1][0]["severity"]], kv[0])))


def _is_evidence(rule_id: str) -> bool:
    return not rule_id.startswith("context.")


def _headline(r: "ChangeResult") -> str:
    """The strongest evidence, in a reviewer's words."""
    grouped = [rid for rid in _group_findings(r.findings) if _is_evidence(rid)]
    combos = [rid for rid in grouped if rid.startswith(("combo.", "tag."))]
    lead = (combos or grouped or ["(no evidence)"])[0]
    return RULE_TITLES.get(lead, lead)


def _strongest(r: "ChangeResult") -> str:
    grouped = _group_findings(r.findings)
    for rid, hits in grouped.items():
        if _is_evidence(rid):
            return f"{rid} ({hits[0]['severity']})"
    return "-"


def _roles(r: "ChangeResult") -> str:
    total = sum(r.file_roles.values())
    if not total:
        return "-"
    parts = [f"{r.file_roles[role]} {role}" for role in ROLE_ORDER if r.file_roles.get(role)]
    return f"{total}: " + ", ".join(parts)


def _model(r: "ChangeResult") -> str:
    if r.refused:
        return "**declined**"
    if r.verdict:
        return f"{r.verdict} ({r.confidence:.2f})"
    if r.tier2_error:
        return "error"
    return "not briefed"


def _checklist(r: "ChangeResult", grouped: dict[str, list[dict]]) -> list[str]:
    """Deterministic first checks for the reviewer, one per kind of signal, with the
    links that answer them. Unlike the model's next steps these cannot be steered by the
    change's author: they are chosen by which rules fired."""
    items: list[str] = []

    def at(hit: dict | None) -> str:
        path = (hit or {}).get("file_path")
        if not path:
            return ""
        label = _inline(path + (f":{hit['line']}" if hit.get("line") else ""))
        link = _file_link(r, path, hit.get("line"))
        return f"{label} <{link}>" if link else label

    ids = set(grouped)
    first = {rid: hits[0] for rid, hits in grouped.items()}
    if ids & ENCODED_RULES:
        hit = next(first[rid] for rid in grouped if rid in ENCODED_RULES)
        items.append(f"Decode the encoded literal at {at(hit)} offline (`base64 -d`) and read "
                     "what it is. Do not execute it.")
    if "content.suspicious_host" in ids:
        items.append(f"Identify what is fetched from or sent to the endpoint at "
                     f"{at(first['content.suspicious_host'])}.")
    if ids & {"content.secret_access", "combo.credential_exfiltration"}:
        items.append(f"Trace where the credential or environment read at "
                     f"{at(first.get('content.secret_access') or first['combo.credential_exfiltration'])} "
                     "ends up.")
    if "content.unbounded_loop" in ids:
        items.append(f"Confirm the loop at {at(first['content.unbounded_loop'])} can terminate.")
    if "content.shell_exec" in ids and first["content.shell_exec"]["severity"] != "low":
        items.append(f"Read the command run at {at(first['content.shell_exec'])}: is its input "
                     "fixed, or can a caller influence it?")
    if "content.network_in_build" in ids:
        items.append(f"Check what the build step at {at(first['content.network_in_build'])} "
                     "downloads, and whether it is pinned or verified.")
    if ids & {"content.install_hook_network", "content.install_hook_exec",
              "content.install_hook_silenced", "content.install_hook_recon"}:
        hook = next(first[rid] for rid in grouped if rid.startswith("content.install_hook_"))
        items.append(f"Read the install hook in {at(hook)} -- it runs on every `npm install`.")
    if "content.binary_added" in ids:
        items.append(f"Identify the binary {at(first['content.binary_added'])}: what produces "
                     "it, and does the repository have a build step that would?")
    if "content.dependency_added" in ids and r.repo:
        hit = first["content.dependency_added"]
        names = [n.strip() for n in hit.get("evidence", "").rstrip(".").split(",") if n.strip()]
        npm = [f"<https://www.npmjs.com/package/{quote(n, safe='@/')}>" for n in names[:5]
               if re.fullmatch(r"[\w@./-]+", n)]
        if hit.get("file_path", "").endswith("package.json") and npm:
            items.append("Check each new package's age, maintainers and install scripts: "
                         + ", ".join(npm) + (" ..." if len(names) > 5 else ""))
        else:
            items.append(f"Check the added dependencies at {at(hit)}.")
    if ids & {"context.new_maintainer_direct_push", "combo.new_maintainer_adds_dependency"} \
            and r.author and "/" in r.repo:
        items.append("Review the author's other commits here: "
                     f"<https://github.com/{r.repo}/commits?author={quote(r.author)}>")
    if ids & {"tag.on_no_branch", "tag.moved", "tag.version_collapse"} and "/" in r.repo:
        if r.parent_sha and r.sha:
            items.append("Compare the tagged commit with its parent -- this is what consumers "
                         f"of the tag run that no branch contains: "
                         f"<{_gh(r.repo, 'compare', r.parent_sha + '...' + r.sha)}>")
        items.append(f"Check the repository's tags and releases: <{_gh(r.repo, 'tags')}>")
    if "context.diff_unavailable" in ids:
        items.append(f"Tier 0 could not read {at(first['context.diff_unavailable'])}; read "
                     "that diff on GitHub.")
    if r.message and items:
        items.append("Check that the commit message describes what the change actually does.")
    return [f"- [ ] {item}" for item in items]


def _findings_section(r: "ChangeResult", grouped: dict[str, list[dict]], evidence: bool) -> list[str]:
    out: list[str] = []
    for rule_id, hits in grouped.items():
        if _is_evidence(rule_id) != evidence:
            continue
        top = hits[0]
        places = [h["file_path"] + (f":{h['line']}" if h.get("line") else "")
                  for h in hits if h.get("file_path")]
        where = ""
        if places:
            more = (f" and {len(places) - MAX_PLACES_SHOWN} more"
                    if len(places) > MAX_PLACES_SHOWN else "")
            where = " in " + ", ".join(_inline(p) for p in places[:MAX_PLACES_SHOWN]) + more
        count = f" x{len(hits)}" if len(hits) > 1 else ""
        out += ["", f"- **{rule_id}** ({top['severity']}){count}{where} -- {top['rationale']}"]
        if top.get("precedent"):
            out += [f"  Precedent: {top['precedent']}."]
        for h in [h for h in hits if h.get("evidence")][:MAX_EVIDENCE_SHOWN]:
            out += ["", _block(h["evidence"], limit=300)]
    return out or ["", "_None._"]


def write_triage(results: list[ChangeResult], path: Path, *, scanned: int,
                 repos: list[str] | None = None) -> Path:
    """Write the ranked Markdown queue of escalated changes for the investigator.

    Laid out for review rather than for the record: a table to pick from, then one card
    per alert -- what fired and why, a checklist of first checks with the links that
    answer them, and only then the untrusted text. Everything an author controls renders
    through `_inline` or `_block`, which cannot be escaped from.
    """
    alerts = rank([r for r in results if r.escalated])
    briefed = [r for r in alerts if r.verdict or r.tier2_error]
    cost = sum(r.cost_usd for r in alerts)

    out = [
        "# Kitsunox triage queue",
        "",
        f"Generated {datetime.now().isoformat(timespec='minutes')} -- "
        f"{scanned} changes scanned across {len(repos or [])} repositories -- "
        f"**{len(alerts)} to review** -- {len(briefed)} briefed (${cost:.4f}).",
        "",
        "**How to review.** Work down the table. For each alert, read the evidence, run the "
        "checklist, then record a disposition (`benign`, `suspicious`, `malicious` or "
        "`unclear`) and the minutes spent against its key in `dispositions.csv` next to "
        "this file. `kitsunox tally` turns those into the result.",
        "",
        "**Trust.** Headings, tables, rule text and checklists are generated by Kitsunox. "
        "Everything in an indented block -- commit messages, code evidence, the model's "
        "brief -- is written or steerable by the change's author. Read the change itself "
        "before deciding.",
    ]
    if not alerts:
        out += ["", "_Nothing escalated._"]
    else:
        out += ["", "## At a glance", "",
                "| # | Change | Score | Strongest signal | Files | Model |",
                "|---|---|---|---|---|---|"]
        for n, r in enumerate(alerts, start=1):
            out.append(f"| {n} | [{_inline(r.key)}](#{n}) | {r.total_score} | "
                       f"{_strongest(r)} | {_roles(r)} | {_model(r)} |")

    for n, r in enumerate(alerts, start=1):
        grouped = _group_findings(r.findings)
        out += ["", "---", "", f'<a id="{n}"></a>', "",
                f"## {n}. {_headline(r)} -- {_inline(r.key)}", ""]
        if r.refused:
            out += ["**The model declined to analyse this change. Review it first.**", ""]

        landed = f"{r.source}" + (f", {r.committed_at}" if r.committed_at else "")
        if r.pr_number and "/pull/" not in r.url:
            landed += f", via PR <https://github.com/{r.repo}/pull/{r.pr_number}>"
        tenure = (f" -- {r.tenure_days} days in this repo, {r.prior_commits} prior commits"
                  if r.tenure_days is not None else "")
        out += [
            "| | |",
            "|---|---|",
            f"| Change | <{r.url}> |" if r.url else "| Change | (no link) |",
            f"| Landed | {landed} |",
            f"| Author | {_cell(r.author or 'unknown')}{tenure} |",
            f"| Files | {_roles(r)} -- +{r.additions} / -{r.deletions} lines |",
            f"| Score | {r.total_score} total, {r.evidence_score} from evidence "
            f"(escalates at {rules.ESCALATION_THRESHOLD}) |",
            f"| Model | {_model(r)}" + (f", ${r.cost_usd:.4f}" if r.cost_usd else "") + " |",
        ]

        out += ["", "### Evidence -- why it escalated"]
        out += _findings_section(r, grouped, evidence=True)
        context = _findings_section(r, grouped, evidence=False)
        if context != ["", "_None._"]:
            out += ["", "### Context -- ranks the alert, cannot escalate it"] + context

        checks = _checklist(r, grouped)
        if checks:
            out += ["", "### Checklist", ""] + checks

        out += ["", "### Commit message (untrusted)", "", _block(r.message, limit=800)]
        if r.rationale or r.next_steps:
            out += ["", f"### Model brief (untrusted, steerable by the author)", "",
                    _block(r.rationale or "")]
            if r.next_steps:
                out += ["", "**Model's suggested next steps** (untrusted)", "",
                        _block("\n".join(f"{i}. {s}" for i, s in enumerate(r.next_steps, 1)))]
        elif r.tier2_error and not r.refused:
            out += ["", f"_Brief unavailable: {r.tier2_error}_"]
        out += ["", f"**Record:** {_inline(r.key)} in `dispositions.csv`."]

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
