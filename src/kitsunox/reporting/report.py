"""`report.json`: the canonical output of a run, built from Stage 4's `correlate.jsonl`.

One entry per reported version, highest score first. An entry carries what a reviewer needs to
act: what changed (versions, publisher, popularity), why it was reported (every finding, grouped
by stage, and how the score adds up), and where to look (registry, file browser, diff,
repository at the compared commit). Manifests are left out: they are large and the findings
already quote the parts that matter.

The report is a pure function of `correlate.jsonl` and `correlate.json`, and, once Stage 5
has rendered the run, `sandbox.jsonl` and `sandbox.json`: a reported version is then taken from
`sandbox.jsonl` (Stage 4's candidate plus Stage 5's findings, which count in its score). No
clock, sorted output, so the same inputs always give the same bytes. Stage 5 rewrites its
output when results arrive, and the report is rebuilt after it (`collect.run_sandbox`).
Every string from a package is untrusted; `reporting/markdown.py` escapes it for display.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Final
from urllib.parse import quote

from pydantic import Field

from kitsunox.core.models import Candidate, Finding, Persisted, Record, Severity
from kitsunox.core.run import RunManifest
from kitsunox.sandbox.results import SANDBOX_INFO
from kitsunox.stages.correlate import CORRELATE_INFO, LOW_CAP, CandidateFile, score
from kitsunox.stages.correlate import STAGE_ID as CORRELATE_STAGE
from kitsunox.stages.repo import ReleaseSource
from kitsunox.stages.sandbox import SANDBOX_JSONL
from kitsunox.util.files import atomic_write

REPORT_DIR: Final = "report"
STAGE_NAMES: Final = {
    "npm.": "Stage 1: metadata",
    "static.": "Stage 2: static",
    "code.": "Stage 3: capabilities",
    "repo.": "Stage 4: repository",
    "sandbox.": "Stage 5: sandbox",
}
STAGE_OF_RULE: Final = {
    # Rules whose id prefix doesn't say which stage produced them.
    "npm.artifact.": "Stage 2: static",
    "npm.install-script-code": "Stage 3: capabilities",
    "npm.install-script-changed": "Stage 3: capabilities",
    "npm.install-script-obfuscated": "Stage 3: capabilities",
    "npm.undeclared-package": "Stage 3: capabilities",
    "npm.provenance.": "Stage 4: correlation",
    "npm.dependency.known-malware": "Stage 4: correlation",
    "npm.dependency.fresh-foreign": "Stage 4: correlation",
    "npm.dependency.missing": "Stage 4: correlation",
    "npm.dependency.name-embeds-popular": "Stage 4: correlation",
    "npm.undeclared.missing": "Stage 4: correlation",
    "npm.combination.": "Stage 4: correlation",
    "npm.repo.": "Stage 4: repository",
}


def stage_of(rule_id: str) -> str:
    for prefix, stage in STAGE_OF_RULE.items():
        if rule_id.startswith(prefix):
            return stage
    for prefix, stage in STAGE_NAMES.items():
        if rule_id.startswith(prefix):
            return stage
    return "other"


class ScoreTerm(Record):
    rule_id: str
    severity: Severity
    weight: float
    count: int  # findings of this rule (the score counts the rule once)


class Links(Record):
    registry: str
    files: str
    diff: str | None = None
    repository: str | None = None
    compared_commit: str | None = None


class ReportEntry(Record):
    rank: int
    ref: str
    name: str
    version: str
    previous_version: str | None
    published_at: datetime | None
    publisher: str | None
    watched: bool
    downloads: int | None = Field(description="Downloads over `downloads_period_days`.")
    downloads_period_days: int | None
    score: float
    reason: str
    severity: Severity  # the highest among the findings
    score_terms: tuple[ScoreTerm, ...]
    findings: tuple[Finding, ...]
    stages: tuple[str, ...] = Field(description="Stage of each finding, same order.")
    links: Links


class Report(Persisted):
    run_id: str
    ecosystem: str
    as_of: datetime
    window_start: datetime
    window_end: datetime
    versions: int
    reported: int
    by_severity: dict[str, int]
    correlation: dict[str, object] = Field(description="`correlate.json`: label set, rules.")
    sandbox: dict[str, object] = Field(
        default_factory=dict,
        description="From `sandbox.json`, if Stage 5 rendered the run: network and counts.",
    )
    entries: tuple[ReportEntry, ...]

    def network_uncompared(self) -> tuple[int, bool]:
        """Versions Stage 4 could not compare with their repository because of the network,
        even after its retries, and whether it skipped the retries as an outage. Reports from
        before Stage 4 recorded this (`stage_version` 1) give (0, False)."""
        network = self.correlation.get("repo_network")
        if not isinstance(network, dict):
            return 0, False
        return _still_failing(network)

    def dependency_network_failures(self) -> tuple[int, bool]:
        """Dependency names whose registry record Stage 4 could not fetch because of the
        network, even after its retries (the versions adding them were not checked for
        dependency age and accounts), and whether it skipped the retries as an outage. Reports
        from before Stage 4 retried them (`stage_version` < 5) give (0, False)."""
        lookups = self.correlation.get("dependency_lookups")
        if not isinstance(lookups, dict):
            return 0, False
        return _still_failing(lookups)


def _still_failing(network: dict[object, object]) -> tuple[int, bool]:
    failing = network.get("still_failing")
    count = failing if isinstance(failing, int) and not isinstance(failing, bool) else 0
    return count, network.get("retry_skipped") == "outage"


def build_report(run_dir: Path) -> Report:
    manifest = RunManifest.load_json((run_dir / "manifest.json").read_bytes())
    # One version at a time: only the reported ones are kept (a 110k-version run's candidates
    # take ~4 GB as objects).
    versions = CandidateFile(run_dir / "correlate.jsonl")
    try:
        forwarded = [c for c in versions if c.history and c.history[-1].forwarded]
        count = len(versions)
    finally:
        versions.close()
    stage5, sandbox = _stage5(run_dir)
    reported = sorted(
        (stage5.get(str(c.change.new.ref), c) for c in forwarded),
        key=lambda c: (-_score(c), str(c.change.new.ref)),
    )
    entries = tuple(_entry(rank, c) for rank, c in enumerate(reported, start=1))
    by_severity: dict[str, int] = {}
    for entry in entries:
        by_severity[entry.severity.value] = by_severity.get(entry.severity.value, 0) + 1
    info = run_dir / CORRELATE_INFO
    return Report(
        run_id=manifest.run_id,
        ecosystem=manifest.ecosystem,
        as_of=manifest.as_of,
        window_start=manifest.window.start,
        window_end=manifest.window.end,
        versions=count,
        reported=len(entries),
        by_severity=dict(sorted(by_severity.items())),
        correlation=json.loads(info.read_bytes()) if info.exists() else {},
        sandbox=sandbox,
        entries=entries,
    )


def _stage5(run_dir: Path) -> tuple[dict[str, Candidate], dict[str, object]]:
    """Stage 5's view of the reported versions (by ref) and what the report shows of
    `sandbox.json`; empty when Stage 5 hasn't rendered the run, or its record is unreadable
    (`sandbox.jsonl` is written before `sandbox.json`)."""
    try:
        info = json.loads((run_dir / SANDBOX_INFO).read_bytes())
        lines = (run_dir / SANDBOX_JSONL).read_bytes().splitlines()
    except OSError, ValueError:
        return {}, {}
    if not isinstance(info, dict):
        return {}, {}
    candidates = (Candidate.model_validate_json(line) for line in lines if line.strip())
    return (
        {str(c.change.new.ref): c for c in candidates},
        {"network": info.get("network"), "counts": info.get("counts")},
    )


def write_report(run_dir: Path, report: Report) -> Path:
    path = run_dir / REPORT_DIR / "report.json"
    atomic_write(path, report.model_dump_json(indent=2).encode() + b"\n")
    return path


def score_rule(entry: ReportEntry) -> str:
    """How `entry.score` adds up, in words: the LOW cap is named when it applied (a report
    written before the cap has the plain sum)."""
    plain = "Each rule counts once, at its largest weight"
    if sum(t.weight for t in entry.score_terms) > entry.score:
        return f"{plain}; rules with only LOW findings together count at most {LOW_CAP:g}."
    return f"{plain}."


def _score(candidate: Candidate) -> float:
    return score(candidate.findings)


def score_terms(findings: Iterable[Finding]) -> tuple[ScoreTerm, ...]:
    """How the score adds up: each rule once, at its largest weight (as `stages.correlate`,
    which also caps the LOW rules' total at `LOW_CAP`)."""
    terms: dict[str, ScoreTerm] = {}
    for f in findings:
        if f.severity == Severity.INFO:
            continue
        old = terms.get(f.rule_id)
        terms[f.rule_id] = ScoreTerm(
            rule_id=f.rule_id,
            severity=max(f.severity, old.severity, key=_rank) if old else f.severity,
            weight=max(f.weight, old.weight) if old else f.weight,
            count=old.count + 1 if old else 1,
        )
    return tuple(sorted(terms.values(), key=lambda t: (-t.weight, t.rule_id)))


_ORDER: Final = list(Severity)


def _rank(severity: Severity) -> int:
    return _ORDER.index(severity)


def _entry(rank: int, candidate: Candidate) -> ReportEntry:
    change = candidate.change
    new, previous = change.new, change.previous
    name, version = new.ref.name, new.ref.version
    findings = tuple(
        sorted(candidate.findings, key=lambda f: (-_rank(f.severity), stage_of(f.rule_id)))
    )
    severity = max((f.severity for f in findings), key=_rank, default=Severity.INFO)
    popularity = change.popularity
    return ReportEntry(
        rank=rank,
        ref=str(new.ref),
        name=name,
        version=version,
        previous_version=previous.ref.version if previous else None,
        published_at=new.publish.published_at,
        publisher=new.publish.publisher,
        watched=bool(popularity and popularity.watched),
        downloads=popularity.downloads if popularity else None,
        downloads_period_days=popularity.period_days if popularity else None,
        score=_score(candidate),
        reason=_stage4_reason(candidate),
        severity=severity,
        score_terms=score_terms(findings),
        findings=findings,
        stages=tuple(stage_of(f.rule_id) for f in findings),
        links=_links(candidate),
    )


def _stage4_reason(candidate: Candidate) -> str:
    """Why Stage 4 reported it (Stage 5 adds a decision after Stage 4's)."""
    decisions = [d for d in candidate.history if d.stage == CORRELATE_STAGE]
    return (decisions or list(candidate.history))[-1].reason


def _links(candidate: Candidate) -> Links:
    change = candidate.change
    name, version = change.new.ref.name, change.new.ref.version
    package = quote(name, safe="@/")
    previous = change.previous.ref.version if change.previous else None
    compared = None
    for finding in candidate.findings:
        if finding.rule_id == "repo.compared" and finding.evidence and finding.evidence[0].after:
            source = ReleaseSource.model_validate_json(finding.evidence[0].after)
            path = f"/{quote(source.directory)}" if source.directory else ""
            compared = f"https://github.com/{source.repo}/tree/{source.commit}{path}"
    return Links(
        registry=f"https://www.npmjs.com/package/{package}/v/{quote(version)}",
        files=f"https://www.npmjs.com/package/{package}/v/{quote(version)}?activeTab=code",
        diff=(
            f"https://npmdiff.dev/{package}/{quote(previous)}/{quote(version)}/"
            if previous
            else None
        ),
        # Only GitHub URLs are normalised; anything else is the publisher's text.
        repository=change.repository_url
        if change.repository_url and change.repository_url.startswith("https://")
        else None,
        compared_commit=compared,
    )
