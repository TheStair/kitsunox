"""`report.json`: the canonical output of a run, built from Stage 4's `correlate.jsonl`.

One entry per reported version, highest score first. An entry carries what a reviewer needs to
act: what changed (versions, publisher, popularity), why it was reported (every finding, grouped
by stage, and how the score adds up), and where to look (registry, file browser, diff,
repository at the compared commit). Manifests are left out: they are large and the findings
already quote the parts that matter.

The report is a pure function of `correlate.jsonl` and `correlate.json`: no clock, sorted
output, so the same run always gives the same bytes. Every string from a package is untrusted;
`reporting/markdown.py` escapes it for display.
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
from kitsunox.stages.correlate import CORRELATE_INFO
from kitsunox.stages.repo import ReleaseSource
from kitsunox.util.files import atomic_write

REPORT_DIR: Final = "report"
STAGE_NAMES: Final = {
    "npm.": "Stage 1: metadata",
    "static.": "Stage 2: static",
    "code.": "Stage 3: capabilities",
    "repo.": "Stage 4: repository",
}
STAGE_OF_RULE: Final = {
    # Rules whose id prefix doesn't say which stage produced them.
    "npm.artifact.": "Stage 2: static",
    "npm.install-script-code": "Stage 3: capabilities",
    "npm.provenance.": "Stage 4: correlation",
    "npm.dependency.known-malware": "Stage 4: correlation",
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
    entries: tuple[ReportEntry, ...]


def build_report(run_dir: Path) -> Report:
    manifest = RunManifest.load_json((run_dir / "manifest.json").read_bytes())
    candidates = [
        Candidate.model_validate_json(line)
        for line in (run_dir / "correlate.jsonl").read_bytes().splitlines()
        if line.strip()
    ]
    reported = sorted(
        (c for c in candidates if c.history and c.history[-1].forwarded),
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
        versions=len(candidates),
        reported=len(entries),
        by_severity=dict(sorted(by_severity.items())),
        correlation=json.loads(info.read_bytes()) if info.exists() else {},
        entries=entries,
    )


def write_report(run_dir: Path, report: Report) -> Path:
    path = run_dir / REPORT_DIR / "report.json"
    atomic_write(path, report.model_dump_json(indent=2).encode() + b"\n")
    return path


def _score(candidate: Candidate) -> float:
    return sum(t.weight for t in score_terms(candidate.findings))


def score_terms(findings: Iterable[Finding]) -> tuple[ScoreTerm, ...]:
    """How the score adds up: each rule once, at its largest weight (as `stages.correlate`)."""
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
        reason=candidate.history[-1].reason,
        severity=severity,
        score_terms=score_terms(findings),
        findings=findings,
        stages=tuple(stage_of(f.rule_id) for f in findings),
        links=_links(candidate),
    )


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
