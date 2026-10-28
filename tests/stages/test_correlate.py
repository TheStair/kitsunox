"""Stage 4 core: correlation rules, score and report decision, and the run file."""

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from kitsunox.core.models import (
    Candidate,
    Change,
    Finding,
    PackageBatch,
    PackageVersionRef,
    PublishInfo,
    Severity,
    VersionSnapshot,
)
from kitsunox.stages.correlate import (
    CORRELATE_INFO,
    CorrelationContext,
    correlate,
    correlate_run,
    decide,
    score,
)
from kitsunox.stages.ingest import write_jsonl

CTX = CorrelationContext(as_of=datetime(2026, 10, 28, tzinfo=UTC))


def finding(rule_id: str, severity: Severity, weight: float) -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_version=1,
        severity=severity,
        weight=weight,
        title="t",
        explanation="e",
    )


def candidate(version: str = "1.0.1", *findings: Finding, name: str = "kx") -> Candidate:
    snapshot = VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name=name, version=version),
        publish=PublishInfo(),
        manifest={},
    )
    return Candidate(change=Change(new=snapshot), findings=findings)


def test_score_counts_each_rule_once_and_ignores_info() -> None:
    found = [
        finding("a", Severity.LOW, 1.0),
        finding("a", Severity.LOW, 1.0),  # Stage 2: one finding per matching file
        finding("b", Severity.LOW, 2.0),
        finding("c", Severity.INFO, 9.0),
    ]
    assert score(found) == 3.0


def test_report_on_severity_or_score() -> None:
    assert not decide([finding("a", Severity.LOW, 1.0)], report_score=3).forwarded
    lows = [finding("a", Severity.LOW, 1.0), finding("b", Severity.LOW, 2.0)]
    decision = decide(lows, report_score=3)
    assert decision.forwarded and decision.reason == "score 3 >= 3"
    medium = decide([finding("m", Severity.MEDIUM, 0.5)], report_score=3)
    assert medium.forwarded and medium.reason == "score 0.5; medium: m"


class Echo:
    """Adds a LOW finding naming how many findings it saw."""

    version = 1

    def __init__(self, rule_id: str) -> None:
        self.id = rule_id

    def evaluate_candidate(self, c: Candidate, ctx: CorrelationContext) -> Sequence[Finding]:
        return [finding(f"{self.id}:{len(c.findings)}", Severity.LOW, 1.0)]


def test_rules_see_earlier_findings() -> None:
    result = correlate(
        candidate("1.0.1", finding("s1", Severity.LOW, 1.0)),
        CTX,
        [Echo("x"), Echo("y")],
        report_score=3,
    )
    assert [f.rule_id for f in result.findings] == ["s1", "x:1", "y:2"]
    assert result.history[-1].stage == "correlate" and result.history[-1].forwarded


def test_run_reads_every_triaged_version(tmp_path: Path) -> None:
    routed, quiet = candidate("1.0.1"), candidate("2.0.0", name="other")
    analysed = routed.model_copy(update={"findings": (finding("s2", Severity.MEDIUM, 3.0),)})
    write_jsonl(tmp_path / "triage.jsonl", [routed, quiet])
    batch = PackageBatch(ecosystem="npm", name="kx", base=None, versions=(analysed,))
    write_jsonl(tmp_path / "ast.jsonl", [batch])
    first, second = correlate_run(tmp_path, CTX, [Echo("x")], report_score=5)
    assert [f.rule_id for f in first.findings] == ["s2", "x:1"] and first.history[-1].forwarded
    assert [f.rule_id for f in second.findings] == ["x:0"] and not second.history[-1].forwarded
    assert len((tmp_path / "correlate.jsonl").read_bytes().splitlines()) == 2
    info = json.loads((tmp_path / CORRELATE_INFO).read_text())
    assert info["known_bad"] is None and info["report_score"] == 5
