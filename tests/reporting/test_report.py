"""Reports: built from correlate.jsonl, ordered by score, byte-stable, and safe to render."""

import json
from datetime import UTC, datetime
from pathlib import Path

from kitsunox.core.models import (
    Candidate,
    Change,
    Evidence,
    EvidenceKind,
    Finding,
    PackageVersionRef,
    PublishInfo,
    Severity,
    StageDecision,
    VersionSnapshot,
    Window,
)
from kitsunox.core.run import RunManifest
from kitsunox.reporting.markdown import code, link, page_name, render_entry, text
from kitsunox.reporting.publish import publish_report
from kitsunox.reporting.report import build_report, stage_of
from kitsunox.stages.ingest import write_jsonl

T0 = datetime(2026, 10, 28, tzinfo=UTC)


def finding(rule_id: str, severity: Severity, weight: float, **evidence: object) -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_version=1,
        severity=severity,
        weight=weight,
        title="t",
        explanation="e",
        evidence=(Evidence(kind=EvidenceKind.FILE_SPAN, **evidence),) if evidence else (),
    )


def candidate(name: str, reported: bool, *findings: Finding, url: str | None = None) -> Candidate:
    def snap(version: str) -> VersionSnapshot:
        return VersionSnapshot(
            ref=PackageVersionRef(ecosystem="npm", name=name, version=version),
            publish=PublishInfo(published_at=T0, publisher="p"),
            manifest={"big": "x" * 1000},
        )

    return Candidate(
        change=Change(new=snap("1.0.1"), previous=snap("1.0.0"), repository_url=url),
        findings=findings,
        history=(StageDecision(stage="correlate", forwarded=reported, reason="r"),),
    )


def run_dir(tmp_path: Path, candidates: list[Candidate]) -> Path:
    manifest = RunManifest(
        run_id="r1",
        tool_version="0",
        ecosystem="npm",
        as_of=T0,
        window=Window(start=datetime(2026, 10, 27, tzinfo=UTC), end=T0),
        cursor_since=0,
        cursor_until=1,
        snapshot_sha256="0",
        changes_sha256="0",
        change_count=len(candidates),
        skipped_count=0,
        packages_seen=len(candidates),
    )
    (tmp_path / "manifest.json").write_text(manifest.model_dump_json())
    write_jsonl(tmp_path / "correlate.jsonl", candidates)
    return tmp_path


def test_report_orders_by_score_and_drops_manifests(tmp_path: Path) -> None:
    low = candidate("low", True, finding("npm.install-hook", Severity.MEDIUM, 5.0))
    high = candidate(
        "high",
        True,
        finding("static.network", Severity.LOW, 1.0, path="a.js"),
        finding("static.network", Severity.LOW, 1.0, path="b.js"),  # counted once
        finding("npm.publish-method.downgrade", Severity.HIGH, 5.0),
        finding("repo.compared", Severity.INFO, 0.0),
    )
    quiet = candidate("quiet", False)
    report = build_report(run_dir(tmp_path, [low, quiet, high]))
    assert [e.name for e in report.entries] == ["high", "low"]
    top = report.entries[0]
    assert top.score == 6.0 and top.severity == Severity.HIGH
    assert [(t.rule_id, t.count) for t in top.score_terms] == [
        ("npm.publish-method.downgrade", 1),
        ("static.network", 2),
    ]
    assert report.versions == 3 and report.by_severity == {"high": 1, "medium": 1}
    assert "x" * 1000 not in report.model_dump_json()


def test_publish_is_byte_stable_and_replaces_old_pages(tmp_path: Path) -> None:
    directory = run_dir(tmp_path, [candidate("a", True, finding("x", Severity.MEDIUM, 1.0))])
    publish_report(directory)
    first = (directory / "report" / "report.json").read_bytes()
    stale = directory / "report" / "entries" / "9999-old.md"
    stale.write_text("old")
    publish_report(directory)
    assert (directory / "report" / "report.json").read_bytes() == first
    assert not stale.exists()
    assert json.loads(first)["entries"][0]["name"] == "a"
    assert (directory / "report" / "index.md").read_text().count("[a@1.0.1]") == 1


def test_stage_of_rules() -> None:
    assert stage_of("npm.install-hook") == "Stage 1: metadata"
    assert stage_of("npm.artifact.size-mismatch") == "Stage 2: static"
    assert stage_of("npm.install-script-code") == "Stage 3: capabilities"
    assert stage_of("npm.dependency.known-malware") == "Stage 4: correlation"
    assert stage_of("repo.code-differs") == "Stage 4: repository"


def test_untrusted_text_cannot_escape() -> None:
    assert text("a|b <script>`x`\nnext") == r"a\|b &lt;script&gt;\`x\` next"
    assert text("safe‮txt.js") == "safetxt.js"  # bidi override dropped
    hostile = "```\n# Injected heading\n````"
    block = code(hostile)
    fence = block.split("\n", 1)[0]
    assert fence == "`````" and block.endswith("\n" + fence)
    assert hostile in block


def test_links_only_for_plain_https() -> None:
    assert link("https://github.com/o/r", "repo") == "[repo](<https://github.com/o/r>)"
    assert "](" not in link("javascript:alert(1)", "x")
    assert "](" not in link("https://x.test/a b>", "x")


def test_page_names_are_safe(tmp_path: Path) -> None:
    hostile = candidate("../../etc/passwd", True, finding("x", Severity.MEDIUM, 1.0))
    (entry,) = build_report(run_dir(tmp_path, [hostile])).entries
    name = page_name(entry)
    assert "/" not in name and not name.startswith(".") and name.startswith("0001-")
    page = render_entry(entry)
    assert "<script" not in page
