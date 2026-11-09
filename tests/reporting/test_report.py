"""Reports: built from correlate.jsonl, ordered by score, byte-stable, and safe to render."""

import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from conftest import make_report
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
from kitsunox.reporting.markdown import (
    code,
    link,
    page_name,
    render_entry,
    render_index,
    strip_controls,
    text,
)
from kitsunox.reporting.publish import publish_report
from kitsunox.reporting.report import build_report, stage_of
from kitsunox.stages.correlate import LOW_CAP
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


def test_stage5_findings_join_the_report_once_stage5_has_run(tmp_path: Path) -> None:
    a = candidate("a", True, finding("npm.install-hook", Severity.MEDIUM, 3.0))
    b = candidate("b", True, finding("npm.install-hook", Severity.MEDIUM, 4.0))
    directory = run_dir(tmp_path, [a, b])
    assert [e.name for e in build_report(directory).entries] == ["b", "a"]
    analysed = a.model_copy(
        update={
            "findings": (*a.findings, finding("sandbox.bait-exfil", Severity.CRITICAL, 10.0)),
            "history": (
                *a.history,
                StageDecision(stage="sandbox", forwarded=True, reason="analysed (completed)"),
            ),
        }
    )
    write_jsonl(directory / "sandbox.jsonl", [analysed, b])
    counts = {"reported": 2, "selected": 1, "deferred": 0, "analysed": 1, "pending": 0}
    (directory / "sandbox.json").write_text(
        json.dumps({"network": "airgapped", "counts": counts, "keys": {}})
    )
    report = build_report(directory)
    assert [e.name for e in report.entries] == ["a", "b"]
    top = report.entries[0]
    assert top.score == 13.0 and top.severity == Severity.CRITICAL
    assert top.reason == "r"  # Stage 4's reason, not Stage 5's decision
    assert top.stages[top.findings.index(analysed.findings[-1])] == "Stage 5: sandbox"
    assert report.sandbox == {"network": "airgapped", "counts": counts}
    index = render_index(report)
    assert "Stage 5 (package-analysis, airgapped): 1 of 2 reported versions" in index
    assert "1 analysed, 0 awaiting analysis, 0 over the cap" in index
    (directory / "sandbox.json").write_text("[]")  # unreadable record: Stage 5 left out
    assert build_report(directory).sandbox == {}


def test_stage_of_rules() -> None:
    assert stage_of("npm.install-hook") == "Stage 1: metadata"
    assert stage_of("npm.artifact.size-mismatch") == "Stage 2: static"
    assert stage_of("npm.install-script-code") == "Stage 3: capabilities"
    assert stage_of("npm.load-fingerprint") == "Stage 3: capabilities"
    assert stage_of("npm.publish-at-load") == "Stage 3: capabilities"
    assert stage_of("npm.install-agent-user-wide") == "Stage 3: capabilities"
    assert stage_of("npm.install-explained") == "Stage 3: capabilities"
    assert stage_of("npm.install-build-tool") == "Stage 3: capabilities"
    assert stage_of("agent.hostile-instructions") == "Stage 3: capabilities"
    assert stage_of("npm.dependency.known-malware") == "Stage 4: correlation"
    assert stage_of("npm.dependency.fresh-foreign") == "Stage 4: correlation"
    assert stage_of("npm.dependency.name-embeds-popular") == "Stage 4: correlation"
    assert stage_of("npm.dependency.added") == "Stage 1: metadata"
    assert stage_of("repo.code-differs") == "Stage 4: repository"


def test_untrusted_text_cannot_escape() -> None:
    assert text("a|b <script>`x`\nnext") == r"a\|b &lt;script&gt;\`x\` next"
    # A bidi override is dropped, and flagged in bold that package text can't forge.
    assert text("safe‮txt.js") == r"safetxt.js **\[1 hidden character removed\]**"
    assert (
        text(r"**\[1 hidden character removed\]**") == r"\*\*\\\[1 hidden character removed\\\]\*\*"
    )
    assert text("\u200b") == r"**\[1 hidden character removed\]**"
    assert text("plain caf\u00e9 1.0.0") == "plain caf\u00e9 1.0.0"
    hostile = "```\n# Injected heading\n````"
    block = code(hostile)
    fence = block.split("\n", 1)[0]
    assert fence == "`````" and block.endswith("\n" + fence)
    assert hostile in block
    assert code("ok") == "```\nok\n```"


def test_hidden_payload_characters_are_dropped_and_counted() -> None:
    # GlassWorm hid code in variation selectors, os-info-checker-es6 in private-use characters.
    payload = "eval(" + "\ufe01\U000e0100" * 3 + "\ue000\U000e0041\u3164\x85\r" + ")"
    assert text(payload) == r"eval\(\) **\[11 hidden characters removed\]**"
    block = code(f"x = 1{payload}\n")
    assert block == "```\nx = 1eval()\n\n```\n\n**\\[11 hidden characters removed\\]**"
    assert strip_controls(f"a{payload}\tb\n") == "aeval()\tb\n"


def test_crlf_and_a_leading_bom_are_not_flagged() -> None:
    # Windows- and BOM-prefixed files are ordinary: their snippets get no marker, and the
    # output is what LF text gives.
    assert code("\ufeffa\r\nb\r\n") == code("a\nb\n") == "```\na\nb\n\n```"
    assert text("\ufeffname\r\n") == "name"
    assert code("a\rb") == "```\nab\n```\n\n**\\[1 hidden character removed\\]**"


def test_links_only_for_plain_https() -> None:
    assert link("https://github.com/o/r", "repo") == "[repo](<https://github.com/o/r>)"
    assert link("https://www.npmjs.com/package/@s/x", "npm") == (
        "[npm](<https://www.npmjs.com/package/@s/x>)"
    )
    for url in (
        "javascript:alert(1)",
        "https://x.test/a b>",
        "https://www.npmjs.com@evil.example/",
        "https://x.test/\x01",
        "https://x.test/\u202e",
        "https://x.test/a\\b",
        'https://x.test/"x',
        "https://exa\u043cple.com/",
        "http://x.test/",
    ):
        rendered = link(url, "x")
        assert "](" not in rendered and "(not linked)" in rendered, url


def outside_code_spans(markdown: str) -> str:
    """`markdown` with its inline code spans (fence, content, fence) removed."""
    return re.sub(r"(`+).*?(?<!`)\1(?!`)", "", markdown)


@pytest.mark.parametrize(
    "url",
    [
        "https://www.npmjs.com@evil.example/",  # user info: really goes to evil.example
        "https://npm\u0458s.com/x",  # Cyrillic je: a homoglyph host
        "https://x.test/a b",
        "http://www.example.com/",
        "https://x.test/```",
        "`https://x.test/`",
        "https://x.test/a|b\\|c",
        "https://x.test/\u202eevil",
        "https://x.test/\nwww.evil.example",
    ],
)
def test_rejected_urls_cannot_be_autolinked(url: str) -> None:
    # GitHub's extended autolinks and linkify previews link bare URLs, www. hosts and e-mail
    # addresses in text, never inside code: so nothing URL-like may be left outside the span.
    rendered = link(url, "x")
    assert "(not linked)" in rendered
    outside = outside_code_spans(rendered)
    assert "://" not in outside and "www." not in outside and "@" not in outside, rendered
    assert "\n" not in rendered
    # A table cell can't be ended early: every pipe is escaped.
    assert re.search(r"(?<!\\)\|", rendered) is None


def test_rejected_url_spans() -> None:
    assert link("https://www.npmjs.com@evil.example/", "npm") == (
        "`https://www.npmjs.com@evil.example/` (not linked)"
    )
    assert link("https://x.test/``a", "x") == "```https://x.test/``a``` (not linked)"
    assert link("`x`", "x") == "`` `x` `` (not linked)"
    assert link("a|b", "x") == "`a\\|b` (not linked)"
    assert link("https://x.test/\u202e", "x") == (
        r"`https://x.test/` (not linked) **\[1 hidden character removed\]**"
    )
    assert link("\u200b", "x") == r"(empty URL, not linked) **\[1 hidden character removed\]**"
    assert link("", "x") == "(empty URL, not linked)"
    assert link(None, "x") == "n/a"


def test_page_names_are_safe(tmp_path: Path) -> None:
    hostile = candidate("../../etc/passwd", True, finding("x", Severity.MEDIUM, 1.0))
    (entry,) = build_report(run_dir(tmp_path, [hostile])).entries
    name = page_name(entry)
    assert "/" not in name and not name.startswith(".") and name.startswith("0001-")
    page = render_entry(entry)
    assert "<script" not in page


@pytest.mark.parametrize(
    ("network", "expected"),
    [
        (None, (0, False)),  # a report from before Stage 4 recorded it
        ({"still_failing": 3, "retry_skipped": None}, (3, False)),
        ({"still_failing": 40, "retry_skipped": "outage"}, (40, True)),
        ({"still_failing": True}, (0, False)),  # malformed: not a count
        ({"still_failing": "3"}, (0, False)),
        ("garbage", (0, False)),
    ],
)
def test_network_uncompared_versions_are_said_in_the_index(
    network: object, expected: tuple[int, bool]
) -> None:
    correlation = {} if network is None else {"repo_network": network}
    report = make_report("r", correlation=correlation)
    assert report.network_uncompared() == expected
    index = render_index(report)
    count, outage = expected
    assert ("not compared with their repository" in index) == bool(count)
    assert ("skipped as an outage" in index) == outage


@pytest.mark.parametrize(
    ("lookups", "expected"),
    [
        (None, (0, False)),  # a report from before Stage 4 retried dependency lookups
        ({"still_failing": 2, "retry_skipped": None}, (2, False)),
        ({"still_failing": 30, "retry_skipped": "outage"}, (30, True)),
        ({"still_failing": False}, (0, False)),
        ("garbage", (0, False)),
    ],
)
def test_failed_dependency_lookups_are_said_in_the_index(
    lookups: object, expected: tuple[int, bool]
) -> None:
    correlation = {} if lookups is None else {"dependency_lookups": lookups}
    report = make_report("r", correlation=correlation)
    assert report.dependency_network_failures() == expected
    assert report.network_uncompared() == (0, False)  # the repository count is separate
    index = render_index(report)
    count, outage = expected
    assert (f"**{count:,} dependency lookups failed**" in index) == bool(count)
    assert ("skipped as an outage" in index) == outage


def test_the_score_caps_low_rules_and_says_so(tmp_path: Path) -> None:
    lows = [finding(f"static.r{i}", Severity.LOW, 1.0) for i in range(5)]
    capped = candidate("capped", True, finding("npm.install-hook", Severity.MEDIUM, 3.0), *lows)
    plain = candidate("plain", True, finding("npm.install-hook", Severity.MEDIUM, 3.0))
    report = build_report(run_dir(tmp_path, [capped, plain]))
    by_name = {e.name: e for e in report.entries}
    assert by_name["capped"].score == 3.0 + LOW_CAP
    assert "together count at most 3" in render_entry(by_name["capped"])
    assert "together count" not in render_entry(by_name["plain"])
