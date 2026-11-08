"""Reviewer verdicts: the append-only log, each version's verdict now, and the queue without
reviewed versions."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from conftest import make_report, report_entry, run_manifest
from kitsunox.core.models import Severity
from kitsunox.core.run import DataDir
from kitsunox.reporting.queue import build_queue, render_queue
from kitsunox.reporting.report import write_report
from kitsunox.reporting.verdicts import (
    MAX_NOTE_CHARS,
    VerdictRecord,
    append_verdict,
    current,
    probes,
    read_verdicts,
    reasons,
    tally,
    verdict_label,
    verdict_record,
    verdicts_path,
)

RUN = "20261029T210500Z-npm"
T0 = datetime(2026, 10, 30, 12, tzinfo=UTC)
REPORT = make_report(
    RUN,
    report_entry(1, "evil-pkg", "1.0.3", 14, Severity.HIGH, "npm.install-hook"),
    report_entry(2, "evil-pkg", "1.0.2", 9, Severity.MEDIUM, "static.exfil-endpoint"),
    report_entry(3, "fine-pkg", "2.0.0", 7, Severity.MEDIUM, "code.capability-gained"),
)


def record(rank: int, verdict: str, at: datetime = T0, **extra: object):  # type: ignore[no-untyped-def]
    entry = next(e for e in REPORT.entries if e.rank == rank)
    return verdict_record(REPORT, entry, verdict, by="owner", at=at, **extra)  # type: ignore[arg-type]


def test_the_log_keeps_history_and_the_last_record_is_the_verdict(tmp_path: Path) -> None:
    append_verdict(tmp_path, record(1, "unverified", note="needs the tarball", reason="gone"))
    append_verdict(tmp_path, record(1, "malicious", T0 + timedelta(minutes=5), note="exfil"))
    append_verdict(tmp_path, record(3, "benign"))
    append_verdict(tmp_path, record(3, "reopened", T0 + timedelta(minutes=1)))
    with verdicts_path(tmp_path, "npm").open("ab") as handle:
        handle.write(b"{damaged\n")
    log = read_verdicts(tmp_path, "npm")
    assert [r.verdict for r in log] == ["unverified", "malicious", "benign", "reopened"]
    assert log[0].reason == "gone" and log[1].reason is None
    now = current(log)
    assert set(now) == {("evil-pkg", "1.0.3")}  # fine-pkg was reopened: back in the queue
    malicious = now[("evil-pkg", "1.0.3")]
    assert (malicious.note, malicious.score, malicious.rules) == (
        "exfil",
        14,
        ("npm.install-hook",),
    )
    assert tally(now) == {"malicious": 1, "unwanted": 0, "benign": 0, "unverified": 0}
    assert read_verdicts(tmp_path / "absent", "npm") == []


def test_reviewer_names_and_notes_are_bounded() -> None:
    with pytest.raises(ValueError, match="reviewer name"):
        verdict_record(REPORT, REPORT.entries[0], "benign", by="Evil Name<script>", at=T0)
    long = record(1, "benign", note="x" * (MAX_NOTE_CHARS + 50))
    assert len(long.note) == MAX_NOTE_CHARS
    with pytest.raises(ValueError):
        verdicts_path(Path("/x"), "../etc")


def test_a_probe_tag_qualifies_a_verdict_and_is_counted(tmp_path: Path) -> None:
    tagged = record(1, "malicious", tags=["probe", "probe"])
    assert tagged.tags == ("probe",)
    with pytest.raises(ValueError, match="no tags"):
        record(1, "reopened", tags=["probe"])
    append_verdict(tmp_path, tagged)
    append_verdict(tmp_path, record(3, "malicious"))
    now = current(read_verdicts(tmp_path, "npm"))
    assert (probes(now, "malicious"), probes(now, "benign")) == (1, 0)
    untagged = tagged.model_dump(mode="json")
    del untagged["tags"]  # a line written before tags existed
    assert VerdictRecord.model_validate(untagged).tags == ()


def test_the_queue_leaves_reviewed_versions_out(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    run_dir = data.run_dir(RUN)
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text(run_manifest(RUN).model_dump_json())
    write_report(run_dir, REPORT)
    before = build_queue(data, "npm", days=7)
    assert before is not None and (before.packages, before.versions, before.reviewed) == (2, 3, 0)
    append_verdict(tmp_path, record(1, "malicious"))
    append_verdict(tmp_path, record(3, "benign"))
    after = build_queue(data, "npm", days=7)
    assert after is not None
    assert [(e.name, [v.version for v in e.versions]) for e in after.entries] == [
        ("evil-pkg", ["1.0.2"])
    ]
    assert (after.reviewed, after.verdicts) == (
        2,
        {"malicious": 1, "unwanted": 0, "benign": 1, "unverified": 0},
    )
    assert "2 reported versions already have a verdict" in render_queue(after)


def test_unverified_needs_a_reason_and_nothing_else_takes_one() -> None:
    gone = record(1, "unverified", reason="gone")
    assert (gone.verdict, gone.reason, verdict_label(gone)) == (
        "unverified",
        "gone",
        "unverified (code gone)",
    )
    with pytest.raises(ValueError, match="needs a reason"):
        record(1, "unverified")
    for kind in ("malicious", "unwanted", "benign", "reopened"):
        with pytest.raises(ValueError, match="only an unverified"):
            record(1, kind, reason="remote")
    probe = record(1, "unwanted", tags=["probe"])
    assert (probe.verdict, probe.tags, verdict_label(probe)) == ("unwanted", ("probe",), "unwanted")
    raw = gone.model_dump(mode="json")
    with pytest.raises(ValidationError):  # a stored record can't pair a reason with another verdict
        VerdictRecord.model_validate({**raw, "verdict": "benign"})
    with pytest.raises(ValidationError):
        VerdictRecord.model_validate({**raw, "reason": "lost"})


def test_a_legacy_inconclusive_record_loads_as_unverified_without_a_reason(tmp_path: Path) -> None:
    legacy = record(1, "malicious").model_dump(mode="json")
    legacy.update(verdict="inconclusive", note="obfuscated loader")
    del legacy["reason"]  # written before reasons existed
    path = verdicts_path(tmp_path, "npm")
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(legacy) + "\n")
    append_verdict(tmp_path, record(3, "unwanted", note="marker-only beacon"))
    log = read_verdicts(tmp_path, "npm")
    assert [(r.verdict, r.reason) for r in log] == [("unverified", None), ("unwanted", None)]
    assert verdict_label(log[0]) == "unverified (no reason (was inconclusive))"
    now = current(log)
    assert tally(now) == {"malicious": 0, "unwanted": 1, "benign": 0, "unverified": 1}
    assert reasons(now) == {"none": 1}
    append_verdict(tmp_path, record(1, "unverified", T0 + timedelta(hours=1), reason="binary"))
    assert reasons(current(read_verdicts(tmp_path, "npm"))) == {"binary": 1}  # reclassified
