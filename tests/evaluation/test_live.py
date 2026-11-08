import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from conftest import REPORT_AS_OF, LiveVersion, write_live_run
from kitsunox.cli import app
from kitsunox.core.models import Severity
from kitsunox.evaluation import live as E
from kitsunox.evaluation.confirmations import Takedown, TakedownLog, takedowns_path
from kitsunox.evaluation.intervals import wilson, zero_bound
from kitsunox.evaluation.labels import AffectedRange, LabelSet, MalwareLabel
from kitsunox.evaluation.ledger import backfill
from kitsunox.reporting.verdicts import VerdictRecord, append_verdict

R1 = "20261029T210500Z-npm"
R2 = "20261029T220500Z-npm"
R3 = "20261029T230500Z-npm"
OLD_LABELS = datetime(2026, 10, 30, tzinfo=UTC)
LABELS_AT = datetime(2026, 11, 20, tzinfo=UTC)
PUBLISHED = REPORT_AS_OF - timedelta(minutes=30)
WINDOW = E.LiveWindow(
    name="A", start=datetime(2026, 10, 29, tzinfo=UTC), end=datetime(2026, 10, 30, tzinfo=UTC)
)


def label(record: str, *, published: datetime = PUBLISHED, **kw: object) -> MalwareLabel:
    return MalwareLabel.model_validate({"id": record, "published": published, **kw})


def save_labels(root: Path, fetched: datetime, labels: dict[str, tuple[MalwareLabel, ...]]) -> None:
    labelset = LabelSet(
        ecosystem="npm", source="t", fetched_at=fetched, source_sha256="0", labels=labels
    )
    path = root / "labels" / "npm" / f"{labelset.id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(labelset.model_dump_json())


def verdict(root: Path, name: str, kind: str, at: datetime, version: str = "1.0.1") -> None:
    append_verdict(
        root,
        VerdictRecord.model_validate(
            {
                "ecosystem": "npm",
                "name": name,
                "version": version,
                "verdict": kind,
                "at": at,
                "by": "claude",
                "run_id": R1,
                "rank": 1,
                "score": 6.0,
                "severity": "high",
            }
        ),
    )


def reported(name: str, score: float = 7, **kw: object) -> LiveVersion:
    return LiveVersion(
        name,
        static="rules: static.network",
        score=score,
        reported=True,
        rules=(("static.network", Severity.MEDIUM),),
        tarball_size=100,
        **kw,  # type: ignore[arg-type]
    )


@pytest.fixture
def data(tmp_path: Path) -> Path:
    root = tmp_path / "data"
    runs = root / "runs"
    write_live_run(
        runs,
        R1,
        [
            reported("evil-a"),  # OSV, reported: TP
            LiveVersion("evil-b", previous=None, triage="new package"),  # FN
            reported("probe"),  # OSV but reviewed benign: FP (behaviour), TP (OSV)
            reported("verd-mal"),  # reviewed malicious only: TP
            reported("noise"),  # unreviewed: FP
            LiveVersion("quiet"),  # TN
            reported("unsure"),  # inconclusive: excluded
            LiveVersion("taken"),  # takedown only: TN, FN with weak positives
            LiveVersion("proj"),  # projected: excluded
            LiveVersion("hold", version="0.0.1-security", publisher="npm"),  # placeholder
            LiveVersion("below", static="no signal", score=2, rules=(("npm.x", Severity.LOW),)),
            LiveVersion("nofiles", static="files unavailable: declared unpacked size 1 bytes"),
        ],
    )
    write_live_run(
        runs,
        R2,
        [
            LiveVersion("quiet"),  # seen in R1: counted once
            LiveVersion("late", published=REPORT_AS_OF - timedelta(hours=10)),  # catch-up
            LiveVersion("fresh", published=LABELS_AT - timedelta(days=1)),  # provisional
            LiveVersion("evil-c", published=REPORT_AS_OF - timedelta(hours=8)),  # catch-up FN
        ],
        as_of=REPORT_AS_OF + timedelta(hours=1),
        rules_hash="r2",
    )
    write_live_run(
        runs, R3, [LiveVersion("x")], as_of=REPORT_AS_OF + timedelta(hours=2), finished=False
    )
    save_labels(root, OLD_LABELS, {"evil-a": (label("MAL-1", versions=("1.0.1",)),)})
    save_labels(
        root,
        LABELS_AT,
        {
            "evil-a": (label("MAL-1", versions=("1.0.1",)),),
            "evil-b": (
                label(
                    "MAL-2",
                    published=PUBLISHED + timedelta(days=5),
                    ranges=(AffectedRange(introduced="0"),),
                ),
            ),
            "probe": (label("MAL-3", versions=("1.0.1",)),),
            "proj": (
                label(
                    "MAL-4",
                    published=PUBLISHED - timedelta(days=9),
                    ranges=(AffectedRange(introduced="0"),),
                ),
            ),
            "hold": (label("MAL-5", ranges=(AffectedRange(introduced="0"),)),),
            "evil-c": (label("MAL-6", versions=("1.0.1",)),),
        },
    )
    log = TakedownLog(
        ecosystem="npm",
        scanned_through=R2,
        takedowns=(
            Takedown(
                name="taken",
                version="0.0.1-security",
                published_at=PUBLISHED + timedelta(hours=3),
                run_id=R2,
            ),
            Takedown(
                name="evil-a",
                version="0.0.1-security",
                published_at=PUBLISHED + timedelta(hours=40),
                run_id=R2,
            ),
        ),
    )
    takedowns_path(root, "npm").parent.mkdir(parents=True)
    takedowns_path(root, "npm").write_text(log.model_dump_json())
    day = datetime(2026, 11, 1, tzinfo=UTC)
    verdict(root, "probe", "benign", day)
    verdict(root, "verd-mal", "malicious", day)
    verdict(root, "unsure", "inconclusive", day)
    verdict(root, "noise", "malicious", LABELS_AT + timedelta(days=1))  # after as_of: ignored
    return root


def build(data: Path) -> tuple[E.LiveReport, Path]:
    live = data.parent / "live"
    backfill(data / "runs", live)
    report, _, path = E.run_live_eval(
        E.LiveSources(data, live), built_at=LABELS_AT, windows=(WINDOW,)
    )
    return report, path


def test_matrices_follow_the_definitions(data: Path) -> None:
    report, _ = build(data)
    a = report.windows["A"]
    headline = a.matrices["behaviour"]
    assert (headline.tp, headline.fp, headline.fn, headline.tn) == (2, 2, 1, 4)
    assert headline.fp_unreviewed == 1
    assert headline.excluded == {
        "inconclusive": 1,
        "placeholder": 1,
        "projected": 1,
        "provisional": 1,
    }
    osv = a.matrices["osv"]
    assert (osv.tp, osv.fp, osv.fn) == (3, 1, 1)
    only = a.matrices["osv-only"]
    assert (only.tp, only.fp, only.fn, only.tn) == (2, 3, 1, 4)  # verd-mal, unsure: benign
    weak = a.matrices["behaviour+takedowns"]
    assert (weak.fn, weak.tn) == (2, 3)
    assert a.matrices["behaviour/D3"].tn == 4
    assert a.matrices["behaviour/D14"].excluded["provisional"] == 1
    assert a.versions == 13
    assert report.windows[E.CATCH_UP].matrices["behaviour"].fn == 1
    assert report.malicious == ("evil-a@1.0.1", "evil-b@1.0.1", "verd-mal@1.0.1")
    assert [m.name for m in report.misses] == ["evil-b"]
    assert report.misses[0].cause == "not read by Stage 2"
    assert (report.unfinished_runs, report.pending_runs) == (1, 0)
    assert a.recall_by_record.k == 1 and a.recall_by_record.n == 2
    assert a.late_labels == {"D3": 1, "D7": 0, "D14": 0}
    assert a.miss_causes == {"not read by Stage 2": {"new": 1}}
    assert a.funnel_malicious["all"]["entered"] == 3
    assert a.funnel_malicious["B"]["s1 forwarded"] == 1
    assert a.rules_tp_fp["static.network"] == [2, 2]
    assert a.verdicts_after_confirmation == 1  # probe: reviewed after MAL-3 was public
    sets = a.rule_sets
    assert sets.stage4 == {"8/r1": 1, "8/r2": 1} and not sets.single_version
    assert sets.unrecorded_pipeline == 2
    timing = report.timing
    assert timing["capture -> OSV published"].n == 4
    assert timing["capture -> npm takedown"].n == 1


def test_dataset_records_inputs_and_is_reproducible(data: Path) -> None:
    path = build(data)[1]
    first = path.read_bytes()
    header, samples = E.read_live_dataset(path)
    assert header.inputs.label_set == "20261120T000000Z"
    assert list(header.inputs.label_history) == ["20261030T000000Z"]
    assert header.inputs.verdict_lines == 3 and header.inputs.verdict_lines_total == 4
    assert len(header.inputs.ledgers) == 2 and header.unfinished == {R3: 4812}
    by = {s.name: s for s in samples}
    assert by["evil-a"].osv_first_set == "20261030T000000Z"
    assert by["evil-b"].osv_first_set == "20261120T000000Z"
    assert by["evil-a"].takedown is not None and by["proj"].projected
    assert by["hold"].placeholder and by["probe"].confirmation_seen
    build(data)
    assert path.read_bytes() == first
    log = E.read_log(data.parent / "live" / "log.jsonl")
    assert len(log) == 1  # the same dataset is logged once
    assert log[0].malicious == 3 and log[0].newly_labeled == 3


def test_newly_labeled_counts_against_the_previous_build(data: Path) -> None:
    build(data)
    verdict(data, "quiet", "malicious", LABELS_AT - timedelta(hours=1))
    build(data)
    log = E.read_log(data.parent / "live" / "log.jsonl")
    assert [x.newly_labeled for x in log] == [3, 1]


def test_markdown_escapes_and_covers_the_tables(data: Path) -> None:
    report, _ = build(data)
    md = E.render_live_markdown(report)
    assert "Behaviour truth (verdict wins; headline)" in md
    assert "| Why missed | New | Update |" in md
    assert "static.network" in md and "Single rule version: no" in md
    assert "capture -> OSV published" in md


def test_unfinished_runs_count_as_loss(data: Path) -> None:
    write_live_run(
        data / "runs",
        "20261119T230500Z-npm",
        [],
        as_of=LABELS_AT - timedelta(hours=1),
        finished=False,
    )
    write_live_run(
        data / "runs",
        "20261121T230500Z-npm",
        [],
        as_of=LABELS_AT + timedelta(hours=1),
        finished=False,
    )
    report, _ = build(data)
    assert (report.unfinished_runs, report.unfinished_changes) == (1, 4812)
    assert report.pending_runs == 1


def test_no_labels(tmp_path: Path) -> None:
    with pytest.raises(LookupError):
        E.build_live_dataset(E.LiveSources(tmp_path, tmp_path / "live"))


def test_missing_label_set_and_takedowns(data: Path) -> None:
    with pytest.raises(LookupError):
        E.build_live_dataset(E.LiveSources(data, data / "live"), label_set_id="nope")
    takedowns_path(data, "npm").unlink()
    (data / "runs" / "junk").mkdir()
    (data / "runs" / "junk" / "manifest.json").write_text("{}")
    report, _ = build(data)
    assert report.windows["A"].matrices["behaviour+takedowns"].fn == 1


def test_wilson_and_zero_bound() -> None:
    rate = wilson(34, 134)
    assert rate.low is not None and rate.high is not None
    assert (round(rate.low, 3), round(rate.high, 3)) == (0.188, 0.334)  # the proposal's numbers
    assert wilson(0, 0).value is None
    assert zero_bound(150) == pytest.approx(0.0198, abs=1e-4)
    assert zero_bound(0) is None


def test_stats_and_windows() -> None:
    t = E._stats([1.0, 2.0, 3.0, 10.0])
    assert (t.n, t.median_h, t.p75_h, t.max_h) == (4, 2.5, 3.0, 10.0)
    assert E._stats([]).median_h is None
    w = E.parse_window("B:2026-11-12:2026-11-19")
    assert w.contains(datetime(2026, 11, 18, 23, tzinfo=UTC))
    assert not w.contains(datetime(2026, 11, 19, tzinfo=UTC))


def test_truth_without_publish_time_is_provisional() -> None:
    sample = E.LiveSample(name="a", version="1", run_id=R1)
    assert E.truth(sample, "behaviour", settle_by=LABELS_AT) == "provisional"


def test_cli_eval_and_misses(data: Path) -> None:
    live = data.parent / "elsewhere"
    runner = CliRunner()
    args = ["--data-dir", str(data), "--live-dir", str(live)]
    empty = runner.invoke(app, ["live", "misses", *args])
    assert empty.exit_code == 2
    bad = runner.invoke(app, ["live", "eval", *args, "--window", "nonsense"])
    assert bad.exit_code == 2
    result = runner.invoke(app, ["live", "eval", *args, "--window", "A:2026-10-29:2026-10-30"])
    assert result.exit_code == 0, result.output
    assert "A         TP 2 FP 2 FN 1 TN 4" in result.output
    misses = runner.invoke(app, ["live", "misses", *args])
    assert misses.exit_code == 0 and "'evil-b'" in misses.output
    assert "1 missed" in misses.output
    nolabels = runner.invoke(app, ["live", "eval", *args, "--labels", "nope"])
    assert nolabels.exit_code == 2
    assert json.loads((live / "log.jsonl").read_text().splitlines()[0])["malicious"] == 3
