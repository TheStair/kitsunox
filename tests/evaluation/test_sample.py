from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from conftest import REPORT_AS_OF, LiveVersion, write_live_run
from kitsunox.cli import app
from kitsunox.core.models import Severity
from kitsunox.evaluation import sample as S
from kitsunox.evaluation.labels import LabelSet
from kitsunox.evaluation.ledger import LedgerRow, backfill, ledgers
from kitsunox.evaluation.live import LiveSources, LiveWindow, render_live_markdown, run_live_eval
from kitsunox.reporting.verdicts import VerdictRecord, current, read_verdicts

DAY1 = "20261029T210500Z-npm"
DAY1B = "20261029T220500Z-npm"
DAY2 = "20261030T010500Z-npm"
DAY = date(2026, 10, 29)


def many(prefix: str, n: int, **kw: object) -> list[LiveVersion]:
    return [LiveVersion(f"{prefix}{i}", **kw) for i in range(n)]  # type: ignore[arg-type]


def setup(tmp_path: Path) -> tuple[Path, Path]:
    runs, live = tmp_path / "data" / "runs", tmp_path / "live"
    write_live_run(
        runs,
        DAY1,
        [
            *many("u1-", 30, score=2, rules=(("npm.x", Severity.LOW),)),
            *many("u2-", 25, previous=None),
            *many("u3-", 10, watched=True),
            LiveVersion("rep", reported=True, score=9, rules=(("static.network", Severity.HIGH),)),
            LiveVersion("hold", version="0.0.1-security", publisher="npm"),
        ],
    )
    write_live_run(
        runs,
        DAY1B,
        [*many("u3-", 3, watched=True), LiveVersion("hooked", hook=True)],
        as_of=REPORT_AS_OF + timedelta(hours=1),
    )
    write_live_run(runs, DAY2, [LiveVersion("next")], as_of=REPORT_AS_OF + timedelta(hours=4))
    backfill(runs, live)
    return runs, live


def test_strata() -> None:
    row = LedgerRow(name="a", version="1", previous="0")
    assert S.stratum(row) == "U3"
    assert S.stratum(row.model_copy(update={"score": 1.0})) == "U1"
    assert S.stratum(row.model_copy(update={"hook": True})) == "U2"
    assert S.stratum(row.model_copy(update={"hook": True, "watched": True})) == "U3"
    assert S.stratum(row.model_copy(update={"rank": 3})) is None
    assert S.stratum(row.model_copy(update={"placeholder": True})) is None


def test_daily_sample_is_label_blind_and_deterministic(tmp_path: Path) -> None:
    runs, live = setup(tmp_path)
    assert S.due_days(runs, live) == [DAY]  # day 2 isn't over: no later run yet
    written = S.write_samples(runs, live)
    assert [s.day for s in written] == [DAY]
    sample = written[0]
    assert sample.population == {"U1": 30, "U2": 26, "U3": 10}  # u3- re-emitted counts once
    counts = {s: sum(v.stratum == s for v in sample.versions) for s in ("U1", "U2", "U3")}
    assert counts == {"U1": 20, "U2": 20, "U3": 10}
    expected = sorted((S.order_key(DAY, "npm", f"u1-{i}", "1.0.1"), f"u1-{i}") for i in range(30))[
        :20
    ]
    assert [v.name for v in sample.versions if v.stratum == "U1"] == [n for _, n in expected]
    again = S.draw(DAY, [lg for lg in ledgers(live) if lg.header.run_id != DAY2])
    assert again == sample
    assert S.write_samples(runs, live) == []  # written once
    md = S.sample_path(live, DAY).with_suffix(".md").read_text()
    assert "kitsunox live verdict" in md and "u1\\-" in md
    assert [s.day for s in S.read_samples(live)] == [DAY]


def test_open_day_waits_for_its_runs(tmp_path: Path) -> None:
    runs, live = setup(tmp_path)
    write_live_run(
        runs, "20261029T230500Z-npm", [], as_of=REPORT_AS_OF + timedelta(hours=2), finished=False
    )
    (runs / "junk").mkdir()
    assert S.due_days(runs, live) == []
    assert S.write_samples(runs, live) == []
    assert S.due_days(runs, live, since=date(2026, 10, 30)) == []
    assert S.due_days(runs, tmp_path / "nothing") == []
    assert S.read_samples(tmp_path / "nothing") == []


def verdict_on(name: str, kind: str) -> VerdictRecord:
    return VerdictRecord.model_validate(
        {
            "ecosystem": "npm",
            "name": name,
            "version": "1.0.1",
            "verdict": kind,
            "at": REPORT_AS_OF,
            "by": "claude",
            "run_id": DAY1,
            "rank": 0,
            "score": 0,
            "severity": "info",
        }
    )


def test_bound_from_reviewed_sample(tmp_path: Path) -> None:
    runs, live = setup(tmp_path)
    sample = S.write_samples(runs, live)[0]
    u1 = [v.name for v in sample.versions if v.stratum == "U1"]
    u2 = [v.name for v in sample.versions if v.stratum == "U2"]
    verdicts = {(n, "1.0.1"): verdict_on(n, "benign") for n in u1}
    verdicts[(u2[0], "1.0.1")] = verdict_on(u2[0], "malicious")
    verdicts[(u2[1], "1.0.1")] = verdict_on(u2[1], "inconclusive")
    bound = S.sample_bound(
        [sample],
        verdicts,
        {"A": (DAY, date(2026, 10, 30)), "B": (date(2026, 11, 12), date(2026, 11, 19))},
    )
    strata = bound["all"]["strata"]  # type: ignore[index]
    assert strata["U1"]["reviewed"] == 20 and strata["U1"]["malicious"] == 0
    assert strata["U1"]["upper"] == pytest.approx(1 - 0.05 ** (1 / 20))
    assert strata["U2"]["reviewed"] == 1 and strata["U2"]["upper"] == 1.0
    assert strata["U3"]["upper"] is None
    assert bound["all"]["unreviewed_strata"] == ["U3"]  # type: ignore[index]
    assert bound["A"]["days"] == 1 and bound["B"]["days"] == 0  # type: ignore[index]
    assert bound["B"]["upper_share"] is None  # type: ignore[index]


def test_ledger_verdict_has_rank_zero(tmp_path: Path) -> None:
    _, live = setup(tmp_path)
    header, row = S.find_row(live, DAY1, "u1-3", "1.0.1")
    record = S.ledger_verdict(header, row, "benign", by="claude", at=REPORT_AS_OF, tags=("probe",))
    assert (record.rank, record.severity, record.rules, record.tags) == (
        0,
        "low",
        ("npm.x",),
        ("probe",),
    )
    header, rep = S.find_row(live, DAY1, "rep", "1.0.1")
    assert S.ledger_verdict(header, rep, "malicious", by="x", at=REPORT_AS_OF).rank == 1
    with pytest.raises(ValueError, match="reviewer"):
        S.ledger_verdict(header, row, "benign", by="Bad Name", at=REPORT_AS_OF)
    with pytest.raises(ValueError, match="tags"):
        S.ledger_verdict(header, row, "reopened", by="x", at=REPORT_AS_OF, tags=("probe",))
    with pytest.raises(LookupError):
        S.find_row(live, DAY1, "absent", "1")
    with pytest.raises(LookupError):
        S.find_row(live, "nope", "a", "1")


def test_cli_sample_and_verdict(tmp_path: Path) -> None:
    runs, live = setup(tmp_path)
    data = runs.parent
    args = ["--data-dir", str(data), "--live-dir", str(live)]
    runner = CliRunner()
    assert runner.invoke(app, ["live", "sample", *args, "--since", "x"]).exit_code == 2
    result = runner.invoke(app, ["live", "sample", *args])
    assert result.exit_code == 0, result.output
    assert "sample 2026-10-29: 50 versions" in result.output and "to review" in result.output
    name = S.read_samples(live)[0].versions[0].name
    ok = runner.invoke(
        app, ["live", "verdict", DAY1, name, "1.0.1", "benign", "--by", "claude", "--probe", *args]
    )
    assert ok.exit_code == 0, ok.output
    assert "rank 0" in ok.output
    assert current(read_verdicts(data, "npm"))[(name, "1.0.1")].verdict == "benign"
    listed = runner.invoke(app, ["live", "sample", *args])
    assert f"'{name}' '1.0.1' score" in listed.output and ": benign" in listed.output
    bad = runner.invoke(app, ["live", "verdict", DAY1, name, "1.0.1", "evil", *args])
    assert bad.exit_code == 2
    missing = runner.invoke(app, ["live", "verdict", DAY1, "zzz", "1", "benign", *args])
    assert missing.exit_code == 2
    empty = runner.invoke(
        app,
        ["live", "sample", "--data-dir", str(tmp_path / "x"), "--live-dir", str(tmp_path / "y")],
    )
    assert "no sample yet" in empty.output


def test_bound_reaches_the_live_report(tmp_path: Path) -> None:
    runs, live = setup(tmp_path)
    S.write_samples(runs, live)
    data = runs.parent
    labels = LabelSet(
        ecosystem="npm",
        source="t",
        fetched_at=datetime(2026, 11, 20, tzinfo=UTC),
        source_sha256="0",
        labels={},
    )
    (data / "labels" / "npm").mkdir(parents=True)
    (data / "labels" / "npm" / f"{labels.id}.json").write_text(labels.model_dump_json())
    window = LiveWindow(
        name="A", start=datetime(2026, 10, 29, tzinfo=UTC), end=datetime(2026, 10, 31, tzinfo=UTC)
    )
    report, _, _ = run_live_eval(
        LiveSources(data, live), built_at=labels.fetched_at, windows=(window,)
    )
    assert report.sample_bound["A"]["days"] == 1  # type: ignore[index]
    assert "Review sample: malware nobody labeled" in render_live_markdown(report)
