import json
import shutil
from datetime import timedelta
from pathlib import Path

from typer.testing import CliRunner

from conftest import REPORT_AS_OF, LiveVersion, write_live_run
from kitsunox import collect
from kitsunox.cli import app
from kitsunox.core.models import Severity
from kitsunox.evaluation import ledger as L

RUN = "20261029T210500Z-npm"


def versions() -> list[LiveVersion]:
    return [
        LiveVersion("quiet"),
        LiveVersion(
            "evil",
            previous=None,
            triage="new package",
            static="rules: static.exfil",
            ast="rules: code.x",
            score=9,
            reported=True,
            rules=(("static.exfil", Severity.HIGH), ("repo.compared", Severity.INFO)),
            tarball_size=900,
            hook=True,
        ),
        LiveVersion(
            "big",
            triage="unpacked size grew by 70000 bytes",
            static="files unavailable: declared unpacked size 99999999 bytes",
            ast="files unavailable: declared unpacked size 99999999 bytes",
        ),
        LiveVersion(
            "popular",
            watched=True,
            triage="watched package",
            static="no signal",
            ast="no signal",
            tarball_size=70_000,
            base_size=60_000,
            score=2,
            rules=(("npm.x", Severity.LOW),),
        ),
    ]


def test_ledger_rows_record_each_stage(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    write_live_run(runs, RUN, versions())
    path = L.write_ledger(runs, tmp_path / "live", RUN)
    assert path == L.ledger_path(tmp_path / "live", RUN)
    header, rows = L.read_ledger(path)
    by = {r.name: r for r in rows}
    assert header.versions == 4 and header.reported == 1
    assert (header.stage4_version, header.stage4_rules, header.report_score) == (8, "r1", 6.0)
    assert header.pipeline is None and header.variant == "tick"
    assert set(header.inputs) >= {"correlate.jsonl", "report.json", "static-snapshot.json"}
    evil = by["evil"]
    assert (evil.s1, evil.s1_forwarded, evil.s2, evil.s3) == ("new", True, "flagged", "flagged")
    assert evil.new_package and evil.hook and evil.reported and evil.rank == 1
    assert evil.rules == ("static.exfil@1:high",)  # INFO left out
    assert evil.rule_ids == ("static.exfil",)
    assert evil.tarball is not None and evil.tarball_size == 900
    assert (by["quiet"].s1, by["quiet"].s2, by["quiet"].rank) == ("none", "unread", None)
    assert (by["big"].s1, by["big"].s2) == ("grown", "no-files")
    popular = by["popular"]
    assert (popular.s1, popular.s2, popular.score) == ("watched", "clear", 2.0)
    assert popular.base_tarball_size == 60_000 and popular.watched


def test_ledger_is_deterministic_and_written_once(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    write_live_run(runs, RUN, versions())
    first = L.build_ledger(runs / RUN)
    assert first == L.build_ledger(runs / RUN)
    assert L.write_ledger(runs, tmp_path / "live", RUN) is not None
    assert L.write_ledger(runs, tmp_path / "live", RUN) is None  # already written


def test_unfinished_run_gets_no_ledger(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    write_live_run(runs, RUN, versions(), finished=False)
    assert L.write_ledger(runs, tmp_path / "live", RUN) is None
    assert L.write_ledger(runs, tmp_path / "live", RUN, "rescored") is None


def test_rescored_run_keeps_the_ticks_decisions(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    run_dir = write_live_run(runs, RUN, versions())
    originals = run_dir / L.RESCORE_ORIGINALS
    originals.mkdir()
    for name in ("correlate.jsonl", "correlate.json", "static-snapshot.json"):
        shutil.copy2(run_dir / name, originals / name)
    shutil.copytree(run_dir / "report", originals / "report")
    # The re-score reports nothing.
    write_live_run(runs, RUN, [LiveVersion(v.name) for v in versions()], rules_hash="r2")
    (run_dir / L.RESCORE_INFO).write_text(json.dumps({"rescored_at": "2026-11-01T00:00:00"}))
    live = tmp_path / "live"
    written = L.backfill(runs, live)
    assert [p.name for p in written] == [f"{RUN}.jsonl.zst", f"{RUN}.rescored.jsonl.zst"]
    tick = L.ledgers(live)
    rescored = L.ledgers(live, "rescored")
    assert [t.header.reported for t in tick] == [1]
    assert tick[0].header.stage4_rules == "r1"
    assert [(r.header.reported, r.header.stage4_rules) for r in rescored] == [(0, "r2")]
    assert sum(1 for _ in tick[0].rows()) == 4
    assert L.backfill(runs, live) == []  # nothing new
    (run_dir / L.RESCORE_INFO).write_text(json.dumps({"rescored_at": "2026-11-02T00:00:00"}))
    assert L.backfill(runs, live) == [L.ledger_path(live, RUN, "rescored")]


def test_constants_match_collect() -> None:
    assert L.RESCORE_ORIGINALS == collect.RESCORE_ORIGINALS
    assert L.RESCORE_INFO == collect.RESCORE_INFO


def test_stage1_routes() -> None:
    assert L.stage1_route("install hook") == "hook"
    assert L.stage1_route("unpacked size unknown") == "size-unknown"
    assert L.stage1_route("something new") == "other"
    assert L.stage1_route("rules: npm.install-hook") == "rules"


def test_pipeline_fingerprints_cover_every_stage() -> None:
    prints = L.pipeline_fingerprints()
    assert set(prints) == {"tool", "stage1", "stage2", "stage3", "stage4", "stage4_version"}


def test_lenient_readers(tmp_path: Path) -> None:
    (tmp_path / "r.json").write_text(
        '{"entries": [{"name": 1}, "x", {"name": "a", "version": "1", "rank": 2}]}'
    )
    assert L.report_ranks(tmp_path / "r.json") == {("a", "1"): 2}
    (tmp_path / "s.json").write_text('{"entries": {"k": {"status": 200, "url": 3}, "j": 4}}')
    assert L.captured_tarballs(tmp_path / "s.json") == {}
    assert L.captured_tarballs(tmp_path / "missing.json") == {}
    assert L.ledgers(tmp_path) == []
    assert (L._int(True), L._float("x"), L._str(1)) == (None, None, None)


def test_cli_backfill_outside_the_data_dir(tmp_path: Path) -> None:
    data = tmp_path / "data"
    write_live_run(data / "runs", RUN, versions())
    write_live_run(
        data / "runs",
        "20261029T220500Z-npm",
        [LiveVersion("later")],
        as_of=REPORT_AS_OF + timedelta(hours=1),
    )
    live = tmp_path / "elsewhere"
    result = CliRunner().invoke(
        app, ["live", "ledger", "--data-dir", str(data), "--live-dir", str(live)]
    )
    assert result.exit_code == 0, result.output
    assert "2 ledgers written" in result.output
    assert not (data / ".lock").exists()  # outside the data dir: no lock taken
    inside = CliRunner().invoke(app, ["live", "ledger", RUN, "--data-dir", str(data)])
    assert inside.exit_code == 0 and "1 ledgers written" in inside.output
    assert (data / ".lock").exists()
