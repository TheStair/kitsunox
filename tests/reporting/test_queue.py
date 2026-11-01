"""The review queue: one entry per package across runs, each version once, byte-stable."""

from datetime import timedelta
from pathlib import Path

from conftest import REPORT_AS_OF, make_report, report_entry, run_manifest
from kitsunox.core.models import Severity
from kitsunox.core.run import DataDir
from kitsunox.evaluation.confirmations import Confirmations, Takedown
from kitsunox.reporting.markdown import write_markdown
from kitsunox.reporting.queue import build_queue, render_queue, write_queue
from kitsunox.reporting.report import Report, write_report
from kitsunox.reporting.verdicts import verdict_record

HIGH, MEDIUM = Severity.HIGH, Severity.MEDIUM
T = REPORT_AS_OF


def save(data: DataDir, report: Report) -> None:
    """A run as `collect` leaves it: manifest, report.json and the Markdown pages."""
    run_dir = data.run_dir(report.run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    manifest = run_manifest(report.run_id, as_of=report.as_of, ecosystem=report.ecosystem)
    (run_dir / "manifest.json").write_text(manifest.model_dump_json())
    write_report(run_dir, report)
    write_markdown(run_dir / "report", report)


def test_versions_are_grouped_by_package_and_counted_once(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    first = make_report(
        "20261029T200000Z-npm",
        report_entry(1, "cli", "0.1", 9, MEDIUM, "a", "b", published_at=T - timedelta(hours=2)),
        report_entry(2, "cli", "0.2", 7, MEDIUM, "a", published_at=T - timedelta(minutes=70)),
        as_of=T - timedelta(hours=1),
    )
    # The next chained run overlaps: it reports 0.2 again, then 0.3.
    second = make_report(
        "20261029T210500Z-npm",
        report_entry(1, "cli", "0.3", 12, HIGH, "a", "c"),
        report_entry(2, "cli", "0.2", 8, MEDIUM, "a", published_at=T - timedelta(minutes=70)),
        report_entry(3, "other", "1.0", 3, MEDIUM, "b"),
    )
    save(data, first)
    save(data, second)
    queue = build_queue(data, "npm", days=7)
    assert queue is not None
    assert (queue.packages, queue.versions) == (2, 4)
    assert queue.runs == ("20261029T200000Z-npm", "20261029T210500Z-npm")
    cli, other = queue.entries
    assert (cli.rank, cli.name, cli.score, cli.severity) == (1, "cli", 12, HIGH)
    assert [v.version for v in cli.versions] == ["0.3", "0.2", "0.1"]  # newest first
    # 0.2 keeps its stronger sighting: the later run scored it 8.
    v02 = cli.versions[1]
    assert (v02.run_id, v02.score) == ("20261029T210500Z-npm", 8)
    assert v02.page == "../runs/20261029T210500Z-npm/report/entries/0002-cli@0.2.md"
    assert [(r.rule_id, r.versions) for r in cli.rules] == [("a", 3), ("b", 1), ("c", 1)]
    assert other.rank == 2
    assert queue.by_severity == {"high": 1, "medium": 1}


def test_order_is_score_then_severity_then_name(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    save(
        data,
        make_report(
            "r",
            report_entry(1, "b", "1", 5, MEDIUM),
            report_entry(2, "a", "1", 5, MEDIUM),
            report_entry(3, "c", "1", 5, HIGH),
            report_entry(4, "d", "1", 9, MEDIUM),
        ),
    )
    queue = build_queue(data, "npm", days=7)
    assert queue is not None
    assert [e.name for e in queue.entries] == ["d", "c", "a", "b"]


def test_window_ends_at_the_newest_report_not_the_clock(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    save(
        data, make_report("old", report_entry(1, "old", "1", 9, HIGH), as_of=T - timedelta(days=8))
    )
    save(data, make_report("new", report_entry(1, "new", "1", 9, HIGH)))
    save(data, make_report("pypi", report_entry(1, "py", "1", 9, HIGH), ecosystem="pypi"))
    queue = build_queue(data, "npm", days=7)
    assert queue is not None
    assert queue.as_of == T and queue.since == T - timedelta(days=7)
    assert [e.name for e in queue.entries] == ["new"]
    assert build_queue(DataDir(tmp_path / "empty"), "npm", days=7) is None


def test_unreadable_reports_are_listed_not_fatal(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    save(data, make_report("good", report_entry(1, "x", "1", 9, HIGH)))
    save(data, make_report("broken", as_of=T - timedelta(hours=1)))
    save(data, make_report("ancient", as_of=T - timedelta(days=30)))
    for run_id in ("broken", "ancient"):
        (data.run_dir(run_id) / "report" / "report.json").write_bytes(b'{"truncated": ')
    queue = build_queue(data, "npm", days=7)
    assert queue is not None
    # Only reports inside the window are read, and so only those can be unreadable.
    assert queue.skipped == ("broken",) and queue.runs == ("good",) and queue.packages == 1
    assert "Unreadable reports, left out: broken" in render_queue(queue)


def test_queue_is_byte_stable(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    save(data, make_report("r", report_entry(1, "x", "1", 9, HIGH, "a")))
    queue = build_queue(data, "npm", days=7)
    assert queue is not None
    directory = write_queue(data, queue)
    before = {p.name: p.read_bytes() for p in directory.iterdir()}
    again = build_queue(data, "npm", days=7)
    assert again is not None
    write_queue(data, again)
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == before
    assert set(before) == {"queue.json", "index.md"}


def test_untrusted_names_cannot_break_the_table(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    name = "evil|<script>x</script>[a](javascript:b)\n| 2 |"
    save(data, make_report("r", report_entry(1, name, "1|`v`", 9, HIGH)))
    queue = build_queue(data, "npm", days=7)
    assert queue is not None
    index = render_queue(queue)
    row = next(line for line in index.splitlines() if line.startswith("| 1 |"))
    assert "<script>" not in index and "\n| 2 |" not in index
    # Exactly the table's own 8 column separators remain unescaped.
    assert row.replace("\\|", "").count("|") == 9


def test_empty_queue_says_so(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    save(data, make_report("r"))
    queue = build_queue(data, "npm", days=7)
    assert queue is not None and queue.packages == 0
    assert "Nothing to review." in render_queue(queue)


def test_a_tie_keeps_the_earliest_sighting(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    save(data, make_report("a", report_entry(1, "x", "1", 5, HIGH), as_of=T - timedelta(hours=1)))
    save(data, make_report("b", report_entry(3, "x", "1", 5, HIGH)))
    queue = build_queue(data, "npm", days=7)
    assert queue is not None
    assert queue.entries[0].versions[0].run_id == "a"


def test_every_version_link_resolves(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    crafted = "@sc/x (a) ../../etc"
    save(
        data,
        make_report(
            "r1",
            report_entry(1, crafted, "1.0.0 (beta)/../x", 9, HIGH),
            report_entry(2, "plain", "2.0.0", 4, MEDIUM),
        ),
    )
    queue = build_queue(data, "npm", days=7)
    assert queue is not None
    directory = write_queue(data, queue)
    pages = [v.page for e in queue.entries for v in e.versions]
    assert len(pages) == 2
    for page in pages:
        target = (directory / page).resolve()
        assert target.is_file(), page
        assert target.is_relative_to((tmp_path / "runs" / "r1" / "report" / "entries").resolve())
        assert " " not in page and "(" not in page and ")" not in page


def test_versions_confirmed_since_are_flagged_never_scored(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    save(
        data,
        make_report(
            "r",
            report_entry(
                1, "stealer", "1.0.0", 5, MEDIUM, "a", published_at=T - timedelta(hours=3)
            ),
            report_entry(
                2, "cleared", "2.0.0", 4, MEDIUM, "b", published_at=T - timedelta(hours=3)
            ),
            report_entry(3, "queued", "0.1.0", 3, MEDIUM, "c", published_at=T - timedelta(hours=3)),
        ),
    )
    report = Report.load_json((data.run_dir("r") / "report" / "report.json").read_bytes())
    at = T - timedelta(hours=1)
    stealer, cleared = report.entries[:2]
    reviewed = {
        ("stealer", "1.0.0"): verdict_record(report, stealer, "malicious", by="claude", at=at),
        ("cleared", "2.0.0"): verdict_record(report, cleared, "benign", by="claude", at=at),
    }
    takedowns = [
        Takedown(name=n, version="0.0.1-security", published_at=at, run_id="r")
        for n in ("stealer", "cleared", "queued")
    ]
    queue = build_queue(
        data, "npm", days=7, reviewed=reviewed, confirmations=Confirmations(takedowns, None, T)
    )
    assert queue is not None
    (entry,) = queue.entries
    assert (entry.name, entry.score, entry.confirmed) == ("queued", 3, True)  # score unchanged
    assert [(c.verdict, c.name) for c in queue.confirmed] == [
        ("benign", "cleared"),  # a missed attack first
        ("malicious", "stealer"),
    ]
    page = render_queue(queue)
    assert "1 malicious, 0 inconclusive, 1 benign" in page
    assert (
        "- **benign** cleared@2.0.0: removed by the registry 2026-10-29. Review it again." in page
    )
    assert "stealer@1.0.0" not in page  # confirmed malicious: counted, not listed
    assert page.rstrip().endswith("| removed by the registry 2026-10-29 |")


def test_a_version_like_one_reviewed_benign_is_hinted_not_dropped(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    old = report_entry(1, "cli", "1.0.0", 5, MEDIUM, "a", published_at=T - timedelta(hours=5))
    old = old.model_copy(update={"publisher": "alice"})
    same = report_entry(2, "cli", "1.0.1", 5, MEDIUM, "a").model_copy(update={"publisher": "alice"})
    other = report_entry(3, "cli", "1.0.2", 5, MEDIUM, "b").model_copy(
        update={"publisher": "alice"}
    )
    taken = report_entry(4, "cli", "1.0.3", 5, MEDIUM, "a").model_copy(update={"publisher": "eve"})
    save(data, make_report("r", old, same, other, taken))
    report = Report.load_json((data.run_dir("r") / "report" / "report.json").read_bytes())
    reviewed = {("cli", "1.0.0"): verdict_record(report, report.entries[0], "benign", by="x", at=T)}
    queue = build_queue(data, "npm", days=7, reviewed=reviewed)
    assert queue is not None
    (entry,) = queue.entries
    assert {v.version: v.like for v in entry.versions} == {
        "1.0.1": "1.0.0",  # same publisher, same rules
        "1.0.2": None,  # another rule fired
        "1.0.3": None,  # another publisher
    }
    assert "(like 1.0.0, cleared)" in render_queue(queue)
