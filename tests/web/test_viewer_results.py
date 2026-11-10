"""The dashboard, the live-evaluation results and the review sample in the viewer.

The live reports are built with the real `evaluate_live` from a few inline samples, one of
which (a miss, and a sampled version) carries a crafted package name."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest

from conftest import REPORT_AS_OF, assert_inert, make_report, report_entry, run_manifest
from kitsunox.core.models import Severity
from kitsunox.core.run import DataDir
from kitsunox.evaluation.intervals import percent
from kitsunox.evaluation.live import (
    MATRIX_TITLES,
    LiveDatasetHeader,
    LiveInputs,
    LiveReport,
    LiveSample,
    RunInfo,
    evaluate_live,
    render_live_markdown,
    write_live_report,
)
from kitsunox.evaluation.sample import DailySample, SampledVersion, sample_bound, sample_path
from kitsunox.reporting.queue import build_queue, write_queue
from kitsunox.reporting.report import write_report
from kitsunox.reporting.verdicts import VerdictRecord, append_verdict
from kitsunox.util.hashing import sha256_hex
from kitsunox.web.library import Library
from kitsunox.web.server import Form, route

RUN = "20261030T120000Z-npm"  # on disk, with a report
GONE = "20261031T120000Z-npm"  # pruned: in the report, not on disk
OLD = "live-20261108T151126Z"
NEW = "live-20261109T113623Z"
AS_OF = datetime(2026, 11, 9, 11, 36, 23, tzinfo=UTC)
EVIL = '<script>alert("x")</script>'
EVIL_VERSION = "1.0.0\"'><img src=x onerror=alert(1)>"
TOKEN = "t" * 43


def sample(name: str, version: str, run_id: str = RUN, **fields: object) -> LiveSample:
    run_as_of = datetime(2026, 10, 30, 12, tzinfo=UTC)
    return LiveSample.model_validate(
        {
            "name": name,
            "version": version,
            "run_id": run_id,
            "published_at": run_as_of - timedelta(hours=1),
            "s2": "flagged",
            **fields,
        }
    )


def live_report(dataset: str = NEW, *, as_of: datetime = AS_OF, caught: bool = True) -> LiveReport:
    """TP 1 (or FN), FP 2, FN 2 (one crafted), TN 1, a placeholder and an unverified version."""
    samples = [
        sample(
            "caught", "1.0.0", rank=1 if caught else None, osv=("MAL-1",), rules=("r.a@1:high",)
        ),
        sample(EVIL, EVIL_VERSION, osv=("MAL-<b>2</b>",), verdict="malicious"),
        sample("gone-miss", "2.0.0", GONE, osv=("MAL-3",)),
        sample("noisy", "1.0.0", rank=2, rules=("r.a@1:high", "r.b@2:low")),
        sample("noisy", "1.0.1", rank=3, rules=("r.b@2:low",), verdict="benign"),
        sample("quiet", "1.0.0"),
        sample("held", "0.0.1-security", placeholder=True),
        sample("unsure", "1.0.0", rank=4, verdict="unverified", verdict_reason="gone"),
    ]
    header = LiveDatasetHeader(
        name=dataset,
        ecosystem="npm",
        as_of=as_of,
        inputs=LiveInputs(
            label_set=dataset.removeprefix("live-"),
            label_set_sha256="0" * 64,
            label_history={},
            takedowns_sha256=None,
            takedowns_scanned_through=None,
            verdicts_sha256="0" * 64,
            verdict_lines=0,
            verdict_lines_total=0,
            ledgers={},
        ),
        runs={
            run_id: RunInfo(
                as_of=datetime(2026, 10, 30, 12, tzinfo=UTC),
                window_hours=1.0,
                stage4_version=8,
                stage4_rules="abc",
                pipeline=None,
            )
            for run_id in (RUN, GONE)
        },
        unfinished={"20261101T000000Z-npm": 1234},
        pending={},
        samples=len(samples),
    )
    report = evaluate_live(header, samples, dataset_sha256=sha256_hex(dataset.encode()))
    bound = sample_bound([daily()], {}, {"A": (date(2026, 10, 29), date(2026, 11, 4))})
    return report.model_copy(update={"sample_bound": bound})


def daily(day: date = date(2026, 11, 8)) -> DailySample:
    return DailySample(
        day=day,
        ecosystem="npm",
        sizes={"U1": 20, "U2": 20, "U3": 15},
        ledgers={},
        population={"U1": 120, "U2": 30, "U3": 900},
        versions=(
            SampledVersion(
                stratum="U1",
                run_id=RUN,
                name=EVIL,
                version=EVIL_VERSION,
                score=1,
                new=True,
                hook=True,
                watched=False,
                rules=("static.network@1:medium",),
                tarball="ab" * 32,
                tarball_size=2048,
            ),
            SampledVersion(
                stratum="U3",
                run_id=GONE,
                name="plain",
                version="3.0.0",
                score=0,
                new=False,
                hook=False,
                watched=False,
            ),
        ),
    )


def verdict(name: str, version: str, kind: str, rank: int = 0, **fields: object) -> VerdictRecord:
    return VerdictRecord.model_validate(
        {
            "ecosystem": "npm",
            "name": name,
            "version": version,
            "verdict": kind,
            "at": AS_OF + timedelta(hours=2),
            "by": "claude",
            "run_id": RUN,
            "rank": rank,
            "score": 1,
            "severity": "low",
            **fields,
        }
    )


def populate(root: Path) -> DataDir:
    """A run with a report and a queue, two live builds, two sample days and some verdicts."""
    data = DataDir(root)
    report = make_report(
        RUN,
        report_entry(1, "queued", "1.0.0", 9, Severity.HIGH, "npm.install-hook"),
        as_of=REPORT_AS_OF + timedelta(days=11),
    )
    run_dir = data.run_dir(RUN)
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text(run_manifest(RUN).model_dump_json())
    write_report(run_dir, report)
    queue = build_queue(data, "npm", days=30)
    assert queue is not None
    write_queue(data, queue)
    live = root / "eval" / "live"
    for dataset, as_of, caught, built in (
        (OLD, AS_OF - timedelta(days=1), False, AS_OF - timedelta(hours=20)),
        (NEW, AS_OF, True, AS_OF + timedelta(hours=3)),
    ):
        built_report = live_report(dataset, as_of=as_of, caught=caught)
        write_live_report(live, built_report, render_live_markdown(built_report), built_at=built)
    for day in (date(2026, 11, 7), date(2026, 11, 8)):
        path = sample_path(live, day)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(daily(day).model_dump_json())
    append_verdict(root, verdict(EVIL, EVIL_VERSION, "benign", note="read it"))
    append_verdict(root, verdict("queued", "0.9.0", "malicious", rank=1))
    return data


@pytest.fixture
def library(tmp_path: Path) -> Library:
    return Library(populate(tmp_path / "data").root)


def get(library: Library, target: str, token: str | None = None) -> str:
    response = route(library, "GET", target, token=token)
    assert response.status == 200, target
    document = response.body.decode()
    assert_inert(document)
    return document


ALL_PAGES = (
    "/",
    "/queue",
    "/results",
    f"/results/{OLD}",
    f"/results/{NEW}",
    "/results/sample",
    "/results/sample/2026-11-07",
    "/verdicts",
)


# ----------------------------------------------------------------------------- results


def test_results_page_shows_the_headline_grid_and_every_matrix(library: Library) -> None:
    document = get(library, "/results")
    report = library.live_report(NEW)
    assert isinstance(report, LiveReport)
    assert f"<h1>Live evaluation {NEW}</h1>" in document
    assert '<table class="confusion">' in document
    assert '<span class="cell-label">TP</span> 1</td>' in document
    assert '<span class="cell-label">FN</span> 2</td>' in document
    assert '<span class="cell-label">FP</span> 2 <span class="note">1 unreviewed</span>' in document
    for title in MATRIX_TITLES.values():
        assert title in document
    assert "Behaviour truth, D = 3" in document and "Behaviour truth, D = 14" in document
    assert '<span class="tag">headline</span>' in document
    assert '<span class="tag">conservative</span>' in document
    # "all" first, then the report's own windows, as `render_live_markdown` lists them
    assert document.index("<h2>Window all</h2>") < document.index("<h2>Window A</h2>")
    assert document.index("<h2>Window A</h2>") < document.index("<h2>Window B</h2>")
    assert "<h2>Window B</h2>\n<p>runs from 2026-11-16 to 2026-11-23" in document
    assert "No versions yet." in document
    # the same numbers as the Markdown, in the same format
    headline = report.windows["all"].matrices["behaviour"]
    for rate in (headline.recall, headline.precision, headline.fpr):
        assert percent(rate) in document and percent(rate) in render_live_markdown(report)
    assert "before the rule freeze (window B, 2026-11-16 to 2026-11-23" in document
    assert "1 runs that never finished (1,234 changes)" in document
    assert "unverified 1" in document and "placeholder 1" in document
    for heading in ("Headline by shape", "Funnel", "Why missed", "Label timing", "Upper bounds"):
        assert heading in document
    assert "Recall by unit: version" in document and "Single rule version" in document


def test_rules_are_sorted_by_false_positives_with_precision(library: Library) -> None:
    document = get(library, "/results")
    section = document[document.index("most FP first") :]
    assert section.index("<code>r.b</code>") < section.index("<code>r.a</code>")
    assert '<code>r.b</code></td><td class="num">0</td><td class="num">2</td>' in section


def test_misses_are_listed_escaped_and_linked_where_kept(library: Library) -> None:
    document = get(library, "/results")
    misses = document[document.index("<h2>Misses (2)</h2>") : document.index("<h2>Trend</h2>")]
    assert "<script>" not in document and "&lt;script&gt;alert(&quot;x&quot;)" in misses
    assert "onerror=alert(1)&gt;" in misses and "<img" not in document
    assert "MAL-&lt;b&gt;2&lt;/b&gt;" in misses
    assert f'<a href="/runs/{RUN}">{RUN}</a>' in misses  # its run is on disk
    assert f'{GONE} <span class="note">(not on disk)</span>' in misses
    assert "read, findings below the report bar" in misses or "read, no finding" in misses


def test_a_specific_dataset_and_the_report_list(library: Library) -> None:
    older = get(library, f"/results/{OLD}")
    assert f"<h1>Live evaluation {OLD}</h1>" in older
    assert '<span class="cell-label">TP</span> 0</td>' in older
    assert f'<li><a href="/results/{NEW}">{NEW}</a>' in older
    assert f'<li>{OLD} <span class="tag">shown</span>' in older


@pytest.mark.parametrize(
    "target",
    [
        "/results/live-20991109T113623Z",  # well formed, not on disk
        "/results/live-2026",
        f"/results/{NEW}.json",
        f"/results/{NEW}.md",
        "/results/..%2flog.jsonl",
        "/results/../queue",
        "/results/datasets",
        "/results/sample/2026-01-01",
        "/results/sample/2026-11-08.json",
        "/results/sample/x",
        "/results/sample/2026-11-08/x",
        f"/results/{NEW}/x",
    ],
)
def test_unknown_or_malformed_ids_are_404(library: Library, target: str) -> None:
    assert route(library, "GET", target).status == 404


def test_trend_chart_and_table(library: Library) -> None:
    document = get(library, "/results")
    trend = document[document.index("<h2>Trend</h2>") :]
    assert '<svg class="chart"' in trend and "style=" not in trend
    assert trend.count('<circle class="m-recall"') == 2
    assert trend.count('<rect class="m-precision"') == 2
    assert "<title>Recall 33.3%, built" in trend and "<title>Recall 0.0%, built" in trend
    assert f'<a href="/results/{OLD}">{OLD}</a>' in trend
    assert '33.3% <span class="note">(1/3)</span>' in trend


def test_one_build_has_no_chart_yet(tmp_path: Path) -> None:
    report = live_report()
    write_live_report(
        tmp_path / "eval" / "live", report, render_live_markdown(report), built_at=AS_OF
    )
    document = get(Library(tmp_path), "/results")
    assert "The chart appears once two builds are logged." in document
    assert "<svg" not in document


# ----------------------------------------------------------------------------- sample


def test_sample_page_shows_progress_and_current_verdicts(library: Library) -> None:
    document = get(library, "/results/sample")
    assert "<h1>Review sample 2026-11-08</h1>" in document
    assert "1 of 2 sampled versions have a verdict</strong>: 1 reviewed" in document
    assert '<span class="v-benign"><strong>Benign</strong></span>' in document
    assert '<span class="note">not reviewed</span>' in document
    assert "U1: unreported, score &gt; 0" in document and ">120<" in document
    assert "yes (2,048 B)" in document and "new, hook" in document
    assert "<script>" not in document and "&lt;script&gt;" in document
    assert '<a href="/results/sample/2026-11-07">2026-11-07</a>' in document
    day = get(library, "/results/sample/2026-11-07")
    assert "<h1>Review sample 2026-11-07</h1>" in day


# ----------------------------------------------------------------------------- dashboard


def test_dashboard_shows_the_headline_review_state_and_freshness(library: Library) -> None:
    document = get(library, "/")
    assert f'<a href="/results/{NEW}">{NEW}</a>' in document
    assert '<p class="tile-value">33.3%</p>' in document  # recall 1/3
    assert '<p class="tile-value">33.3%</p>' in document  # precision 1/3
    assert "1 of 3" in document
    assert "Strict, malicious only" in document and "OSV truth (OSV wins" in document
    assert "Verified malicious: 1" in document
    assert '<a href="/queue">Review queue: 1 packages</a> (1 versions)' in document
    assert '<a href="/results/sample/2026-11-08">Review sample 2026-11-08</a>: 1 of 2' in document
    assert f'Newest run <a href="/runs/{RUN}">{RUN}</a>' in document
    # "now" is the newest run's as_of (2026-11-09 21:05), never the clock
    assert "(9 h before the newest run)" in document


def test_rendering_is_byte_stable_and_writes_nothing(tmp_path: Path) -> None:
    one = Library(populate(tmp_path / "one").root)
    two = Library(populate(tmp_path / "two").root)
    before = sorted(p.relative_to(one.root) for p in one.root.rglob("*"))
    first = [get(one, target) for target in ALL_PAGES]
    assert first == [get(one, target) for target in ALL_PAGES]
    assert first == [get(two, target) for target in ALL_PAGES]
    assert sorted(p.relative_to(one.root) for p in one.root.rglob("*")) == before


# ----------------------------------------------------------------------------- empty, broken


def test_no_live_evaluation_is_a_helpful_empty_state(tmp_path: Path) -> None:
    library = Library(tmp_path)
    for target in ("/", "/results"):
        assert "No live evaluation yet: run <code>kitsunox live eval</code>" in get(library, target)
    assert "No review sample yet" in get(library, "/results/sample")
    assert "No run has a report yet" in get(library, "/")


def test_broken_files_are_error_boxes(library: Library) -> None:
    live = library.root / "eval" / "live"
    (live / "reports" / f"{NEW}.json").write_text('{"schema_version": 1, "dataset": 5}')
    (live / "sample" / "2026-11-08.json").write_text("not json")
    with (live / "log.jsonl").open("a") as handle:
        handle.write("{broken\n")
    results_page = get(library, "/results")
    assert '<div class="error" role="alert">' in results_page
    assert f"<code>reports/{NEW}.json</code> does not match this build" in results_page
    assert f'<a href="/results/{OLD}">{OLD}</a>' in results_page  # the others stay reachable
    dashboard = get(library, "/")
    assert f"<code>{NEW}.json</code> does not match" in dashboard
    sample_page = get(library, "/results/sample")
    assert "<code>sample/2026-11-08.json</code>" in sample_page
    older = get(library, f"/results/{OLD}")
    assert "1 lines of the log could not be read." in older
    assert 'class="bad">' in get(library, "/results/sample/2026-11-07")


def test_files_are_reloaded_when_rewritten(library: Library) -> None:
    assert "<h1>Review sample 2026-11-08</h1>" in get(library, "/results/sample")
    path = sample_path(library.root / "eval" / "live", date(2026, 11, 9))
    path.write_text(daily(date(2026, 11, 9)).model_dump_json())
    assert "<h1>Review sample 2026-11-09</h1>" in get(library, "/results/sample")
    append_verdict(library.root, verdict("plain", "3.0.0", "unverified", reason="remote"))
    assert "2 of 2 sampled versions have a verdict" in get(library, "/results/sample")


# ----------------------------------------------------------------------------- the queue


def test_the_queue_moved_and_verdicts_return_to_it(library: Library) -> None:
    queue = route(library, "GET", "/queue", token=TOKEN).body.decode()  # forms: not `get`
    assert "<h1>Review queue (npm)</h1>" in queue
    assert '<input type="hidden" name="back" value="/queue">' in queue
    assert '<input type="hidden" name="back" value="/">' not in queue
    nav = '<a href="/">Dashboard</a> <a href="/queue">Queue</a> <a href="/results">Results</a>'
    assert nav in queue
    for back, expected in (("/queue", "/queue"), ("", "/queue"), ("/", "/"), ("//x", "/queue")):
        fields = f"token={TOKEN}&run={RUN}&rank=1&verdict=reopened" + (
            f"&back={back}" if back else ""
        )
        response = route(library, "POST", "/verdict", token=TOKEN, form=Form(fields.encode(), True))
        assert response.status == 303
        assert dict(response.headers)["Location"] == expected


def test_every_page_is_inert(library: Library) -> None:
    for target in ALL_PAGES:
        get(library, target)
