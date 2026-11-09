"""The viewer's pages: what they show, escaping of untrusted text, schemas, stability.

The fixture data directory is laid out as `collect` leaves it, with one crafted entry whose
every package string tries to break out of the page."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from conftest import REPORT_AS_OF, assert_inert, make_report, report_entry, run_manifest
from kitsunox.core.models import Evidence, EvidenceKind, Finding, Severity
from kitsunox.core.run import DataDir
from kitsunox.reporting.markdown import write_markdown
from kitsunox.reporting.queue import build_queue, write_queue
from kitsunox.reporting.report import Links, Report, ReportEntry, ScoreTerm, write_report
from kitsunox.util.text import safe_url
from kitsunox.web import library as library_module
from kitsunox.web import pages, results
from kitsunox.web.html import block, clean, esc, link, page, plain, removed, when
from kitsunox.web.library import Library, LoadError

RUN_OLD = "20261029T200500Z-npm"
RUN_NEW = "20261029T210500Z-npm"
RUN_UNREPORTED = "20261029T190500Z-npm"

EVIL_NAME = '<script>alert("name")</script>'
EVIL_VERSION = "1.0.0\"'><img src=x onerror=alert(1)>"
BIDI = "\u202e"


def crafted_entry(rank: int = 1) -> ReportEntry:
    """Every package-controlled field carries markup, quotes, bidi or a hostile URL."""
    findings = (
        Finding(
            rule_id="npm.install-script.added",
            rule_version=2,
            severity=Severity.HIGH,
            weight=5,
            title="<b>Install hook</b> added",
            explanation=f'postinstall runs "node x.js" {BIDI}evil{BIDI} <a href=javascript:x>',
            evidence=(
                Evidence(
                    kind=EvidenceKind.MANIFEST_FIELD,
                    path="package.json</p><script>p()</script>",
                    before=None,
                    after='"node x.js"; </pre><script>alert(2)</script>',
                ),
            ),
        ),
        Finding(
            rule_id="static.exfil-endpoint",
            rule_version=1,
            severity=Severity.MEDIUM,
            weight=3,
            title="Webhook",
            explanation="Discord webhook in index.js",
            evidence=(
                Evidence(
                    kind=EvidenceKind.FILE_SPAN,
                    path="../../etc/passwd",
                    line_start=3,
                    line_end=5,
                    snippet="fetch('https://discord.com/api/webhooks/1/x')\n</pre><style>*{}</style>\x07",
                ),
                Evidence(kind=EvidenceKind.FILE_SPAN, path="b.js", line_start=9, line_end=9),
            ),
        ),
    )
    return ReportEntry(
        rank=rank,
        ref=f"npm:{EVIL_NAME}@{EVIL_VERSION}",
        name=EVIL_NAME,
        version=EVIL_VERSION,
        previous_version="0.9<i>",
        published_at=REPORT_AS_OF - timedelta(minutes=5),
        publisher=f"mallory{BIDI}gnp.exe",
        watched=True,
        downloads=12345,
        downloads_period_days=7,
        score=8,
        reason="combination: <u>hook</u> & webhook",
        severity=Severity.HIGH,
        score_terms=(
            ScoreTerm(
                rule_id="npm.install-script.added", severity=Severity.HIGH, weight=5, count=1
            ),
            ScoreTerm(rule_id="static.exfil-endpoint", severity=Severity.MEDIUM, weight=3, count=2),
        ),
        findings=findings,
        stages=("Stage 1: metadata", "Stage 2: static"),
        links=Links(
            registry="javascript:alert(1)",
            files='https://www.npmjs.com/x"onmouseover="alert(1)',
            diff="data:text/html,<script>alert(1)</script>",
            repository="https://github.com/a/b",
            compared_commit=f"https://github.com/a/b/tree/{BIDI}c",
        ),
    )


def save(data: DataDir, report: Report) -> None:
    """A run as `collect` leaves it: manifest, report.json and the Markdown pages."""
    run_dir = data.run_dir(report.run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    manifest = run_manifest(report.run_id, as_of=report.as_of, ecosystem=report.ecosystem)
    (run_dir / "manifest.json").write_text(manifest.model_dump_json())
    write_report(run_dir, report)
    write_markdown(run_dir / "report", report)


def populate(root: Path) -> DataDir:
    data = DataDir(root)
    old = make_report(
        RUN_OLD,
        report_entry(1, "left-pad", "1.0.1", 4, Severity.MEDIUM, "static.entropy"),
        as_of=REPORT_AS_OF - timedelta(hours=1),
    )
    new = make_report(
        RUN_NEW,
        crafted_entry(1),
        report_entry(2, "left-pad", "1.0.2", 3, Severity.LOW, "static.entropy", watched=True),
        correlation={
            "repo_network": {"still_failing": 3, "retry_skipped": "outage"},
            "labels": f"<x>{BIDI}",
        },
    )
    save(data, old)
    save(data, new)
    unreported = data.run_dir(RUN_UNREPORTED)
    unreported.mkdir(parents=True)
    (unreported / "manifest.json").write_text(run_manifest(RUN_UNREPORTED).model_dump_json())
    (root / "runs" / "not-a-run" / "report").mkdir(parents=True)
    (root / "runs" / "not-a-run" / "report" / "report.json").write_text("{}")
    queue = build_queue(data, "npm", days=7)
    assert queue is not None
    write_queue(data, queue)
    return data


@pytest.fixture
def data(tmp_path: Path) -> DataDir:
    return populate(tmp_path / "data")


def check_html(document: str) -> None:
    assert_inert(document)


# --------------------------------------------------------------------------- inertness


def html_of(page: pages.Page | None) -> str:
    assert page is not None
    assert page.status == 200
    return page.html


def every_page(library: Library) -> list[str]:
    documents = [
        html_of(results.dashboard_page(library)),
        html_of(pages.queue_page(library)),
        html_of(pages.runs_page(library)),
        html_of(pages.verdicts_index(library)),
        html_of(results.results_page(library)),
        html_of(results.sample_page(library)),
    ]
    for run_id in library.run_ids():
        documents.append(html_of(pages.run_page(library, run_id)))
        report = library.report(run_id)
        assert report is not None and not isinstance(report, LoadError)
        documents += [html_of(pages.entry_page(library, run_id, e.rank)) for e in report.entries]
    return documents


# ----------------------------------------------------------------------------- content


def test_queue_page_ranks_packages_and_links_each_version(data: DataDir) -> None:
    document = html_of(pages.queue_page(Library(data.root)))
    check_html(document)
    assert "2 packages to review" in document
    assert f'href="/runs/{RUN_NEW}/entries/1"' in document  # the crafted version
    assert f'href="/runs/{RUN_NEW}/entries/2"' in document  # left-pad 1.0.2
    assert f'href="/runs/{RUN_OLD}/entries/1"' in document  # left-pad 1.0.1
    assert document.index("&lt;script&gt;") < document.index("left-pad")  # score 8 before 4
    assert "<code>static.entropy</code> (2)" in document
    assert "Packages by highest severity: 1 high, 1 medium." in document


def test_runs_page_lists_reported_runs_newest_first(data: DataDir) -> None:
    document = html_of(pages.runs_page(Library(data.root)))
    check_html(document)
    assert "2 runs with a report" in document
    assert document.index(RUN_NEW) < document.index(RUN_OLD)
    assert RUN_UNREPORTED not in document  # no report yet
    assert "not-a-run" not in document  # not a run id
    assert "3 versions were not compared with their repository" in document
    assert "retries were skipped as an outage" in document


def test_runs_page_paginates(data: DataDir, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pages, "RUNS_PER_PAGE", 1)
    library = Library(data.root)
    first = html_of(pages.runs_page(library, 1))
    second = html_of(pages.runs_page(library, 2))
    assert RUN_NEW in first and RUN_OLD not in first
    assert 'href="/runs/page/2"' in first
    assert RUN_OLD in second and 'href="/runs"' in second
    assert "page 2 of 2" in second
    assert pages.runs_page(library, 3) is None
    assert pages.runs_page(library, 0) is None


def test_run_page_shows_entries_warning_and_settings(data: DataDir) -> None:
    document = html_of(pages.run_page(Library(data.root), RUN_NEW))
    check_html(document)
    assert "<strong>2 to review</strong>" in document
    assert "By highest severity: 1 high, 1 low." in document
    assert 'class="warning"' in document
    assert "correlate.json" in document
    assert "\\u202e" in document  # settings are JSON with non-ASCII escaped, not raw bidi


def test_entry_page_shows_why_and_where_to_look(data: DataDir) -> None:
    library = Library(data.root)
    document = html_of(pages.entry_page(library, RUN_NEW, 1))
    check_html(document)
    assert "<strong>Score 8</strong>" in document
    assert '<td class="num">8</td>' in document  # the total of the score terms
    assert "12,345 downloads / 7 days (watched)" in document
    assert "<h3>Stage 1: metadata</h3>" in document and "<h3>Stage 2: static</h3>" in document
    assert "lines 3-5" in document and "line 9" in document
    assert ", 1 places" not in document and "v2, " in document
    assert '<a href="https://github.com/a/b" rel="noopener noreferrer nofollow">' in document
    assert "Next: #2 left-pad@1.0.2" in document
    second = html_of(pages.entry_page(library, RUN_NEW, 2))
    assert "Previous: #1" in second and "none (new package)" in second
    assert "No findings recorded." in second
    assert pages.entry_page(library, RUN_NEW, 3) is None
    assert pages.entry_page(library, RUN_UNREPORTED, 1) is None


def test_empty_and_missing_data_dirs(tmp_path: Path) -> None:
    for root in (tmp_path / "missing", tmp_path):
        library = Library(root)
        queue = html_of(pages.queue_page(library))
        runs = html_of(pages.runs_page(library))
        check_html(queue)
        check_html(runs)
        assert "No review queue yet" in queue
        assert "No run has a report yet" in runs
        assert pages.runs_page(library, 2) is None
        assert pages.run_page(library, RUN_NEW) is None


def test_queue_with_nothing_to_review_and_skipped_reports(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    save(data, make_report(RUN_NEW))
    queue = {
        "schema_version": 1,
        "ecosystem": "npm",
        "as_of": REPORT_AS_OF.isoformat(),
        "since": REPORT_AS_OF.isoformat(),
        "runs": [RUN_NEW],
        "skipped": [RUN_OLD, "../x<y>"],
        "packages": 0,
        "versions": 0,
        "by_severity": {},
        "entries": [],
    }
    (tmp_path / "queue").mkdir()
    (tmp_path / "queue" / "queue.json").write_text(json.dumps(queue))
    library = Library(tmp_path)
    document = html_of(pages.queue_page(library))
    assert "Nothing to review." in document
    assert f'<a href="/runs/{RUN_OLD}">' in document
    assert "../x&lt;y&gt;" in document and 'href="/runs/../' not in document
    assert "Nothing to review in this run." in html_of(pages.run_page(library, RUN_NEW))


# ----------------------------------------------------------------------------- untrusted


def test_untrusted_fields_cannot_break_any_page(data: DataDir) -> None:
    for document in every_page(Library(data.root)):
        check_html(document)
        assert "<script" not in document.lower()
        assert "<img" not in document.lower() and "<style" not in document.lower()
        assert "style=" not in document
    entry = html_of(pages.entry_page(Library(data.root), RUN_NEW, 1))
    assert "&lt;script&gt;alert(&quot;name&quot;)&lt;/script&gt;" in entry
    assert "1.0.0&quot;&#x27;&gt;&lt;img src=x onerror=alert(1)&gt;" in entry
    assert "&lt;b&gt;Install hook&lt;/b&gt;" in entry
    assert "&lt;/pre&gt;&lt;script&gt;alert(2)&lt;/script&gt;" in entry
    assert "combination: &lt;u&gt;hook&lt;/u&gt; &amp; webhook" in entry
    # Hostile URLs are shown as text and never linked.
    assert "javascript:alert(1)</span>" in entry
    assert 'href="javascript:' not in entry and 'href="data:' not in entry
    assert "x&quot;onmouseover=&quot;alert(1)</span>" in entry


def test_hidden_characters_are_removed_and_flagged(data: DataDir) -> None:
    entry = html_of(pages.entry_page(Library(data.root), RUN_NEW, 1))
    assert BIDI not in entry and "\x07" not in entry
    assert f"mallorygnp.exe{removed(1)}" in entry
    assert entry.count("hidden character") >= 4  # publisher, explanation, snippet, compared URL
    assert esc(f"a{BIDI}b") == 'ab<span class="flag">[1 hidden character removed]</span>'
    assert esc("a\u200bb\u2066c\x85") == f"abc{removed(3)}"
    assert clean("tab\tand\nnewline") == ("tab\tand\nnewline", 0)
    assert esc("") == "" and removed(0) == ""
    assert plain(f'<x y="{BIDI}">') == "&lt;x y=&quot;&quot;&gt;"


# Payload-hiding characters seen in real npm malware and in Unicode's invisible sets: GlassWorm's
# variation selectors, os-info-checker-es6's private use, tag characters, Hangul fillers.
GLASSWORM = "eval(\ufe00\ufe0f\U000e0100\U000e01ef)"
INVISIBLE = (
    "\ufe00\ufe0f\U000e0100\U000e01ef"  # variation selectors
    "\U000e0001\U000e0041\U000e007f"  # tag characters
    "\u115f\u1160\u3164\uffa0"  # Hangul fillers
    "\u034f\ufff9\ufffa\ufffb\U0001d173\U0001d17a\u17b4\u17b5\u180b\u180f"
    "\ue000\U000f0000\U0010fffd"  # private use
    "\u2028\u2029\x85\u00ad\u200b\u200d\u2060\ufeff\u202e\u2066\r\x00\x7f"
)


def test_payload_hiding_characters_are_counted() -> None:
    assert esc(GLASSWORM) == f"eval(){removed(4)}"
    shown = esc(f"a{INVISIBLE}b")
    assert shown == f"ab{removed(len(INVISIBLE))}"
    assert f"[{len(INVISIBLE)} hidden characters removed]" in shown
    snippet = block(f"x{INVISIBLE}\ty\nz")
    assert snippet.startswith("<pre>x\ty\nz</pre>") and removed(len(INVISIBLE)) in snippet
    # A lone surrogate can't even be encoded; it is removed, not a 500.
    assert esc("a\ud800b") == f"ab{removed(1)}"
    # Visible non-ASCII text is kept.
    assert esc("caf\u00e9 \u65e5\u672c \u0430") == "caf\u00e9 \u65e5\u672c \u0430"


@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(1)",
        "JAVASCRIPT:alert(1)",
        "data:text/html,x",
        "http://example.com/",
        "//example.com/",
        "https://",
        "https://-bad.example/",
        "https://example.com@evil.example/",
        'https://example.com/"onmouseover=x',
        "https://example.com/<x>",
        "https://example.com/a b",
        "https://example.com/a\\b",
        "https://example.com/\x01",
        "https://exa\u043cple.com/",  # Cyrillic homoglyph
        "https://example.com/\u202e",
        " https://example.com/",
    ],
)
def test_unsafe_urls_are_never_links(url: str) -> None:
    assert safe_url(url) is None
    shown = link(url, "label")
    assert "<a " not in shown and "(not linked)" in shown


@pytest.mark.parametrize(
    "url",
    [
        "https://www.npmjs.com/package/@scope/x/v/1.0.0?activeTab=code",
        "https://npmdiff.dev/x/1.0.0/1.0.1/",
        "https://github.com/a/b/tree/0123abc/packages/x",
        "https://localhost:8443/a#frag",
    ],
)
def test_plain_https_urls_are_links(url: str) -> None:
    assert safe_url(url) == url
    assert link(url, "<l>") == (f'<a href="{url}" rel="noopener noreferrer nofollow">&lt;l&gt;</a>')


def test_link_helpers_and_blocks() -> None:
    assert link(None, "x") == "n/a"
    assert when(None) == "unknown"
    assert block("<x>") == "<pre>&lt;x&gt;</pre>"
    cut = block("abcdef", limit=3)
    assert cut.startswith("<pre>abc</pre>") and "Cut at 3 of 6 characters" in cut


def test_crlf_and_a_leading_bom_get_no_marker() -> None:
    assert block("\ufeffa\r\nb\r\nc") == block("a\nb\nc") == "<pre>a\nb\nc</pre>"
    assert "hidden character" in block("a\rb")


# ----------------------------------------------------------------------------- schemas


def test_report_from_before_stage4_network_counts_renders(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    save(data, make_report(RUN_NEW, report_entry(1, "a", "1", 2, Severity.LOW, "r")))
    document = html_of(pages.run_page(Library(tmp_path), RUN_NEW))
    assert 'class="warning"' not in document and "correlate.json" not in document
    runs = html_of(pages.runs_page(Library(tmp_path)))
    assert "not compared" not in runs


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        ('{"schema_version": 2}', "schema_version 2, this build reads 1"),
        ("{}", "schema_version none (unversioned)"),
        ("not json <script>", "not valid JSON"),
        (b'{"a": "\xc3\x28"}', "not valid JSON (not UTF-8)"),
    ],
)
def test_unreadable_reports_show_an_error_box(
    tmp_path: Path, content: str | bytes, expected: str
) -> None:
    data = DataDir(tmp_path)
    save(data, make_report(RUN_NEW, report_entry(1, "a", "1", 2, Severity.LOW, "r")))
    path = data.run_dir(RUN_NEW) / "report" / "report.json"
    path.write_bytes(content.encode() if isinstance(content, str) else content)
    library = Library(tmp_path)
    for document in (
        html_of(pages.run_page(library, RUN_NEW)),
        html_of(pages.entry_page(library, RUN_NEW, 1)),
        html_of(pages.runs_page(library)),
    ):
        check_html(document)
        assert expected in document
        assert "Traceback" not in document and "<script" not in document


def test_newer_report_fields_show_an_error_box_without_quoting_input(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    save(data, make_report(RUN_NEW))
    path = data.run_dir(RUN_NEW) / "report" / "report.json"
    raw = json.loads(path.read_text())
    raw["new_field"] = "<secret-input>"
    path.write_text(json.dumps(raw))
    document = html_of(pages.run_page(Library(tmp_path), RUN_NEW))
    assert 'class="error"' in document
    assert "does not match this build&#x27;s Report format (ValidationError)" in document
    assert "secret-input" not in document


def test_unreadable_queue_shows_an_error_box(data: DataDir) -> None:
    (data.root / "queue" / "queue.json").write_text('{"schema_version": 1, "entries": 3}')
    document = html_of(pages.queue_page(Library(data.root)))
    check_html(document)
    assert 'class="error"' in document and "Queue format" in document


def test_a_report_that_cannot_be_opened(data: DataDir, monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(self: Path, *args: object) -> object:
        raise PermissionError(13, "denied")

    monkeypatch.setattr(Path, "open", refuse)
    document = html_of(pages.run_page(Library(data.root), RUN_NEW))
    assert "could not be read (PermissionError)" in document


def test_misaligned_stages_fall_back_to_the_rule_stage(tmp_path: Path) -> None:
    entry = crafted_entry().model_copy(update={"stages": ()})
    data = DataDir(tmp_path)
    save(data, make_report(RUN_NEW))
    write_report(data.run_dir(RUN_NEW), make_report(RUN_NEW, entry))  # Markdown needs stages
    document = html_of(pages.entry_page(Library(tmp_path), RUN_NEW, 1))
    assert "<h3>Stage 1: metadata</h3>" in document and "<h3>Stage 2: static</h3>" in document


def test_evidence_is_capped_per_rule(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pages, "MAX_EVIDENCE_PER_GROUP", 2)
    finding = Finding(
        rule_id="static.entropy",
        rule_version=1,
        severity=Severity.LOW,
        weight=1,
        title="t",
        explanation="e",
        evidence=tuple(
            Evidence(kind=EvidenceKind.METADATA, before=str(i) if i else None) for i in range(5)
        ),
    )
    entry = report_entry(1, "a", "1", 1, Severity.LOW, "static.entropy").model_copy(
        update={"findings": (finding, finding), "stages": ("Stage 2: static",) * 2}
    )
    save(DataDir(tmp_path), make_report(RUN_NEW, entry))
    document = html_of(pages.entry_page(Library(tmp_path), RUN_NEW, 1))
    assert ", 2 places" in document
    assert "... and 8 more places" in document
    assert '<p class="where">metadata</p>' in document
    assert '<p class="note">(none)</p>' in document  # an after-less before/after pair


# ----------------------------------------------------------------------------- stability


def test_rendering_is_byte_stable(tmp_path: Path) -> None:
    first = every_page(Library(populate(tmp_path / "one").root))
    again = every_page(Library(populate(tmp_path / "one-again").root))
    assert first == again
    assert first == every_page(Library(tmp_path / "one"))


def test_rewritten_files_are_reloaded(data: DataDir) -> None:
    library = Library(data.root)
    assert "left-pad" in html_of(pages.run_page(library, RUN_OLD))
    assert html_of(pages.runs_page(library)) == html_of(pages.runs_page(library))  # cached
    save(data, make_report(RUN_OLD, report_entry(1, "right-pad", "2", 1, Severity.LOW, "r")))
    assert "right-pad" in html_of(pages.run_page(library, RUN_OLD))
    assert "left-pad" in html_of(pages.queue_page(library))
    (data.root / "queue" / "queue.json").unlink()
    assert "No review queue yet" in html_of(pages.queue_page(library))


def test_report_cache_is_bounded(data: DataDir, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(library_module, "REPORT_CACHE_BYTES", 1)  # less than any one file
    library = Library(data.root)
    for _ in range(2):
        assert isinstance(library.report(RUN_NEW), Report)
        assert isinstance(library.report(RUN_OLD), Report)
    assert list(library._reports) == [library._report_path(RUN_OLD)]  # the newest stays
    monkeypatch.setattr(library_module, "REPORT_CACHE_BYTES", 10**9)
    library.report(RUN_NEW)
    assert len(library._reports) == 2
    assert library._cached_bytes() == sum(sig[1] for sig, _ in library._reports.values())
    assert library.report("../" + RUN_NEW) is None
    assert library.summary(RUN_UNREPORTED) is None


def test_rendering_never_writes_to_the_data_dir(data: DataDir) -> None:
    def tree() -> dict[str, tuple[int, bytes]]:
        return {
            str(p.relative_to(data.root)): (p.stat().st_mtime_ns, p.read_bytes())
            for p in sorted(data.root.rglob("*"))
            if p.is_file()
        }

    before = tree()
    every_page(Library(data.root))
    assert tree() == before


def test_small_helpers() -> None:
    naive = datetime(2026, 10, 29, 21, 5)
    assert when(naive) == "2026-10-29 21:05 UTC"
    assert when(REPORT_AS_OF) == "2026-10-29 21:05 UTC"
    assert '<nav aria-label="Breadcrumb">' not in page("t", "<p>b</p>")
    assert library_module._signature(Path("/nonexistent/kitsunox")) == (-1, -1, -1)


def test_queue_is_cached_until_rewritten(data: DataDir) -> None:
    library = Library(data.root)
    first = library.queue()
    assert first is library.queue()


def test_a_run_removed_while_listing_is_left_out(
    data: DataDir, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = Library(data.root)
    monkeypatch.setattr(library, "summary", lambda run_id: None)
    document = html_of(pages.runs_page(library))
    assert f"/runs/{RUN_NEW}" not in document


def test_findings_without_evidence(tmp_path: Path) -> None:
    finding = Finding(
        rule_id="npm.x", rule_version=1, severity=Severity.LOW, weight=1, title="t", explanation="e"
    )
    entry = report_entry(1, "a", "1", 1, Severity.LOW, "npm.x").model_copy(
        update={"findings": (finding,), "stages": ("Stage 1: metadata",)}
    )
    save(DataDir(tmp_path), make_report(RUN_NEW, entry))
    document = html_of(pages.entry_page(Library(tmp_path), RUN_NEW, 1))
    assert '<ul class="evidence">' not in document and "<p>e</p>" in document


# ----------------------------------------------------------------------------- limits


def test_deeply_nested_json_is_an_unreadable_row(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    save(data, make_report(RUN_OLD, report_entry(1, "a", "1", 2, Severity.LOW, "r")))
    save(data, make_report(RUN_NEW, report_entry(1, "b", "1", 2, Severity.LOW, "r")))
    nested = b'{"schema_version": 1, "x": ' + b"[" * 200_000 + b"]" * 200_000 + b"}"
    (data.run_dir(RUN_NEW) / "report" / "report.json").write_bytes(nested)
    library = Library(tmp_path)
    runs = html_of(pages.runs_page(library))  # 200
    check_html(runs)
    assert "could not be parsed (RecursionError)" in runs
    assert f"/runs/{RUN_OLD}" in runs  # the readable run is still listed
    assert library.report(RUN_NEW) is library.report(RUN_NEW)  # the LoadError is cached


def test_files_over_the_cap_are_not_read(data: DataDir, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(library_module, "MAX_FILE_BYTES", 10)
    size = (data.run_dir(RUN_NEW) / "report" / "report.json").stat().st_size
    loaded = Library(data.root).report(RUN_NEW)
    assert isinstance(loaded, LoadError)
    assert loaded.message == f"too large to show ({size / 2**20:,.0f} MB)."
    document = html_of(pages.queue_page(Library(data.root)))
    assert "too large to show" in document
