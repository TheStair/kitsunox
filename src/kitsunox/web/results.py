"""The dashboard and the live-evaluation pages: results, their trend, and the review sample.

They show what `kitsunox live eval` and `kitsunox live sample` wrote under `eval/live/`
(`evaluation/live.py`, `evaluation/sample.py`; definitions in `docs/evaluation.md` and
decision 0019), with the same titles and number formats as the Markdown report
(`live.matrix_title`, `intervals.percent`), so the two always agree. Nothing here writes, and
the datasets are never read: the reports already hold every number.

Rendering is a pure function of the files: no clock. "How old" is measured against the newest
run's `as_of`, the freeze status against the report's own `as_of`. Package names, versions and
rule ids are untrusted text and go through `web.html`; numbers are formatted here.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Final

from kitsunox.evaluation.intervals import Rate, percent, wilson
from kitsunox.evaluation.live import (
    ALL,
    CATCH_UP,
    CATCH_UP_SPAN,
    CONSERVATIVE,
    DEFAULT_WINDOWS,
    FUNNEL,
    HEADLINE,
    LiveReport,
    LogLine,
    Matrix,
    WindowReport,
    matrix_title,
)
from kitsunox.evaluation.sample import STRATA, DailySample, StratumBound
from kitsunox.reporting.queue import Queue
from kitsunox.reporting.verdicts import (
    FLAG_WORTHY,
    NO_REASON,
    REASON_LABELS,
    SEEN,
    VerdictRecord,
)
from kitsunox.web.html import error_box, esc, internal, page, warning_box, when
from kitsunox.web.library import LIVE_ID, SAMPLE_DAY, Library, LiveLog, LoadError
from kitsunox.web.pages import (
    QUEUE,
    VERDICT_LABELS,
    Crumbs,
    Page,
    entry_href,
    load_error,
    run_link,
    tally,
    unreviewed,
    verdict_tags,
)

STRICT: Final = "strict"
FREEZE: Final = "B"  # the rule freeze's window (decision 0019)
SHAPES: Final = {"A": "A (update)", "B": "B (new package)"}
TIMING_UNIT: Final = "hours"
NO_LIVE: Final = (
    "<p>No live evaluation yet: run <code>kitsunox live eval</code> (and "
    "<code>kitsunox live ledger</code> first, for runs from before the ledgers). "
    "<code>kitsunox collect</code> builds one daily.</p>"
)
NO_SAMPLE: Final = (
    "<p>No review sample yet: <code>kitsunox live sample</code> draws one for each day once "
    "none of its runs can still finish (<code>kitsunox collect</code> does it daily).</p>"
)


# ----------------------------------------------------------------------------- shared


def _rate(rate: Rate) -> str:
    """A rate with its Wilson interval, and its k of n."""
    if rate.n == 0:
        return "n/a"
    return f'{esc(percent(rate))} <span class="note">({rate.k:,}/{rate.n:,})</span>'


def _value(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.1%}"


def _ago(earlier: datetime, later: datetime) -> str:
    """How long before `later` `earlier` was ("3 h before", "2.5 days after")."""
    seconds = (later - earlier).total_seconds()
    word = "before" if seconds >= 0 else "after"
    hours = abs(seconds) / 3600
    if hours < 1:
        return f"{abs(seconds) / 60:.0f} min {word}"
    if hours < 48:
        return f"{hours:.0f} h {word}"
    return f"{hours / 24:.1f} days {word}"


def _freeze_status(report: LiveReport) -> str:
    """Where the report's `as_of` falls against the rule freeze (window B)."""
    window = report.windows.get(FREEZE)
    default = next(w for w in DEFAULT_WINDOWS if w.name == FREEZE)
    start = window.start if window and window.start else default.start
    end = window.end if window and window.end else default.end
    span = f"window {FREEZE}, {start:%Y-%m-%d} to {end:%Y-%m-%d}, end exclusive"
    if report.as_of < start:
        return f"before the rule freeze ({span})"
    if report.as_of < end:
        return f"<strong>during the rule freeze</strong> ({span})"
    return f"after the rule freeze ({span})"


def _results_href(dataset: str) -> str | None:
    return f"/results/{dataset}" if LIVE_ID.fullmatch(dataset) else None


def _sample_href(day: str) -> str | None:
    return f"/results/sample/{day}" if SAMPLE_DAY.fullmatch(day) else None


def _run_cell(library: Library, run_id: str) -> str:
    """A link to the run while its report is on disk; else its id, marked."""
    if library.find_run(run_id) is not None:
        return run_link(run_id)
    return f'{esc(run_id)} <span class="note">(not on disk)</span>'


def _verdict_cell(record: VerdictRecord | None) -> str:
    if record is None:
        return '<span class="note">not reviewed</span>'
    return (
        f'<span class="v-{record.verdict}"><strong>{VERDICT_LABELS[record.verdict]}</strong>'
        f"</span>{verdict_tags(record)} "
        f'<span class="note">({esc(record.by)}, {when(record.at)})</span>'
    )


def _table(caption: str, head: Sequence[str], rows: Sequence[str], css: str = "") -> str:
    """A table; `caption` and `head` are our own text, `rows` finished `<tr>` markup."""
    cls = f' class="{css}"' if css else ""
    cells = "".join(f'<th scope="col">{h}</th>' for h in head)
    return (
        f"<table{cls}>\n<caption>{caption}</caption>\n<thead><tr>{cells}</tr></thead>\n"
        f"<tbody>\n{'\n'.join(rows)}\n</tbody>\n</table>"
    )


def _num(value: int) -> str:
    return f'<td class="num">{value:,}</td>'


# ----------------------------------------------------------------------------- dashboard


def dashboard_page(library: Library) -> Page:
    """`/`: the latest results, the review state and how fresh everything is."""
    run_ids = library.run_ids()
    newest = library.summary(run_ids[0]) if run_ids else None
    now = newest.as_of if newest is not None and not isinstance(newest, LoadError) else None
    parts = ["<h1>Kitsunox</h1>", "<h2>Latest results</h2>", _dashboard_results(library, now)]
    parts += ["<h2>Review</h2>", _dashboard_review(library, now)]
    parts += ["<h2>Collection</h2>"]
    if not run_ids:
        parts.append("<p>No run has a report yet. <code>kitsunox collect</code> writes one.</p>")
    elif isinstance(newest, LoadError):
        parts.append(error_box(f"Newest run {run_link(run_ids[0])}: {esc(newest.message)}"))
    elif newest is not None:
        parts.append(
            f"<p>Newest run {run_link(newest.run_id)}, as of {when(newest.as_of)}: "
            f"{newest.versions:,} versions analysed, {newest.reported:,} reported. "
            f"{len(run_ids):,} runs with a report ({internal('/runs', 'all runs')}). "
            "Ages on this page are measured against this run, not the clock.</p>"
        )
    return Page(200, page("Dashboard", "\n".join(parts), [(None, "Dashboard")]))


def _dashboard_results(library: Library, now: datetime | None) -> str:
    ids = library.live_ids()
    if not ids:
        return NO_LIVE
    report = library.live_report(ids[0])
    if report is None or isinstance(report, LoadError):
        message = esc(report.message) if isinstance(report, LoadError) else "is gone"
        return error_box(f"<code>{esc(ids[0])}.json</code> {message}") + (
            f"<p>{internal('/results', 'All results')}</p>"
        )
    window = report.windows.get(ALL)
    age = f" ({_ago(report.as_of, now)} the newest run)" if now else ""
    head = (
        f"<p>{internal(f'/results/{report.dataset}', esc(report.dataset))}: labels as of "
        f"{when(report.as_of)}{age}, {_freeze_status(report)}. window all, benign "
        f"once released {report.headline_d} days before the labels.</p>"
    )
    if window is None or HEADLINE not in window.matrices:
        return head + warning_box("This report has no window all.")
    headline = window.matrices[HEADLINE]
    tiles = [
        _tile("Recall, flag-worthy (headline)", headline.recall),
        _tile("Precision, flag-worthy (headline)", headline.precision),
    ]
    rows = [
        _summary_row(key, window.matrices[key])
        for key in (HEADLINE, STRICT, CONSERVATIVE)
        if key in window.matrices
    ]
    table = _table(
        "Beside the headline",
        ["Matrix", "TP", "FP", "FN", "TN", "Recall", "Precision"],
        rows,
    )
    misses = (
        f"<p>{len(report.misses):,} flag-worthy versions were not reported "
        f"({internal(f'/results/{report.dataset}', 'see the misses')}).</p>"
    )
    return "\n".join([head, f'<div class="tiles">{"".join(tiles)}</div>', table, misses])


def _tile(label: str, rate: Rate) -> str:
    value = "n/a" if rate.value is None else f"{rate.value:.1%}"
    interval = (
        f"95% CI {rate.low:.1%}-{rate.high:.1%}, {rate.k:,} of {rate.n:,}"
        if rate.low is not None and rate.high is not None
        else "no versions yet"
    )
    return (
        f'<div class="tile"><p class="tile-label">{label}</p>'
        f'<p class="tile-value">{value}</p><p class="note">{interval}</p></div>'
    )


def _summary_row(key: str, m: Matrix) -> str:
    return (
        f"<tr><td>{esc(matrix_title(key))}{_marker(key)}</td>{_num(m.tp)}{_num(m.fp)}"
        f"{_num(m.fn)}{_num(m.tn)}<td>{_rate(m.recall)}</td><td>{_rate(m.precision)}</td></tr>"
    )


def _dashboard_review(library: Library, now: datetime | None) -> str:
    verdicts = library.verdicts()
    parts = [tally(verdicts)]
    queue = library.queue()
    if queue is None:
        parts.append(f"<p>No review queue yet ({internal(QUEUE, 'queue')}).</p>")
    elif isinstance(queue, LoadError):
        parts.append(error_box(f"<code>{esc(queue.path)}</code> {esc(queue.message)}"))
    else:
        left: Queue = unreviewed(queue, library.verdicts(queue.ecosystem))
        age = f", built {_ago(queue.as_of, now)} the newest run" if now else ""
        parts.append(
            f"<p>{internal(QUEUE, f'Review queue: {left.packages:,} packages')} "
            f"({left.versions:,} versions) to review{age}.</p>"
        )
    days = library.sample_days()
    if days:
        sample = library.sample(days[0])
        if isinstance(sample, DailySample):
            now_verdicts = library.verdicts(sample.ecosystem).now
            done = sum((v.name, v.version) in now_verdicts for v in sample.versions)
            href = _sample_href(days[0]) or "/results/sample"
            parts.append(
                f"<p>{internal(href, f'Review sample {esc(days[0])}')}: {done} of "
                f"{len(sample.versions)} sampled versions have a verdict.</p>"
            )
    return "\n".join(parts)


# ----------------------------------------------------------------------------- results


def results_page(library: Library, dataset: str | None = None) -> Page | None:
    """`/results` (the newest live report) or `/results/<dataset>`; None for an unknown id."""
    ids = library.live_ids()
    crumbs: Crumbs = [("/", "Dashboard"), ("/results", "Results")]
    if dataset is not None and dataset not in ids:
        return None
    chosen = dataset or (ids[0] if ids else None)
    log = library.live_log()
    if chosen is None:
        body = "<h1>Live evaluation</h1>\n" + NO_LIVE + _trend(library, log, None)
        return Page(200, page("Results", body, [("/", "Dashboard"), (None, "Results")]))
    crumbs = [*crumbs, (None, esc(chosen))]
    report = library.live_report(chosen)
    if report is None:
        return None
    if isinstance(report, LoadError):
        body = "\n".join(
            [load_error(f"Live evaluation {chosen}", report), _builds(library, log, chosen)]
        )
        return Page(200, page(f"Results {chosen}", body, crumbs))
    parts = [
        f"<h1>Live evaluation {esc(report.dataset)}</h1>",
        _facts(report),
        _reading(),
    ]
    order = [ALL, *(name for name in report.windows if name != ALL)]
    for name in order:
        window = report.windows.get(name)
        if window is not None:
            parts.append(_window(window, report.headline_d))
    parts += [
        _timing(report),
        _sample_bound(report),
        _misses(library, report),
        _trend(library, log, report.dataset),
        _builds(library, log, report.dataset),
    ]
    return Page(200, page(f"Results {report.dataset}", "\n".join(parts), crumbs))


def _facts(report: LiveReport) -> str:
    window = report.windows.get(ALL)
    catch_up = report.windows.get(CATCH_UP)
    versions = f"{window.versions:,} in window all" if window else "no window all"
    if catch_up is not None:
        versions += f", {catch_up.versions:,} in catch-up (counted apart)"
    facts = [
        (
            "Dataset",
            f"<code>{esc(report.dataset)}</code>, sha256 "
            f"<code>{esc(report.dataset_sha256[:16])}</code>",
        ),
        ("Labels as of", f"{when(report.as_of)}, {_freeze_status(report)}"),
        ("Label set", f"<code>{esc(report.dataset.removeprefix('live-'))}</code>"),
        (
            "Headline D",
            f"{report.headline_d} days (a version without a label counts as benign "
            "once released that long before the labels; younger ones are provisional)",
        ),
        ("Versions", versions),
        ("Flag-worthy versions", f"{len(report.malicious):,}; {len(report.misses):,} not reported"),
        (
            "Operational loss",
            f"{report.unfinished_runs:,} runs that never finished "
            f"({report.unfinished_changes:,} changes)",
        ),
        ("Pending runs", f"{report.pending_runs:,} (may still finish)"),
    ]
    rows = "\n".join(f'<tr><th scope="row">{k}</th><td>{v}</td></tr>' for k, v in facts)
    return f'<table class="facts">\n<tbody>\n{rows}\n</tbody>\n</table>'


def _reading() -> str:
    return (
        "<details><summary>How to read the matrices</summary>"
        "<p><strong>TP</strong>: reported and flag-worthy; <strong>FP</strong>: reported and "
        "benign (unreviewed: of those, how many have no verdict and are presumed "
        "benign); <strong>FN</strong>: not reported and flag-worthy; <strong>TN</strong>: "
        "not reported and benign. Recall = TP/(TP+FN), precision = TP/(TP+FP), FP rate = "
        "FP/(FP+TN), each with a Wilson 95% interval and its k/n.</p>"
        "<p>The <strong>headline</strong> is behaviour truth: a reviewer's verdict wins "
        "(malicious and unwanted are flag-worthy, benign is not, unverified is left out), "
        "then an OSV record. <strong>Strict</strong> counts malware only (unwanted is a "
        "negative). Best and worst cases put the unverified versions back as the pipeline "
        "decided or the opposite; the true value lies between them. <strong>OSV "
        "truth</strong> is the conservative view: an OSV record wins over any verdict, so no "
        "reviewer can clear a labeled version. OSV only ignores verdicts. The rest are "
        "sensitivity rows on the headline: npm takedowns as positives, the report after "
        "re-scores (for recall), and other values of D. Definitions: "
        "<code>docs/evaluation.md</code>, decision 0019.</p></details>"
    )


def _window_title(window: WindowReport) -> str:
    if window.name == ALL:
        return (
            f"every run, versions captured within {CATCH_UP_SPAN.total_seconds() / 3600:.0f} "
            "hours of their release"
        )
    if window.name == CATCH_UP:
        return (
            f"versions captured more than {CATCH_UP_SPAN.total_seconds() / 3600:.0f} hours "
            "after their release, in no window: npm may already have removed the malware, so "
            "recall here is survivor-biased"
        )
    span = (
        f"runs from {window.start:%Y-%m-%d} to {window.end:%Y-%m-%d}, end exclusive"
        if window.start and window.end
        else "runs in this window"
    )
    return span + (", the rule freeze" if window.name == FREEZE else "")


def _window(window: WindowReport, d: int) -> str:
    title = f"<h2>Window {esc(window.name)}</h2>\n<p>{_window_title(window)}. "
    if window.versions == 0:
        return title + "No versions yet.</p>"
    parts = [title + f"{window.versions:,} versions.</p>"]
    headline = window.matrices.get(HEADLINE)
    if headline is not None:
        parts.append(_grid(headline, d))
    rows = [_matrix_row(key, m) for key, m in window.matrices.items()]
    parts.append(
        _table(
            "Every matrix",
            ["Matrix", "TP", "FP", "FN", "TN", "Recall", "Precision", "FP rate", "Excluded"],
            rows,
            "matrices",
        )
    )
    parts += [_shapes(window), _units(window), _funnel(window), _causes(window)]
    parts += [_rules(window), _rule_sets(window)]
    return "\n".join(p for p in parts if p)


def _grid(m: Matrix, d: int) -> str:
    """The headline matrix as a 2x2 confusion grid."""
    unreviewed_fp = f'<span class="note">{m.fp_unreviewed:,} unreviewed</span>'
    return (
        '<table class="confusion">\n'
        f"<caption>Headline: {esc(matrix_title(HEADLINE))}, D = {d}</caption>\n"
        '<thead><tr><td></td><th scope="col">Flag-worthy</th>'
        '<th scope="col">Benign</th></tr></thead>\n<tbody>\n'
        '<tr><th scope="row">Reported</th>'
        f'<td class="cell good"><span class="cell-label">TP</span> {m.tp:,}</td>'
        f'<td class="cell bad"><span class="cell-label">FP</span> {m.fp:,} {unreviewed_fp}</td>'
        "</tr>\n"
        '<tr><th scope="row">Not reported</th>'
        f'<td class="cell bad"><span class="cell-label">FN</span> {m.fn:,}</td>'
        f'<td class="cell good"><span class="cell-label">TN</span> {m.tn:,}</td></tr>\n'
        "</tbody>\n</table>\n"
        f"<p>Recall {_rate(m.recall)}, precision {_rate(m.precision)}, FP rate "
        f"{_rate(m.fpr)}. Excluded: {_excluded(m)}.</p>"
    )


def _excluded(m: Matrix) -> str:
    return ", ".join(f"{esc(k)} {v:,}" for k, v in m.excluded.items()) or "none"


def _marker(key: str) -> str:
    if key == HEADLINE:
        return ' <span class="tag">headline</span>'
    if key == CONSERVATIVE:
        return ' <span class="tag">conservative</span>'
    return ""


def _matrix_row(key: str, m: Matrix) -> str:
    css = ' class="headline"' if key == HEADLINE else ""
    return (
        f"<tr{css}><td>{esc(matrix_title(key))}{_marker(key)}</td>{_num(m.tp)}"
        f'<td class="num">{m.fp:,} <span class="note">({m.fp_unreviewed:,} unreviewed)</span>'
        f"</td>{_num(m.fn)}{_num(m.tn)}<td>{_rate(m.recall)}</td><td>{_rate(m.precision)}</td>"
        f"<td>{_rate(m.fpr)}</td><td>{_excluded(m)}</td></tr>"
    )


def _shapes(window: WindowReport) -> str:
    rows = [
        f"<tr><td>{esc(SHAPES.get(shape, shape))}</td>{_num(m.tp)}{_num(m.fp)}{_num(m.fn)}"
        f"{_num(m.tn)}<td>{_rate(m.recall)}</td><td>{_rate(m.precision)}</td></tr>"
        for shape, m in window.by_shape.items()
    ]
    head = ["Shape", "TP", "FP", "FN", "TN", "Recall", "Precision"]
    return _table("Headline by shape", head, rows) if rows else ""


def _units(window: WindowReport) -> str:
    headline = window.matrices.get(HEADLINE)
    by_version = _rate(headline.recall) if headline else "n/a"
    reasons = {"none": NO_REASON, **{str(k): v for k, v in REASON_LABELS.items()}}
    verdicts = ", ".join(f"{v:,} {esc(k)}" for k, v in window.verdicts.items()) or "none"
    why = ", ".join(f"{esc(reasons.get(k, k))} {v:,}" for k, v in window.unverified_reasons.items())
    late = ", ".join(f"{esc(k)} {v:,}" for k, v in window.late_labels.items()) or "none"
    return (
        f"<p>Recall by unit: version {by_version}, OSV record "
        f"{_rate(window.recall_by_record)}, publisher account "
        f"{_rate(window.recall_by_account)}.</p>\n"
        f"<p>OSV labels later than D days after the release: {late}. Verdicts recorded after "
        f"a confirmation was public: {window.verdicts_after_confirmation:,}.</p>\n"
        f"<p>Verdicts: {verdicts}" + (f" (unverified: {why})" if why else "") + ".</p>"
    )


def _funnel(window: WindowReport) -> str:
    rows = []
    for label, funnel in (("malicious", window.funnel_malicious), ("benign", window.funnel_benign)):
        for shape, steps in funnel.items():
            cells = "".join(_num(steps.get(s, 0)) for s in FUNNEL)
            rows.append(f"<tr><td>{label} {esc(shape)}</td>{cells}</tr>")
    return _table("Funnel", ["Versions", *FUNNEL], rows) if rows else ""


def _causes(window: WindowReport) -> str:
    if not window.miss_causes:
        return ""
    rows = [
        f"<tr><td>{esc(cause)}</td>{_num(kinds.get('new', 0))}{_num(kinds.get('update', 0))}</tr>"
        for cause, kinds in window.miss_causes.items()
    ]
    return _table("Why missed", ["Cause", "New", "Update"], rows) + (
        f"<p>{window.misses_watched:,} of the misses are watched packages.</p>"
    )


def _rules(window: WindowReport) -> str:
    """Every rule that fired on a reported version, most false positives first."""
    if not window.rules_tp_fp:
        return ""
    ordered = sorted(window.rules_tp_fp.items(), key=lambda kv: (-kv[1][1], -kv[1][0], kv[0]))
    rows = [
        f"<tr><td><code>{esc(rule)}</code></td>{_num(tp)}{_num(fp)}"
        f"<td>{_rate(wilson(tp, tp + fp))}</td></tr>"
        for rule, (tp, fp, *_) in ordered
    ]
    caption = "Rules on reported versions: TP and FP (headline truth), most FP first"
    return _table(caption, ["Rule", "TP", "FP", "Precision"], rows)


def _rule_sets(window: WindowReport) -> str:
    sets = window.rule_sets
    stage4 = ", ".join(f"<code>{esc(k)}</code> x{v}" for k, v in sets.stage4.items()) or "none"
    conflicts = (
        ", ".join(
            f"<code>{esc(k)}</code> {esc(', '.join(map(str, v)))}"
            for k, v in sets.conflicting_rules.items()
        )
        or "none"
    )
    recorded = sets.runs - sets.unrecorded_pipeline
    return (
        f"<p>Rule sets: {sets.runs:,} runs; Stage 4 {stage4}; full fingerprints recorded for "
        f"{recorded:,} runs ({len(sets.pipeline):,} distinct); rules with more than one "
        f"version: {conflicts}. <strong>Single rule version: "
        f"{'yes' if sets.single_version else 'no'}.</strong></p>"
    )


def _timing(report: LiveReport) -> str:
    if not report.timing:
        return ""

    def cell(value: float | None) -> str:
        return '<td class="num">n/a</td>' if value is None else f'<td class="num">{value:g}</td>'

    rows = [
        f"<tr><td>{esc(label)}</td>{_num(t.n)}{cell(t.median_h)}{cell(t.p75_h)}{cell(t.max_h)}</tr>"
        for label, t in report.timing.items()
    ]
    return "<h2>Label timing</h2>\n" + _table(
        f"Per OSV record, from its earliest capture ({TIMING_UNIT})",
        ["Interval", "n", "Median", "p75", "Max"],
        rows,
    )


def _sample_bound(report: LiveReport) -> str:
    """The review sample's 95% upper bounds on flag-worthy versions nobody labeled."""
    rows = []
    for group, raw in report.sample_bound.items():
        if not isinstance(raw, dict) or not raw.get("days"):
            continue
        strata = raw.get("strata")
        for name, value in (strata if isinstance(strata, dict) else {}).items():
            try:
                b = StratumBound.model_validate(value)
            except ValueError:
                continue
            upper = "n/a" if b.upper is None else f"{b.upper:.2%}"
            rows.append(
                f"<tr><td>{esc(group)}</td><td>{esc(name)}</td>{_num(b.population)}"
                f"{_num(b.sampled)}{_num(b.reviewed)}{_num(b.malicious)}{_num(b.unwanted)}"
                f'<td class="num">{upper}</td></tr>'
            )
        share, versions = raw.get("upper_share"), raw.get("upper_versions")
        if isinstance(share, float):
            bound = f"{share:.2%}" + (
                f" (≤ {versions:,} versions)" if isinstance(versions, int) else ""
            )
            rows.append(
                f'<tr><td>{esc(group)}</td><td>weighted</td><td colspan="5"></td>'
                f'<td class="num">{bound}</td></tr>'
            )
    if not rows:
        return ""
    return (
        f"<h2>Review sample: flag-worthy versions nobody labeled</h2>\n<p>95% upper bounds "
        f"from the label-blind daily sample ({internal('/results/sample', 'the sample')}).</p>\n"
        + _table(
            "Upper bounds",
            [
                "Group",
                "Stratum",
                "Population",
                "Sampled",
                "Reviewed",
                "Malicious",
                "Unwanted",
                "Upper bound",
            ],
            rows,
        )
    )


def _misses(library: Library, report: LiveReport) -> str:
    """Every flag-worthy version that wasn't reported, linked where its run still is."""
    head = f"<h2>Misses ({len(report.misses):,})</h2>"
    if not report.misses:
        return head + "\n<p>None: every flag-worthy version was reported.</p>"
    now = library.verdicts().now
    rows = []
    for m in report.misses:
        label = f"{esc(m.name)}@{esc(m.version)}"
        record = now.get((m.name, m.version))
        href = (
            entry_href(record.run_id, record.rank)
            if record is not None and record.rank > 0 and library.find_run(record.run_id)
            else None
        )
        osv = ", ".join(esc(i) for i in m.osv) or "none"
        rows.append(
            f"<tr><td>{internal(href, label) if href else label}</td>"
            f"<td>{_run_cell(library, m.run_id)}</td><td>{esc(m.cause)}</td>"
            f"<td>{esc(SHAPES.get(m.shape, m.shape))}</td><td>{osv}</td>"
            f"<td>{esc(m.verdict or 'none')}</td><td>{'yes' if m.tarball else 'no'}</td>"
            f'<td class="num">{m.score:g}</td></tr>'
        )
    note = (
        "<p>Flag-worthy under the headline truth and not reported by the tick that saw them "
        "(catch-up versions are left out). A miss has no entry page unless a verdict was "
        "recorded on a report that listed it; the run links while its report is on disk. "
        "<code>kitsunox live misses</code> lists them for adjudication.</p>"
    )
    head_cells = [
        "Version",
        "Run",
        "Cause",
        "Shape",
        "OSV",
        "Verdict (at the labels)",
        "Tarball",
        "Score",
    ]
    return "\n".join([head, note, _table("Labeled flag-worthy, not reported", head_cells, rows)])


# ----------------------------------------------------------------------------- trend


def _trend(library: Library, log: LiveLog | LoadError | None, current: str | None) -> str:
    """Every build in `log.jsonl`: a recall/precision chart and the table."""
    head = "<h2>Trend</h2>"
    if log is None:
        return ""
    if isinstance(log, LoadError):
        return head + error_box(f"<code>{esc(log.path)}</code> {esc(log.message)}")
    lines = log.lines
    parts = [head]
    if log.unreadable:
        parts.append(warning_box(f"{log.unreadable:,} lines of the log could not be read."))
    if not lines:
        parts.append("<p>No build is logged yet.</p>")
        return "\n".join(parts)
    parts.append(_chart(lines))
    known = set(library.live_ids())
    rows = []
    for line in reversed(lines):
        name = esc(line.dataset)
        href = _results_href(line.dataset) if line.dataset in known else None
        shown = internal(href, name) if href else name
        if line.dataset == current:
            shown += ' <span class="tag">shown</span>'
        strict = (
            f"{line.strict_reported:,}/{line.strict_malicious:,}"
            if line.strict_reported is not None and line.strict_malicious is not None
            else "n/a"
        )
        rows.append(
            f"<tr><td>{when(line.built_at)}</td><td>{shown}</td>{_num(line.versions)}"
            f'<td class="num">{_value(line.recall)} <span class="note">'
            f"({line.reported_malicious:,}/{line.malicious:,})</span></td>"
            f'<td class="num">{_value(line.precision)}</td><td class="num">{strict}</td>'
            f'<td class="num">{"n/a" if line.unverified is None else f"{line.unverified:,}"}</td>'
            f'<td class="num">{line.newly_labeled:,} ({line.newly_reported:,})</td>'
            f"{_num(line.sample_unreviewed)}</tr>"
        )
    parts.append(
        _table(
            "Builds, newest first (flag-worthy, window all)",
            [
                "Built",
                "Dataset",
                "Versions",
                "Recall",
                "Precision",
                "Strict reported",
                "Unverified",
                "Newly labeled (reported)",
                "Sample unreviewed",
            ],
            rows,
        )
    )
    return "\n".join(parts)


CHART_W: Final = 640
CHART_H: Final = 220
PLOT: Final = (52, 16, 480, 168)  # left, top, width, height; room for direct labels


def _chart(lines: Sequence[LogLine]) -> str:
    """Recall and precision per build as an inline SVG: no script, no inline style (the
    stylesheet colours it by class), a native tooltip on every point."""
    if len(lines) < 2:
        return '<p class="note">The chart appears once two builds are logged.</p>'
    left, top, width, height = PLOT
    step = width / (len(lines) - 1)

    def x(i: int) -> float:
        return round(left + i * step, 1)

    def y(value: float) -> float:
        return round(top + height * (1 - value), 1)

    grid = []
    for tick in (0.0, 0.25, 0.5, 0.75, 1.0):
        grid.append(
            f'<line class="grid" x1="{left}" y1="{y(tick)}" x2="{left + width}" y2="{y(tick)}">'
            "</line>"
            f'<text class="axis" x="{left - 6}" y="{y(tick) + 4}" text-anchor="end">'
            f"{tick:.0%}</text>"
        )
    every = max(1, -(-len(lines) // 8))
    for i, line in enumerate(lines):
        if i % every == 0 or i == len(lines) - 1:
            grid.append(
                f'<text class="axis" x="{x(i)}" y="{top + height + 18}" text-anchor="middle">'
                f"{line.built_at:%m-%d}</text>"
            )
    series = []
    for css, label, values in (
        ("recall", "Recall", [line.recall for line in lines]),
        ("precision", "Precision", [line.precision for line in lines]),
    ):
        segments: list[list[str]] = [[]]
        marks = []
        for i, value in enumerate(values):
            if value is None:
                segments.append([])
                continue
            segments[-1].append(f"{x(i)},{y(value)}")
            when_ = f"{lines[i].built_at:%Y-%m-%d %H:%M}"
            shape = (
                f'<circle class="m-{css}" cx="{x(i)}" cy="{y(value)}" r="4">'
                if css == "recall"
                else f'<rect class="m-{css}" x="{x(i) - 4}" y="{y(value) - 4}" width="8" '
                'height="8">'
            )
            close = "</circle>" if css == "recall" else "</rect>"
            marks.append(f"{shape}<title>{label} {value:.1%}, built {when_}</title>{close}")
        lines_svg = "".join(
            f'<polyline class="s-{css}" points="{" ".join(seg)}"></polyline>'
            for seg in segments
            if len(seg) > 1
        )
        last = next(((i, v) for i, v in reversed(list(enumerate(values))) if v is not None), None)
        direct = (
            f'<text class="direct" x="{x(last[0]) + 8}" y="{y(last[1]) + 4}">'
            f"{label} {last[1]:.1%}</text>"
            if last
            else ""
        )
        series.append(f"<g>{lines_svg}{''.join(marks)}{direct}</g>")
    svg = (
        f'<svg class="chart" viewBox="0 0 {CHART_W} {CHART_H}" role="img" '
        'aria-label="Recall and precision of the headline matrix per build">'
        f"<title>Headline recall and precision per build</title>{''.join(grid)}"
        f"{''.join(series)}</svg>"
    )
    legend = (
        '<p class="legend"><span class="key key-recall"></span> Recall (solid, circles) '
        '<span class="key key-precision"></span> Precision (dashed, squares), flag-worthy, '
        "window all; the table below has the numbers.</p>"
    )
    return f'<div class="chart-box">{svg}{legend}</div>'


def _builds(library: Library, log: LiveLog | LoadError | None, current: str | None) -> str:
    """Every live report on disk, newest first."""
    ids = library.live_ids()
    if not ids:
        return ""
    built = {}
    if isinstance(log, LiveLog):
        built = {line.dataset: line.built_at for line in log.lines}
    items = []
    for dataset in ids:
        href = _results_href(dataset)
        label = esc(dataset)
        shown = internal(href, label) if href and dataset != current else label
        mark = ' <span class="tag">shown</span>' if dataset == current else ""
        at = f" (built {when(built[dataset])})" if dataset in built else ""
        items.append(f"<li>{shown}{mark}{at}</li>")
    return f"<h2>All reports ({len(ids)})</h2>\n<ul>{''.join(items)}</ul>"


# ----------------------------------------------------------------------------- sample


def sample_page(library: Library, day: str | None = None) -> Page | None:
    """`/results/sample` (the newest day) or `/results/sample/<day>`; None for an unknown day."""
    days = library.sample_days()
    if day is not None and day not in days:
        return None
    chosen = day or (days[0] if days else None)
    base: Crumbs = [("/", "Dashboard"), ("/results", "Results")]
    if chosen is None:
        body = "<h1>Review sample</h1>\n" + NO_SAMPLE
        return Page(200, page("Review sample", body, [*base, (None, "Sample")]))
    crumbs: Crumbs = [*base, ("/results/sample", "Sample"), (None, esc(chosen))]
    sample = library.sample(chosen)
    if sample is None:
        return None
    if isinstance(sample, LoadError):
        body = load_error(f"Review sample {chosen}", sample) + _days(library, chosen)
        return Page(200, page(f"Review sample {chosen}", body, crumbs))
    now = library.verdicts(sample.ecosystem).now
    parts = [
        f"<h1>Review sample {esc(sample.day.isoformat())}</h1>",
        "<p>Label-blind: chosen by hash within each stratum before any label is read. Review "
        "each version by what its code does (decision 0015) and record the verdict with "
        "<code>kitsunox live verdict RUN_ID NAME VERSION malicious|unwanted|benign --by "
        "NAME</code>, or <code>... unverified --reason gone|remote|obfuscated|binary</code>. "
        "Only malicious, unwanted and benign verdicts count as reviewed in the bound. Verdicts "
        "here are the verdict log's now; a live report counts those recorded by its labels' "
        "time.</p>",
        _progress(sample, now),
        _strata(sample, now),
        _sampled(library, sample, now),
        _days(library, chosen),
    ]
    return Page(200, page(f"Review sample {chosen}", "\n".join(parts), crumbs))


def _progress(sample: DailySample, now: dict[tuple[str, str], VerdictRecord]) -> str:
    found = [now.get((v.name, v.version)) for v in sample.versions]
    seen = sum(r is not None and r.verdict in SEEN for r in found)
    unverified = sum(r is not None and r.verdict == "unverified" for r in found)
    missing = sum(r is None for r in found)
    return (
        f'<p class="tally"><strong>{len(found) - missing} of {len(found)} sampled versions '
        f"have a verdict</strong>: {seen} reviewed (malicious, unwanted or benign), "
        f"{unverified} unverified; {missing} not reviewed.</p>"
    )


def _strata(sample: DailySample, now: dict[tuple[str, str], VerdictRecord]) -> str:
    rows = []
    for name, population in sample.population.items():
        members = [v for v in sample.versions if v.stratum == name]
        found = [now.get((v.name, v.version)) for v in members]
        seen = [r for r in found if r is not None and r.verdict in SEEN]
        rows.append(
            f"<tr><td>{esc(name)}: {esc(STRATA.get(name, name))}</td>{_num(population)}"
            f"{_num(len(members))}{_num(len(seen))}"
            f"{_num(sum(r.verdict in FLAG_WORTHY for r in seen))}"
            f"{_num(sum(r is not None and r.verdict == 'unverified' for r in found))}"
            f"{_num(sum(r is None for r in found))}</tr>"
        )
    head = [
        "Stratum",
        "Population",
        "Sampled",
        "Reviewed",
        "Flag-worthy",
        "Unverified",
        "Not reviewed",
    ]
    return _table("Strata", head, rows)


def _sampled(
    library: Library, sample: DailySample, now: dict[tuple[str, str], VerdictRecord]
) -> str:
    rows = []
    for i, v in enumerate(sample.versions, 1):
        traits = ", ".join(
            word for word, on in (("new", v.new), ("hook", v.hook), ("watched", v.watched)) if on
        )
        rules = "".join(
            f"<li><code>{esc(r.split('@', 1)[0])}</code></li>" for r in dict.fromkeys(v.rules)
        )
        tarball = (
            f"yes ({v.tarball_size:,} B)"
            if v.tarball and v.tarball_size
            else ("yes" if v.tarball else "no")
        )
        rows.append(
            f'<tr><td class="num">{i}</td><td>{esc(v.stratum)}</td>'
            f"<td>{esc(v.name)}@{esc(v.version)}</td><td>{_run_cell(library, v.run_id)}</td>"
            f'<td class="num">{v.score:g}</td><td>{traits}</td>'
            f'<td><ul class="flat">{rules}</ul></td><td>{tarball}</td>'
            f"<td>{_verdict_cell(now.get((v.name, v.version)))}</td></tr>"
        )
    head = ["#", "Stratum", "Version", "Run", "Score", "Traits", "Rules", "Tarball", "Verdict"]
    return _table("Sampled versions", head, rows)


def _days(library: Library, current: str) -> str:
    """Every sampled day, newest first, with its progress."""
    rows = []
    for day in library.sample_days():
        sample = library.sample(day)
        href = _sample_href(day)
        label = internal(href, esc(day)) if href and day != current else esc(day)
        if day == current:
            label += ' <span class="tag">shown</span>'
        if not isinstance(sample, DailySample):
            message = esc(sample.message) if isinstance(sample, LoadError) else "gone"
            rows.append(f'<tr><td>{label}</td><td colspan="3" class="bad">{message}</td></tr>')
            continue
        now = library.verdicts(sample.ecosystem).now
        done = sum((v.name, v.version) in now for v in sample.versions)
        rows.append(
            f"<tr><td>{label}</td>{_num(len(sample.versions))}{_num(done)}"
            f"{_num(len(sample.versions) - done)}</tr>"
        )
    return "<h2>Every day</h2>\n" + _table(
        "Samples", ["Day", "Sampled", "With a verdict", "Not reviewed"], rows
    )
