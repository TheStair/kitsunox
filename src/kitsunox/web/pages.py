"""The viewer's pages, rendered from a `Library` as complete HTML documents.

Rendering is a pure function of the files read: no clock, and everything in a fixed order
(the queue's and reports' own ranks, runs newest first by id, severities highest first), so
the same files always give the same bytes. All package text goes through `web.html`.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from kitsunox.core.models import Evidence, Finding, Severity
from kitsunox.reporting.queue import Queue, QueueEntry
from kitsunox.reporting.report import Report, ReportEntry, stage_of
from kitsunox.web.html import block, error_box, esc, internal, link, page, warning_box, when
from kitsunox.web.library import RUN_ID, Library, LoadError, RunSummary

RUNS_PER_PAGE: Final = 50
MAX_EVIDENCE_PER_GROUP: Final = 50
TOP_RULES: Final = 3
_SEVERITIES: Final = [s.value for s in Severity]

type Crumbs = Sequence[tuple[str | None, str]]


@dataclass(frozen=True, slots=True)
class Page:
    status: int
    html: str


def run_href(run_id: str) -> str | None:
    """The viewer's URL for a run, if `run_id` (read from a file) is a well-formed id."""
    return f"/runs/{run_id}" if RUN_ID.fullmatch(run_id) else None


def entry_href(run_id: str, rank: int) -> str | None:
    base = run_href(run_id)
    return f"{base}/entries/{rank}" if base and rank > 0 else None


def not_found(what: str = "This page does not exist.") -> Page:
    body = f"<h1>Not found</h1>\n{error_box(what)}"
    return Page(404, page("Not found", body, [("/", "Review queue")]))


def failure(status: int, title: str, message: str) -> Page:
    """An error page; `title` and `message` are plain text."""
    body = f"<h1>{esc(title)}</h1>\n{error_box(esc(message))}"
    return Page(status, page(title, body, [("/", "Review queue")]))


# ----------------------------------------------------------------------------- queue


def queue_page(library: Library) -> Page:
    queue = library.queue()
    crumbs: Crumbs = [(None, "Review queue")]
    if queue is None:
        body = (
            "<h1>Review queue</h1>\n"
            "<p>No review queue yet. <code>kitsunox queue</code> builds it, and "
            "<code>kitsunox collect</code> rebuilds it after every tick.</p>\n"
            f"<p>{internal('/runs', 'Browse the runs')} instead.</p>"
        )
        return Page(200, page("Review queue", body, crumbs))
    if isinstance(queue, LoadError):
        return Page(200, page("Review queue", _load_error("Review queue", queue), crumbs))
    return Page(200, page(f"Review queue ({queue.ecosystem})", _queue_body(queue), crumbs))


def _queue_body(queue: Queue) -> str:
    parts = [
        f"<h1>Review queue ({esc(queue.ecosystem)})</h1>",
        f"<p>Reports from {when(queue.since)} to {when(queue.as_of)} ({len(queue.runs)} runs): "
        f"<strong>{queue.packages} packages to review</strong> ({queue.versions} versions), "
        "highest score first. Each version links to its entry in the run that reported it "
        "most strongly.</p>",
    ]
    if queue.by_severity:
        parts.append(f"<p>Packages by highest severity: {_severity_counts(queue.by_severity)}.</p>")
    if queue.skipped:
        runs = ", ".join(_run_link(r) for r in queue.skipped)
        parts.append(warning_box(f"Unreadable reports, left out of the queue: {runs}."))
    if not queue.entries:
        parts.append("<p>Nothing to review.</p>")
        return "\n".join(parts)
    rows = "\n".join(_queue_row(e) for e in queue.entries)
    parts.append(
        "<table>\n<caption>Packages to review</caption>\n<thead><tr>"
        '<th scope="col">#</th><th scope="col">Package</th><th scope="col">Score</th>'
        '<th scope="col">Severity</th><th scope="col">Versions (newest first)</th>'
        '<th scope="col">Rules (versions)</th><th scope="col">Watched</th>'
        '<th scope="col">Last published</th>'
        f"</tr></thead>\n<tbody>\n{rows}\n</tbody>\n</table>"
    )
    return "\n".join(parts)


def _queue_row(entry: QueueEntry) -> str:
    versions = []
    for v in entry.versions:
        label = esc(v.version)
        href = entry_href(v.run_id, v.rank)
        shown = internal(href, label) if href else label
        versions.append(f'<li>{shown} <span class="note">{v.score:g}</span></li>')
    rules = "".join(f"<li><code>{esc(r.rule_id)}</code> ({r.versions})</li>" for r in entry.rules)
    return (
        f'<tr><td class="num">{entry.rank}</td><td>{esc(entry.name)}</td>'
        f'<td class="num">{entry.score:g}</td><td>{_severity(entry.severity)}</td>'
        f'<td><ul class="flat">{"".join(versions)}</ul></td>'
        f'<td><ul class="flat">{rules}</ul></td><td>{_yes(entry.watched)}</td>'
        f"<td>{when(entry.last_published)}</td></tr>"
    )


# ----------------------------------------------------------------------------- runs


def runs_page(library: Library, number: int = 1) -> Page | None:
    """Runs with a report, newest first, `RUNS_PER_PAGE` at a time; None past the last page
    (page 1 always exists)."""
    run_ids = library.run_ids()
    pages = max(1, -(-len(run_ids) // RUNS_PER_PAGE))
    if not 1 <= number <= pages:
        return None
    crumbs: Crumbs = [("/", "Review queue"), (None, "Runs")]
    if not run_ids:
        body = (
            "<h1>Runs</h1>\n<p>No run has a report yet. <code>kitsunox collect</code> writes "
            "one per run after Stage 4; <code>kitsunox report &lt;run_id&gt;</code> "
            "rewrites one.</p>"
        )
        return Page(200, page("Runs", body, crumbs))
    shown = run_ids[(number - 1) * RUNS_PER_PAGE : number * RUNS_PER_PAGE]
    rows = []
    for run_id in shown:
        summary = library.summary(run_id)
        if summary is not None:
            rows.append(_run_row(run_id, summary))
    body = "\n".join(
        [
            "<h1>Runs</h1>",
            f"<p>{len(run_ids)} runs with a report, newest first"
            + (f" (page {number} of {pages})" if pages > 1 else "")
            + ".</p>",
            "<table>\n<caption>Runs</caption>\n<thead><tr>"
            '<th scope="col">Run</th><th scope="col">Releases published</th>'
            '<th scope="col">Versions</th><th scope="col">To review</th>'
            '<th scope="col">By highest severity</th><th scope="col">Notes</th>'
            f"</tr></thead>\n<tbody>\n{'\n'.join(rows)}\n</tbody>\n</table>",
            _pager(number, pages),
        ]
    )
    title = "Runs" if number == 1 else f"Runs, page {number}"
    return Page(200, page(title, body, crumbs))


def _run_row(run_id: str, summary: RunSummary | LoadError) -> str:
    run = _run_link(run_id)
    if isinstance(summary, LoadError):
        return (
            f'<tr><td>{run}</td><td colspan="5" class="bad">report.json '
            f"{esc(summary.message)}</td></tr>"
        )
    notes = _uncompared_note(summary.uncompared, summary.outage) if summary.uncompared else ""
    return (
        f"<tr><td>{run}</td><td>{when(summary.window_start)} to {when(summary.window_end)}</td>"
        f'<td class="num">{summary.versions:,}</td><td class="num">{summary.reported}</td>'
        f"<td>{_severity_counts(dict(summary.by_severity))}</td><td>{notes}</td></tr>"
    )


def _pager(number: int, pages: int) -> str:
    if pages == 1:
        return ""
    links = []
    if number > 1:
        previous = "/runs" if number == 2 else f"/runs/page/{number - 1}"
        links.append(f"<li>{internal(previous, 'Newer runs')}</li>")
    if number < pages:
        links.append(f"<li>{internal(f'/runs/page/{number + 1}', 'Older runs')}</li>")
    return f'<nav aria-label="Pages"><ul class="pager">{"".join(links)}</ul></nav>'


# ----------------------------------------------------------------------------- run report


def run_page(library: Library, run_id: str) -> Page | None:
    report = library.report(run_id)
    if report is None:
        return None
    crumbs: Crumbs = [("/", "Review queue"), ("/runs", "Runs"), (None, esc(run_id))]
    if isinstance(report, LoadError):
        return Page(200, page(f"Run {run_id}", _load_error(f"Run {run_id}", report), crumbs))
    return Page(200, page(f"Run {report.run_id}", _report_body(run_id, report), crumbs))


def _report_body(run_id: str, report: Report) -> str:
    parts = [
        f"<h1>Run {esc(report.run_id)}</h1>",
        f"<p>Releases published {when(report.window_start)} to {when(report.window_end)} "
        f"({esc(report.ecosystem)}). {report.versions:,} versions analysed, "
        f"<strong>{report.reported} to review</strong>, highest score first.</p>",
    ]
    if report.by_severity:
        parts.append(f"<p>By highest severity: {_severity_counts(report.by_severity)}.</p>")
    uncompared, outage = report.network_uncompared()
    if uncompared:
        parts.append(warning_box(_uncompared_note(uncompared, outage)))
    if report.entries:
        rows = "\n".join(_report_row(run_id, e) for e in report.entries)
        parts.append(
            "<table>\n<caption>Versions to review</caption>\n<thead><tr>"
            '<th scope="col">#</th><th scope="col">Package</th><th scope="col">Score</th>'
            '<th scope="col">Severity</th><th scope="col">Top rules</th>'
            '<th scope="col">Watched</th>'
            f"</tr></thead>\n<tbody>\n{rows}\n</tbody>\n</table>"
        )
    else:
        parts.append("<p>Nothing to review in this run.</p>")
    if report.correlation:
        settings = json.dumps(report.correlation, indent=2, sort_keys=True, default=str)
        parts.append(
            "<details><summary>Stage 4 settings (<code>correlate.json</code>)</summary>"
            f"{block(settings)}</details>"
        )
    return "\n".join(parts)


def _report_row(run_id: str, entry: ReportEntry) -> str:
    label = f"{esc(entry.name)}@{esc(entry.version)}"
    href = entry_href(run_id, entry.rank)
    rules = "".join(
        f"<li><code>{esc(t.rule_id)}</code></li>" for t in entry.score_terms[:TOP_RULES]
    )
    return (
        f'<tr><td class="num">{entry.rank}</td>'
        f"<td>{internal(href, label) if href else label}</td>"
        f'<td class="num">{entry.score:g}</td><td>{_severity(entry.severity)}</td>'
        f'<td><ul class="flat">{rules}</ul></td><td>{_yes(entry.watched)}</td></tr>'
    )


# ----------------------------------------------------------------------------- one entry


def entry_page(library: Library, run_id: str, rank: int) -> Page | None:
    report = library.report(run_id)
    if report is None:
        return None
    run_crumb = (f"/runs/{run_id}", esc(run_id))
    crumbs: Crumbs = [("/", "Review queue"), ("/runs", "Runs"), run_crumb]
    if isinstance(report, LoadError):
        title = f"Run {run_id}, entry {rank}"
        return Page(200, page(title, _load_error(title, report), [*crumbs, (None, f"#{rank}")]))
    ranked = sorted(report.entries, key=lambda e: e.rank)
    index = next((i for i, e in enumerate(ranked) if e.rank == rank), None)
    if index is None:
        return None
    entry = ranked[index]
    neighbours = []
    if index > 0:
        before = ranked[index - 1]
        neighbours.append(f"<li>{_entry_link(run_id, before, 'Previous')}</li>")
    if index + 1 < len(ranked):
        after = ranked[index + 1]
        neighbours.append(f"<li>{_entry_link(run_id, after, 'Next')}</li>")
    pager = f'<nav aria-label="Entries"><ul class="pager">{"".join(neighbours)}</ul></nav>'
    body = "\n".join([_entry_body(entry), pager if neighbours else ""])
    title = f"{entry.name}@{entry.version}"
    return Page(200, page(title, body, [*crumbs, (None, f"#{entry.rank}")]))


def _entry_link(run_id: str, entry: ReportEntry, word: str) -> str:
    label = f"{word}: #{entry.rank} {esc(entry.name)}@{esc(entry.version)}"
    return internal(f"/runs/{run_id}/entries/{entry.rank}", label)


def _entry_body(entry: ReportEntry) -> str:
    previous = esc(entry.previous_version) if entry.previous_version else "none (new package)"
    downloads = (
        f"{entry.downloads:,} downloads / {entry.downloads_period_days} days"
        if entry.downloads is not None
        else "unknown"
    )
    links = entry.links
    registry = f"{link(links.registry, 'npm')} ({link(links.files, 'browse files')})"
    repository = link(links.repository, links.repository or "")
    facts = [
        ("Previous version", previous),
        ("Published", f"{when(entry.published_at)} by {esc(entry.publisher or 'unknown')}"),
        ("Popularity", downloads + (" (watched)" if entry.watched else "")),
        ("Registry", registry),
        ("Diff", link(links.diff, "npmdiff")),
        ("Repository", repository),
        ("Compared with", link(links.compared_commit, "repository at commit")),
    ]
    rows = "\n".join(f'<tr><th scope="row">{k}</th><td>{v}</td></tr>' for k, v in facts)
    terms = "\n".join(
        f"<tr><td><code>{esc(t.rule_id)}</code></td><td>{_severity(t.severity)}</td>"
        f'<td class="num">{t.weight:g}</td><td class="num">{t.count}</td></tr>'
        for t in entry.score_terms
    )
    total = sum(t.weight for t in entry.score_terms)
    parts = [
        f"<h1>#{entry.rank} {esc(entry.name)}@{esc(entry.version)}</h1>",
        f"<p><strong>Score {entry.score:g}</strong>, highest severity "
        f"{_severity(entry.severity)}. Stage 4: {esc(entry.reason)}.</p>",
        "<h2>What changed</h2>",
        f'<table class="facts">\n<tbody>\n{rows}\n</tbody>\n</table>',
        "<h2>How the score adds up</h2>",
        "<p>Each rule counts once, at its largest weight.</p>",
        "<table>\n<thead><tr>"
        '<th scope="col">Rule</th><th scope="col">Severity</th><th scope="col">Weight</th>'
        '<th scope="col">Findings</th>'
        f"</tr></thead>\n<tbody>\n{terms}\n</tbody>\n"
        f'<tfoot><tr><th scope="row" colspan="2">Total</th><td class="num">{total:g}</td>'
        "<td></td></tr></tfoot>\n</table>",
        "<h2>Findings</h2>",
    ]
    if not entry.findings:
        parts.append("<p>No findings recorded.</p>")
    current = None
    for stage, group in _grouped(entry):
        if stage != current:
            parts.append(f"<h3>{esc(stage)}</h3>")
            current = stage
        parts.append(_finding_group(group))
    return "\n".join(parts)


def _grouped(entry: ReportEntry) -> list[tuple[str, list[Finding]]]:
    """Findings of the same rule together, in report order. A report whose `stages` doesn't
    line up with its findings falls back to the rule id's stage."""
    groups: dict[tuple[str, str], list[Finding]] = {}
    for i, finding in enumerate(entry.findings):
        stage = entry.stages[i] if len(entry.stages) == len(entry.findings) else None
        key = (stage or stage_of(finding.rule_id), finding.rule_id)
        groups.setdefault(key, []).append(finding)
    return [(stage, group) for (stage, _), group in groups.items()]


def _finding_group(group: list[Finding]) -> str:
    first = group[0]
    places = f", {len(group)} places" if len(group) > 1 else ""
    parts = [
        '<section class="finding">',
        f"<h4>{esc(first.title)}</h4>",
        f'<p class="meta"><code>{esc(first.rule_id)}</code> v{first.rule_version}, '
        f"{_severity(first.severity)}, weight {first.weight:g}{places}</p>",
    ]
    parts += [f"<p>{esc(text)}</p>" for text in dict.fromkeys(f.explanation for f in group)]
    evidence = [e for f in group for e in f.evidence]
    shown = evidence[:MAX_EVIDENCE_PER_GROUP]
    if shown:
        parts.append('<ul class="evidence">')
        parts += [f"<li>{_evidence(e)}</li>" for e in shown]
        parts.append("</ul>")
    hidden = len(evidence) - len(shown)
    if hidden > 0:
        parts.append(
            f'<p class="note">... and {hidden} more places (all in <code>report.json</code>).</p>'
        )
    parts.append("</section>")
    return "\n".join(parts)


def _evidence(evidence: Evidence) -> str:
    where = esc(evidence.path) if evidence.path else esc(evidence.kind.value)
    if evidence.line_start is not None:
        end = evidence.line_end
        lines = f"{evidence.line_start}-{end}" if end and end != evidence.line_start else ""
        where += f", lines {lines}" if lines else f", line {evidence.line_start}"
    parts = [f'<p class="where">{where}</p>']
    if evidence.snippet:
        parts.append(block(evidence.snippet))
    if evidence.before is not None or evidence.after is not None:
        parts.append('<div class="change">')
        for label, value in (("Before", evidence.before), ("After", evidence.after)):
            shown = block(value) if value is not None else '<p class="note">(none)</p>'
            parts.append(f'<div><p class="label">{label}</p>{shown}</div>')
        parts.append("</div>")
    return "".join(parts)


# ----------------------------------------------------------------------------- shared


def _load_error(title: str, error: LoadError) -> str:
    return f"<h1>{esc(title)}</h1>\n" + error_box(
        f"<code>{esc(error.path)}</code> {esc(error.message)}"
    )


def _run_link(run_id: str) -> str:
    href = run_href(run_id)
    return internal(href, esc(run_id)) if href else esc(run_id)


def _severity(severity: Severity) -> str:
    return f'<span class="sev sev-{severity.value}">{severity.value}</span>'


def _severity_counts(counts: dict[str, int]) -> str:
    """Highest severity first; names this build doesn't know (untrusted keys) last."""
    ordered = sorted(counts.items(), key=lambda kv: (-_severity_rank(kv[0]), kv[0]))
    return ", ".join(f"{n} {esc(name)}" for name, n in ordered) or "none"


def _severity_rank(name: str) -> int:
    return _SEVERITIES.index(name) if name in _SEVERITIES else -1


def _uncompared_note(count: int, outage: bool) -> str:
    why = " (most lookups failed, so retries were skipped as an outage)" if outage else ""
    return (
        f"{count:,} versions were not compared with their repository: network "
        f"failures{why}. Their scores lack the repository evidence."
    )


def _yes(value: bool) -> str:
    return "yes" if value else ""
