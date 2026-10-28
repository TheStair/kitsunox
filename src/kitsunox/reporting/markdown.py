"""Markdown views of `report.json`: `index.md` (the review queue) and one page per reported
version.

Every string that came from a package (names, versions, snippets, explanations quoting
manifests, URLs) is untrusted and may be crafted to break out of its place: a backtick run to
end a code block, a `|` to forge a table cell, `<script>` or a `javascript:` link for viewers
that render HTML. So:

- code and evidence go in fenced blocks whose fence is longer than any backtick run inside;
- inline text has HTML and Markdown control characters escaped, and newlines flattened;
- links are emitted only for `https://` URLs without spaces or angle brackets, in `<...>`
  form; anything else is shown as escaped text.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Final

from kitsunox.core.models import Evidence, Finding
from kitsunox.reporting.report import Report, ReportEntry
from kitsunox.util.files import atomic_write

MAX_EVIDENCE_PER_FINDING: Final = 5
_CONTROL: Final = re.compile(r"[\x00-\x08\x0b-\x1f\x7f‪-‮⁦-⁩]")
_SPECIAL: Final = re.compile(r"([\\`*_{}\[\]()#+!|~>-])")
_SAFE_URL: Final = re.compile(r"^https://[^\s<>\"'`]+$")


def text(value: object) -> str:
    """Inline, untrusted: one line, HTML neutralised, Markdown punctuation escaped. Also drops
    control and bidirectional-override characters, which can make text read differently from
    what it is."""
    flat = " ".join(_CONTROL.sub("", str(value)).split())
    flat = flat.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return _SPECIAL.sub(r"\\\1", flat)


def code(value: str, language: str = "") -> str:
    """A fenced block that `value` cannot close."""
    clean = _CONTROL.sub("", value)
    longest = max((len(run) for run in re.findall(r"`+", clean)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{language}\n{clean}\n{fence}"


def link(url: str | None, label: str) -> str:
    if url is None:
        return "n/a"
    if not _SAFE_URL.match(url):
        return text(url)
    return f"[{text(label)}](<{url}>)"


def _when(moment: datetime | None) -> str:
    return moment.strftime("%Y-%m-%d %H:%M UTC") if moment else "unknown"


def page_name(entry: ReportEntry) -> str:
    """A safe file name: rank first (unique), then a sanitised package@version."""
    slug = re.sub(r"[^A-Za-z0-9._@-]+", "_", f"{entry.name}@{entry.version}").strip("._")
    return f"{entry.rank:04d}-{slug[:120]}.md"


def render_index(report: Report) -> str:
    lines = [
        f"# Kitsunox report: run {text(report.run_id)}",
        "",
        f"Releases published {_when(report.window_start)} to {_when(report.window_end)} "
        f"({text(report.ecosystem)}). {report.versions:,} versions analysed, "
        f"**{report.reported} to review**, highest score first.",
        "",
    ]
    if report.by_severity:
        counts = ", ".join(f"{n} {text(s)}" for s, n in report.by_severity.items())
        lines += [f"By highest severity: {counts}.", ""]
    if not report.entries:
        return "\n".join([*lines, "Nothing to review in this run.", ""])
    lines += [
        "| # | Package | Score | Severity | Why | Watched |",
        "|---|---|---|---|---|---|",
    ]
    for entry in report.entries:
        top = ", ".join(f"`{t.rule_id}`" for t in entry.score_terms[:3])  # our ids, not input
        lines.append(
            f"| {entry.rank} | [{text(entry.name)}@{text(entry.version)}]({page_name(entry)}) "
            f"| {entry.score:g} | {entry.severity.value} | {top} "
            f"| {'yes' if entry.watched else ''} |"
        )
    return "\n".join([*lines, ""])


def render_entry(entry: ReportEntry) -> str:
    previous = text(entry.previous_version) if entry.previous_version else "none (new package)"
    downloads = (
        f"{entry.downloads:,} downloads / {entry.downloads_period_days} days"
        if entry.downloads is not None
        else "unknown"
    )
    lines = [
        f"# {entry.rank}. {text(entry.name)}@{text(entry.version)}",
        "",
        f"**Score {entry.score:g}**, highest severity **{entry.severity.value}**. "
        f"Stage 4: {text(entry.reason)}.",
        "",
        "| | |",
        "|---|---|",
        f"| Previous version | {previous} |",
        f"| Published | {_when(entry.published_at)} by {text(entry.publisher or 'unknown')} |",
        f"| Popularity | {downloads}{' (watched)' if entry.watched else ''} |",
        f"| Registry | {link(entry.links.registry, 'npm')} "
        f"({link(entry.links.files, 'browse files')}) |",
        f"| Diff | {link(entry.links.diff, 'npmdiff') if entry.links.diff else 'n/a'} |",
        f"| Repository | {link(entry.links.repository, entry.links.repository or '')} |",
        f"| Compared with | {link(entry.links.compared_commit, 'repository at commit')} |",
        "",
        "## How the score adds up",
        "",
        "| Rule | Severity | Weight | Findings |",
        "|---|---|---|---|",
        *(
            f"| `{t.rule_id}` | {t.severity.value} | {t.weight:g} | {t.count} |"
            for t in entry.score_terms
        ),
        "",
        "## Findings",
    ]
    current = None
    for stage, group in _grouped(entry):
        if stage != current:
            lines += ["", f"### {text(stage)}"]
            current = stage
        lines += ["", *_finding_group(group)]
    return "\n".join([*lines, ""])


def _grouped(entry: ReportEntry) -> list[tuple[str, list[Finding]]]:
    """Findings of the same rule together (Stage 2 reports one per file), in report order."""
    groups: dict[tuple[str, str], list[Finding]] = {}
    for finding, stage in zip(entry.findings, entry.stages, strict=True):
        groups.setdefault((stage, finding.rule_id), []).append(finding)
    return [(stage, group) for (stage, _), group in groups.items()]


def _finding_group(group: list[Finding]) -> list[str]:
    first = group[0]
    count = f", {len(group)} places" if len(group) > 1 else ""
    lines = [
        f"**{text(first.title)}** (`{first.rule_id}` v{first.rule_version}, "
        f"{first.severity.value}, weight {first.weight:g}{count})",
    ]
    explanations = list(dict.fromkeys(f.explanation for f in group))
    evidence = [e for f in group for e in f.evidence]
    shown = evidence[:MAX_EVIDENCE_PER_FINDING]
    for explanation in explanations[:MAX_EVIDENCE_PER_FINDING]:
        lines += ["", text(explanation)]
    for item in shown:
        lines += ["", *_evidence(item)]
    hidden = len(evidence) - len(shown)
    if hidden > 0:
        lines += ["", f"... and {hidden} more places (all in `report.json`)."]
    return lines


def _evidence(evidence: Evidence) -> list[str]:
    where = text(evidence.path or evidence.kind.value)
    if evidence.line_start is not None:
        where += f", line {evidence.line_start}"
    lines = [f"- {where}"]
    if evidence.snippet:
        lines += ["", code(evidence.snippet)]
    if evidence.before is not None or evidence.after is not None:
        lines += ["", code(f"before: {evidence.before}\nafter:  {evidence.after}")]
    return lines


def write_markdown(directory: Path, report: Report) -> None:
    """`index.md` plus `entries/<page>.md`; pages from an earlier render are removed first, so
    the directory always matches `report`."""
    pages = directory / "entries"
    if pages.exists():
        for old in pages.glob("*.md"):
            old.unlink()
    for entry in report.entries:
        atomic_write(pages / page_name(entry), render_entry(entry).encode())
    atomic_write(directory / "index.md", render_index(report).encode())
