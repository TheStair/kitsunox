"""The review queue: every run's report over the last few days, one entry per package.

A run's `report.json` lists reported *versions*. Across runs that has two problems:

- **Packages that release often** fill the list: 27 `@lightdash/cli` versions in one day were 27
  entries. The queue groups them: one entry per package, with every reported version and how
  many versions each rule fired on.
- **Chained runs overlap** (15 minutes, `CHAIN_OVERLAP`), so the same version can be reported
  twice. Each version counts once, from its strongest sighting (severity, then score; the
  earliest run on a tie): a later run may have known more, and a missed attack costs more than
  a false positive. (Evaluation datasets keep the earliest sighting; that is about labels.)

Versions a reviewer has given a verdict (`reporting.verdicts`: malicious, inconclusive, benign)
are left out; the counts say how many, and the verdict tally rides along.

The queue is a pure function of the reports and the verdict log it reads: `as_of` is the newest
report's, never the clock, and the output is sorted, so the same files always give the same
bytes. It is written
to `data/queue/queue.json` (canonical) and `data/queue/index.md`, whose version links point at
each run's per-version pages. Package strings are untrusted and go through `markdown.text`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Final

from pydantic import Field

from kitsunox.core.models import Persisted, Record, Severity
from kitsunox.core.run import DataDir, RunManifest
from kitsunox.reporting.markdown import page_name, text
from kitsunox.reporting.report import REPORT_DIR, Report, ReportEntry
from kitsunox.reporting.verdicts import VerdictRecord, current, read_verdicts, tally
from kitsunox.util.files import atomic_write

QUEUE_DIR: Final = "queue"
VERSIONS_SHOWN: Final = 6
RULES_SHOWN: Final = 4
_ORDER: Final = list(Severity)


class QueueVersion(Record):
    version: str
    run_id: str
    rank: int = Field(description="Rank in that run's report.")
    score: float
    severity: Severity
    published_at: datetime | None
    page: str = Field(description="The version's page, relative to the queue directory.")


class RuleCount(Record):
    rule_id: str
    versions: int = Field(description="Reported versions of the package this rule fired on.")


class QueueEntry(Record):
    rank: int
    name: str
    score: float  # the highest among its versions
    severity: Severity  # the highest among its versions
    watched: bool
    first_published: datetime | None
    last_published: datetime | None
    versions: tuple[QueueVersion, ...]  # newest first
    rules: tuple[RuleCount, ...]  # most versions first


class Queue(Persisted):
    ecosystem: str
    as_of: datetime = Field(description="The newest report's `as_of`.")
    since: datetime = Field(description="Reports with an `as_of` after this are included.")
    runs: tuple[str, ...]
    skipped: tuple[str, ...] = Field(description="Reports that could not be read.")
    packages: int
    versions: int
    by_severity: dict[str, int] = Field(description="Packages by their highest severity.")
    entries: tuple[QueueEntry, ...]
    reviewed: int = Field(default=0, description="Versions left out: a verdict was recorded.")
    verdicts: dict[str, int] = Field(
        default_factory=dict, description="Versions per verdict, over the whole verdict log."
    )


def build_queue(
    data: DataDir,
    ecosystem: str,
    *,
    days: int,
    reviewed: Mapping[tuple[str, str], VerdictRecord] | None = None,
) -> Queue | None:
    """The queue over reports from the last `days` before the newest one; None if no run of
    `ecosystem` has a report yet. The window is chosen from the runs' small manifests, then
    the reports inside it are read one at a time: runs (and their reports) outlive pruning, so
    the cost must follow the window, not the whole history."""
    runs = _reported_runs(data, ecosystem)
    if not runs:
        return None
    as_of = runs[-1][0]
    since = as_of - timedelta(days=days)
    window = [(moment, run_id) for moment, run_id in runs if moment > since]

    verdicts = reviewed if reviewed is not None else current(read_verdicts(data.root, ecosystem))
    left_out: set[tuple[str, str]] = set()
    best: dict[tuple[str, str], _Sighting] = {}
    read, skipped = [], []
    for _, run_id in window:  # earliest first: a tie keeps the earliest sighting
        try:
            report = Report.load_json(
                (data.run_dir(run_id) / REPORT_DIR / "report.json").read_bytes()
            )
        except OSError, ValueError:  # damaged, or written with another schema version
            skipped.append(run_id)
            continue
        read.append(run_id)
        for entry in report.entries:
            key = (entry.name, entry.version)
            if key in verdicts:
                left_out.add(key)
                continue
            sighting = _Sighting.of(report.run_id, entry)
            if key not in best or sighting.strength > best[key].strength:
                best[key] = sighting
    by_package: dict[str, list[_Sighting]] = {}
    for sighting in best.values():
        by_package.setdefault(sighting.name, []).append(sighting)

    unranked = [_package(name, sightings) for name, sightings in by_package.items()]
    unranked.sort(key=lambda e: (-e.score, -_ORDER.index(e.severity), e.name))
    entries = tuple(e.model_copy(update={"rank": i}) for i, e in enumerate(unranked, start=1))
    by_severity: dict[str, int] = {}
    for queued in entries:
        by_severity[queued.severity.value] = by_severity.get(queued.severity.value, 0) + 1
    return Queue(
        ecosystem=ecosystem,
        as_of=as_of,
        since=since,
        runs=tuple(read),
        skipped=tuple(skipped),
        packages=len(entries),
        versions=sum(len(e.versions) for e in entries),
        by_severity=dict(sorted(by_severity.items())),
        entries=entries,
        reviewed=len(left_out),
        verdicts=tally(verdicts),
    )


def write_queue(data: DataDir, queue: Queue) -> Path:
    directory = data.root / QUEUE_DIR
    atomic_write(directory / "queue.json", queue.model_dump_json(indent=2).encode() + b"\n")
    atomic_write(directory / "index.md", render_queue(queue).encode())
    return directory


def render_queue(queue: Queue) -> str:
    lines = [
        f"# Kitsunox review queue ({text(queue.ecosystem)})",
        "",
        f"Reports from {_when(queue.since)} to {_when(queue.as_of)} ({len(queue.runs)} runs): "
        f"**{queue.packages} packages to review** ({queue.versions} versions), highest score "
        "first. Each version links to its page in the run that reported it first.",
        "",
    ]
    if queue.by_severity:
        counts = ", ".join(
            f"{n} {text(s)}"
            for s, n in sorted(queue.by_severity.items(), key=lambda kv: _desc(kv[0]))
        )
        lines += [f"Packages by highest severity: {counts}.", ""]
    if queue.reviewed or any(queue.verdicts.values()):
        counts = ", ".join(f"{n} {kind}" for kind, n in queue.verdicts.items())
        lines += [
            f"{queue.reviewed} reported versions already have a verdict and are left out. "
            f"Verdicts so far: {counts}.",
            "",
        ]
    if queue.skipped:
        lines += [f"Unreadable reports, left out: {', '.join(map(text, queue.skipped))}.", ""]
    if not queue.entries:
        return "\n".join([*lines, "Nothing to review.", ""])
    lines += [
        "| # | Package | Score | Severity | Versions | Rules (versions) | Watched |",
        "|---|---|---|---|---|---|---|",
    ]
    for entry in queue.entries:
        shown = ", ".join(f"[{text(v.version)}]({v.page})" for v in entry.versions[:VERSIONS_SHOWN])
        more = len(entry.versions) - VERSIONS_SHOWN
        if more > 0:
            shown += f" and {more} more"
        rules = ", ".join(  # our rule ids, not input
            f"`{r.rule_id}` ({r.versions})" for r in entry.rules[:RULES_SHOWN]
        )
        lines.append(
            f"| {entry.rank} | {text(entry.name)} | {entry.score:g} | {entry.severity.value} "
            f"| {shown} | {rules} | {'yes' if entry.watched else ''} |"
        )
    return "\n".join([*lines, ""])


@dataclass(frozen=True, slots=True)
class _Sighting:
    """What the queue keeps of one reported version (not the whole report entry)."""

    name: str
    version: QueueVersion
    rules: tuple[str, ...]
    watched: bool

    @classmethod
    def of(cls, run_id: str, entry: ReportEntry) -> _Sighting:
        version = QueueVersion(
            version=entry.version,
            run_id=run_id,
            rank=entry.rank,
            score=entry.score,
            severity=entry.severity,
            published_at=entry.published_at,
            page=f"../runs/{run_id}/{REPORT_DIR}/entries/{page_name(entry)}",
        )
        rules = tuple(t.rule_id for t in entry.score_terms)
        return cls(name=entry.name, version=version, rules=rules, watched=entry.watched)

    @property
    def strength(self) -> tuple[int, float]:
        """A version seen in two overlapping runs keeps the stronger sighting: a later run
        may have known more (a tag pushed since, a new label set). Missing an attack costs more
        than a false positive."""
        return _ORDER.index(self.version.severity), self.version.score


def _reported_runs(data: DataDir, ecosystem: str) -> list[tuple[datetime, str]]:
    """(as_of, run_id) of every `ecosystem` run with a report file, oldest first."""
    runs = data.root / "runs"
    found = []
    for run_dir in sorted(runs.iterdir()) if runs.exists() else ():
        if not (run_dir / REPORT_DIR / "report.json").is_file():
            continue
        try:
            manifest = RunManifest.load_json((run_dir / "manifest.json").read_bytes())
        except OSError, ValueError:
            continue  # not a complete run
        if manifest.ecosystem == ecosystem:
            found.append((manifest.as_of, manifest.run_id))
    return sorted(found)


def _package(name: str, sightings: list[_Sighting]) -> QueueEntry:
    versions = sorted(
        (s.version for s in sightings),
        key=lambda v: (v.published_at is not None, v.published_at, v.version),
        reverse=True,
    )
    rules: dict[str, int] = {}
    for sighting in sightings:
        for rule_id in sighting.rules:
            rules[rule_id] = rules.get(rule_id, 0) + 1
    published = [v.published_at for v in versions if v.published_at is not None]
    return QueueEntry(
        rank=0,
        name=name,
        score=max(v.score for v in versions),
        severity=max((v.severity for v in versions), key=_ORDER.index),
        watched=any(s.watched for s in sightings),
        first_published=min(published, default=None),
        last_published=max(published, default=None),
        versions=tuple(versions),
        rules=tuple(
            RuleCount(rule_id=rule_id, versions=n)
            for rule_id, n in sorted(rules.items(), key=lambda kv: (-kv[1], kv[0]))
        ),
    )


def _desc(severity: str) -> int:
    values = [s.value for s in _ORDER]
    return -values.index(severity) if severity in values else 1


def _when(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%d %H:%M UTC")
