"""Reviewer verdicts on reported versions: malicious, inconclusive or benign.

A reviewer (the owner in the viewer, or an analyst with `kitsunox verdict`) reads a version's
entry and records what it is. The version then leaves the review queue (`reporting.queue`, and
the viewer at once) and is listed on its verdict's page; `reopened` puts it back.

- **Append-only log**, `data/verdicts/<ecosystem>.jsonl`, one `VerdictRecord` a line. The last
  record for a version is its verdict; the whole history stays. A line is written with one
  `write` on a file opened `O_APPEND`, under an exclusive `flock`, so the viewer and the CLI
  can both write while `collect` reads.
- **A verdict outlives its run.** Runs are pruned after a week, so each record copies what
  the reviewer saw: score, severity, rules, publisher and publish time, and the run and rank
  it came from (the link works while the run is kept).
- **Package text stays untrusted.** Names, versions and rule ids come from the run's report
  (never from a form), and every renderer escapes them and the note.
"""

from __future__ import annotations

import fcntl
import os
import re
from collections.abc import Iterable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Final, Literal, get_args

from pydantic import Field, ValidationError

from kitsunox.core.models import Record
from kitsunox.reporting.report import Report, ReportEntry

VERDICTS_DIR: Final = "verdicts"
Verdict = Literal["malicious", "inconclusive", "benign", "reopened"]
KINDS: Final[tuple[Verdict, ...]] = ("malicious", "inconclusive", "benign")
VERDICTS: Final[Mapping[str, Verdict]] = {v: v for v in get_args(Verdict)}  # parses a form
MAX_NOTE_CHARS: Final = 2000
MAX_LOG_BYTES: Final = 64 * 2**20  # a longer log is read up to here
REVIEWER: Final = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")
OWNER: Final = "owner"  # who the viewer records verdicts as


class VerdictRecord(Record):
    """One verdict on one version, with the entry as it was reviewed."""

    ecosystem: str
    name: str
    version: str
    verdict: Verdict
    at: datetime
    by: str = Field(description="Who recorded it: `owner` from the viewer, or a CLI name.")
    note: str = ""
    run_id: str
    rank: int
    score: float
    severity: str
    rules: tuple[str, ...] = ()
    publisher: str | None = None
    published_at: datetime | None = None

    @property
    def key(self) -> tuple[str, str]:
        return (self.name, self.version)


def verdict_record(
    report: Report,
    entry: ReportEntry,
    verdict: Verdict,
    *,
    by: str,
    note: str = "",
    at: datetime,
) -> VerdictRecord:
    """The record for `entry` of `report`. `by` must match `REVIEWER`; the note is cut at
    MAX_NOTE_CHARS."""
    if not REVIEWER.fullmatch(by):
        raise ValueError("a reviewer name is 1-32 of a-z, 0-9, _ and -")
    return VerdictRecord(
        ecosystem=report.ecosystem,
        name=entry.name,
        version=entry.version,
        verdict=verdict,
        at=at,
        by=by,
        note=note.strip()[:MAX_NOTE_CHARS],
        run_id=report.run_id,
        rank=entry.rank,
        score=entry.score,
        severity=entry.severity.value,
        rules=entry_rules(entry),
        publisher=entry.publisher,
        published_at=entry.published_at,
    )


def entry_rules(entry: ReportEntry) -> tuple[str, ...]:
    """The rules that fired on an entry, as a verdict record keeps them: score terms first,
    then every finding's rule, each once."""
    return tuple(
        dict.fromkeys(
            [*(t.rule_id for t in entry.score_terms), *(f.rule_id for f in entry.findings)]
        )
    )


def verdicts_path(root: Path, ecosystem: str) -> Path:
    if not re.fullmatch(r"[a-z0-9]{1,32}", ecosystem):
        raise ValueError("not an ecosystem name")
    return root / VERDICTS_DIR / f"{ecosystem}.jsonl"


def append_verdict(root: Path, record: VerdictRecord) -> None:
    """Add `record` to its ecosystem's log (`root` is the data directory)."""
    path = verdicts_path(root, record.ecosystem)
    path.parent.mkdir(parents=True, exist_ok=True)
    line = record.model_dump_json().encode() + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.write(fd, line)
        os.fsync(fd)
    finally:
        os.close(fd)  # releases the lock


def read_verdicts(root: Path, ecosystem: str) -> list[VerdictRecord]:
    """Every record in the log, oldest first; unreadable lines are skipped."""
    try:
        with verdicts_path(root, ecosystem).open("rb") as handle:
            raw = handle.read(MAX_LOG_BYTES)
    except FileNotFoundError:
        return []
    records = []
    for line in raw.splitlines():
        try:
            records.append(VerdictRecord.model_validate_json(line))
        except ValidationError:
            continue
    return records


def current(records: Iterable[VerdictRecord]) -> dict[tuple[str, str], VerdictRecord]:
    """Each version's verdict now: its last record, unless that reopened it."""
    latest: dict[tuple[str, str], VerdictRecord] = {}
    for record in records:
        latest[record.key] = record
    return {key: r for key, r in latest.items() if r.verdict != "reopened"}


def tally(verdicts: Mapping[tuple[str, str], VerdictRecord]) -> dict[str, int]:
    """Versions per verdict, in `KINDS` order."""
    return {kind: sum(1 for r in verdicts.values() if r.verdict == kind) for kind in KINDS}
