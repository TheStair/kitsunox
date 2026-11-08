"""Reviewer verdicts on reported versions: malicious, unwanted, benign or unverified.

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
- **Four categories** (decision 0015, addendum 2026-11-08): `malicious` (harmful behaviour
  shown), `unwanted` (behaviour fully seen: covert or intrusive, not harmful enough to call
  malicious, like an antivirus "PUA"), `benign` (seen and legitimate) and `unverified` (we
  couldn't confirm). An `unverified` verdict names why in `reason`: `gone` (the code was
  unpublished or never captured), `remote` (the payload came from a repository or URL we
  couldn't see), `obfuscated` (we couldn't decode it) or `binary` (an unexplained native or
  binary payload); no other verdict takes a reason.
- **Legacy records.** Before 2026-11-08 the grey category was `inconclusive`. Such a record
  still loads, as `unverified` with no reason, until a newer record reclassifies the version.
  Only legacy records are `unverified` without a reason: `verdict_record` refuses to write one.
- **Tags qualify a verdict.** `probe` marks a security researcher's probe (a
  dependency-confusion or bug-bounty test) so counts can tell them from commodity malware. The
  verdict itself follows what the code does, not what it claims (`docs/viewer.md`, "What
  counts as malicious").
- **Versions in no report** (live evaluation's review sample, or a missed version under
  adjudication) are recorded from their ledger row with `kitsunox live verdict`, as the same
  record with **rank 0** (`evaluation/sample.py`, decision 0019). Ranks in a report start at 1,
  and the viewer links only those.
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
from typing import Any, Final, Literal, Self, get_args

from pydantic import Field, ValidationError, field_validator, model_validator

from kitsunox.core.models import Record
from kitsunox.reporting.report import Report, ReportEntry

VERDICTS_DIR: Final = "verdicts"
Verdict = Literal["malicious", "unwanted", "benign", "unverified", "reopened"]
KINDS: Final[tuple[Verdict, ...]] = ("malicious", "unwanted", "benign", "unverified")
FLAG_WORTHY: Final[frozenset[str]] = frozenset({"malicious", "unwanted"})
SEEN: Final[frozenset[str]] = frozenset({"malicious", "unwanted", "benign"})  # behaviour seen
VERDICTS: Final[Mapping[str, Verdict]] = {v: v for v in get_args(Verdict)}  # parses a form
LEGACY: Final[Mapping[str, Verdict]] = {"inconclusive": "unverified"}  # old name -> now
Reason = Literal["gone", "remote", "obfuscated", "binary"]
REASONS: Final[Mapping[str, Reason]] = {r: r for r in get_args(Reason)}  # parses a form
REASON_LABELS: Final[Mapping[Reason, str]] = {
    "gone": "code gone",
    "remote": "remote payload",
    "obfuscated": "obfuscated",
    "binary": "binary payload",
}
NO_REASON: Final = "no reason (was inconclusive)"  # a legacy record's
Tag = Literal["probe"]
TAGS: Final[Mapping[str, Tag]] = {t: t for t in get_args(Tag)}  # parses a form
TAG_LABELS: Final[Mapping[Tag, str]] = {"probe": "Research probe"}
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
    tags: tuple[Tag, ...] = ()
    reason: Reason | None = Field(
        default=None, description="Why an `unverified` verdict couldn't be confirmed."
    )
    run_id: str
    rank: int
    score: float
    severity: str
    rules: tuple[str, ...] = ()
    publisher: str | None = None
    published_at: datetime | None = None

    @field_validator("verdict", mode="before")
    @classmethod
    def _legacy(cls, value: Any) -> Any:
        """A legacy `inconclusive` record reads as `unverified` (with no reason)."""
        return LEGACY.get(value, value) if isinstance(value, str) else value

    @model_validator(mode="after")
    def _reason_only_unverified(self) -> Self:
        if self.reason is not None and self.verdict != "unverified":
            raise ValueError("only an unverified verdict has a reason")
        return self

    @property
    def key(self) -> tuple[str, str]:
        return (self.name, self.version)


def check_verdict(
    verdict: Verdict, *, by: str, tags: Iterable[Tag] = (), reason: Reason | None = None
) -> tuple[Tag, ...]:
    """Refuse what a new record may not say, and return its tags once each, in `TAGS` order.
    `by` must match `REVIEWER`; `reopened` takes no tags; `unverified` needs a reason and no
    other verdict takes one."""
    if not REVIEWER.fullmatch(by):
        raise ValueError("a reviewer name is 1-32 of a-z, 0-9, _ and -")
    given = set(tags)
    if given and verdict == "reopened":
        raise ValueError("a reopened version has no tags")
    if verdict == "unverified" and reason is None:
        raise ValueError("an unverified verdict needs a reason: " + ", ".join(REASONS))
    if verdict != "unverified" and reason is not None:
        raise ValueError("only an unverified verdict takes a reason")
    return tuple(t for t in TAGS.values() if t in given)


def verdict_label(record: VerdictRecord) -> str:
    """`unverified (code gone)`, or the verdict itself; plain text."""
    if record.verdict != "unverified":
        return record.verdict
    return f"unverified ({REASON_LABELS[record.reason] if record.reason else NO_REASON})"


def verdict_record(
    report: Report,
    entry: ReportEntry,
    verdict: Verdict,
    *,
    by: str,
    note: str = "",
    tags: Iterable[Tag] = (),
    reason: Reason | None = None,
    at: datetime,
) -> VerdictRecord:
    """The record for `entry` of `report`, checked by `check_verdict`; the note is cut at
    MAX_NOTE_CHARS."""
    kept = check_verdict(verdict, by=by, tags=tags, reason=reason)
    return VerdictRecord(
        ecosystem=report.ecosystem,
        name=entry.name,
        version=entry.version,
        verdict=verdict,
        at=at,
        by=by,
        note=note.strip()[:MAX_NOTE_CHARS],
        tags=kept,
        reason=reason,
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


def reasons(verdicts: Mapping[tuple[str, str], VerdictRecord]) -> dict[str, int]:
    """Unverified versions per reason, in `REASONS` order, then `none` (legacy records)."""
    found = [r.reason or "none" for r in verdicts.values() if r.verdict == "unverified"]
    return {k: found.count(k) for k in (*REASONS, "none") if k in found}


def probes(verdicts: Mapping[tuple[str, str], VerdictRecord], kind: str) -> int:
    """How many of the versions whose verdict is `kind` are tagged `probe`."""
    return sum(1 for r in verdicts.values() if r.verdict == kind and "probe" in r.tags)
