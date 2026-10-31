"""After-the-fact confirmations: the registry later removed a version as malware, or an OSV
`MAL-` record later covered it.

Kitsunox has to find malware on its own evidence, so none of this feeds a rule or a score (the
owner's decision, 2026-10-31). It is a check on the pipeline and on the reviewer, shown with the
review queue and the verdicts (`reporting.queue`, the viewer):

- a version reviewed **benign** that is later confirmed is a missed attack, to read again;
- an **inconclusive** one is settled by someone with more evidence (npm sees abuse reports,
  downloads and the account behind a package);
- a **malicious** verdict confirmed by someone else is evidence that what the pipeline reports
  is real malware.

Two sources:

- **Registry takedowns** (`data/takedowns/<ecosystem>.json`). When npm removes a malicious
  package it publishes an empty `0.0.1-security` version from its own `npm` account, and that
  publish reaches the registry's changes feed like any other, so Stage 0 records it in the run's
  `changes.jsonl`. `collect` scans each new run for them (`scan_takedowns`) and keeps what it
  finds here, because runs are pruned after a week. A takedown covers the versions published
  before it.
- **OSV `MAL-` records** in the label set `kitsunox labels sync` refreshes daily, when a record
  covers the version.

Both are read as of a moment (the queue's `as_of`), so the queue stays a pure function of the
files it reads.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import datetime
from pathlib import Path
from typing import Final, Literal

from pydantic import Field, ValidationError

from kitsunox.core.models import Persisted, Record, VersionSnapshot
from kitsunox.core.run import DataDir, RunManifest
from kitsunox.evaluation.labels import LabelSet, label_store
from kitsunox.stages.ingest import changes_file, iter_changes
from kitsunox.util.files import atomic_write

TAKEDOWNS_DIR: Final = "takedowns"
Source = Literal["registry", "osv"]


class Takedown(Record):
    name: str
    version: str = Field(description="The holder's version, e.g. `0.0.1-security`.")
    published_at: datetime = Field(description="When the registry published the holder.")
    run_id: str = Field(description="The first run whose feed carried it.")


class TakedownLog(Persisted):
    ecosystem: str
    scanned_through: str | None = Field(
        default=None, description="The newest run scanned; later runs are scanned next."
    )
    takedowns: tuple[Takedown, ...] = Field(default=(), description="By name, then time.")


class Confirmation(Record):
    source: Source
    id: str = Field(description="The OSV record id, or the holder version a takedown left.")
    published: datetime


def takedowns_path(root: Path, ecosystem: str) -> Path:
    return root / TAKEDOWNS_DIR / f"{ecosystem}.json"


def read_takedowns(root: Path, ecosystem: str) -> TakedownLog:
    """The log, or an empty one (nothing scanned yet) if it is missing or unreadable: the next
    scan then reads every run still kept."""
    try:
        return TakedownLog.load_json(takedowns_path(root, ecosystem).read_bytes())
    except OSError, ValueError, ValidationError:
        return TakedownLog(ecosystem=ecosystem)


def scan_takedowns(
    data: DataDir, ecosystem: str, is_takedown: Callable[[VersionSnapshot], bool]
) -> tuple[TakedownLog, int, int]:
    """Read the changes of every complete `ecosystem` run after the log's `scanned_through`,
    add the takedowns found, and save the log. Returns (log, runs scanned, takedowns added).
    Chained runs overlap, so a takedown seen twice is kept once, with its first run. The caller
    holds `DataDir.lock()`."""
    log = read_takedowns(data.root, ecosystem)
    runs = sorted(
        d.name
        for d in (data.root / "runs").glob(f"*-{ecosystem}")
        if (log.scanned_through is None or d.name > log.scanned_through)
        and _complete(d / "manifest.json", ecosystem)
    )
    known = {(t.name, t.version, t.published_at): t for t in log.takedowns}
    before = len(known)
    for run_id in runs:
        for change in iter_changes(changes_file(data.run_dir(run_id))):
            new = change.new
            when = new.publish.published_at
            if when is None or not is_takedown(new):
                continue
            ref = new.ref
            known.setdefault(
                (ref.name, ref.version, when),
                Takedown(name=ref.name, version=ref.version, published_at=when, run_id=run_id),
            )
    if not runs:
        return log, 0, 0
    log = TakedownLog(
        ecosystem=ecosystem,
        scanned_through=runs[-1],
        takedowns=tuple(sorted(known.values(), key=lambda t: (t.name, t.published_at, t.version))),
    )
    path = takedowns_path(data.root, ecosystem)
    atomic_write(path, log.model_dump_json(indent=2).encode() + b"\n")
    return log, len(runs), len(known) - before


class Confirmations:
    """Who else has called a version malware, as of `as_of`."""

    def __init__(
        self, takedowns: Iterable[Takedown], labels: LabelSet | None, as_of: datetime
    ) -> None:
        self._takedowns: dict[str, list[Takedown]] = {}
        for takedown in takedowns:
            if takedown.published_at <= as_of:
                self._takedowns.setdefault(takedown.name, []).append(takedown)
        self._labels = labels
        self._as_of = as_of

    def of(
        self, name: str, version: str, published_at: datetime | None
    ) -> tuple[Confirmation, ...]:
        """Takedowns of `name` after the version was published (a name can be registered again
        after a takedown, and the new owner's releases are not the removed malware), then OSV
        records covering the version, oldest first."""
        found = [
            Confirmation(source="registry", id=t.version, published=t.published_at)
            for t in self._takedowns.get(name, ())
            if published_at is None or published_at <= t.published_at
        ]
        if self._labels is not None:
            found += [
                Confirmation(source="osv", id=label.id, published=label.published)
                for label in self._labels.labels.get(name, ())
                if label.published <= self._as_of and label.affects(version)
            ]
        return tuple(sorted(found, key=lambda c: (c.published, c.source, c.id)))


def load_confirmations(data: DataDir, ecosystem: str, as_of: datetime) -> Confirmations:
    """The takedown log and the newest label set fetched by `as_of`."""
    store = label_store(data)
    labels_id = store.latest_id(ecosystem, not_after=as_of)
    labels = store.load(ecosystem, labels_id) if labels_id else None
    return Confirmations(read_takedowns(data.root, ecosystem).takedowns, labels, as_of)


def _complete(manifest: Path, ecosystem: str) -> bool:
    try:
        return RunManifest.load_json(manifest.read_bytes()).ecosystem == ecosystem
    except OSError, ValueError:
        return False
