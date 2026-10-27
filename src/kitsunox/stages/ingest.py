"""Stage 0: turn change-feed entries into `Change` records for versions published in a window.

Packages that fail (fetch errors, malformed packuments) are recorded as skipped with a reason,
never silently dropped. Output order is fully determined by the input, regardless of how many
worker threads fetched it.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from pydantic import ValidationError

from kitsunox.core.interfaces import ChangeStub, Ecosystem
from kitsunox.core.models import Change, Record, Window
from kitsunox.util.http import FetchError

STAGE_ID = "ingest"


class SkippedPackage(Record):
    name: str
    cursor: int
    reason: str


class IngestResult(Record):
    changes: tuple[Change, ...]
    skipped: tuple[SkippedPackage, ...]
    packages_seen: int


def run_ingest(
    ecosystem: Ecosystem, window: Window, *, since: int, until: int, workers: int = 8
) -> IngestResult:
    stubs = ecosystem.list_changes(since, until)

    def build(stub: ChangeStub) -> list[Change] | SkippedPackage:
        try:
            return ecosystem.build_changes(stub, window)
        except (FetchError, ValueError, ValidationError) as exc:
            # PackumentError is a ValueError; ValidationError covers hostile field types.
            reason = f"{type(exc).__name__}: {exc}".splitlines()[0][:500]
            return SkippedPackage(name=stub.name, cursor=stub.cursor, reason=reason)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        outcomes = list(pool.map(build, stubs))

    changes: list[Change] = []
    skipped: list[SkippedPackage] = []
    for outcome in outcomes:
        if isinstance(outcome, SkippedPackage):
            skipped.append(outcome)
        else:
            changes.extend(outcome)
    return IngestResult(
        changes=tuple(sorted(changes, key=lambda c: c.sort_key)),
        skipped=tuple(sorted(skipped, key=lambda s: s.name)),
        packages_seen=len(stubs),
    )


def write_jsonl(path: Path, records: Iterable[Record]) -> None:
    """One JSON object per line, in the given order. Byte-stable for identical records."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(record.model_dump_json())
            handle.write("\n")


def read_changes(path: Path) -> Sequence[Change]:
    with path.open(encoding="utf-8") as handle:
        return [Change.model_validate_json(line) for line in handle if line.strip()]
