"""Stage 0: turn change-feed entries into `Change` records for versions published in a window.

Packages that fail (fetch errors, malformed packuments) are recorded as skipped with a reason,
never silently dropped. Skips caused by the network (`TransientFetchError`) are marked
`transient`; chained runs fetch those packages again in the next run, over the window they were
missed in (`RetryItem`). Output order is fully determined by the input, regardless of how many
worker threads fetched it.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from compression import zstd
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Protocol

from pydantic import ValidationError

from kitsunox.core.interfaces import DIFF_BASE, ChangeStub, Ecosystem, PackageChanges
from kitsunox.core.models import Change, Persisted, Popularity, Record, Window
from kitsunox.core.watchlist import WEEKLY_CUTOFF, Watchlist
from kitsunox.util.http import FetchError, TransientFetchError

STAGE_ID = "ingest"


class SkippedPackage(Persisted):
    name: str
    cursor: int
    reason: str
    transient: bool = False


class RetryItem(Record):
    """A package an earlier run skipped because of the network. It is fetched again, and its
    changes are looked for from `window_start` (the start of the run that missed it)."""

    name: str
    cursor: int
    window_start: datetime


class IngestResult(Record):
    changes: tuple[Change, ...]
    skipped: tuple[SkippedPackage, ...]
    packages_seen: int
    popularity_failures: tuple[str, ...] = ()
    feed_start_estimate: datetime | None = None
    window_covered: bool | None = None


class PopularitySource(Protocol):
    label: str

    def lookup(self, names: Sequence[str], as_of: datetime) -> Mapping[str, Popularity]:
        """Popularity per name; names whose lookup failed are absent."""
        ...


class WatchlistPopularity:
    """Default source: membership in a prebuilt watchlist. No network calls per change."""

    def __init__(self, watchlist: Watchlist) -> None:
        self.watchlist = watchlist
        self.label = f"watchlist:{watchlist.id}"

    def lookup(self, names: Sequence[str], as_of: datetime) -> Mapping[str, Popularity]:
        return self.watchlist.lookup(names)


class DownloadsApiPopularity:
    """Optional source: per-package download counts from the ecosystem's API (slow)."""

    label = "downloads-api"

    def __init__(self, ecosystem: Ecosystem, weekly_cutoff: int = WEEKLY_CUTOFF) -> None:
        self.ecosystem = ecosystem
        self.weekly_cutoff = weekly_cutoff

    def lookup(self, names: Sequence[str], as_of: datetime) -> Mapping[str, Popularity]:
        result = self.ecosystem.download_counts(names, as_of)
        return {
            name: Popularity(
                source=result.source,
                downloads=downloads,
                period_days=result.period_days,
                watched=downloads is not None
                and downloads * 7 >= self.weekly_cutoff * result.period_days,
            )
            for name, downloads in result.counts.items()
        }


def run_ingest(
    ecosystem: Ecosystem,
    window: Window,
    *,
    since: int,
    until: int,
    workers: int = 8,
    popularity: PopularitySource | None = None,
    retry: Sequence[RetryItem] = (),
    diff_base: int = DIFF_BASE,
) -> IngestResult:
    """`retry`: packages to fetch again whatever the feed says; a package both in the feed and
    in `retry` is fetched once, over the wider window. `diff_base`: how each release's diff
    base is chosen (`interfaces.DIFF_BASE`; a replay passes the run's)."""
    stubs = ecosystem.list_changes(since, until)
    starts = {item.name: item.window_start for item in retry}
    listed = {stub.name for stub in stubs}
    stubs = stubs + [
        ChangeStub(name=item.name, cursor=item.cursor) for item in retry if item.name not in listed
    ]

    def build(stub: ChangeStub) -> PackageChanges | SkippedPackage:
        start = min(window.start, starts.get(stub.name, window.start))
        try:
            return ecosystem.build_changes(
                stub, Window(start=start, end=window.end), diff_base=diff_base
            )
        except (FetchError, ValueError, ValidationError) as exc:
            # Expected: network failures, malformed packuments (PackumentError is a ValueError).
            return _skip(stub, exc)
        except Exception as exc:
            # Anything else is a parser bug triggered by hostile data. One package must never
            # take down the run (that would let an attacker blind the scanner by publishing a
            # malformed package), so record it loudly and carry on.
            return _skip(stub, exc, prefix="UNEXPECTED ")

    with ThreadPoolExecutor(max_workers=workers) as pool:
        outcomes = list(pool.map(build, stubs))

    changes: list[Change] = []
    skipped: list[SkippedPackage] = []
    modified: list[datetime] = []
    for outcome in outcomes:
        if isinstance(outcome, SkippedPackage):
            skipped.append(outcome)
        else:
            changes.extend(outcome.changes)
            if outcome.modified_at is not None:
                modified.append(outcome.modified_at)
    feed_start_estimate = _feed_start_estimate(modified)
    popularity_failures: tuple[str, ...] = ()
    if popularity is not None:
        changes, popularity_failures = _with_popularity(popularity, changes, window)
    return IngestResult(
        changes=tuple(sorted(changes, key=lambda c: c.sort_key)),
        skipped=tuple(sorted(skipped, key=lambda s: s.name)),
        packages_seen=len(stubs),
        popularity_failures=popularity_failures,
        feed_start_estimate=feed_start_estimate,
        # Releases before the feed range's start are only seen if their package changed again
        # later, so a window that starts earlier is only partly covered.
        window_covered=None if feed_start_estimate is None else feed_start_estimate <= window.start,
    )


def _feed_start_estimate(modified: list[datetime]) -> datetime | None:
    """1st percentile of the packages' last-modified times. Not the minimum: some packages reach
    the feed long after they last changed (replication lag), which drags the minimum far
    earlier than the range really reaches. Validated 2026-10-27: minimum 18:36, 1st percentile
    19:52, and an independent release list showed coverage starting at ~19:52."""
    if not modified:
        return None
    ordered = sorted(modified)
    return ordered[len(ordered) // 100]


def _skip(stub: ChangeStub, exc: Exception, prefix: str = "") -> SkippedPackage:
    reason = f"{prefix}{type(exc).__name__}: {exc}".splitlines()[0][:500]
    return SkippedPackage(
        name=stub.name,
        cursor=stub.cursor,
        reason=reason,
        transient=isinstance(exc, TransientFetchError),
    )


def _with_popularity(
    source: PopularitySource, changes: list[Change], window: Window
) -> tuple[list[Change], tuple[str, ...]]:
    """Attach popularity to changes of existing packages. Brand-new packages are skipped: they
    have no download history yet. A failed lookup leaves `popularity` as None."""
    wanted = sorted({c.new.ref.name for c in changes if not c.is_new_package})
    if not wanted:
        return changes, ()
    stats = source.lookup(wanted, window.end)
    enriched = [
        c.model_copy(update={"popularity": stats[c.new.ref.name]}) if c.new.ref.name in stats else c
        for c in changes
    ]
    return enriched, tuple(n for n in wanted if n not in stats)


def write_jsonl(path: Path, records: Iterable[Record]) -> None:
    """One JSON object per line, in the given order. Byte-stable for identical records."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(record.model_dump_json())
            handle.write("\n")


def changes_file(run_dir: Path) -> Path:
    """A run's Stage 0 output: `changes.jsonl`, or `changes.jsonl.zst` once retention has
    compressed it."""
    plain = run_dir / "changes.jsonl"
    return plain if plain.exists() else run_dir / "changes.jsonl.zst"


def read_changes(path: Path) -> Sequence[Change]:
    if path.suffix == ".zst":
        with zstd.open(path, "rt", encoding="utf-8") as handle:
            return [Change.load_json(line) for line in handle if line.strip()]
    with path.open(encoding="utf-8") as handle:
        return [Change.load_json(line) for line in handle if line.strip()]
