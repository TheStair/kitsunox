"""Access to a data directory's reports, review queue, reviewer verdicts and live evaluation
(`eval/live`: the reports, the results log and the daily review samples). Everything is
read-only except the verdict log, which `record_verdict` appends to (`reporting.verdicts`).

Request paths never reach the filesystem: a run id from a URL is matched against `RUN_ID` and
then looked up among the names actually listed in `runs/`, and only that listed name is used to
build a path. Files are opened for reading only. A file that can't be read or validated
(damaged, or written with another schema version) becomes a `LoadError` with a short message,
never an exception or a traceback in the page.

Parsed files are cached by (inode, size, mtime), so a page reloads only what `collect` has
rewritten since (it replaces files atomically, which gives a new inode). The report cache is
bounded by the total size of the cached files (`REPORT_CACHE_BYTES`), the live-evaluation
caches by a count (`LIVE_CACHE_FILES`), and a file over `MAX_FILE_BYTES` is not parsed at all.
Live evaluation's datasets (`eval/live/datasets/`, hundreds of thousands of rows) are never
read: the reports already hold what the pages show.
"""

from __future__ import annotations

import os
import re
import threading
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final

from kitsunox.core.models import Persisted
from kitsunox.evaluation.live import LiveReport, LogLine
from kitsunox.evaluation.sample import SAMPLE_DIR, DailySample
from kitsunox.reporting.queue import QUEUE_DIR, Queue
from kitsunox.reporting.report import REPORT_DIR, Report
from kitsunox.reporting.verdicts import (
    VerdictRecord,
    append_verdict,
    current,
    read_verdicts,
    verdicts_path,
)
from kitsunox.util.schema import SchemaVersionError

RUN_ID: Final = re.compile(r"[0-9]{8}T[0-9]{6}Z-[a-z0-9]{1,32}")
LIVE_ID: Final = re.compile(r"live-[0-9]{8}T[0-9]{6}Z")  # a live report (its dataset's name)
SAMPLE_DAY: Final = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
LIVE_DIR: Final = ("eval", "live")
LIVE_CACHE_FILES: Final = 16  # parsed live reports and samples kept, each
MAX_FILE_BYTES: Final = 256 * 2**20
REPORT_CACHE_BYTES: Final = 128 * 2**20  # file sizes; the parsed models take several times more
_MAX_MESSAGE: Final = 300

type _Signature = tuple[int, int, int]


@dataclass(frozen=True, slots=True)
class LoadError:
    """A file that exists but could not be read. `message` is plain text (escape it)."""

    path: str
    message: str


@dataclass(frozen=True, slots=True)
class RunSummary:
    """What the run list shows of one report."""

    run_id: str
    ecosystem: str
    as_of: datetime
    window_start: datetime
    window_end: datetime
    versions: int
    reported: int
    by_severity: tuple[tuple[str, int], ...]
    uncompared: int
    outage: bool

    @classmethod
    def of(cls, report: Report) -> RunSummary:
        uncompared, outage = report.network_uncompared()
        return cls(
            run_id=report.run_id,
            ecosystem=report.ecosystem,
            as_of=report.as_of,
            window_start=report.window_start,
            window_end=report.window_end,
            versions=report.versions,
            reported=report.reported,
            by_severity=tuple(sorted(report.by_severity.items())),
            uncompared=uncompared,
            outage=outage,
        )


@dataclass(frozen=True, slots=True)
class LiveLog:
    """The live results log (`eval/live/log.jsonl`): one line per build, oldest first."""

    lines: tuple[LogLine, ...]
    unreadable: int  # lines that didn't parse (damaged, or another build's format)


@dataclass(frozen=True, slots=True)
class Verdicts:
    log: tuple[VerdictRecord, ...]  # oldest first
    now: dict[tuple[str, str], VerdictRecord]  # (name, version) -> its verdict, if any

    def history(self, name: str, version: str) -> list[VerdictRecord]:
        return [r for r in self.log if r.key == (name, version)]


class Library:
    """The reports and queue under one data directory. Safe to share between threads."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._lock = threading.Lock()
        self._reports: OrderedDict[Path, tuple[_Signature, Report | LoadError]] = OrderedDict()
        self._summaries: dict[Path, tuple[_Signature, RunSummary | LoadError]] = {}
        self._queue: tuple[_Signature, Queue | LoadError] | None = None
        self._verdicts: dict[str, tuple[_Signature, Verdicts]] = {}
        self._live: OrderedDict[Path, tuple[_Signature, LiveReport | LoadError]] = OrderedDict()
        self._samples: OrderedDict[Path, tuple[_Signature, DailySample | LoadError]] = OrderedDict()
        self._log: tuple[_Signature, LiveLog | LoadError] | None = None

    @property
    def queue_path(self) -> Path:
        return self.root / QUEUE_DIR / "queue.json"

    def run_ids(self) -> tuple[str, ...]:
        """Runs with a report, newest first (run ids start with their UTC time)."""
        runs = self.root / "runs"
        try:
            names = [entry.name for entry in runs.iterdir()]
        except OSError:
            return ()
        return tuple(
            sorted(
                (n for n in names if RUN_ID.fullmatch(n) and self._report_path(n).is_file()),
                reverse=True,
            )
        )

    def find_run(self, run_id: str) -> str | None:
        """The listed run whose id is `run_id`, or None: unknown, malformed or no report."""
        if not RUN_ID.fullmatch(run_id):
            return None
        for listed in self.run_ids():
            if listed == run_id:
                return listed
        return None

    def report(self, run_id: str) -> Report | LoadError | None:
        """The run's report; None if there is no such run (or it has no report)."""
        listed = self.find_run(run_id)
        return None if listed is None else self._report_at(self._report_path(listed))

    def summary(self, run_id: str) -> RunSummary | LoadError | None:
        listed = self.find_run(run_id)
        if listed is None:
            return None
        path = self._report_path(listed)
        signature = _signature(path)
        with self._lock:
            cached = self._summaries.get(path)
            if cached is not None and cached[0] == signature:
                return cached[1]
        report = self._report_at(path)
        summary = RunSummary.of(report) if isinstance(report, Report) else report
        with self._lock:
            self._summaries[path] = (signature, summary)
        return summary

    def queue(self) -> Queue | LoadError | None:
        """The review queue; None if it hasn't been built."""
        path = self.queue_path
        if not path.is_file():
            return None
        signature = _signature(path)
        with self._lock:
            if self._queue is not None and self._queue[0] == signature:
                return self._queue[1]
        loaded = _load(Queue, path)
        with self._lock:
            self._queue = (signature, loaded)
        return loaded

    def verdicts(self, ecosystem: str = "npm") -> Verdicts:
        """The ecosystem's verdict log and each version's verdict now."""
        path = verdicts_path(self.root, ecosystem)
        signature = _signature(path)
        with self._lock:
            cached = self._verdicts.get(ecosystem)
            if cached is not None and cached[0] == signature:
                return cached[1]
        records = tuple(read_verdicts(self.root, ecosystem))
        loaded = Verdicts(records, current(records))
        with self._lock:
            self._verdicts[ecosystem] = (signature, loaded)
        return loaded

    def record_verdict(self, record: VerdictRecord) -> None:
        append_verdict(self.root, record)

    # ------------------------------------------------------------------- live evaluation

    @property
    def live_dir(self) -> Path:
        return self.root.joinpath(*LIVE_DIR)

    def live_ids(self) -> tuple[str, ...]:
        """Live reports (`eval/live/reports/live-<labels>.json`), newest first."""
        return _listed(self.live_dir / "reports", LIVE_ID, ".json")

    def live_report(self, dataset: str) -> LiveReport | LoadError | None:
        """The live report of `dataset`; None if there is no such report."""
        if dataset not in self.live_ids():
            return None
        path = self.live_dir / "reports" / f"{dataset}.json"
        return _cached(self._lock, self._live, path, lambda: _load(LiveReport, path))

    def sample_days(self) -> tuple[str, ...]:
        """Days with a review sample (`eval/live/sample/<day>.json`), newest first."""
        return _listed(self.live_dir / SAMPLE_DIR, SAMPLE_DAY, ".json")

    def sample(self, day: str) -> DailySample | LoadError | None:
        if day not in self.sample_days():
            return None
        path = self.live_dir / SAMPLE_DIR / f"{day}.json"
        return _cached(self._lock, self._samples, path, lambda: _load(DailySample, path))

    def live_log(self) -> LiveLog | LoadError | None:
        """The results log; None if no build has written one."""
        path = self.live_dir / "log.jsonl"
        if not path.is_file():
            return None
        signature = _signature(path)
        with self._lock:
            if self._log is not None and self._log[0] == signature:
                return self._log[1]
        loaded = _load_log(path)
        with self._lock:
            self._log = (signature, loaded)
        return loaded

    def _report_at(self, path: Path) -> Report | LoadError:
        signature = _signature(path)
        with self._lock:
            cached = self._reports.get(path)
            if cached is not None and cached[0] == signature:
                self._reports.move_to_end(path)
                return cached[1]
        loaded = _load(Report, path)
        with self._lock:
            self._reports[path] = (signature, loaded)
            self._reports.move_to_end(path)
            # The newest is kept even alone over the budget, so its pages don't reparse it.
            while len(self._reports) > 1 and self._cached_bytes() > REPORT_CACHE_BYTES:
                self._reports.popitem(last=False)
        return loaded

    def _cached_bytes(self) -> int:
        """Bytes of the files behind the cached reports (a LoadError costs nothing)."""
        return sum(
            signature[1]
            for signature, report in self._reports.values()
            if isinstance(report, Report)
        )

    def _report_path(self, listed: str) -> Path:
        return self.root / "runs" / listed / REPORT_DIR / "report.json"


def _listed(directory: Path, pattern: re.Pattern[str], suffix: str) -> tuple[str, ...]:
    """Stems of the files in `directory` named `<pattern><suffix>`, newest (highest) first.
    Only names actually listed are ever used to build a path."""
    try:
        names = [entry.name for entry in directory.iterdir()]
    except OSError:
        return ()
    stems = (n.removesuffix(suffix) for n in names if n.endswith(suffix))
    return tuple(
        sorted(
            (s for s in stems if pattern.fullmatch(s) and (directory / f"{s}{suffix}").is_file()),
            reverse=True,
        )
    )


def _cached[T](
    lock: threading.Lock,
    cache: OrderedDict[Path, tuple[_Signature, T]],
    path: Path,
    load: Callable[[], T],
) -> T:
    """`load()` unless `cache` has `path` at its current signature; at most
    `LIVE_CACHE_FILES` entries, least recently used dropped first."""
    signature = _signature(path)
    with lock:
        cached = cache.get(path)
        if cached is not None and cached[0] == signature:
            cache.move_to_end(path)
            return cached[1]
    loaded = load()
    with lock:
        cache[path] = (signature, loaded)
        cache.move_to_end(path)
        while len(cache) > LIVE_CACHE_FILES:
            cache.popitem(last=False)
    return loaded


def _load_log(path: Path) -> LiveLog | LoadError:
    """Every line that parses as a `LogLine`; the others are counted, never quoted."""
    shown = f"{path.parent.name}/{path.name}"
    try:
        with path.open("rb") as handle:
            size = os.fstat(handle.fileno()).st_size
            if size > MAX_FILE_BYTES:
                return LoadError(shown, f"too large to show ({size / 2**20:,.0f} MB).")
            data = handle.read(MAX_FILE_BYTES)
    except OSError as exc:
        return LoadError(shown, f"could not be read ({type(exc).__name__}).")
    lines: list[LogLine] = []
    unreadable = 0
    for raw in data.splitlines():
        if not raw.strip():
            continue
        try:
            lines.append(LogLine.model_validate_json(raw))
        except ValueError, RecursionError:
            unreadable += 1
    return LiveLog(tuple(lines), unreadable)


def _signature(path: Path) -> _Signature:
    try:
        st = os.stat(path)
    except OSError:
        return (-1, -1, -1)
    return (st.st_ino, st.st_size, st.st_mtime_ns)


def _load[T: Persisted](model: type[T], path: Path) -> T | LoadError:
    shown = f"{path.parent.name}/{path.name}"
    try:
        with path.open("rb") as handle:
            size = os.fstat(handle.fileno()).st_size
            if size > MAX_FILE_BYTES:
                return LoadError(shown, f"too large to show ({size / 2**20:,.0f} MB).")
            data = handle.read(MAX_FILE_BYTES)  # a file grown since is cut, so it won't parse
        return model.load_json(data)
    except SchemaVersionError as exc:  # our own message: which version, which was expected
        return LoadError(shown, str(exc)[:_MAX_MESSAGE])
    except OSError as exc:
        return LoadError(shown, f"could not be read ({type(exc).__name__}).")
    except (RecursionError, MemoryError) as exc:  # nested too deeply, or too big once parsed
        return LoadError(shown, f"could not be parsed ({type(exc).__name__}).")
    except ValueError as exc:  # pydantic's messages quote the (untrusted) input: not shown
        return LoadError(
            shown,
            f"does not match this build's {model.__name__} format ({type(exc).__name__}). "
            "It may be damaged, or written by another version of Kitsunox.",
        )
