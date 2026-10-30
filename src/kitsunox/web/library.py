"""Read-only access to a data directory's reports and review queue.

Request paths never reach the filesystem: a run id from a URL is matched against `RUN_ID` and
then looked up among the names actually listed in `runs/`, and only that listed name is used to
build a path. Files are opened for reading only. A file that can't be read or validated
(damaged, or written with another schema version) becomes a `LoadError` with a short message,
never an exception or a traceback in the page.

Parsed files are cached by (inode, size, mtime), so a page reloads only what `collect` has
rewritten since (it replaces files atomically, which gives a new inode). The report cache is
bounded by the total size of the cached files (`REPORT_CACHE_BYTES`), and a file over
`MAX_FILE_BYTES` is not parsed at all.
"""

from __future__ import annotations

import os
import re
import threading
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final

from kitsunox.core.models import Persisted
from kitsunox.reporting.queue import QUEUE_DIR, Queue
from kitsunox.reporting.report import REPORT_DIR, Report
from kitsunox.util.schema import SchemaVersionError

RUN_ID: Final = re.compile(r"[0-9]{8}T[0-9]{6}Z-[a-z0-9]{1,32}")
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


class Library:
    """The reports and queue under one data directory. Safe to share between threads."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._lock = threading.Lock()
        self._reports: OrderedDict[Path, tuple[_Signature, Report | LoadError]] = OrderedDict()
        self._summaries: dict[Path, tuple[_Signature, RunSummary | LoadError]] = {}
        self._queue: tuple[_Signature, Queue | LoadError] | None = None

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
