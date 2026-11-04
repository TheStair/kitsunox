"""Free disk space. A full disk crashed the VM twice on 2026-11-03: the hourly tick filled it
(a 10-hour catch-up of 55k changes), and the crash left renamed files empty, among them a
Stage 4 snapshot that then stopped every prune. So the tick checks free space between steps
(`collect.py`), and blobs, the bulk of what it writes (tarballs, repository archives,
packuments), are refused below a floor."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Final

GIB: Final = 1 << 30
# Blobs are not written with less than this free: room for the tick's own outputs (a large
# catch-up writes ~1 GB of JSONL), a prune, and the rest of the system. Read at call time
# (`DataDir.blobs`), so tests can lower it.
BLOB_FLOOR = 10 * GIB


class DiskSpaceError(RuntimeError):
    """Free space fell below a floor. Not an `OSError` or a `FetchError`, so handlers that skip
    one bad package don't swallow it: the stage stops, instead of recording every package as
    failed, and the run resumes from that stage on a later tick."""


def free_bytes(path: Path) -> int:
    """Bytes an unprivileged process can still write on the filesystem holding `path` (or its
    nearest existing parent), as `df` shows under Avail."""
    while not path.exists() and path != path.parent:
        path = path.parent
    return shutil.disk_usage(path).free


def require_free(path: Path, floor: int, what: str) -> None:
    free = free_bytes(path)
    if free < floor:
        raise DiskSpaceError(f"{what}: {gib(free)} free, below the {gib(floor)} floor")


def gib(n: int) -> str:
    return f"{n / GIB:.1f} GB"
