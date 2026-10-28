"""Small filesystem helpers."""

from __future__ import annotations

import os
import threading
from pathlib import Path

WRITE_ATTEMPTS = 3


def atomic_write(path: Path, data: bytes) -> None:
    """Write via a temp file unique to this process and thread, then rename into place, so
    readers never see a partial file and concurrent writers of the same path don't collide.

    The temp file is read back before the rename. On 2026-10-28 one cache file (of 1.7M) held a
    TLS record followed by the intended bytes: another thread's HTTPS request had been written
    to the file descriptor the temp file reused. Checking costs a page-cache read and keeps such
    a write from ever becoming visible."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    for _ in range(WRITE_ATTEMPTS):
        tmp.write_bytes(data)
        if tmp.read_bytes() == data:
            os.replace(tmp, path)
            return
    tmp.unlink(missing_ok=True)
    raise OSError(f"{path}: written bytes did not read back intact")
