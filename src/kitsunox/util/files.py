"""Small filesystem helpers."""

from __future__ import annotations

import os
import threading
from pathlib import Path


def atomic_write(path: Path, data: bytes) -> None:
    """Write via a temp file unique to this process and thread, then rename into place, so
    readers never see a partial file and concurrent writers of the same path don't collide."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)
