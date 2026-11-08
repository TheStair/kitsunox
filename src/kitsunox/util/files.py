"""Small filesystem helpers."""

from __future__ import annotations

import os
import threading
import weakref
from array import array
from pathlib import Path

WRITE_ATTEMPTS = 3


def atomic_write(path: Path, data: bytes) -> None:
    """Write via a temp file unique to this process and thread, then rename into place, so
    readers never see a partial file and concurrent writers of the same path don't collide.

    The temp file is read back before the rename. On 2026-10-28 one cache file (of 1.7M) held a
    TLS record followed by the intended bytes: another thread's HTTPS request had been written
    to the file descriptor the temp file reused. Checking costs a page-cache read and keeps such
    a write from ever becoming visible.

    The temp file is synced to disk before the rename. Without that, a crash can persist the
    rename but not the data: the VM went down on 2026-11-07 at 19:30Z, mid Stage 2, and left 211
    tarball blobs empty under their final names (the rename alone survived). A synced write
    costs ~0.8 ms on the VM; the directory entry itself is not synced, so a crash can still lose
    a whole recent file, which every caller already treats as never written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    for _ in range(WRITE_ATTEMPTS):
        tmp.write_bytes(data)
        if tmp.read_bytes() == data:
            _sync(tmp)
            os.replace(tmp, path)
            return
    tmp.unlink(missing_ok=True)
    raise OSError(f"{path}: written bytes did not read back intact")


def _sync(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class LineFile:
    """The non-empty lines of a file, read on demand by index, so a large JSONL file is never
    held in memory: only each line's offset and length are kept (16 bytes a line). Reads use
    `os.pread` on one descriptor opened up front, so threads can share it. The file must not
    be modified in place while open; replacing it (`atomic_write`) is fine, since the open
    descriptor keeps the old file. Lines keep their trailing newline (JSON parsers ignore it)."""

    def __init__(self, path: Path) -> None:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        self._closer = weakref.finalize(self, os.close, fd)
        self._fd = fd
        offsets, lengths = array("q"), array("q")
        position = 0
        with os.fdopen(os.dup(fd), "rb") as handle:
            for line in handle:
                if line.strip():
                    offsets.append(position)
                    lengths.append(len(line))
                position += len(line)
        self._offsets, self._lengths = offsets, lengths

    def __len__(self) -> int:
        return len(self._offsets)

    def __getitem__(self, index: int) -> bytes:
        offset, length = self._offsets[index], self._lengths[index]
        chunks, read = [], 0
        while read < length:
            chunk = os.pread(self._fd, length - read, offset + read)
            if not chunk:
                raise OSError(f"line {index} ends early: the file was modified in place")
            chunks.append(chunk)
            read += len(chunk)
        return b"".join(chunks)

    def close(self) -> None:
        self._closer()
