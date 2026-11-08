"""atomic_write: whole files only, and never a file whose bytes didn't read back intact."""

import os
from pathlib import Path

import pytest

from kitsunox.util import files
from kitsunox.util.files import LineFile, atomic_write


def test_writes_and_replaces(tmp_path: Path) -> None:
    target = tmp_path / "a" / "b.json"
    atomic_write(target, b"1")
    atomic_write(target, b"2")
    assert target.read_bytes() == b"2"
    assert [p.name for p in target.parent.iterdir()] == ["b.json"]  # no temp files left


def test_retries_then_refuses_a_damaged_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Simulates a foreign write landing in the temp file (a reused file descriptor)."""
    real = Path.write_bytes
    damaged = [2]

    def write_bytes(self: Path, data: bytes) -> int:
        if damaged[0]:
            damaged[0] -= 1
            return real(self, b"\x17\x03\x03" + data)
        return real(self, data)

    monkeypatch.setattr(Path, "write_bytes", write_bytes)
    target = tmp_path / "x.json"
    atomic_write(target, b"[]")  # two damaged attempts, the third is intact
    assert target.read_bytes() == b"[]"
    damaged[0] = files.WRITE_ATTEMPTS
    with pytest.raises(OSError, match="read back"):
        atomic_write(target, b"{}")
    assert target.read_bytes() == b"[]"  # the old content stays
    assert [p.name for p in tmp_path.iterdir()] == ["x.json"]


def test_the_data_is_synced_before_the_rename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crash after an unsynced rename left 211 blobs empty under their final names
    (2026-11-07)."""
    events: list[str] = []
    real_fsync, real_replace = os.fsync, os.replace

    def fsync(fd: int) -> None:
        events.append("fsync")
        real_fsync(fd)

    def replace(src: Path, dst: Path) -> None:
        events.append("replace")
        real_replace(src, dst)

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "replace", replace)
    atomic_write(tmp_path / "x.json", b"[]")
    assert events == ["fsync", "replace"]


def test_line_file_reads_non_empty_lines_on_demand(tmp_path: Path) -> None:
    path = tmp_path / "x.jsonl"
    path.write_bytes(b'{"a":1}\n\n  \n{"b":2}\n{"c":3}')
    lines = LineFile(path)
    assert len(lines) == 3
    assert [lines[i] for i in range(3)] == [b'{"a":1}\n', b'{"b":2}\n', b'{"c":3}']
    assert lines[-1] == b'{"c":3}'
    atomic_write(path, b"replaced\n")  # the open descriptor keeps the old file
    assert lines[1] == b'{"b":2}\n'
    lines.close()


def test_line_file_notices_a_file_cut_short(tmp_path: Path) -> None:
    path = tmp_path / "x.jsonl"
    path.write_bytes(b"one\ntwo\n")
    lines = LineFile(path)
    with path.open("r+b") as handle:
        handle.truncate(5)
    with pytest.raises(OSError, match="modified in place"):
        lines[1]
