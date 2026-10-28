"""atomic_write: whole files only, and never a file whose bytes didn't read back intact."""

from pathlib import Path

import pytest

from kitsunox.util import files
from kitsunox.util.files import atomic_write


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
