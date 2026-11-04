"""Free-space checks: the blob store refuses writes below its floor."""

from pathlib import Path

import pytest

from conftest import Disk
from kitsunox.util.disk import GIB, DiskSpaceError, gib, require_free
from kitsunox.util.disk import free_bytes as real_free_bytes  # bound before the fixture patches
from kitsunox.util.http import BlobStore


def test_free_bytes_measures_the_nearest_existing_directory(tmp_path: Path) -> None:
    assert real_free_bytes(tmp_path / "not" / "made" / "yet") == real_free_bytes(tmp_path) > 0


def test_require_free_raises_below_the_floor(free_disk: Disk, tmp_path: Path) -> None:
    free_disk.free = 9 * GIB
    require_free(tmp_path, 8 * GIB, "x")
    with pytest.raises(DiskSpaceError, match=r"x: 9\.0 GB free, below the 10\.0 GB floor"):
        require_free(tmp_path, 10 * GIB, "x")
    assert not issubclass(DiskSpaceError, OSError)  # per-package OSError handlers pass it on
    assert gib(GIB * 3 // 2) == "1.5 GB"


def test_the_blob_store_writes_nothing_below_its_floor(free_disk: Disk, tmp_path: Path) -> None:
    store = BlobStore(tmp_path / "blobs", min_free=10 * GIB)
    kept = store.put(b"already here")
    free_disk.free = 5 * GIB
    with pytest.raises(DiskSpaceError):
        store.put(b"new bytes")
    assert store.put(b"already here") == kept  # nothing to write, so no space needed
    assert len(list((tmp_path / "blobs").rglob("*.zst"))) == 1
    assert BlobStore(tmp_path / "other").put(b"no floor")  # min_free=0: no check
