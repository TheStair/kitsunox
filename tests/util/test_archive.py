import gzip
import tarfile

import pytest

from conftest import TarEntry, make_tar_gz
from kitsunox.util.archive import (
    ArchiveError,
    ExtractLimits,
    extract_tar_gz,
    safe_relative_path,
)


def test_extracts_regular_files_and_strips_prefix() -> None:
    data = make_tar_gz(
        [
            TarEntry("package", type=tarfile.DIRTYPE),
            TarEntry("package/package.json", b"{}"),
            TarEntry("package/lib/index.js", b"module.exports = 1"),
        ]
    )
    tree = extract_tar_gz(data, strip_components=1)
    assert list(tree) == ["lib/index.js", "package.json"]
    assert tree["lib/index.js"] == b"module.exports = 1"
    assert tree.skipped == ()


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("package/a.js", "a.js"),
        ("package/./x//b.js", "x/b.js"),
        ("package/../evil.js", None),
        ("/etc/passwd", None),
        ("C:/x.js", None),
        ("package\\x.js", None),
        ("package/a\x00.js", None),
        ("package", None),
        ("", None),
    ],
)
def test_safe_relative_path(name: str, expected: str | None) -> None:
    assert safe_relative_path(name, strip_components=1) == expected


def test_unsafe_and_special_entries_are_reported_not_extracted() -> None:
    data = make_tar_gz(
        [
            TarEntry("package/ok.js", b"1"),
            TarEntry("package/../../escape.js", b"x"),
            TarEntry("package/link", type=tarfile.SYMTYPE, linkname="/home/user/.npmrc"),
            TarEntry("package/hard", type=tarfile.LNKTYPE, linkname="package/ok.js"),
            TarEntry("package/dev", type=tarfile.CHRTYPE),
            TarEntry("package/pipe", type=tarfile.FIFOTYPE),
        ]
    )
    tree = extract_tar_gz(data, strip_components=1)
    assert list(tree) == ["ok.js"]
    reasons = {s.path: s.reason for s in tree.skipped}
    assert reasons["package/../../escape.js"] == "unsafe path"
    assert reasons["link"] == "symlink -> /home/user/.npmrc"
    assert reasons["hard"].startswith("hardlink")
    assert reasons["dev"] == "device"
    assert reasons["pipe"] == "fifo"


def test_duplicate_paths_keep_last_and_are_reported() -> None:
    data = make_tar_gz([TarEntry("package/a.js", b"first"), TarEntry("package/a.js", b"second")])
    tree = extract_tar_gz(data, strip_components=1)
    assert tree["a.js"] == b"second"
    assert tree.duplicates == ("a.js",)


def test_decompression_bomb_rejected() -> None:
    data = make_tar_gz([TarEntry("package/zeros", b"\0" * 2_000_000)])
    with pytest.raises(ArchiveError, match="decompressed size"):
        extract_tar_gz(data, limits=ExtractLimits(max_ratio=10))


@pytest.mark.parametrize(
    ("limits", "message"),
    [
        (ExtractLimits(max_files=2), "entries"),
        (ExtractLimits(max_file_bytes=10), "per-file limit"),
        (ExtractLimits(max_compressed_bytes=10), "compressed size"),
    ],
)
def test_limits(limits: ExtractLimits, message: str) -> None:
    data = make_tar_gz([TarEntry(f"package/{i}.js", b"x" * 100) for i in range(3)])
    with pytest.raises(ArchiveError, match=message):
        extract_tar_gz(data, limits=limits)


def test_trailing_gzip_member_rejected() -> None:
    data = make_tar_gz([TarEntry("package/a.js", b"1")]) + gzip.compress(b"hidden")
    with pytest.raises(ArchiveError, match="trailing data"):
        extract_tar_gz(data)


@pytest.mark.parametrize("data", [b"not gzip at all", gzip.compress(b"not a tar" * 100)])
def test_malformed_input_raises_archive_error(data: bytes) -> None:
    with pytest.raises(ArchiveError):
        extract_tar_gz(data)
