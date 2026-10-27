import gzip
import io
import tarfile
from pathlib import Path

import pytest

from conftest import TarEntry, make_tar_gz
from kitsunox.util.archive import (
    ArchiveError,
    ExtractLimits,
    extract_tar_gz,
    extract_zip,
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
        ("package/C:/Windows/x.js", None),  # found by fuzzing, 2026-10-27
        ("package/C:", None),
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


def _raw_member(name: str, data: bytes) -> bytes:
    """One tar header + data block, without the end-of-archive marker."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()[: 512 + ((len(data) + 511) // 512) * 512]


EOF_MARKER = b"\0" * 1024


@pytest.mark.parametrize(
    "separator",
    [EOF_MARKER, b"\xff" * 512, b"\0" * 512],
    ids=["after-eof-marker", "after-garbage-header", "after-zero-block"],
)
def test_entries_hidden_from_strict_readers_are_extracted_and_flagged(separator: bytes) -> None:
    # Parser-differential attack: content a lenient installer would extract must not be
    # invisible to analysis. Regression for the 2026-10-27 validation finding.
    raw = (
        _raw_member("package/index.js", b"benign")
        + separator
        + _raw_member("package/evil.js", b"payload")
        + EOF_MARKER
    )
    tree = extract_tar_gz(gzip.compress(raw), strip_components=1)
    assert sorted(tree) == ["evil.js", "index.js"]
    assert tree["evil.js"] == b"payload"
    assert any("strict tar reader" in a for a in tree.anomalies)


def test_trailing_non_zero_bytes_are_flagged() -> None:
    raw = _raw_member("package/index.js", b"x") + EOF_MARKER + b"\x01" * 7
    tree = extract_tar_gz(gzip.compress(raw), strip_components=1)
    assert "non-zero data after the last archive entry" in tree.anomalies


def test_normal_archive_has_no_anomalies() -> None:
    tree = extract_tar_gz(make_tar_gz([TarEntry("package/a.js", b"1")]), strip_components=1)
    assert tree.anomalies == ()


def test_truncated_gzip_is_rejected() -> None:
    data = make_tar_gz([TarEntry("package/a.js", b"x" * 5000), TarEntry("package/b.js", b"y")])
    with pytest.raises(ArchiveError, match="truncated"):
        extract_tar_gz(data[:-20])


def _zip(entries: dict[str, bytes]) -> bytes:
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def test_zip_extraction_applies_path_rules() -> None:
    tree = extract_zip(_zip({"a/b.json": b"{}", "../evil": b"x", "/abs": b"y"}))
    assert list(tree) == ["a/b.json"]
    assert {s.reason for s in tree.skipped} == {"unsafe path"}


def test_zip_bomb_rejected() -> None:
    with pytest.raises(ArchiveError, match="ratio"):
        extract_zip(_zip({"zeros": b"\0" * 5_000_000}), limits=ExtractLimits(max_ratio=100))


def test_malformed_zip_rejected() -> None:
    with pytest.raises(ArchiveError, match="malformed zip"):
        extract_zip(b"PK\x03\x04 not really a zip")


ENCRYPTED = Path(__file__).parents[1] / "fixtures" / "encrypted_infected.zip"  # zip -P infected


def test_encrypted_zip_reads_selected_members_only() -> None:
    tree = extract_zip(
        ENCRYPTED.read_bytes(),
        password=b"infected",
        include=lambda path: path.endswith("package.json"),
    )
    assert list(tree) == ["pkg/package/package.json"]
    assert b'"kx-enc"' in tree["pkg/package/package.json"]


@pytest.mark.parametrize("password", [None, b"wrong"])
def test_encrypted_zip_without_the_password_is_rejected(password: bytes | None) -> None:
    with pytest.raises(ArchiveError, match="decrypt"):
        extract_zip(ENCRYPTED.read_bytes(), password=password)
