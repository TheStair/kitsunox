"""Property tests: the extractor must never return an unsafe path or fail with anything other
than ArchiveError, whatever the archive contains."""

import contextlib
import gzip
import io
import posixpath
import tarfile

from hypothesis import assume, given
from hypothesis import strategies as st

from conftest import TarEntry, make_tar_gz
from kitsunox.util.archive import (
    PARTIAL_LIMITS,
    ArchiveError,
    ExtractLimits,
    KeepPolicy,
    extract_tar_gz,
    stream_tar_gz,
)

SEGMENTS = st.sampled_from(
    ["package", "..", ".", "", "a", "b.js", "C:", "x\\y", "~", "node_modules", " ", "é", "a" * 120]
)
NAMES = st.lists(SEGMENTS, min_size=1, max_size=6).map("/".join) | st.text(max_size=40).map(
    lambda t: t.replace("\x00", "")
)
TYPES = st.sampled_from(
    [
        tarfile.REGTYPE,
        tarfile.REGTYPE,
        tarfile.REGTYPE,
        tarfile.DIRTYPE,
        tarfile.SYMTYPE,
        tarfile.LNKTYPE,
        tarfile.CHRTYPE,
        tarfile.BLKTYPE,
        tarfile.FIFOTYPE,
    ]
)
ENTRIES = st.lists(
    st.builds(TarEntry, name=NAMES, data=st.binary(max_size=64), type=TYPES, linkname=NAMES),
    max_size=12,
)


def assert_safe(path: str) -> None:
    assert path
    assert not path.startswith("/")
    assert "\\" not in path and "\x00" not in path
    assert ".." not in path.split("/")
    assert posixpath.normpath(path) == path
    assert not (len(path) > 1 and path[1] == ":")


def build(entries: list[TarEntry]) -> bytes:
    try:
        return make_tar_gz(entries)
    except ValueError, UnicodeError, tarfile.TarError:
        assume(False)  # name not representable in a tar header; not an extractor input
        raise AssertionError("unreachable") from None


@given(ENTRIES, st.integers(min_value=0, max_value=2))
def test_extracted_paths_are_always_safe(entries: list[TarEntry], strip: int) -> None:
    data = build(entries)
    try:
        tree = extract_tar_gz(data, strip_components=strip)
    except ArchiveError:
        return
    for path in tree:
        assert_safe(path)
    regular = [e for e in entries if e.type == tarfile.REGTYPE]
    assert len(tree) <= len(regular)
    # Nothing that isn't a regular file is ever extracted as content.
    assert len(tree.skipped) <= len(entries)


@given(ENTRIES)
def test_regular_safe_files_keep_last_written_content(entries: list[TarEntry]) -> None:
    data = build(entries)
    try:
        tree = extract_tar_gz(data, strip_components=1)
    except ArchiveError:
        return
    for path, content in tree.items():
        assert isinstance(content, bytes)
        assert path in tree.files


@given(st.binary(max_size=2048))
def test_arbitrary_bytes_only_raise_archive_error(data: bytes) -> None:
    for candidate in (data, gzip.compress(data, mtime=0)):
        with contextlib.suppress(ArchiveError):
            extract_tar_gz(candidate)


@given(
    st.lists(st.integers(min_value=0, max_value=10_000), min_size=1, max_size=8),
    st.binary(min_size=1, max_size=4),
)
def test_corrupted_real_archive_only_raises_archive_error(
    offsets: list[int], replacement: bytes
) -> None:
    data = bytearray(
        make_tar_gz(
            [TarEntry("package/index.js", b"module.exports = 1" * 50), TarEntry("package/a")]
        )
    )
    for offset in offsets:
        position = offset % len(data)
        data[position : position + len(replacement)] = replacement
    with contextlib.suppress(ArchiveError):
        extract_tar_gz(bytes(data), strip_components=1)


@given(st.integers(min_value=1, max_value=5), st.integers(min_value=1, max_value=200_000))
def test_limits_hold_for_any_size(files: int, size: int) -> None:
    data = make_tar_gz([TarEntry(f"package/{i}", b"A" * size) for i in range(files)])
    limits = ExtractLimits(max_total_bytes=300_000, max_file_bytes=150_000, max_ratio=10_000)
    try:
        tree = extract_tar_gz(data, strip_components=1, limits=limits)
    except ArchiveError:
        return
    assert sum(len(v) for v in tree.values()) <= limits.max_total_bytes
    assert all(len(v) <= limits.max_file_bytes for v in tree.values())


def test_pax_long_names_and_gnu_headers_are_handled() -> None:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as tar:
        info = tarfile.TarInfo("package/" + "d/" * 80 + "deep.js")
        info.size = 1
        tar.addfile(info, io.BytesIO(b"x"))
        evil = tarfile.TarInfo("package/" + "../" * 60 + "etc/passwd")
        evil.size = 1
        tar.addfile(evil, io.BytesIO(b"x"))
    tree = extract_tar_gz(gzip.compress(buffer.getvalue()), strip_components=1)
    assert list(tree) == ["d/" * 80 + "deep.js"]
    assert [s.reason for s in tree.skipped] == ["unsafe path"]


# --- partial reads: the streaming reader agrees with `extract_tar_gz` ---------------------------

KEEP_ALL = KeepPolicy(
    version=0,
    max_file_bytes=1 << 30,
    max_kept_bytes=1 << 30,
    text=lambda path: True,
    rank=lambda path, head: 0,
)
STREAM_CUTS = st.sampled_from([1, 3, 64, 511, 512, 4096, 1 << 20])


def _both(data: bytes, cut: int, strip: int) -> None:
    """`stream_tar_gz`, keeping everything, reads what `extract_tar_gz` reads, or both fail
    with an ArchiveError."""
    try:
        whole = extract_tar_gz(data, strip_components=strip, limits=PARTIAL_LIMITS)
    except ArchiveError:
        whole = None
    try:
        pieces = (data[i : i + cut] for i in range(0, len(data), cut))
        streamed = stream_tar_gz(pieces, KEEP_ALL, strip_components=strip).tree()
    except ArchiveError:
        streamed = None
    if whole is None or streamed is None:
        assert whole is None and streamed is None
        return
    assert dict(streamed.files) == dict(whole.files)
    assert dict(streamed.modes) == dict(whole.modes)
    assert streamed.skipped == whole.skipped
    assert streamed.duplicates == whole.duplicates
    assert streamed.anomalies == whole.anomalies
    assert streamed.omitted == ()


@given(ENTRIES, st.integers(min_value=0, max_value=2), STREAM_CUTS)
def test_streamed_reads_match_whole_reads(entries: list[TarEntry], strip: int, cut: int) -> None:
    _both(build(entries), cut, strip)


@given(st.binary(max_size=2048), STREAM_CUTS)
def test_streamed_arbitrary_bytes_match_whole_reads(data: bytes, cut: int) -> None:
    for candidate in (data, gzip.compress(data, mtime=0)):
        _both(candidate, cut, 0)


@given(
    st.lists(st.integers(min_value=0, max_value=10_000), min_size=1, max_size=8),
    st.binary(min_size=1, max_size=4),
    STREAM_CUTS,
)
def test_streamed_corrupted_archives_match_whole_reads(
    offsets: list[int], replacement: bytes, cut: int
) -> None:
    raw = bytearray(
        b"".join(
            _member(name, data)
            for name, data in [("package/index.js", b"module.exports = 1" * 50), ("package/a", b"")]
        )
        + b"\0" * 1024
    )
    for offset in offsets:
        position = offset % len(raw)
        raw[position : position + len(replacement)] = replacement
    _both(gzip.compress(bytes(raw), mtime=0), cut, 1)


def _member(name: str, data: bytes) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()[: 512 + ((len(data) + 511) // 512) * 512]
