"""Partial reads (decision 0021): `stream_tar_gz` keeps text and code, lists the rest, and
applies `extract_tar_gz`'s guards to a stream it never holds whole. Fixtures are synthesized
here: large "binaries" are runs of NUL-bearing bytes, nothing is fetched or executed."""

import gzip
import hashlib
import io
import tarfile
import zlib
from collections.abc import Iterator

import pytest

from conftest import TarEntry, make_tar_gz
from kitsunox.util.archive import (
    ArchiveError,
    ArchiveLimitError,
    ExtractLimits,
    KeepPolicy,
    extract_tar_gz,
    partial_view,
    stream_tar_gz,
)

BINARY = b"\x7fELF\x02\x01\x01\x00" + bytes(range(256)) * 64  # NUL in the first block


def policy(kept: int = 1 << 20, per_file: int = 1 << 20, **kwargs: object) -> KeepPolicy:
    def rank(path: str, head: bytes) -> int:
        if path == "package.json":
            return 0
        if path.endswith(".js") and not path.startswith("node_modules/"):
            return 1
        if path.endswith(".js"):
            return 2
        return 3

    return KeepPolicy(
        version=1,
        max_file_bytes=per_file,
        max_kept_bytes=kept,
        text=lambda p: p.endswith((".js", ".json")),
        rank=rank,
        **kwargs,  # type: ignore[arg-type]
    )


def chunks(data: bytes, size: int) -> Iterator[bytes]:
    for start in range(0, len(data), size):
        yield data[start : start + size]


def tar_gz(entries: list[tuple[str, bytes]], mode: int = 0o644) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(buffer.getvalue(), mtime=0)


def test_text_is_kept_and_binaries_are_listed_with_size_hash_and_head() -> None:
    data = tar_gz(
        [
            ("package/package.json", b'{"name":"x"}'),
            ("package/bin/tool.node", BINARY),
            ("package/install.js", b"require('child_process')"),
            ("package/README.md", b"# x"),
        ],
        mode=0o755,
    )
    archive = stream_tar_gz(chunks(data, 100), policy(), strip_components=1)
    assert sorted(archive.files) == ["README.md", "install.js", "package.json"]
    assert archive.modes["install.js"] == 0o755
    (omitted,) = archive.omitted
    assert omitted.path == "bin/tool.node"
    assert omitted.reason == "binary"
    assert omitted.size == len(BINARY)
    assert omitted.sha256 == hashlib.sha256(BINARY).hexdigest()
    assert omitted.head == BINARY[:512]
    assert archive.entries == 4
    assert archive.compressed_bytes == len(data)
    assert archive.compressed_sha256 == hashlib.sha256(data).hexdigest()
    tree = archive.tree()
    assert tree.omitted == archive.omitted
    assert tree["install.js"] == b"require('child_process')"


def test_a_source_file_with_a_nul_byte_is_still_text() -> None:
    data = tar_gz([("package/a.js", b"var s = '\x00';"), ("package/a.bin", b"\x00")])
    archive = stream_tar_gz([data], policy(), strip_components=1)
    assert list(archive.files) == ["a.js"]
    assert [o.path for o in archive.omitted] == ["a.bin"]


def test_a_text_file_over_the_per_file_limit_is_listed_without_a_head() -> None:
    big = b"x" * 3000
    data = tar_gz([("package/big.js", big), ("package/small.js", b"y")])
    archive = stream_tar_gz([data], policy(per_file=2000), strip_components=1)
    assert list(archive.files) == ["small.js"]
    (omitted,) = archive.omitted
    assert (omitted.reason, omitted.size, omitted.head) == ("file", 3000, b"")
    assert omitted.sha256 == hashlib.sha256(big).hexdigest()


def test_the_budget_keeps_important_files_and_evicts_the_largest_of_the_least() -> None:
    data = tar_gz(
        [
            ("package/docs/a.txt", b"a" * 400),  # rank 3
            ("package/docs/b.txt", b"b" * 300),  # rank 3
            ("package/node_modules/d/index.js", b"d" * 300),  # rank 2
            ("package/install.js", b"i" * 500),  # rank 1: evicts a.txt (largest rank 3)
            ("package/package.json", b"{}"),  # rank 0: fits
            ("package/other.txt", b"o" * 300),  # rank 3: no room left, evicts nothing
        ]
    )
    archive = stream_tar_gz([data], policy(kept=1200), strip_components=1)
    assert sorted(archive.files) == [
        "docs/b.txt",
        "install.js",
        "node_modules/d/index.js",
        "package.json",
    ]
    omitted = {o.path: o for o in archive.omitted}
    assert set(omitted) == {"docs/a.txt", "other.txt"}
    assert all(o.reason == "budget" for o in omitted.values())
    assert omitted["docs/a.txt"].sha256 == hashlib.sha256(b"a" * 400).hexdigest()


def test_a_file_that_cannot_fit_evicts_nothing() -> None:
    data = tar_gz([("package/a.js", b"a" * 600), ("package/b.js", b"b" * 600)])
    archive = stream_tar_gz([data], policy(kept=1000), strip_components=1)
    assert list(archive.files) == ["a.js"]
    assert [(o.path, o.reason) for o in archive.omitted] == [("b.js", "budget")]


def test_the_result_does_not_depend_on_how_the_stream_is_cut() -> None:
    entries = [(f"package/f{i}.js", bytes([65 + i]) * (i * 997)) for i in range(12)]
    entries.append(("package/blob.wasm", BINARY * 3))
    data = tar_gz(entries)
    results = {
        size: stream_tar_gz(chunks(data, size), policy(kept=30_000), strip_components=1)
        for size in (1, 7, 512, 4096, len(data))
    }
    first = results[len(data)]
    for archive in results.values():
        assert archive.files == first.files
        assert archive.omitted == first.omitted


def test_partial_view_selects_as_the_stream_does() -> None:
    entries = [(f"package/f{i}.js", b"x" * (i * 300)) for i in range(10)]
    entries += [("package/m.png", BINARY), ("package/n.md", b"n" * 900)]
    data = tar_gz(entries)
    streamed = stream_tar_gz([data], policy(kept=6000), strip_components=1).tree()
    viewed = partial_view(extract_tar_gz(data, strip_components=1), policy(kept=6000))
    assert dict(viewed.files) == dict(streamed.files)
    assert viewed.omitted == streamed.omitted


def test_duplicates_keep_the_last_entry_and_are_reported() -> None:
    data = make_tar_gz([TarEntry("package/a.js", b"old"), TarEntry("package/a.js", b"new")])
    archive = stream_tar_gz([data], policy(), strip_components=1)
    assert archive.files == {"a.js": b"new"}
    assert archive.duplicates == ("a.js",)


def test_unsafe_and_special_entries_are_skipped() -> None:
    data = make_tar_gz(
        [
            TarEntry("package/../evil.js", b"x"),
            TarEntry("package/link", type=tarfile.SYMTYPE, linkname="/etc/passwd"),
            TarEntry("package/ok.js", b"ok"),
        ]
    )
    archive = stream_tar_gz([data], policy(), strip_components=1)
    assert list(archive.files) == ["ok.js"]
    assert {s.reason for s in archive.skipped} == {"unsafe path", "symlink -> /etc/passwd"}


def _raw_member(name: str, data: bytes) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()[: 512 + ((len(data) + 511) // 512) * 512]


EOF_MARKER = b"\0" * 1024


@pytest.mark.parametrize("separator", [EOF_MARKER, b"\xff" * 512, b"\0" * 512])
def test_entries_hidden_from_strict_readers_are_read_and_flagged_as_extract_does(
    separator: bytes,
) -> None:
    raw = (
        _raw_member("package/index.js", b"benign")
        + separator
        + _raw_member("package/evil.js", b"payload")
        + EOF_MARKER
    )
    data = gzip.compress(raw)
    archive = stream_tar_gz([data], policy(), strip_components=1)
    whole = extract_tar_gz(data, strip_components=1)
    assert archive.files == dict(whole.files)
    assert archive.anomalies == whole.anomalies
    assert any("strict tar reader" in a for a in archive.anomalies)


def test_trailing_non_zero_bytes_are_flagged() -> None:
    raw = _raw_member("package/index.js", b"x") + EOF_MARKER + b"\x01" * 7
    archive = stream_tar_gz([gzip.compress(raw)], policy(), strip_components=1)
    assert archive.anomalies == ("non-zero data after the last archive entry",)


def test_long_names_are_no_anomaly() -> None:
    for fmt in (tarfile.GNU_FORMAT, tarfile.PAX_FORMAT):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w", format=fmt) as tar:
            for name in ("package/" + "a" * 150 + ".js", "package/b.js", "package/é.js"):
                info = tarfile.TarInfo(name)
                info.size = 700
                tar.addfile(info, io.BytesIO(b"x" * 700))
        archive = stream_tar_gz([gzip.compress(buffer.getvalue())], policy(), strip_components=1)
        assert archive.anomalies == ()
        assert len(archive.files) == 3


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (make_tar_gz([TarEntry("package/a.js", b"x" * 5000)])[:-20], "truncated"),
        (make_tar_gz([TarEntry("package/a.js", b"1")]) + gzip.compress(b"x"), "trailing data"),
        (make_tar_gz([TarEntry("package/a.js", b"1")]) + b"junk", "trailing data"),
        (gzip.compress(b"not a tar" * 100), "not a tar"),
        (b"not gzip at all", "malformed gzip"),
        (b"", "truncated"),
    ],
)
def test_malformed_streams_raise_archive_errors(data: bytes, message: str) -> None:
    with pytest.raises(ArchiveError, match=message):
        stream_tar_gz(chunks(data, 3) if data else iter(()), policy())


def test_trailing_data_in_a_later_chunk_is_refused() -> None:
    data = make_tar_gz([TarEntry("package/a.js", b"1")])
    with pytest.raises(ArchiveError, match="trailing data"):
        stream_tar_gz(iter([data, b"", b"x"]), policy())


@pytest.mark.parametrize(
    ("limits", "kind"),
    [
        (ExtractLimits(max_compressed_bytes=100), "compressed"),
        (ExtractLimits(max_total_bytes=10_000), "total"),
        (ExtractLimits(max_ratio=5), "ratio"),
        (ExtractLimits(max_files=2), "files"),
    ],
)
def test_limits_apply_as_the_stream_goes(limits: ExtractLimits, kind: str) -> None:
    data = make_tar_gz([TarEntry(f"package/{i}.js", b"z" * 4000) for i in range(4)])
    with pytest.raises(ArchiveLimitError) as raised:
        stream_tar_gz(chunks(data, 64), policy(), limits=limits)
    assert raised.value.limit == kind


def test_a_bomb_stops_at_the_ratio_without_inflating_it() -> None:
    compressor = zlib.compressobj(9, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
    bomb = compressor.compress(b"\0" * (64 << 20)) + compressor.flush()
    with pytest.raises(ArchiveLimitError) as raised:
        stream_tar_gz(chunks(bomb, 4096), policy(), limits=ExtractLimits(max_ratio=100))
    assert raised.value.limit == "ratio"


def test_every_chunk_is_consumed() -> None:
    data = make_tar_gz([TarEntry("package/a.js", b"x" * 3000)]) + b""
    seen: list[int] = []

    def counted() -> Iterator[bytes]:
        for chunk in chunks(data, 50):
            seen.append(len(chunk))
            yield chunk
        yield b""

    stream_tar_gz(counted(), policy())
    assert sum(seen) == len(data)
