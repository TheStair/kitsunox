"""The stored form of a partial read (decision 0021): a deterministic re-pack, read back with
`extract_tar_gz`."""

import gzip
import io
import tarfile

import pytest

from conftest import TarEntry, make_tar_gz
from kitsunox.util.archive import ArchiveError, KeepPolicy, stream_tar_gz
from kitsunox.util.partial import (
    MANIFEST_NAME,
    pack_partial,
    partial_variant,
    policy_fields,
    read_manifest,
    read_partial,
)

BINARY = b"MZ\x90\x00" + bytes(range(256)) * 8
POLICY = KeepPolicy(
    version=3,
    max_file_bytes=1000,
    max_kept_bytes=10_000,
    text=lambda p: p.endswith(".js"),
    rank=lambda p, h: 0,
)
URL = "https://registry.npmjs.org/x/-/x-1.0.0.tgz"


def archive_bytes() -> bytes:
    return make_tar_gz(
        [
            TarEntry("package/package.json", b'{"name":"x"}'),
            TarEntry("package/z.js", b"z"),
            TarEntry("package/a.dll", BINARY),
            TarEntry("package/big.js", b"b" * 2000),
            TarEntry("package/link", type=tarfile.SYMTYPE, linkname="a.dll"),
            TarEntry("package/z.js", b"z2"),
        ]
    )


def repack(data: bytes) -> bytes:
    archive = stream_tar_gz([data], POLICY, strip_components=1)
    return pack_partial(
        archive, url=URL, integrity="sha512-abc", shasum=None, policy=policy_fields(POLICY)
    )


def test_a_re_pack_reads_back_as_the_streamed_tree() -> None:
    data = archive_bytes()
    streamed = stream_tar_gz([data], POLICY, strip_components=1).tree()
    tree = read_partial(repack(data))
    assert (
        dict(tree.files) == dict(streamed.files) == {"package.json": b'{"name":"x"}', "z.js": b"z2"}
    )
    assert tree.omitted == streamed.omitted
    assert [(o.path, o.reason) for o in tree.omitted] == [("a.dll", "binary"), ("big.js", "file")]
    assert tree.omitted[0].head == BINARY[:512]
    assert tree.skipped == streamed.skipped
    assert tree.duplicates == ("z.js",)
    assert dict(tree.modes) == dict(streamed.modes)


def test_the_re_pack_is_deterministic_and_records_its_source() -> None:
    data = archive_bytes()
    assert repack(data) == repack(data)
    manifest = read_manifest(repack(data))
    assert manifest.source.url == URL
    assert manifest.source.compressed_bytes == len(data)
    assert manifest.source.entries == 6
    assert manifest.policy["version"] == 3
    assert partial_variant(POLICY) == "partial=3"


def test_any_tar_can_open_a_re_pack() -> None:
    with tarfile.open(fileobj=io.BytesIO(repack(archive_bytes())), mode="r:gz") as tar:
        names = tar.getnames()
    assert names == [MANIFEST_NAME, "package/package.json", "package/z.js"]


def _tar_gz(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(buffer.getvalue(), mtime=0)


@pytest.mark.parametrize(
    "blob",
    [
        archive_bytes(),  # a tarball, not a re-pack: no manifest
        _tar_gz({MANIFEST_NAME: b"{}"}),
        _tar_gz({MANIFEST_NAME: b'{"schema_version": 1, "nonsense": 1}'}),
        _tar_gz({"package/a.js": b"1", "elsewhere.js": b"2"}),
    ],
)
def test_anything_but_a_re_pack_is_refused(blob: bytes) -> None:
    with pytest.raises(ArchiveError):
        read_partial(blob)


def test_entries_outside_the_package_are_refused() -> None:
    manifest = read_manifest(repack(archive_bytes())).model_dump_json().encode()
    with pytest.raises(ArchiveError, match="outside"):
        read_partial(_tar_gz({MANIFEST_NAME: manifest, "other/a.js": b"x"}))
