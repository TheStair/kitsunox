"""The stored form of a partial read (decision 0021): a deterministic tar.gz re-pack.

`stream_tar_gz` keeps a large tarball's text and code and only lists the rest. What it kept is
stored as one blob, so a replay analyses the same bytes without the original tarball (which is
never stored): the kept files under `package/` with their modes, and a manifest
(`kitsunox-partial.json`, `PartialManifest`) at the root naming the source (URL, integrity,
compressed size and SHA-256), the policy, and every omitted file, skipped entry, duplicate and
anomaly. Entries are sorted, with mtime 0, owner 0 and no owner names, and gzip's own header
has mtime 0, so the same subset always packs to the same bytes. It is read back with
`extract_tar_gz`, the safe extractor every tarball goes through, and any `tar` can open it.
"""

from __future__ import annotations

import base64
import gzip
import io
import tarfile
from typing import Final

from pydantic import BaseModel, ConfigDict, field_serializer, field_validator

from kitsunox.util.archive import (
    ArchiveError,
    ArtifactTree,
    ExtractLimits,
    KeepPolicy,
    OmitReason,
    OmittedFile,
    PartialArchive,
    SkippedEntry,
    extract_tar_gz,
)
from kitsunox.util.schema import require_schema_version

PARTIAL_SCHEMA_VERSION: Final = 1
# The content type a re-pack is recorded with: the marker that a snapshot entry is a partial
# read, not the tarball the URL serves.
PARTIAL_CONTENT_TYPE: Final = "application/vnd.kitsunox.partial+gzip"
MANIFEST_NAME: Final = "kitsunox-partial.json"
PACKAGE_DIR: Final = "package/"
# What a re-pack can hold: the kept files (a policy keeps at most tens of MB) and a manifest
# of up to 50,000 omitted files with their heads.
REPACK_LIMITS: Final = ExtractLimits(
    max_compressed_bytes=512 * 1024 * 1024,
    max_total_bytes=512 * 1024 * 1024,
    max_file_bytes=256 * 1024 * 1024,
    max_files=50_001,
    max_ratio=1000,
)


class PartialSource(BaseModel):
    """The tarball a partial read streamed."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    url: str
    integrity: str | None = None
    shasum: str | None = None
    compressed_bytes: int
    compressed_sha256: str
    entries: int


class PartialFile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    size: int
    sha256: str
    mode: int
    reason: OmitReason
    head: bytes = b""

    @field_serializer("head")
    def _head_out(self, head: bytes) -> str:
        return base64.b64encode(head).decode()

    @field_validator("head", mode="before")
    @classmethod
    def _head_in(cls, value: object) -> object:
        return base64.b64decode(value, validate=True) if isinstance(value, str) else value


class PartialSkipped(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    reason: str


class PartialManifest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int = PARTIAL_SCHEMA_VERSION
    source: PartialSource
    policy: dict[str, int]
    omitted: tuple[PartialFile, ...] = ()
    skipped: tuple[PartialSkipped, ...] = ()
    duplicates: tuple[str, ...] = ()
    anomalies: tuple[str, ...] = ()


def partial_variant(policy: KeepPolicy) -> str:
    """The request-key suffix of a partial read under `policy` (`util.http.derived_key`)."""
    return f"partial={policy.version}"


def policy_fields(policy: KeepPolicy) -> dict[str, int]:
    """The policy's numbers, as the manifest records them."""
    return {
        "version": policy.version,
        "max_file_bytes": policy.max_file_bytes,
        "max_kept_bytes": policy.max_kept_bytes,
        "head_bytes": policy.head_bytes,
    }


def is_partial(content_type: str | None) -> bool:
    """Whether a snapshot entry with this content type is a partial read's re-pack."""
    return content_type == PARTIAL_CONTENT_TYPE


def pack_partial(
    archive: PartialArchive,
    *,
    url: str,
    integrity: str | None,
    shasum: str | None,
    policy: dict[str, int],
) -> bytes:
    """The re-pack of `archive` (see the module docstring)."""
    manifest = PartialManifest(
        source=PartialSource(
            url=url,
            integrity=integrity,
            shasum=shasum,
            compressed_bytes=archive.compressed_bytes,
            compressed_sha256=archive.compressed_sha256,
            entries=archive.entries,
        ),
        policy=dict(sorted(policy.items())),
        omitted=tuple(
            PartialFile(
                path=o.path, size=o.size, sha256=o.sha256, mode=o.mode, reason=o.reason, head=o.head
            )
            for o in archive.omitted
        ),
        skipped=tuple(PartialSkipped(path=s.path, reason=s.reason) for s in archive.skipped),
        duplicates=archive.duplicates,
        anomalies=archive.anomalies,
    )
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
        _add(tar, MANIFEST_NAME, manifest.model_dump_json(indent=1).encode() + b"\n", 0o644)
        for path in sorted(archive.files):
            _add(tar, PACKAGE_DIR + path, archive.files[path], archive.modes.get(path, 0o644))
    return gzip.compress(buffer.getvalue(), compresslevel=6, mtime=0)


def _add(tar: tarfile.TarFile, name: str, data: bytes, mode: int) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.mtime = 0
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    tar.addfile(info, io.BytesIO(data))


def read_partial(blob: bytes) -> ArtifactTree:
    """The tree a re-pack holds: the kept files with their modes, and the manifest's omitted
    files, skipped entries, duplicates and anomalies (those of the original tarball). Raises
    `ArchiveError` for anything that isn't a re-pack."""
    packed = extract_tar_gz(blob, limits=REPACK_LIMITS)
    raw = packed.files.get(MANIFEST_NAME)
    if raw is None:
        raise ArchiveError(f"partial read without {MANIFEST_NAME}")
    try:
        require_schema_version(raw, PARTIAL_SCHEMA_VERSION, "PartialManifest")
        manifest = PartialManifest.model_validate_json(raw)
    except ValueError as exc:
        raise ArchiveError(f"bad {MANIFEST_NAME}: {exc}"[:300]) from exc
    files: dict[str, bytes] = {}
    modes: dict[str, int] = {}
    for path, content in packed.files.items():
        if path == MANIFEST_NAME:
            continue
        if not path.startswith(PACKAGE_DIR):
            raise ArchiveError(f"partial read with an entry outside {PACKAGE_DIR}: {path}")
        files[path.removeprefix(PACKAGE_DIR)] = content
        modes[path.removeprefix(PACKAGE_DIR)] = packed.modes.get(path, 0o644)
    if packed.skipped or packed.duplicates or packed.anomalies:
        raise ArchiveError("partial read with entries its packer never writes")
    return ArtifactTree(
        files=files,
        skipped=tuple(SkippedEntry(s.path, s.reason) for s in manifest.skipped),
        duplicates=manifest.duplicates,
        anomalies=manifest.anomalies,
        modes=modes,
        omitted=tuple(
            OmittedFile(
                path=o.path, size=o.size, sha256=o.sha256, mode=o.mode, reason=o.reason, head=o.head
            )
            for o in manifest.omitted
        ),
    )


def read_manifest(blob: bytes) -> PartialManifest:
    """Only the manifest of a re-pack (for measurement and the viewer)."""
    packed = extract_tar_gz(blob, limits=REPACK_LIMITS, include=lambda p: p == MANIFEST_NAME)
    raw = packed.files.get(MANIFEST_NAME)
    if raw is None:
        raise ArchiveError(f"partial read without {MANIFEST_NAME}")
    return PartialManifest.model_validate_json(raw)
