"""Safe, in-memory extraction of untrusted .tar.gz archives.

Nothing is written to disk and nothing is executed: the result is a read-only mapping of
normalized relative paths to file bytes. Entries that aren't regular files (symlinks, hardlinks,
devices, FIFOs) and entries with unsafe paths are not extracted; they're reported in `skipped`
because their presence can itself be a signal. Size, file-count and compression-ratio limits guard
against archive bombs.

Parser differentials: a strict tar reader stops at the end-of-archive marker or the first invalid
header, but lenient readers keep going, so an attacker can hide entries that some installer sees
and an analyzer doesn't. We therefore read leniently (skipping zero and invalid blocks) so every
entry any reader could find is extracted, and record an `anomaly` whenever the lenient and strict
readings differ or non-zero bytes follow the last entry. `npm pack` never produces either.
"""

from __future__ import annotations

import io
import posixpath
import tarfile
import zipfile
import zlib
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field


class ArchiveError(ValueError):
    """The archive is malformed or exceeds a safety limit."""


@dataclass(frozen=True)
class ExtractLimits:
    max_compressed_bytes: int = 64 * 1024 * 1024
    max_total_bytes: int = 512 * 1024 * 1024
    max_file_bytes: int = 64 * 1024 * 1024
    max_files: int = 50_000
    max_ratio: int = 1000


DEFAULT_LIMITS = ExtractLimits()


@dataclass(frozen=True)
class SkippedEntry:
    path: str
    reason: str


@dataclass(frozen=True)
class ArtifactTree(Mapping[str, bytes]):
    """Read-only view of an extracted archive: normalized POSIX path -> content."""

    files: Mapping[str, bytes]
    skipped: tuple[SkippedEntry, ...] = ()
    duplicates: tuple[str, ...] = field(default=())
    anomalies: tuple[str, ...] = field(default=())

    def __getitem__(self, path: str) -> bytes:
        return self.files[path]

    def __iter__(self) -> Iterator[str]:
        return iter(sorted(self.files))

    def __len__(self) -> int:
        return len(self.files)


def extract_tar_gz(
    data: bytes, *, strip_components: int = 0, limits: ExtractLimits = DEFAULT_LIMITS
) -> ArtifactTree:
    """Extract a gzip-compressed tar archive into memory. `strip_components` drops leading path
    segments (npm tarballs nest everything under `package/`)."""
    if len(data) > limits.max_compressed_bytes:
        raise ArchiveError(f"compressed size {len(data)} exceeds limit")
    raw = _gunzip_limited(data, limits)

    strict_count = _strict_member_count(raw)
    files: dict[str, bytes] = {}
    skipped: list[SkippedEntry] = []
    duplicates: list[str] = []
    lenient_count = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:", ignore_zeros=True) as tar:
            for count, member in enumerate(tar, start=1):
                lenient_count = count
                if count > limits.max_files:
                    raise ArchiveError(f"more than {limits.max_files} entries")
                if member.isdir():
                    continue  # directories are implied by file paths; nothing to extract
                path = safe_relative_path(member.name, strip_components)
                if path is None:
                    skipped.append(SkippedEntry(member.name, "unsafe path"))
                    continue
                if not member.isfile():
                    skipped.append(SkippedEntry(path, _entry_kind(member)))
                    continue
                if member.size > limits.max_file_bytes:
                    raise ArchiveError(f"{path}: {member.size} bytes exceeds per-file limit")
                handle = tar.extractfile(member)
                if handle is None:
                    skipped.append(SkippedEntry(path, "unreadable"))
                    continue
                if path in files:
                    duplicates.append(path)
                files[path] = handle.read()
            end_offset = tar.offset
    except tarfile.TarError as exc:
        raise ArchiveError(f"malformed tar: {exc}") from exc

    anomalies = []
    if strict_count != lenient_count:
        anomalies.append(
            f"{lenient_count - strict_count} entries follow an end-of-archive marker or invalid "
            "header (a strict tar reader would not see them)"
        )
    if any(raw[end_offset:]):
        anomalies.append("non-zero data after the last archive entry")
    return ArtifactTree(
        files=files,
        skipped=tuple(skipped),
        duplicates=tuple(duplicates),
        anomalies=tuple(anomalies),
    )


def _strict_member_count(raw: bytes) -> int:
    """Entries a strict reader sees. Fails if even the first header is unreadable: then the
    input isn't a tar archive at all, however much a lenient scan might salvage from it."""
    count = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
            for _ in tar:
                count += 1
    except tarfile.TarError as exc:
        if count == 0:
            raise ArchiveError(f"not a tar archive: {exc}") from exc
    return count


def extract_zip(
    data: bytes,
    *,
    limits: ExtractLimits = DEFAULT_LIMITS,
    password: bytes | None = None,
    include: Callable[[str], bool] | None = None,
) -> ArtifactTree:
    """Extract a zip archive into memory with the same path rules and size limits as tarballs.
    Declared sizes are checked before reading, and reads are capped in case a header lies.

    `password` decrypts legacy ZipCrypto entries, e.g. malware datasets that ship as
    `infected`-encrypted zips. `include` selects members by their safe path, so that only the
    files needed are ever decrypted."""
    if len(data) > limits.max_compressed_bytes:
        raise ArchiveError(f"compressed size {len(data)} exceeds limit")
    files: dict[str, bytes] = {}
    skipped: list[SkippedEntry] = []
    duplicates: list[str] = []
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) > limits.max_files:
                raise ArchiveError(f"more than {limits.max_files} entries")
            for info in infos:
                if info.is_dir():
                    continue
                path = safe_relative_path(info.filename)
                if path is None:
                    skipped.append(SkippedEntry(info.filename, "unsafe path"))
                    continue
                if include is not None and not include(path):
                    continue
                if info.file_size > limits.max_file_bytes:
                    raise ArchiveError(f"{path}: {info.file_size} bytes exceeds per-file limit")
                if info.compress_size and info.file_size / info.compress_size > limits.max_ratio:
                    raise ArchiveError(f"{path}: compression ratio exceeds limit")
                with archive.open(info, pwd=password) as handle:
                    content = handle.read(limits.max_file_bytes + 1)
                if len(content) > limits.max_file_bytes:
                    raise ArchiveError(f"{path}: exceeds per-file limit")
                total += len(content)
                if total > limits.max_total_bytes:
                    raise ArchiveError(f"decompressed size exceeds {limits.max_total_bytes} bytes")
                if path in files:
                    duplicates.append(path)
                files[path] = content
    except (zipfile.BadZipFile, zipfile.LargeZipFile, EOFError, zlib.error) as exc:
        raise ArchiveError(f"malformed zip: {exc}") from exc
    except (RuntimeError, NotImplementedError) as exc:  # missing/wrong password, unsupported crypto
        raise ArchiveError(f"cannot decrypt zip: {exc}") from exc
    return ArtifactTree(files=files, skipped=tuple(skipped), duplicates=tuple(duplicates))


def safe_relative_path(name: str, strip_components: int = 0) -> str | None:
    """Normalize an archive member name to a safe relative POSIX path, or None if it is absolute,
    escapes the root, contains NUL/backslashes/drive letters, or is empty after stripping."""
    if not name or "\x00" in name or "\\" in name:
        return None
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        return None
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if ".." in parts:
        return None
    parts = parts[strip_components:]
    if not parts or (len(parts[0]) > 1 and parts[0][1] == ":"):
        return None  # empty, or a drive letter exposed by stripping ("package/C:/x" -> "C:/x")
    return posixpath.join(*parts)


def _gunzip_limited(data: bytes, limits: ExtractLimits) -> bytes:
    cap = min(limits.max_total_bytes, max(len(data), 1) * limits.max_ratio)
    decompressor = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
    try:
        out = decompressor.decompress(data, cap + 1)
    except zlib.error as exc:
        raise ArchiveError(f"malformed gzip: {exc}") from exc
    if len(out) > cap or decompressor.unconsumed_tail:
        raise ArchiveError(f"decompressed size exceeds limit ({cap} bytes)")
    if not decompressor.eof:
        raise ArchiveError("truncated gzip stream")
    if decompressor.unused_data:
        # A second gzip member or trailing bytes: tools disagree on how to read these, which is
        # exactly the kind of ambiguity an attacker could exploit, so refuse.
        raise ArchiveError("trailing data after gzip stream")
    return out


def _entry_kind(member: tarfile.TarInfo) -> str:
    if member.issym():
        return f"symlink -> {member.linkname}"
    if member.islnk():
        return f"hardlink -> {member.linkname}"
    if member.isfifo():  # checked first: tarfile's isdev() is also true for FIFOs
        return "fifo"
    if member.isdev():
        return "device"
    return "non-regular entry"
