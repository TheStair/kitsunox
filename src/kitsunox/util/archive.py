"""Safe, in-memory extraction of untrusted .tar.gz archives.

Nothing is written to disk and nothing is executed: the result is a read-only mapping of
normalized relative paths to file bytes. Entries that aren't regular files (symlinks, hardlinks,
devices, FIFOs) and entries with unsafe paths are not extracted; they're reported in `skipped`
because their presence can itself be a signal. Size, file-count and compression-ratio limits guard
against archive bombs.
"""

from __future__ import annotations

import io
import posixpath
import tarfile
import zlib
from collections.abc import Iterator, Mapping
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

    files: dict[str, bytes] = {}
    skipped: list[SkippedEntry] = []
    duplicates: list[str] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
            for count, member in enumerate(tar, start=1):
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
    except tarfile.TarError as exc:
        raise ArchiveError(f"malformed tar: {exc}") from exc
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
    if not parts:
        return None
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
