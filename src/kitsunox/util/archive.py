"""Safe, in-memory extraction of untrusted .tar.gz archives.

Nothing is written to disk and nothing is executed: the result is a read-only mapping of
normalized relative paths to file bytes. Entries that aren't regular files (symlinks, hardlinks,
devices, FIFOs) and entries with unsafe paths are not extracted; they're reported in `skipped`
because their presence can itself be a signal. Size, file-count and compression-ratio limits guard
against archive bombs. A tarball's regular files also keep their permission bits (`modes`), so
a repacked copy can keep a script executable; zips report none.

Parser differentials: a strict tar reader stops at the end-of-archive marker or the first invalid
header, but lenient readers keep going, so an attacker can hide entries that some installer sees
and an analyzer doesn't. We therefore read leniently (skipping zero and invalid blocks) so every
entry any reader could find is extracted, and record an `anomaly` whenever the lenient and strict
readings differ or non-zero bytes follow the last entry. `npm pack` never produces either.
"""

from __future__ import annotations

import hashlib
import heapq
import io
import posixpath
import tarfile
import zipfile
import zlib
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import IO, Any, Final, Literal


class ArchiveError(ValueError):
    """The archive is malformed or exceeds a safety limit."""


class ArchiveLimitError(ArchiveError):
    """The archive exceeds one of its `ExtractLimits`; `limit` names which, for a caller whose
    limits are a budget (a bundle's remaining bytes and files) rather than a safety bound."""

    def __init__(
        self, message: str, limit: Literal["compressed", "total", "ratio", "file", "files"]
    ) -> None:
        super().__init__(message)
        self.limit = limit


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


OmitReason = Literal["binary", "file", "budget"]


@dataclass(frozen=True)
class OmittedFile:
    """A regular file a partial read (`stream_tar_gz`) did not keep: `binary` (a NUL byte in
    its first bytes), `file` (over the per-file limit) or `budget` (the kept bytes were used
    up by more important files). `head` holds a binary's first bytes, enough to tell its
    format; empty for text."""

    path: str
    size: int
    sha256: str
    mode: int
    reason: OmitReason
    head: bytes = b""


@dataclass(frozen=True)
class ArtifactTree(Mapping[str, bytes]):
    """Read-only view of an extracted archive: normalized POSIX path -> content."""

    files: Mapping[str, bytes]
    skipped: tuple[SkippedEntry, ...] = ()
    duplicates: tuple[str, ...] = field(default=())
    anomalies: tuple[str, ...] = field(default=())
    # Each extracted tar file's permission bits (`mode & 0o7777`), by the same path as `files`.
    modes: Mapping[str, int] = field(default_factory=dict)
    # A partial read's regular files that were not kept (by path); empty for a whole read.
    omitted: tuple[OmittedFile, ...] = ()

    def __getitem__(self, path: str) -> bytes:
        return self.files[path]

    def __iter__(self) -> Iterator[str]:
        return iter(sorted(self.files))

    def __len__(self) -> int:
        return len(self.files)


def extract_tar_gz(
    data: bytes,
    *,
    strip_components: int = 0,
    limits: ExtractLimits = DEFAULT_LIMITS,
    include: Callable[[str], bool] | None = None,
    hidden_entries: bool = True,
) -> ArtifactTree:
    """Extract a gzip-compressed tar archive into memory. `strip_components` drops leading path
    segments (npm tarballs nest everything under `package/`). `include` selects regular files
    by their safe path; the rest are not read (a monorepo archive, one package's directory).
    `hidden_entries` reads the archive a second time, strictly, to report entries only a lenient
    reader sees; a source that never hides any (GitHub's own archives) can skip that pass, a
    fifth of Stage 4's time on 2026-10-30."""
    if len(data) > limits.max_compressed_bytes:
        raise ArchiveLimitError(f"compressed size {len(data)} exceeds limit", "compressed")
    raw = _gunzip_limited(data, limits)

    strict_count = _strict_member_count(raw) if hidden_entries else None
    files: dict[str, bytes] = {}
    modes: dict[str, int] = {}
    skipped: list[SkippedEntry] = []
    duplicates: list[str] = []
    lenient_count = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:", ignore_zeros=True) as tar:
            for count, member in enumerate(tar, start=1):
                lenient_count = count
                if count > limits.max_files:
                    raise ArchiveLimitError(f"more than {limits.max_files} entries", "files")
                if member.isdir():
                    continue  # directories are implied by file paths; nothing to extract
                path = safe_relative_path(member.name, strip_components)
                if path is None:
                    skipped.append(SkippedEntry(member.name, "unsafe path"))
                    continue
                if not member.isfile():
                    skipped.append(SkippedEntry(path, _entry_kind(member)))
                    continue
                if include is not None and not include(path):
                    continue
                if member.size > limits.max_file_bytes:
                    message = f"{path}: {member.size} bytes exceeds per-file limit"
                    raise ArchiveLimitError(message, "file")
                handle = tar.extractfile(member)
                if handle is None:
                    skipped.append(SkippedEntry(path, "unreadable"))
                    continue
                if path in files:
                    duplicates.append(path)
                files[path] = handle.read()
                modes[path] = member.mode & 0o7777
            end_offset = tar.offset
    except tarfile.TarError as exc:
        raise ArchiveError(f"malformed tar: {exc}") from exc

    anomalies = []
    if strict_count is not None and strict_count != lenient_count:
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
        modes=modes,
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
    skip_oversize: bool = False,
) -> ArtifactTree:
    """Extract a zip archive into memory with the same path rules and size limits as tarballs.
    Declared sizes are checked before reading, and reads are capped in case a header lies.

    `password` decrypts legacy ZipCrypto entries, e.g. malware datasets that ship as
    `infected`-encrypted zips. `include` selects members by their safe path, so that only the
    files needed are ever decrypted."""
    if len(data) > limits.max_compressed_bytes:
        raise ArchiveLimitError(f"compressed size {len(data)} exceeds limit", "compressed")
    files: dict[str, bytes] = {}
    skipped: list[SkippedEntry] = []
    duplicates: list[str] = []
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) > limits.max_files:
                raise ArchiveLimitError(f"more than {limits.max_files} entries", "files")
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
                    if skip_oversize:
                        skipped.append(SkippedEntry(info.filename, "over per-file limit"))
                        continue
                    message = f"{path}: {info.file_size} bytes exceeds per-file limit"
                    raise ArchiveLimitError(message, "file")
                if info.compress_size and info.file_size / info.compress_size > limits.max_ratio:
                    raise ArchiveLimitError(f"{path}: compression ratio exceeds limit", "ratio")
                with archive.open(info, pwd=password) as handle:
                    content = handle.read(limits.max_file_bytes + 1)
                if len(content) > limits.max_file_bytes:
                    raise ArchiveLimitError(f"{path}: exceeds per-file limit", "file")
                total += len(content)
                if total > limits.max_total_bytes:
                    message = f"decompressed size exceeds {limits.max_total_bytes} bytes"
                    raise ArchiveLimitError(message, "total")
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
    by_ratio = max(len(data), 1) * limits.max_ratio
    cap = min(limits.max_total_bytes, by_ratio)
    decompressor = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
    try:
        out = decompressor.decompress(data, cap + 1)
    except zlib.error as exc:
        raise ArchiveError(f"malformed gzip: {exc}") from exc
    if len(out) > cap or decompressor.unconsumed_tail:
        limit: Literal["total", "ratio"] = "ratio" if by_ratio < limits.max_total_bytes else "total"
        raise ArchiveLimitError(f"decompressed size exceeds limit ({cap} bytes)", limit)
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


# --- partial reads: stream a large tarball once, keep what the rules read -----------------------

# A partial read's bounds (decision 0021): 1 GiB of declared package plus tar headers. The
# compressed stream is bounded by the same number; neither is ever held whole. The per-file
# limit is the total: an omitted file is only hashed, never held.
PARTIAL_LIMITS: Final = ExtractLimits(
    max_compressed_bytes=1 << 30,
    max_total_bytes=(1 << 30) + (1 << 28),
    max_file_bytes=(1 << 30) + (1 << 28),
    max_files=50_000,
    max_ratio=1000,
)
SNIFF_BYTES: Final = 8192  # a NUL byte in these makes a file binary (as `static.analyse`)
BLOCK: Final = tarfile.BLOCKSIZE
_STREAM_CHUNK: Final = 1 << 20
_TAIL_BYTES: Final = 1024


@dataclass(frozen=True)
class KeepPolicy:
    """What a partial read keeps. A file is binary when its first `SNIFF_BYTES` hold a NUL
    byte, unless `text(path)` (a source or script extension: always text). Binaries are never
    kept; their first `head_bytes` are. Text is kept up to `max_file_bytes` a file and
    `max_kept_bytes` in all; when the budget is full, a file of a lower `rank(path, head)`
    evicts kept files of a higher rank, highest rank and largest first. `version` names the
    policy in request keys: a different policy never serves an older subset."""

    version: int
    max_file_bytes: int
    max_kept_bytes: int
    text: Callable[[str], bool]
    rank: Callable[[str, bytes], int]
    head_bytes: int = 512


@dataclass(frozen=True)
class PartialArchive:
    """What `stream_tar_gz` read: kept files and their modes, every other regular file
    (`omitted`), entries not extracted (`skipped`), duplicates and anomalies as
    `extract_tar_gz` reports them, and the stream's size, SHA-256 and entry count."""

    files: Mapping[str, bytes]
    modes: Mapping[str, int]
    omitted: tuple[OmittedFile, ...]
    skipped: tuple[SkippedEntry, ...]
    duplicates: tuple[str, ...]
    anomalies: tuple[str, ...]
    compressed_bytes: int
    compressed_sha256: str
    entries: int

    def tree(self) -> ArtifactTree:
        return ArtifactTree(
            files=dict(sorted(self.files.items())),
            skipped=self.skipped,
            duplicates=self.duplicates,
            anomalies=self.anomalies,
            modes=dict(sorted(self.modes.items())),
            omitted=self.omitted,
        )


class _Gunzip(io.RawIOBase):
    """The decompressed bytes of a gzip stream that arrives in `chunks`, read once. Applies
    `_gunzip_limited`'s checks as it goes: compressed and decompressed size, ratio, a single
    gzip member with nothing after it, no truncation. Keeps the stream's SHA-256, its first
    block and its last `_TAIL_BYTES` (for the trailing-data check)."""

    def __init__(self, chunks: Iterable[bytes], limits: ExtractLimits) -> None:
        super().__init__()
        self._chunks = iter(chunks)
        self._limits = limits
        self._inflate = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
        self._pending = b""  # compressed input not yet inflated
        self._out = memoryview(b"")
        self._done = False
        self._digest = hashlib.sha256()
        self.compressed = 0
        self.total = 0
        self.first = b""
        self.tail = bytearray()

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        while not self._out and not self._done:
            self._fill()
        n = min(len(buffer), len(self._out))
        buffer[:n] = self._out[:n]
        self._out = self._out[n:]
        return n

    def drain(self) -> None:
        """Read to the end of the stream (and of `chunks`), discarding the bytes."""
        while not self._done:
            self._out = memoryview(b"")
            self._fill()
        self._out = memoryview(b"")

    @property
    def sha256(self) -> str:
        return self._digest.hexdigest()

    def nonzero_after(self, offset: int) -> bool:
        """Whether any byte from `offset` to the end is non-zero (after `drain`). A lenient tar
        reader stops less than a block before the end, well inside the kept tail."""
        start = offset - (self.total - len(self.tail))
        return any(self.tail[max(start, 0) :])

    def _fill(self) -> None:
        if not self._pending:
            chunk = next(self._chunks, None)
            if chunk is None:
                if not self._inflate.eof:
                    raise ArchiveError("truncated gzip stream")
                self._done = True
                return
            self.compressed += len(chunk)
            self._digest.update(chunk)
            if self.compressed > self._limits.max_compressed_bytes:
                message = f"compressed size exceeds {self._limits.max_compressed_bytes} bytes"
                raise ArchiveLimitError(message, "compressed")
            if self._inflate.eof:
                if chunk:
                    raise ArchiveError("trailing data after gzip stream")
                return
            self._pending = chunk
        try:
            out = self._inflate.decompress(self._pending, _STREAM_CHUNK)
        except zlib.error as exc:
            raise ArchiveError(f"malformed gzip: {exc}") from exc
        self._pending = self._inflate.unconsumed_tail
        if self._inflate.eof and self._inflate.unused_data:
            # A second gzip member or trailing bytes, as in `_gunzip_limited`: refused.
            raise ArchiveError("trailing data after gzip stream")
        self.total += len(out)
        if self.total > self._limits.max_total_bytes:
            message = f"decompressed size exceeds limit ({self._limits.max_total_bytes} bytes)"
            raise ArchiveLimitError(message, "total")
        if self.total > max(self.compressed, 1) * self._limits.max_ratio:
            raise ArchiveLimitError("compression ratio exceeds limit", "ratio")
        if len(self.first) < BLOCK:
            self.first += out[: BLOCK - len(self.first)]
        self.tail += out[-_TAIL_BYTES:]
        del self.tail[:-_TAIL_BYTES]
        self._out = memoryview(out)


class _Selection:
    """The kept files and the omitted ones, as a `KeepPolicy` decides, one file at a time in
    archive order. Shared by `stream_tar_gz` and `partial_view`, so both select alike."""

    def __init__(self, policy: KeepPolicy) -> None:
        self.policy = policy
        self.files: dict[str, bytes] = {}
        self.modes: dict[str, int] = {}
        self.ranks: dict[str, int] = {}
        self.omitted: dict[str, OmittedFile] = {}
        self.duplicates: list[str] = []
        self.used = 0
        self.used_by_rank: dict[int, int] = {}
        self._heaps: dict[int, list[tuple[int, str]]] = {}

    def add(self, path: str, size: int, mode: int, head: bytes, rest: Iterable[bytes]) -> None:
        """One regular file: its declared `size`, its first `SNIFF_BYTES` (`head`, all of it
        if shorter) and the remaining bytes (`rest`), consumed here either way. A later entry
        of the same path replaces the earlier one, as in `extract_tar_gz`."""
        if path in self.files or path in self.omitted:
            self.duplicates.append(path)
            self._drop(path)
        policy = self.policy
        binary = b"\x00" in head[:SNIFF_BYTES] and not policy.text(path)
        reason: OmitReason | None = "binary" if binary else None
        if reason is None and size > policy.max_file_bytes:
            reason = "file"
        rank = 0
        if reason is None:
            rank = policy.rank(path, head)
            if not self._room(size, rank):
                reason = "budget"
        if reason is not None:
            digest = hashlib.sha256(head)
            for chunk in rest:
                digest.update(chunk)
            self.omitted[path] = OmittedFile(
                path=path,
                size=size,
                sha256=digest.hexdigest(),
                mode=mode,
                reason=reason,
                head=head[: policy.head_bytes] if binary else b"",
            )
            return
        content = head + b"".join(rest)
        self._evict_for(len(content), rank)
        self.files[path] = content
        self.modes[path] = mode
        self.ranks[path] = rank
        self.used += len(content)
        self.used_by_rank[rank] = self.used_by_rank.get(rank, 0) + len(content)
        heapq.heappush(self._heaps.setdefault(rank, []), (-len(content), path))

    def _room(self, size: int, rank: int) -> bool:
        """Whether `size` bytes fit, once every kept file of a higher rank is evicted."""
        evictable = sum(n for r, n in self.used_by_rank.items() if r > rank)
        return self.used - evictable + size <= self.policy.max_kept_bytes

    def _evict_for(self, size: int, rank: int) -> None:
        """Evict kept files of a higher rank than `rank` (the highest first, then the largest,
        then by path) until `size` more bytes fit."""
        for victim_rank in sorted((r for r in self._heaps if r > rank), reverse=True):
            heap = self._heaps[victim_rank]
            while heap and self.used + size > self.policy.max_kept_bytes:
                negative_size, path = heapq.heappop(heap)
                content = self.files.get(path, b"")
                if (
                    path not in self.files
                    or self.ranks.get(path) != victim_rank
                    or len(content) != -negative_size
                ):
                    continue  # dropped as a duplicate since (and perhaps kept again)
                mode = self.modes[path]
                self._drop(path)
                self.omitted[path] = OmittedFile(
                    path=path,
                    size=len(content),
                    sha256=hashlib.sha256(content).hexdigest(),
                    mode=mode,
                    reason="budget",
                )

    def _drop(self, path: str) -> None:
        self.omitted.pop(path, None)
        content = self.files.pop(path, None)
        rank = self.ranks.pop(path, None)
        self.modes.pop(path, None)
        if content is not None and rank is not None:
            self.used -= len(content)
            self.used_by_rank[rank] -= len(content)

    def omitted_files(self) -> tuple[OmittedFile, ...]:
        return tuple(self.omitted[p] for p in sorted(self.omitted))


def stream_tar_gz(
    chunks: Iterable[bytes],
    policy: KeepPolicy,
    *,
    strip_components: int = 0,
    limits: ExtractLimits = PARTIAL_LIMITS,
) -> PartialArchive:
    """Read a gzip-compressed tar archive arriving in `chunks` once, keeping what `policy`
    keeps (decision 0021). Nothing is written and nothing executed; the archive is never held
    whole. Every chunk is consumed, so a caller checking the stream's integrity sees it all.
    The guards and the lenient reading are `extract_tar_gz`'s: unsafe paths and non-regular
    entries are `skipped`, entries a strict reader would not see are an anomaly (found by their
    offsets: an entry that does not start where the previous one ended), and so are non-zero
    bytes after the last entry. `limits.max_file_bytes` is not checked per file: an omitted
    file is only hashed, and kept ones are bounded by the policy."""
    raw = _Gunzip(chunks, limits)
    selection = _Selection(policy)
    skipped: list[SkippedEntry] = []
    strict_count: int | None = None
    count = 0
    expected = 0
    try:
        with tarfile.open(fileobj=raw, mode="r|", ignore_zeros=True) as tar:
            for count, member in enumerate(tar, start=1):
                if strict_count is None and member.offset != expected:
                    strict_count = count - 1
                expected = tar.offset
                if count > limits.max_files:
                    raise ArchiveLimitError(f"more than {limits.max_files} entries", "files")
                if member.isdir():
                    continue
                path = safe_relative_path(member.name, strip_components)
                if path is None:
                    skipped.append(SkippedEntry(member.name, "unsafe path"))
                    continue
                if not member.isfile():
                    skipped.append(SkippedEntry(path, _entry_kind(member)))
                    continue
                handle = tar.extractfile(member)
                if handle is None:
                    skipped.append(SkippedEntry(path, "unreadable"))
                    continue
                head = handle.read(SNIFF_BYTES)
                selection.add(path, member.size, member.mode & 0o7777, head, _chunks(handle))
            end_offset = tar.offset
        raw.drain()
    except tarfile.TarError as exc:
        raise ArchiveError(f"malformed tar: {exc}") from exc
    if (count == 0 or strict_count == 0) and any(raw.first):
        # A strict reader fails on the first header (`_strict_member_count`): not a tar.
        raise ArchiveError("not a tar archive: the first header is invalid")
    anomalies = []
    if strict_count is not None:
        anomalies.append(
            f"{count - strict_count} entries follow an end-of-archive marker or invalid "
            "header (a strict tar reader would not see them)"
        )
    if raw.nonzero_after(end_offset):
        anomalies.append("non-zero data after the last archive entry")
    return PartialArchive(
        files=selection.files,
        modes=selection.modes,
        omitted=selection.omitted_files(),
        skipped=tuple(skipped),
        duplicates=tuple(selection.duplicates),
        anomalies=tuple(anomalies),
        compressed_bytes=raw.compressed,
        compressed_sha256=raw.sha256,
        entries=count,
    )


def _chunks(handle: IO[bytes]) -> Iterator[bytes]:
    while chunk := handle.read(_STREAM_CHUNK):
        yield chunk


def partial_view(tree: ArtifactTree, policy: KeepPolicy) -> ArtifactTree:
    """What a partial read under `policy` keeps of a tree already in memory, its files taken
    in the order the tree holds them (archive order): the evaluation's view of a version the
    pipeline reads partially. Skipped entries, duplicates and anomalies are the tree's own."""
    selection = _Selection(policy)
    for path, content in tree.files.items():
        rest = (content[SNIFF_BYTES:],)
        selection.add(path, len(content), tree.modes.get(path, 0o644), content[:SNIFF_BYTES], rest)
    return ArtifactTree(
        files=dict(sorted(selection.files.items())),
        skipped=tree.skipped,
        duplicates=tree.duplicates,
        anomalies=tree.anomalies,
        modes=dict(sorted(selection.modes.items())),
        omitted=selection.omitted_files(),
    )
