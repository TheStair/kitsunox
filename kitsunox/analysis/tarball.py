"""Unpack published npm tarballs and diff one version against another.

npm tarballs are gzipped tar with every entry under a ``package/`` prefix, which is
stripped here so paths match what ``require()`` sees.

The published tarball — not the git repo — is the unit of analysis: npm publishes are not
guaranteed to match any tagged commit, and many incidents ship code that never touched
the repo.
"""

from __future__ import annotations

import difflib
import hashlib
import io
import tarfile
from dataclasses import dataclass
from pathlib import Path

import structlog

from kitsunox.ingest.registry_client import RegistryClient, TarballUnavailable
from kitsunox.ir import ChangeType, FileDiff, FileEntry

log = structlog.get_logger(__name__)

# Files above this size are hashed/flagged but never diffed inline (keeps evidence bounded).
MAX_DIFF_BYTES = 512 * 1024
_TEXT_HINT_SUFFIXES = {
    ".js", ".cjs", ".mjs", ".jsx", ".ts", ".tsx", ".json", ".md", ".txt", ".yml",
    ".yaml", ".sh", ".map", ".html", ".css", ".lock", ".toml", ".ini", ".xml",
}
_BINARY_HINT_SUFFIXES = {
    ".node", ".wasm", ".exe", ".dll", ".so", ".dylib", ".png", ".jpg", ".jpeg",
    ".gif", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".gz", ".tgz", ".zip", ".br",
    ".7z", ".bz2", ".pdf", ".class", ".jar",
}


@dataclass
class UnpackedTarball:
    name: str
    version: str
    root: Path  # temp dir, 'package/' prefix stripped
    files: dict[str, FileEntry]

    def read_bytes(self, path: str) -> bytes:
        return (self.root / path).read_bytes()

    def read_text(self, path: str) -> str:
        return (self.root / path).read_text(encoding="utf-8", errors="replace")


def _looks_binary(sample: bytes, path: str) -> bool:
    suffix = Path(path).suffix.lower()
    if suffix in _BINARY_HINT_SUFFIXES:
        return True
    if suffix in _TEXT_HINT_SUFFIXES:
        return False
    return b"\x00" in sample[:8192]


def unpack_tarball(path: Path, name: str, version: str, dest_dir: Path) -> UnpackedTarball:
    root = dest_dir
    root.mkdir(parents=True, exist_ok=True)
    files: dict[str, FileEntry] = {}

    with tarfile.open(path, "r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            rel = member.name
            for prefix in ("package/", "./package/", "./"):
                if rel.startswith(prefix):
                    rel = rel[len(prefix) :]
                    break
            if not rel or rel.startswith("/") or ".." in Path(rel).parts:
                log.warning("skipping suspicious tar entry", entry=member.name)
                continue

            fobj = tf.extractfile(member)
            if fobj is None:
                continue
            data = fobj.read()

            out = root / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(data)

            files[rel] = FileEntry(
                path=rel,
                size=len(data),
                is_binary=_looks_binary(data, rel),
                sha256=hashlib.sha256(data).hexdigest(),
            )

    return UnpackedTarball(name=name, version=version, root=root, files=files)


def _unified(before: bytes, after: bytes, path: str) -> str:
    b = before.decode("utf-8", errors="replace").splitlines(keepends=True)
    a = after.decode("utf-8", errors="replace").splitlines(keepends=True)
    return "".join(
        difflib.unified_diff(b, a, fromfile=f"a/{path}", tofile=f"b/{path}", n=3)
    )


def diff_unpacked(prev: UnpackedTarball | None, cur: UnpackedTarball) -> list[FileDiff]:
    diffs: list[FileDiff] = []
    prev_files = prev.files if prev else {}

    for path, entry in cur.files.items():
        old = prev_files.get(path)
        if old is None:
            diffs.append(
                FileDiff(
                    path=path,
                    change_type=ChangeType.ADDED,
                    is_binary=entry.is_binary,
                    size_before=None,
                    size_after=entry.size,
                    hunks=""
                    if entry.is_binary or entry.size > MAX_DIFF_BYTES
                    else _unified(b"", cur.read_bytes(path), path),
                )
            )
        elif old.sha256 != entry.sha256:
            both_text = not (old.is_binary or entry.is_binary)
            small = max(old.size, entry.size) <= MAX_DIFF_BYTES
            diffs.append(
                FileDiff(
                    path=path,
                    change_type=ChangeType.MODIFIED,
                    is_binary=not both_text,
                    size_before=old.size,
                    size_after=entry.size,
                    hunks=_unified(prev.read_bytes(path), cur.read_bytes(path), path)
                    if (both_text and small and prev)
                    else "",
                )
            )

    for path, old in prev_files.items():
        if path not in cur.files:
            diffs.append(
                FileDiff(
                    path=path,
                    change_type=ChangeType.REMOVED,
                    is_binary=old.is_binary,
                    size_before=old.size,
                    size_after=None,
                )
            )

    diffs.sort(key=lambda d: d.path)
    return diffs


def diff_versions(
    name: str,
    prev_version: str | None,
    cur_version: str,
    *,
    client: RegistryClient,
    workdir: Path,
) -> tuple[list[FileDiff], UnpackedTarball, UnpackedTarball | None]:
    """Download + unpack ``cur_version`` (and ``prev_version`` if given) and diff them.

    Raises ``TarballUnavailable`` if the current version's tarball can't be fetched — the
    caller (scanner / backfill) decides how to record that.
    """
    workdir.mkdir(parents=True, exist_ok=True)

    cur_tar = client.download_tarball(name, cur_version)
    cur = unpack_tarball(cur_tar, name, cur_version, workdir / f"cur-{cur_version}")

    prev: UnpackedTarball | None = None
    if prev_version:
        try:
            prev_tar = client.download_tarball(name, prev_version)
            prev = unpack_tarball(prev_tar, name, prev_version, workdir / f"prev-{prev_version}")
        except TarballUnavailable:
            log.warning(
                "previous version tarball unavailable; treating current as all-added",
                name=name,
                prev_version=prev_version,
            )
            prev = None

    return diff_unpacked(prev, cur), cur, prev


def sniff_tarball_bytes(raw: bytes, name: str, version: str, dest_dir: Path) -> UnpackedTarball:
    """Test helper: unpack an in-memory .tgz."""
    tmp = dest_dir / "_inmem.tgz"
    dest_dir.mkdir(parents=True, exist_ok=True)
    tmp.write_bytes(raw)
    return unpack_tarball(tmp, name, version, dest_dir / "unpacked")


def make_tarball_bytes(files: dict[str, bytes]) -> bytes:
    """Test helper: build a npm-style .tgz (``package/`` prefixed) from a path->bytes map."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for path, data in files.items():
            info = tarfile.TarInfo(name=f"package/{path}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()
