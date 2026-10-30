"""Importing package-analysis results into the data directory, and reading them back.

The results directory is configured by the user (`results`, the results root: where the
owner puts the contents of each export's `results/` directory, one `<key>/` per job) and is
read as **hostile**: package-analysis wrote it,
but most of what it says was chosen by the package it analysed. For each job Kitsunox exported
(`spool.exported_jobs`, the pipeline's own list: the results directory's listing is never the
authority), `import_result` reads `<results>/<key>/<version>.json`:

- `<key>` is opened with `O_NOFOLLOW` as a directory, the file with `O_NOFOLLOW` as a regular
  file of at most `ossf.MAX_RESULT_BYTES` (`spool.read_regular`); a bigger file is rejected
  unread as `ossf.RESULT_TOO_LARGE`, which `sandbox.result-rejected` scores HIGH;
- `<key>/results.json` (package-analysis run without `-version`) is read too: it names no
  version, so it is rejected for the identity check, and both files at once are rejected;
- the bytes must parse and validate (`ossf.parse_dynamic`), including the package, name and
  version the result records.

An accepted file is copied byte for byte to `data/sandbox/<key>/result.json`, with
`import.json` (`ImportRecord`: the job it answered and the file's sha256) written last to mark
it complete. It is final: a later file for the key is not read. A file that fails is
recorded as `rejected.json` (`RejectedResult`, a fixed reason and the file's sha256) and the
version gets a scored `sandbox.result-rejected`: a sample that could break its record might be
hiding what it did. A rejection is retried when the file's bytes change (a wrong file put
right); the same bytes are rejected once. Nothing in the results directory can make importing
raise; problems writing the pipeline's own cache do.

`load_cached` re-parses the cached bytes with the job recorded in `import.json`, so a version
that ships the same tarball as another (same key) shares its analysis, and parsing is the same
on every read: a replay re-derives exactly what the live call used.

`prune_sandbox` (with `prune_cache`, `keys_in_use` and `prune_exports`) is the retention hook
for `data/sandbox/`, called after the data-dir prune (`collect`, `kitsunox data prune`), under
`DataDir.lock()`.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import stat
from collections.abc import Collection, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from pydantic import Field

from kitsunox.core.models import Persisted
from kitsunox.core.run import DataDir
from kitsunox.sandbox.models import SandboxJob
from kitsunox.sandbox.ossf import (
    MAX_RESULT_BYTES,
    RESULT_TOO_LARGE,
    UNVERSIONED_FILE,
    MalformedResultError,
    SandboxResult,
    parse_dynamic,
    result_file_names,
)
from kitsunox.sandbox.spool import (
    CACHE_DIR,
    EXPORT_DIR,
    KEY_PATTERN,
    RUN_ID_PATTERN,
    OversizeFileError,
    UnsafeFileError,
    key_of,
    open_dir,
    read_regular,
)
from kitsunox.util.files import atomic_write
from kitsunox.util.hashing import sha256_hex

RESULT_FILE: Final = "result.json"
IMPORT_FILE: Final = "import.json"
REJECTED_FILE: Final = "rejected.json"
SANDBOX_INFO: Final = "sandbox.json"  # in a run directory; written by `stages/sandbox.py`
MAX_RECORD_BYTES: Final = 64 * 1024
UNREADABLE: Final = "the result file could not be read"
UNSAFE: Final = "the result is a symlink or not a regular file"
TWO_FILES: Final = "two result files (<version>.json and results.json)"
NO_VERSION: Final = "results.json names no version (package-analysis was run without -version)"


class ImportRecord(Persisted):
    """`data/sandbox/<key>/import.json`: which job an accepted result answered."""

    job: SandboxJob
    result_sha256: str
    source: str = Field(max_length=300, description="The result's file name, as read.")


class RejectedResult(Persisted):
    """Why the result for `key` was refused. `result_sha256` is None when it couldn't be
    read at all."""

    key: str
    reason: str = Field(max_length=200)
    result_sha256: str | None = None


@dataclass(frozen=True)
class CacheProblem:
    """The pipeline's own cache entry for a key can't be used (unreadable or tampered with).
    Not the package's doing, so not scored: the stage reports it as `sandbox.not-run`."""

    reason: str


Cached = SandboxResult | RejectedResult | CacheProblem


# --- reading the results directory ----------------------------------------------------------


@dataclass(frozen=True)
class _Found:
    name: str
    data: bytes


def _read_result(results: Path, job: SandboxJob) -> _Found | None:
    """The job's result file, or None while there is none. Raises `MalformedResultError`
    (unsafe or two files) and `OSError` (unreadable)."""
    try:
        with open_dir(results, job.key) as fd:
            found = []
            for name in result_file_names(job):
                try:
                    found.append(_Found(name, read_regular(name, MAX_RESULT_BYTES, dir_fd=fd)))
                except FileNotFoundError:
                    continue
    except FileNotFoundError:
        return None
    except OversizeFileError:  # never read: the size alone is the verdict (`RESULT_TOO_LARGE`)
        raise MalformedResultError(RESULT_TOO_LARGE) from None
    except UnsafeFileError:
        raise MalformedResultError(UNSAFE) from None
    if len(found) > 1:
        raise MalformedResultError(TWO_FILES)
    return found[0] if found else None


def _parse(found: _Found, job: SandboxJob) -> SandboxResult:
    if found.name == UNVERSIONED_FILE:  # package-analysis then records Version ""
        raise MalformedResultError(NO_VERSION)
    return parse_dynamic(found.data, job)


ImportOutcome = Literal["cached", "accepted", "rejected", "unchanged", "absent"]


def import_result(results: Path, cache_root: Path, job: SandboxJob) -> ImportOutcome:
    """Bring the result for an exported `job` into the cache. `cached`: already accepted;
    `unchanged`: rejected before, and the file hasn't changed; `absent`: no result yet."""
    if not KEY_PATTERN.fullmatch(job.key) or key_of(job) != job.key:
        raise ValueError("job key does not match its inputs")  # a pipeline bug
    cached = cache_root / job.key
    if (cached / IMPORT_FILE).exists():
        return "cached"
    sha: str | None = None
    try:
        found = _read_result(results, job)
        if found is None:
            return "absent"
        sha = sha256_hex(found.data)
        _parse(found, job)
    except MalformedResultError as exc:
        reason = str(exc)
    except OSError:  # PermissionError, a vanished file, EIO
        reason = UNREADABLE
    else:
        atomic_write(cached / RESULT_FILE, found.data)
        record = ImportRecord(job=job, result_sha256=sha, source=found.name)
        atomic_write(cached / IMPORT_FILE, record.model_dump_json(indent=2).encode())
        with contextlib.suppress(FileNotFoundError):
            (cached / REJECTED_FILE).unlink()
        return "accepted"
    rejected = RejectedResult(key=job.key, reason=reason, result_sha256=sha)
    if _cached_rejection(cached) == rejected:
        return "unchanged"
    atomic_write(cached / REJECTED_FILE, rejected.model_dump_json(indent=2).encode())
    return "rejected"


def import_results(
    results: Path, cache_root: Path, jobs: Iterable[SandboxJob]
) -> dict[str, ImportOutcome]:
    """`import_result` for each job (once per key, in key order). `{}` when `results` isn't a
    directory (not mounted, or misconfigured): nothing is imported then."""
    if not results.is_dir():
        return {}
    unique = {job.key: job for job in jobs}
    return {key: import_result(results, cache_root, unique[key]) for key in sorted(unique)}


# --- reading the cache --------------------------------------------------------------------------


def _cached_rejection(cached: Path) -> RejectedResult | None:
    try:
        data = read_regular(cached / REJECTED_FILE, MAX_RECORD_BYTES)
        return RejectedResult.model_validate_json(data, strict=True)
    except OSError, ValueError:  # ValidationError and UnsafeFileError are ValueErrors
        return None


def peek(cache_root: Path, key: str) -> ImportRecord | RejectedResult | None:
    """The small record of what is cached for `key` (an accepted result's `import.json`, else
    the rejection), without reading the result; None when nothing readable is cached."""
    cached = cache_root / key
    try:
        data = read_regular(cached / IMPORT_FILE, MAX_RECORD_BYTES)
        record = ImportRecord.model_validate_json(data, strict=True)
    except FileNotFoundError:
        return _cached_rejection(cached)
    except OSError, ValueError:
        return None
    return record if record.job.key == key else None


def load_accepted(
    cache_root: Path, key: str, sha256: str | None = None
) -> SandboxResult | CacheProblem | None:
    """The accepted result for `key`, re-parsed from the cached bytes; None when nothing was
    accepted. With `sha256`, the cached file must be that one."""
    cached = cache_root / key
    if not os.path.lexists(cached / IMPORT_FILE):
        return None
    try:
        with open_dir(cache_root, key) as fd:
            record = ImportRecord.model_validate_json(
                read_regular(IMPORT_FILE, MAX_RECORD_BYTES, dir_fd=fd), strict=True
            )
            data = read_regular(RESULT_FILE, MAX_RESULT_BYTES, dir_fd=fd)
    except OSError, ValueError:
        return CacheProblem("cache: the cached result is unreadable")
    if record.job.key != key or key_of(record.job) != key:
        return CacheProblem("cache: the cached result is for another job")
    if sha256_hex(data) != record.result_sha256 or (sha256 and sha256 != record.result_sha256):
        return CacheProblem("cache: the cached result has changed")
    try:
        return parse_dynamic(data, record.job)
    except MalformedResultError:
        return CacheProblem("cache: the cached result no longer validates")


def load_cached(cache_root: Path, key: str) -> Cached | None:
    """The cached answer for `key`: an accepted result (re-validated), else a rejection, else
    None. A cache entry that can't be used is a `CacheProblem`."""
    accepted = load_accepted(cache_root, key)
    if accepted is not None:
        return accepted
    cached = cache_root / key
    if not os.path.lexists(cached / REJECTED_FILE):
        return None
    rejected = _cached_rejection(cached)
    if rejected is None:
        return CacheProblem("cache: the cached rejection is unreadable")
    if rejected.key != key:
        return CacheProblem("cache: the cached rejection is for another job")
    return rejected


# --- retention -----------------------------------------------------------------------------------


def prune_cache(data: DataDir, keep_keys: Collection[str]) -> int:
    """Delete every `data/sandbox/<key>/` not in `keep_keys`; returns how many went. Only
    entries named like a key and that are real directories are touched (`export/` and
    anything else in there isn't ours to judge). The caller holds `DataDir.lock()`."""
    root = data.root / CACHE_DIR
    if not root.is_dir():
        return 0
    removed = 0
    for entry in sorted(os.listdir(root)):
        path = root / entry
        if entry in keep_keys or not KEY_PATTERN.fullmatch(entry):
            continue
        if stat.S_ISDIR(path.lstat().st_mode):
            shutil.rmtree(path)
            removed += 1
    return removed


def prune_exports(data: DataDir, keep_run_ids: Collection[str]) -> int:
    """Delete every `data/sandbox/export/<run_id>/` not in `keep_run_ids` (pass the runs that
    aren't pruned); returns how many went. The caller holds `DataDir.lock()`."""
    root = data.root / CACHE_DIR / EXPORT_DIR
    if not root.is_dir():
        return 0
    removed = 0
    for entry in sorted(os.listdir(root)):
        path = root / entry
        if entry in keep_run_ids or not RUN_ID_PATTERN.fullmatch(entry):
            continue
        if stat.S_ISDIR(path.lstat().st_mode):
            shutil.rmtree(path)
            removed += 1
    return removed


def prune_sandbox(data: DataDir, pinned_names: Collection[str] = ()) -> tuple[int, int]:
    """After the data-dir prune has marked old runs (`retention.json`): drop the exports of
    pruned runs and every cached result no run still refers to (`keys_in_use`). Returns
    (exports, results) removed. The caller holds `DataDir.lock()`."""
    runs = data.root / "runs"
    unpruned = (
        {p.name for p in runs.iterdir() if p.is_dir() and not (p / "retention.json").exists()}
        if runs.is_dir()
        else set()
    )
    exports = prune_exports(data, unpruned)
    return exports, prune_cache(data, keys_in_use(data, pinned_names))


def keys_in_use(data: DataDir, pinned_names: Collection[str] = ()) -> set[str]:
    """The cache keys a run still refers to (`sandbox.json` "keys": version -> key): every
    unpruned run's, and, for runs already pruned (`retention.json`), those of packages in
    `pinned_names`, as Stage 2's tarballs of OSV-labelled packages are pinned. A run whose
    `sandbox.json` can't be read keeps nothing alive (and has nothing to replay)."""
    runs = data.root / "runs"
    if not runs.is_dir():
        return set()
    keys: set[str] = set()
    for run_dir in sorted(p for p in runs.iterdir() if p.is_dir()):
        pruned = (run_dir / "retention.json").exists()
        for ref, key in _recorded_keys(run_dir).items():
            if not pruned or _ref_name(ref) in pinned_names:
                keys.add(key)
    return keys


def _recorded_keys(run_dir: Path) -> dict[str, str]:
    try:
        raw = json.loads((run_dir / SANDBOX_INFO).read_bytes())
        recorded = raw["keys"]
    except OSError, ValueError, KeyError, TypeError:
        return {}
    if not isinstance(recorded, dict):
        return {}
    return {
        ref: key
        for ref, key in recorded.items()
        if isinstance(ref, str) and isinstance(key, str) and KEY_PATTERN.fullmatch(key)
    }


def _ref_name(ref: str) -> str:
    """The package name in `str(PackageVersionRef)`, `ecosystem:name@version` (a scoped npm
    name keeps its leading `@`; versions never contain one)."""
    return ref.partition(":")[2].rpartition("@")[0]
