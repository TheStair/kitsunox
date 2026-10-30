"""The export: the tarballs Stage 5 hands to OpenSSF package-analysis, and helpers for reading
files Kitsunox didn't write.

The project owner runs package-analysis themselves, on an **airgapped** analysis VM (their
decision; decision 0014), following its own documentation (`models.ANALYSER_DOCS`); Kitsunox
never runs it, Docker or package code. For each run whose selected versions have no cached
result, Stage 5 writes (under `DataDir.lock()`, like every pipeline write):

    data/sandbox/export/<run_id>/
        <key>.tgz        the tarball: the registry's bytes, verified against its integrity, or
                         the Kitsunox-built offline bundle of the package and its dependencies
                         (`bundle.py`)
        <key>.bundle.json  for a bundle: its `BundleRecord` (what was added, skipped,
                         rewritten), Kitsunox's own data
        jobs.json        an `ExportManifest`: per job, the package, version, file, key, sha256,
                         hooks, network ("airgapped"), its results directory, the bundle summary
                         and record file (or why a version with dependencies isn't bundled), and
                         the arguments for package-analysis's `scripts/run_analysis.sh` (an
                         argv list, plus the same as one shell-quoted command line)
        README.txt       what this is, how the images and the files cross the airgap, the exact
                         per-job command, and the docs to follow

**Portable.** Every path in `jobs.json` is relative to the export directory (`<key>.tgz`,
`results/<key>`), so the owner can carry the directory to the airgapped VM, run each job from
inside it, and carry `results/` back. Kitsunox reads results only from the configured results
root, as `<results root>/<key>/<version>.json` (`results.py`): the owner puts the contents of
`results/` there. Nothing in the export names a path on the Kitsunox host.

**One results directory per job.** package-analysis names its result `<version>.json`, so two
packages with the same version would collide in one directory; each job gets its own,
`results/<key>/` (`RESULTS_DIR` for that job). Which tarball a result describes is known from
this export: package-analysis doesn't record the tarball's hash.

**Airgapped.** Every job's args carry the script's `-fully-offline` (the outer analysis
container gets `--network none`) and `-nointeractive`, then package-analysis's own `-nopull`
(use the sandbox images already in the VM's container store) and `-offline` (the sandbox
container gets `--network=none`). There is no online mode; `analysis_args` always adds them.

The export is the pipeline's own data, and its manifest is validated when read back
(`exported_jobs`) anyway: a job whose key doesn't match its fields is ignored. Tarballs come
from the data directory's blob store, found through the run's own fetch records
(`static-snapshot.json`, `correlate-snapshot.json`), so which tarball a version maps to is
replayable; the bytes are checked twice (the blob store's sha256, then the registry's SRI).
Exports are deleted with their run by retention (`results.prune_exports`).

`read_regular` and `open_dir` read files another program wrote (package-analysis's results)
without following symlinks; `results.py` uses them.
"""

from __future__ import annotations

import contextlib
import errno
import os
import re
import shlex
import stat
from collections.abc import Iterable, Iterator, Mapping, Sequence
from compression.zstd import ZstdError
from pathlib import Path
from typing import ClassVar, Final, Literal

from pydantic import Field

from kitsunox.core.models import PackageVersionRef, Persisted, Record, VersionSnapshot
from kitsunox.core.run import CORRELATE_SNAPSHOT, STATIC_SNAPSHOT, DataDir
from kitsunox.sandbox.models import (
    ANALYSER,
    ANALYSER_DOCS,
    ANALYSER_RELEASE,
    UPSTREAM_SOURCE,
    JobBundle,
    Network,
    SandboxJob,
)
from kitsunox.util.archive import ExtractLimits
from kitsunox.util.files import atomic_write
from kitsunox.util.hashing import IntegrityError, sha256_hex, verify_integrity
from kitsunox.util.http import BlobStore, FetchError, Snapshot, SnapshotEntry, request_key

CACHE_DIR: Final = "sandbox"  # under the data directory: data/sandbox/<key>/ and export/
EXPORT_DIR: Final = "export"  # in CACHE_DIR
JOBS_FILE: Final = "jobs.json"
README_FILE: Final = "README.txt"
MAX_MANIFEST_BYTES: Final = 16 * 1024 * 1024
# The largest file the export writes: a bundle's cap (`bundle.BundleCaps`), over Stage 2's.
MAX_EXPORT_BYTES: Final = 128 * 1024 * 1024
# A reported version's own tarball, as Stage 5 reads it: up to what the export can hold, and
# extracted within the bundle's unpacked cap (`bundle.BundleCaps`). Stage 2's 16 MB cap is for
# parsing every file; Stage 5 only reads package.json and binding.gyp, and exports the bytes.
MAX_TARBALL_BYTES: Final = MAX_EXPORT_BYTES
MAX_TARBALL_UNPACKED_BYTES: Final = 512 * 1024 * 1024
TARBALL_LIMITS: Final = ExtractLimits(
    max_compressed_bytes=MAX_TARBALL_BYTES, max_total_bytes=MAX_TARBALL_UNPACKED_BYTES
)
MAX_BUNDLE_RECORD_BYTES: Final = 64 * 1024 * 1024
KEY_PATTERN: Final = re.compile(r"[0-9a-f]{64}")
RUN_ID_PATTERN: Final = re.compile(r"[0-9A-Za-z][0-9A-Za-z._-]{0,127}")
_DIR_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

RESULTS_SUBDIR: Final = "results"  # in an export directory, on the analysis VM
COMMAND_ENV: Final = "PACKAGE_ANALYSIS"  # the owner's package-analysis checkout
_CONTROL: Final = re.compile(r"[\x00-\x1f\x7f]")

README: Final = f"""\
Kitsunox Stage 5 export: npm tarballs for OpenSSF package-analysis ({ANALYSER_RELEASE}).

These are untrusted package tarballs, some possibly malicious. Never install, unpack or run
them outside package-analysis's sandbox. Kitsunox does not run package-analysis: install and
run it yourself, on your airgapped analysis VM, following its documentation:

    {ANALYSER_DOCS}

The analysis VM is airgapped: no network at all. Nothing reaches it or leaves it except what
you carry across. Kitsunox's docs/stages/sandbox.md and docs/decisions/0014 give the full
steps and the risks.

0. Images, once per pin. The VM can't pull, so the {ANALYSER_RELEASE} images cross as files:
   on a connected machine, build or pull package-analysis's analysis image and its
   dynamic-analysis sandbox image, save each to a file with `docker save`, carry the files
   over, and load them on the VM: the analysis image into Docker (`docker load`), the sandbox
   image into the podman store run_analysis.sh mounts (/var/lib/containers), the way
   package-analysis's Makefile "sync" target does (`docker save ... | podman load`).
   package-analysis's docs for building and loading them:
     {UPSTREAM_SOURCE}/sandboxes/README.md
     {UPSTREAM_SOURCE}/Makefile
     {UPSTREAM_SOURCE}/README.md#local-analysis
   run_analysis.sh starts the analysis image with no tag (":latest"), so it must also be
   known under that name; check both images against the digests in docs/stages/sandbox.md.
1. Carry this whole directory to the analysis VM and cd into it. Every path in jobs.json is
   relative to it; keep the file names (the <key>.tgz name is how a result is matched).
2. For each job in jobs.json, run its "command" from inside this directory, with
   {COMMAND_ENV} set to your package-analysis checkout. It is the job's "args", quoted
   for a POSIX shell, after RESULTS_DIR="$PWD/<results_dir>":

     RESULTS_DIR="$PWD/results/<key>" "${COMMAND_ENV}/scripts/run_analysis.sh" \\
       -fully-offline -nointeractive -ecosystem npm -package <name> -version <version> \\
       -local <key>.tgz -mode dynamic -image-tag {ANALYSER_RELEASE} -nopull -offline

   Never type a package name into a shell line yourself: names are untrusted text. Use the
   job's "command" (built with shlex.quote) or pass "args" as an argv list. A job whose
   arguments hold control characters has no "command"; pass its "args" as a list.
3. Keep every flag. -fully-offline (run_analysis.sh's own) takes the network away from the
   analysis container, -nopull makes package-analysis use the loaded sandbox image instead
   of pulling it, and -offline gives the sandbox no network (--network=none). Keep -version:
   Kitsunox reads <results_dir>/<version>.json and checks the package, name and version it
   records.
   A job whose "bundle" is set is a Kitsunox-built offline bundle: the package's own files
   plus every dependency npm would install, under its node_modules/, with an explicit
   bundleDependencies list, so npm installs it without a network. Its "bundle_record" file
   (<key>.bundle.json) says what was added and rewritten; it stays here. A job with an
   "unbundled_reason" needs registry dependencies Kitsunox couldn't bundle completely: its
   install will most likely fail without a network; Kitsunox reports that failure.
4. Carry the results/ directory back and put its contents (one directory per key) in the
   results root Kitsunox is configured with. Kitsunox imports them on its next run, as
   untrusted data, into the run that exported them (until that run is pruned). Carry nothing
   else off the VM.
"""


class UnsafeFileError(ValueError):
    """A file is a symlink, not the expected file type, or larger than allowed."""


class OversizeFileError(UnsafeFileError):
    """A file is larger than allowed."""


class ExportEntry(Record):
    """One job in `jobs.json`, flat for the person running package-analysis. Paths are
    relative to the export directory."""

    ecosystem: str
    name: str = Field(description="The registry's name for the package.")
    version: str
    install_name: str | None = Field(
        description="The tarball's own package.json name, when it differs (what -package is)."
    )
    file: str = Field(description="The tarball, in the export directory: <key>.tgz.")
    key: str
    sha256: str
    integrity: str | None
    hooks: tuple[str, ...]
    network: Network
    analyser: str
    bundle: JobBundle | None = Field(
        description="The offline dependency bundle the tarball is; None: the registry "
        "tarball as published."
    )
    bundle_record: str | None = Field(
        description="For a bundle, its record in the export directory: <key>.bundle.json."
    )
    unbundled_reason: str | None = Field(
        description="Why a version that needs dependencies is exported unbundled."
    )
    results_dir: str = Field(
        description="RESULTS_DIR for this job, relative to the export directory: "
        "results/<key>. Its contents go into the results root as <key>/."
    )
    args: tuple[str, ...] = Field(description="Arguments for scripts/run_analysis.sh.")
    command: str | None = Field(
        description="The same as one POSIX shell line, run from the export directory; None "
        "when an argument holds a control character."
    )

    def job(self) -> SandboxJob:
        return SandboxJob(
            ref=PackageVersionRef(ecosystem=self.ecosystem, name=self.name, version=self.version),
            tarball_sha256=self.sha256,
            integrity=self.integrity,
            hooks=self.hooks,
            install_name=self.install_name,
            network=self.network,
            analyser=self.analyser,
            bundle=self.bundle,
            unbundled_reason=self.unbundled_reason,
            key=self.key,
        )


class ExportManifest(Persisted):
    """`jobs.json`: every job a run has exported, by key."""

    SCHEMA_VERSION: ClassVar[int] = 4
    # 4: offline bundles (typed summary, record file, unbundled reason); 3: airgapped only (no
    # online mode), bundle hook; 2: relative paths, install name, command
    schema_version: int = 4

    run_id: str
    release: str = ANALYSER_RELEASE
    docs: str = ANALYSER_DOCS
    jobs: tuple[ExportEntry, ...]


def job_key(
    tarball_sha256: str,
    package: str,
    analyser: str = ANALYSER,
    *,
    bundle: JobBundle | None = None,
) -> str:
    """The cache key: two jobs with the same key are the same analysis (same tarball, same
    `-package` name, same analyser release, airgapped). For a bundle the tarball is named by
    the sha256 of its *uncompressed* tar (gzip output can differ between zlib builds), its
    format and its dependency set, not by the `.tgz` bytes; an unbundled job keeps the
    registry tarball's sha256, so its key is the same as before bundling existed."""
    if bundle is None:
        return sha256_hex("\n".join([tarball_sha256, analyser, package]).encode())
    parts = [bundle.tar_sha256, analyser, package, bundle.format, bundle.dependencies_sha256]
    return sha256_hex("\n".join(parts).encode())


def key_of(job: SandboxJob) -> str:
    return job_key(job.tarball_sha256, job.package, job.analyser, bundle=job.bundle)


def build_job(
    snapshot: VersionSnapshot,
    tarball_sha256: str,
    hooks: tuple[str, ...],
    *,
    install_name: str | None = None,
    bundle: JobBundle | None = None,
    unbundled_reason: str | None = None,
) -> SandboxJob:
    """The job for a version. `install_name` is the tarball's own package.json name (None when
    it has no valid one); it is recorded only when it differs from the registry's name.
    `tarball_sha256` is the exported file's: the registry tarball's, or with `bundle` the
    bundle's `.tgz`. `unbundled_reason` says why a version that needs dependencies isn't
    bundled (never with `bundle`)."""
    if bundle is not None and unbundled_reason is not None:
        raise ValueError("a bundled job has no unbundled reason")
    integrity = snapshot.artifact.integrity if snapshot.artifact else None
    own = install_name if install_name and install_name != snapshot.ref.name else None
    return SandboxJob(
        ref=snapshot.ref,
        tarball_sha256=tarball_sha256,
        integrity=integrity,
        hooks=hooks,
        install_name=own,
        bundle=bundle,
        unbundled_reason=unbundled_reason,
        key=job_key(tarball_sha256, own or snapshot.ref.name, bundle=bundle),
    )


# --- reading files someone else wrote --------------------------------------------------------


def _open_child(parent_fd: int, name: str) -> int:
    """`name` in `parent_fd`, as a directory, never through a symlink."""
    try:
        return os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise UnsafeFileError(f"{name} is a symlink or not a directory") from exc
        raise


@contextlib.contextmanager
def open_dir(root: Path, *names: str) -> Iterator[int]:
    """A descriptor for `root/names...`. `root` is configuration and resolved normally; each
    name below it is opened relative to its parent with `O_NOFOLLOW`, so none can be a
    symlink. Raises `FileNotFoundError` when a component is missing and `UnsafeFileError`
    when one is a symlink or not a directory."""
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for name in names:
            child = _open_child(fd, name)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def read_regular(path: Path | str, max_bytes: int, *, dir_fd: int | None = None) -> bytes:
    """Read a file another program may have written: refuse a symlink (`O_NOFOLLOW`), a
    non-regular file (a FIFO would block, a device could be endless) and anything over
    `max_bytes`, checked on the open descriptor so the file can't be swapped in between.
    With `dir_fd`, `path` is a name in that directory."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    name = Path(path).name
    try:
        fd = os.open(path, flags, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:  # the last component is a symlink
            raise UnsafeFileError(f"{name} is a symlink") from exc
        raise
    try:
        info = os.fstat(fd)  # before `fdopen`, which raises its own error on a directory
        if not stat.S_ISREG(info.st_mode):
            raise UnsafeFileError(f"{name} is not a regular file")
        if info.st_size > max_bytes:
            raise OversizeFileError(f"{name} is over {max_bytes} bytes")
    except BaseException:
        os.close(fd)
        raise
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise OversizeFileError(f"{name} is over {max_bytes} bytes")
    return data


# --- tarballs -----------------------------------------------------------------------------------


# Where an earlier stage recorded a reported version's own tarball. Stage 5's own snapshot
# isn't read here: a tarball Stage 5 downloaded itself is looked up through its fetcher, with
# the outcome recorded in sandbox.json, so a replay sees what the live call saw.
TARBALL_SNAPSHOTS: Final = (STATIC_SNAPSHOT, CORRELATE_SNAPSHOT)


class TarballIndex:
    """Artifact URL -> the response a run recorded for it, from the run's stage snapshots.
    Read-only: it never fetches. A tarball no stage fetched in this run is "not captured"
    (Stage 4 reads only versions Stage 2 read, so a reported version's tarball is normally in
    `static-snapshot.json`)."""

    def __init__(self, entries: Mapping[str, SnapshotEntry]) -> None:
        self.entries = dict(entries)

    @classmethod
    def for_run(cls, run_dir: Path, names: Iterable[str] = TARBALL_SNAPSHOTS) -> TarballIndex:
        entries: dict[str, SnapshotEntry] = {}
        for name in names:
            path = run_dir / name
            if path.exists():
                for key, entry in Snapshot.load(path).entries.items():
                    entries.setdefault(key, entry)
        return cls(entries)

    def find(self, snapshot: VersionSnapshot) -> SnapshotEntry | None:
        artifact = snapshot.artifact
        if artifact is None:
            return None
        entry = self.entries.get(request_key(artifact.url, None))
        return entry if entry is not None and 200 <= entry.status < 300 else None


TarballProblem = Literal["missing", "oversize", "integrity"]


def load_tarball(
    blobs: BlobStore, entry: SnapshotEntry, snapshot: VersionSnapshot
) -> bytes | TarballProblem:
    """The verified tarball bytes, or why they can't be used."""
    if entry.size > MAX_TARBALL_BYTES:
        return "oversize"
    if not blobs.exists(entry.sha256):
        return "missing"
    try:
        data = blobs.get(entry.sha256)
    except FetchError, ZstdError:  # the blob store's sha256 check failed, or not zstd
        return "integrity"
    if len(data) > MAX_TARBALL_BYTES:
        return "oversize"
    artifact = snapshot.artifact
    try:
        verify_integrity(
            data,
            integrity=artifact.integrity if artifact else None,
            shasum=artifact.shasum if artifact else None,
        )
    except IntegrityError:
        return "integrity"
    return data


# --- the export -------------------------------------------------------------------------------


def export_dir(data: DataDir, run_id: str) -> Path:
    if not RUN_ID_PATTERN.fullmatch(run_id):
        raise ValueError("not a run id")
    return data.root / CACHE_DIR / EXPORT_DIR / run_id


def tarball_name(job: SandboxJob) -> str:
    return f"{job.key}.tgz"


def bundle_record_name(job: SandboxJob) -> str | None:
    """The bundle's record in the export directory, for a bundled job."""
    return f"{job.key}.bundle.json" if job.bundle is not None else None


def results_dir(job: SandboxJob) -> str:
    """The job's RESULTS_DIR, relative to the export directory."""
    return f"{RESULTS_SUBDIR}/{job.key}"


# run_analysis.sh's own flags (it strips them before starting the analysis image), and
# cmd/analyze's: use the sandbox images already loaded, give the sandbox no network.
SCRIPT_FLAGS: Final = ("-fully-offline", "-nointeractive")
AIRGAP_FLAGS: Final = ("-nopull", "-offline")


def analysis_args(job: SandboxJob) -> tuple[str, ...]:
    """Arguments for package-analysis's `scripts/run_analysis.sh` (README "Local Analysis"),
    run from inside the export directory on the airgapped VM. First the script's own flags
    (`SCRIPT_FLAGS`; `-fully-offline` gives the analysis container `--network none`), then
    `cmd/analyze`'s: the job's tarball by its relative name (the script resolves it and mounts
    it at `/<key>.tgz`), dynamic analysis only, the name npm installs the tarball under as
    -package (so the import phase can `require` it), the version (so the result is named
    `<version>.json` and records it), the sandbox images pinned to the release, and
    `AIRGAP_FLAGS` (`-nopull`: the images already loaded; `-offline`: the sandbox gets
    `--network=none`). Every value follows its flag, which the script and Go's flag parser
    both take as the value whatever it starts with."""
    return (
        *SCRIPT_FLAGS,
        "-ecosystem",
        job.ref.ecosystem,
        "-package",
        job.package,
        "-version",
        job.ref.version,
        "-local",
        tarball_name(job),
        "-mode",
        "dynamic",
        "-image-tag",
        ANALYSER_RELEASE,
        *AIRGAP_FLAGS,
    )


def shell_command(job: SandboxJob) -> str | None:
    """The job as one POSIX shell line, run from the export directory with
    `$PACKAGE_ANALYSIS` set to the owner's checkout. Every argument is `shlex.quote`d (package
    names are untrusted); None when one holds a control character, which a pasted line could
    mangle."""
    args = analysis_args(job)
    if any(_CONTROL.search(a) for a in args):
        return None
    script = f'"${COMMAND_ENV}/scripts/run_analysis.sh"'
    quoted = " ".join(shlex.quote(a) for a in args)
    return f'RESULTS_DIR="$PWD/{results_dir(job)}" {script} {quoted}'


def _entry(job: SandboxJob) -> ExportEntry:
    return ExportEntry(
        ecosystem=job.ref.ecosystem,
        name=job.ref.name,
        version=job.ref.version,
        install_name=job.install_name,
        file=tarball_name(job),
        key=job.key,
        sha256=job.tarball_sha256,
        integrity=job.integrity,
        hooks=job.hooks,
        network=job.network,
        analyser=job.analyser,
        bundle=job.bundle,
        bundle_record=bundle_record_name(job),
        unbundled_reason=job.unbundled_reason,
        results_dir=results_dir(job),
        args=analysis_args(job),
        command=shell_command(job),
    )


def _read_manifest(directory: Path) -> ExportManifest | None:
    try:
        return ExportManifest.load_json(read_regular(directory / JOBS_FILE, MAX_MANIFEST_BYTES))
    except OSError, ValueError:  # missing, unsafe, or not a manifest
        return None


def _write_file(path: Path, data: bytes, max_bytes: int) -> None:
    with contextlib.suppress(OSError, ValueError):
        if read_regular(path, max_bytes) == data:
            return  # already exported
    atomic_write(path, data)


def _write_tarball(
    directory: Path, job: SandboxJob, tarball: bytes, record: bytes | None = None
) -> None:
    if sha256_hex(tarball) != job.tarball_sha256:
        raise ValueError("tarball bytes do not match the job's sha256")
    name = bundle_record_name(job)
    if (name is None) != (record is None):
        raise ValueError("a bundled job is exported with its record, and only a bundled job")
    if name is not None and record is not None:  # the record first: the tarball marks a job
        _write_file(directory / name, record, MAX_BUNDLE_RECORD_BYTES)
    _write_file(directory / tarball_name(job), tarball, MAX_EXPORT_BYTES)


def exported_file(data: DataDir, run_id: str, job: SandboxJob) -> bool:
    """The job's tarball is in the run's export as a regular file (not re-hashed: it is the
    pipeline's own file, written atomically)."""
    try:
        path = export_dir(data, run_id) / tarball_name(job)
        return stat.S_ISREG(path.lstat().st_mode)
    except OSError, ValueError:
        return False


def read_bundle_record(data: DataDir, run_id: str, job: SandboxJob) -> bytes | None:
    """A bundled job's `<key>.bundle.json` from the run's export, or None."""
    name = bundle_record_name(job)
    if name is None:
        return None
    try:
        return read_regular(export_dir(data, run_id) / name, MAX_BUNDLE_RECORD_BYTES)
    except OSError, ValueError:
        return None


def export_jobs(
    data: DataDir,
    run_id: str,
    jobs: Sequence[tuple[SandboxJob, bytes]],
    records: Mapping[str, bytes] | None = None,
) -> frozenset[str]:
    """Write each job's tarball (and, for a bundle, its record from `records`, by key) and add
    it to the run's `jobs.json` (jobs already listed stay listed), then the README. Returns the
    keys now exported. A tarball that can't be written is left out; if the manifest can't be
    written, nothing counts as exported. The caller holds `DataDir.lock()`."""
    if not jobs:
        return frozenset()
    directory = export_dir(data, run_id)
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError:
        return frozenset()
    written: dict[str, SandboxJob] = {}
    for job, tarball in jobs:
        if job.key in written:
            continue
        try:
            _write_tarball(directory, job, tarball, (records or {}).get(job.key))
        except OSError:
            continue
        written[job.key] = job
    previous = _read_manifest(directory)
    listed = {e.key: e for e in previous.jobs} if previous is not None else {}
    for key, job in written.items():
        listed[key] = _entry(job)
    manifest = ExportManifest(run_id=run_id, jobs=tuple(listed[k] for k in sorted(listed)))
    try:
        atomic_write(directory / README_FILE, README.encode())
        atomic_write(directory / JOBS_FILE, manifest.model_dump_json(indent=2).encode() + b"\n")
    except OSError:
        return frozenset()
    return frozenset(written)


def exported_jobs(data: DataDir, run_id: str) -> tuple[SandboxJob, ...]:
    """The jobs a run's export lists, in key order; `()` without a readable manifest. An
    entry whose key doesn't match its tarball hash and analyser is ignored."""
    try:
        directory = export_dir(data, run_id)
    except ValueError:
        return ()
    manifest = _read_manifest(directory)
    if manifest is None or manifest.run_id != run_id:
        return ()
    jobs = []
    for entry in manifest.jobs:
        job = entry.job()  # every field was validated with the manifest
        if KEY_PATTERN.fullmatch(job.key) and key_of(job) == job.key:
            jobs.append(job)
    return tuple(jobs)
