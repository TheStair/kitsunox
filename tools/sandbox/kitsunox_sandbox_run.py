#!/usr/bin/python3 -I
"""Kitsunox Stage 5 local runner: OpenSSF package-analysis jobs, in Docker, on this machine.

Installed by `tools/sandbox/setup.sh` as `/usr/local/sbin/kitsunox-sandbox-run` (a root-owned
copy: root never runs a file the pipeline's user can edit) and started by the root systemd timer
`kitsunox-sandbox.timer`. Each run reads the jobs Kitsunox exported (`data/sandbox/export/
<run_id>/jobs.json`), and for each job with no result yet:

1. checks the job against the shape Kitsunox writes (`check_job`): a 64-hex key, `<key>.tgz`,
   the airgapped analyser, and exactly the argument list `spool.analysis_args` builds, so a
   tampered `jobs.json` can't add a flag, mount or network;
2. copies the tarball into a root-only work directory, after checking it is a regular file of
   at most 128 MiB whose sha256 is the job's (`stage_tarball`);
3. runs package-analysis's analysis image, pinned by digest, the way `scripts/run_analysis.sh`
   does, but with every directory per job, the tarball read-only, no network for the outer
   container (`--network none`, the script's `-fully-offline`) or the sandbox (`-offline`), the
   pinned sandbox image only (`-nopull`), memory, CPU and process limits and a timeout
   (`docker_command`);
4. moves the job's results directory into the results root as `<key>/` in one rename, owned by
   the Kitsunox user, after a size check. Kitsunox imports it on its next tick, as hostile data.

The package runs inside gVisor (runsc, systrap platform: no /dev/kvm needed) in the sandbox
container. The analysis container itself is `--privileged` (package-analysis needs it to run
podman and gVisor), so gVisor is the boundary that matters; see docs/decisions/0014 (addendum
2026-11-01) for the risks and what else limits them.

Usage: kitsunox-sandbox-run [--config PATH] [--smoke [--keep DIR]] [--max-jobs N]
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

CONFIG_PATH: Final = Path("/etc/kitsunox-sandbox.json")
LOCK_PATH: Final = Path("/run/kitsunox-sandbox.lock")
RELEASE: Final = "rel-38"
ANALYSER: Final = f"ossf/package-analysis {RELEASE} dynamic airgapped"
ANALYSIS_IMAGE: Final = "gcr.io/ossf-malware-analysis/analysis"
SANDBOX_IMAGE: Final = f"gcr.io/ossf-malware-analysis/dynamic-analysis:{RELEASE}"
KEY: Final = re.compile(r"[0-9a-f]{64}")
DIGEST: Final = re.compile(r"sha256:[0-9a-f]{64}")
RUN_ID: Final = re.compile(r"[0-9A-Za-z][0-9A-Za-z._-]{0,127}")
CONTROL: Final = re.compile(r"[\x00-\x1f\x7f]")
MAX_MANIFEST_BYTES: Final = 16 * 2**20
MAX_TARBALL_BYTES: Final = 128 * 2**20
MAX_RESULT_BYTES: Final = 256 * 2**20  # a job's whole results directory
MAX_ATTEMPTS: Final = 2  # an infrastructure failure is retried once, on a later run
# The directories run_analysis.sh mounts, each per job here (its defaults share /tmp/... dirs).
JOB_DIRS: Final = {
    "results": "/results",
    "static": "/staticResults",
    "writes": "/writeResults",
    "logs": "/tmp",  # noqa: S108 - a path inside the container, backed by a per-job directory
    "analyzed": "/analyzedPackages",
    "strace": "/straceLogs",
}
# rel-38 starts its packet capture on podman's `cni-analysis` bridge even with `-offline`, where
# the sandbox joins no network and the bridge never exists: the run fails before the package is
# installed ("couldn't query interface cni-analysis"). An empty dummy interface of that name in
# the analysis container's own network namespace lets the capture start; it sees no packets
# (the sandbox has `--network=none`). The script is fixed text: the job's values reach
# `analyze` as "$@", never as shell words.
PCAP_SHIM: Final = 'ip link add cni-analysis type dummy && ip link set cni-analysis up && exec "$@"'
BUCKETS: Final = (
    "-dynamic-bucket",
    "file:///results/",
    "-file-writes-bucket",
    "file:///writeResults/",
    "-static-bucket",
    "file:///staticResults/",
    "-analyzed-pkg-bucket",
    "file:///analyzedPackages/",
    "-execution-log-bucket",
    "file:///results",
)


class JobError(ValueError):
    """A job that doesn't have the shape Kitsunox writes: skipped, never run."""


@dataclass(frozen=True)
class Config:
    export_dir: Path  # Kitsunox's data/sandbox/export
    results_dir: Path  # the results root (KITSUNOX_SANDBOX_RESULTS)
    work_dir: Path  # root-only: per-job directories while a job runs, and state.json
    store_dir: Path  # root-only: the podman store holding the pinned sandbox image
    owner_uid: int  # the Kitsunox user, who owns the results root
    owner_gid: int
    analysis_digest: str
    sandbox_image_id: str  # what `podman image inspect` reported at setup
    memory: str = "6g"
    cpus: str = "2"
    pids: int = 4096
    timeout_s: int = 1200

    @classmethod
    def load(cls, path: Path) -> Config:
        raw = json.loads(path.read_text())
        config = cls(
            export_dir=Path(raw["export_dir"]),
            results_dir=Path(raw["results_dir"]),
            work_dir=Path(raw["work_dir"]),
            store_dir=Path(raw["store_dir"]),
            owner_uid=int(raw["owner_uid"]),
            owner_gid=int(raw["owner_gid"]),
            analysis_digest=str(raw["analysis_digest"]),
            sandbox_image_id=str(raw["sandbox_image_id"]),
            memory=str(raw.get("memory", "6g")),
            cpus=str(raw.get("cpus", "2")),
            pids=int(raw.get("pids", 4096)),
            timeout_s=int(raw.get("timeout_s", 1200)),
        )
        if not DIGEST.fullmatch(config.analysis_digest):
            raise ValueError("analysis_digest is not a sha256 digest")
        return config


@dataclass(frozen=True)
class Job:
    key: str
    package: str  # -package: the name npm installs the tarball under (untrusted text)
    version: str  # -version (untrusted text)
    sha256: str
    tarball: Path  # in the export directory


def check_job(entry: Mapping[str, Any], export: Path) -> Job:
    """The job if it has exactly the shape `spool.analysis_args` writes; JobError otherwise.
    Package text is only ever passed as a single argv element, never through a shell."""
    key = entry.get("key")
    if not isinstance(key, str) or not KEY.fullmatch(key):
        raise JobError("key is not 64 hex digits")
    if entry.get("file") != f"{key}.tgz" or entry.get("results_dir") != f"results/{key}":
        raise JobError("file or results_dir doesn't match the key")
    if entry.get("analyser") != ANALYSER or entry.get("network") != "airgapped":
        raise JobError("not an airgapped job for this analyser")
    if entry.get("ecosystem") != "npm":
        raise JobError("not an npm job")
    sha = entry.get("sha256")
    if not isinstance(sha, str) or not KEY.fullmatch(sha):
        raise JobError("sha256 is not 64 hex digits")
    args = entry.get("args")
    if not isinstance(args, list) or len(args) != 16 or not all(isinstance(a, str) for a in args):
        raise JobError("args is not the 16-element list Kitsunox writes")
    fixed = {
        0: "-fully-offline",
        1: "-nointeractive",
        2: "-ecosystem",
        3: "npm",
        4: "-package",
        6: "-version",
        8: "-local",
        9: f"{key}.tgz",
        10: "-mode",
        11: "dynamic",
        12: "-image-tag",
        13: RELEASE,
        14: "-nopull",
        15: "-offline",
    }
    for i, want in fixed.items():
        if args[i] != want:
            raise JobError(f"args[{i}] is not {want!r}")
    package, version = args[5], args[7]
    for value in (package, version):
        if not value or len(value) > 214 or CONTROL.search(value) or value.startswith("-"):
            raise JobError("package or version is empty, too long or has control characters")
    return Job(key=key, package=package, version=version, sha256=sha, tarball=export / f"{key}.tgz")


def docker_command(config: Config, job: Job, work: Path) -> list[str]:
    """`docker run` for one job: run_analysis.sh's command (`--cgroupns=host --privileged
    --rm`, its mounts and `analyze` arguments) with `-fully-offline`'s `--network none`,
    per-job directories, the tarball read-only, limits, the image pinned by digest, and
    `analyze` started through PCAP_SHIM."""
    mounts = [f"{config.store_dir}:/var/lib/containers"]
    mounts += [f"{work / name}:{target}" for name, target in JOB_DIRS.items()]
    mounts.append(f"{work / 'input' / (job.key + '.tgz')}:/{job.key}.tgz:ro")
    command = [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name(job.key),
        "--cgroupns=host",
        "--privileged",
        "--network",
        "none",
        "--memory",
        config.memory,
        "--memory-swap",
        config.memory,
        "--cpus",
        config.cpus,
        "--cpu-shares",
        "256",  # a quarter of the default: Kitsunox's hourly tick goes first
        "--pids-limit",
        str(config.pids),
    ]
    for mount in mounts:
        command += ["-v", mount]
    command += [
        f"{ANALYSIS_IMAGE}@{config.analysis_digest}",
        "/bin/sh",
        "-c",
        PCAP_SHIM,
        "kitsunox-sandbox",  # $0
        "analyze",
        *BUCKETS,
        "-ecosystem",
        "npm",
        "-package",
        job.package,
        "-version",
        job.version,
        "-local",
        f"/{job.key}.tgz",
        "-mode",
        "dynamic",
        "-image-tag",
        RELEASE,
        "-nopull",
        "-offline",
    ]
    return command


def container_name(key: str) -> str:
    return f"kitsunox-sandbox-{key[:16]}"


def stage_tarball(job: Job, work: Path) -> None:
    """Copy the job's tarball into the work directory if it is a regular file (not a link) of
    at most MAX_TARBALL_BYTES whose sha256 is the job's. The container mounts the copy, so the
    file Kitsunox's user can change is never what runs."""
    fd = os.open(job.tarball, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_TARBALL_BYTES:
            raise JobError("tarball is not a regular file of at most 128 MiB")
        data = handle.read(MAX_TARBALL_BYTES + 1)
    if hashlib.sha256(data).hexdigest() != job.sha256:
        raise JobError("tarball sha256 doesn't match the job")
    target = work / "input" / f"{job.key}.tgz"
    target.write_bytes(data)
    target.chmod(0o444)


def exported_jobs(config: Config) -> Iterator[tuple[str, Job | JobError]]:
    """(run id, job or why it was refused) for every job of every export, oldest run first."""
    if not config.export_dir.is_dir():
        return
    for run_dir in sorted(config.export_dir.iterdir()):
        if not RUN_ID.fullmatch(run_dir.name) or not run_dir.is_dir() or run_dir.is_symlink():
            continue
        manifest = run_dir / "jobs.json"
        try:
            fd = os.open(manifest, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            with os.fdopen(fd, "rb") as handle:
                raw = handle.read(MAX_MANIFEST_BYTES + 1)
            if len(raw) > MAX_MANIFEST_BYTES:
                raise ValueError("jobs.json too large")
            jobs = json.loads(raw)["jobs"]
            if not isinstance(jobs, list):
                raise ValueError("jobs is not a list")
        except (OSError, ValueError, KeyError, TypeError) as error:
            yield run_dir.name, JobError(f"unreadable jobs.json: {type(error).__name__}")
            continue
        for entry in jobs:
            try:
                if not isinstance(entry, dict):
                    raise JobError("job is not an object")
                yield run_dir.name, check_job(entry, run_dir)
            except JobError as error:
                yield run_dir.name, error


def results_size(path: Path) -> int:
    total = 0
    for root, _, files in os.walk(path):
        for name in files:
            with contextlib.suppress(OSError):
                total += os.lstat(os.path.join(root, name)).st_size
    return total


def chown_tree(path: Path, uid: int, gid: int) -> None:
    for root, dirs, files in os.walk(path):
        for name in [*dirs, *files]:
            os.lchown(os.path.join(root, name), uid, gid)
    os.lchown(path, uid, gid)


def run_job(config: Config, job: Job, log: Any) -> str:
    """Run one job; returns its outcome word. Results go to the results root only after the
    container exited 0 and the directory passed the size check."""
    work = config.work_dir / job.key
    shutil.rmtree(work, ignore_errors=True)
    for name in [*JOB_DIRS, "input"]:
        (work / name).mkdir(parents=True, mode=0o700)
    try:
        stage_tarball(job, work)
        command = docker_command(config, job, work)
        started = time.monotonic()
        try:
            done = subprocess.run(  # noqa: S603 - fixed argv; package text as single elements
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=config.timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired:
            subprocess.run(  # noqa: S603
                ["docker", "rm", "-f", container_name(job.key)],  # noqa: S607
                capture_output=True,
                check=False,
            )
            return "timeout"
        elapsed = time.monotonic() - started
        if done.returncode != 0:
            tail = done.stderr.decode("utf-8", "replace").strip().splitlines()[-3:]
            print(f"  docker exited {done.returncode}: {' | '.join(tail)[:400]!r}", file=log)
            return "failed"
        results = work / "results"
        if not any(results.iterdir()):
            return "no result"
        if results_size(results) > MAX_RESULT_BYTES:
            return "result too large"
        chown_tree(results, config.owner_uid, config.owner_gid)
        os.rename(results, config.results_dir / job.key)  # one rename: never a partial result
        return f"done in {elapsed:.0f} s"
    finally:
        shutil.rmtree(work, ignore_errors=True)


def check_sandbox_image(config: Config) -> None:
    """The pinned sandbox image is still the one setup loaded: the store is shared by jobs, so
    a package that got out of gVisor into the analysis container could replace it."""
    done = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "docker",
            "run",
            "--rm",
            "--privileged",
            "--cgroupns=host",
            "--network",
            "none",
            "-v",
            f"{config.store_dir}:/var/lib/containers",
            f"{ANALYSIS_IMAGE}@{config.analysis_digest}",
            "podman",
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            SANDBOX_IMAGE,
        ],
        capture_output=True,
        check=False,
        timeout=300,
    )
    found = done.stdout.decode().strip()
    if done.returncode != 0 or found != config.sandbox_image_id:
        raise SystemExit(f"sandbox image changed or missing (got {found[:24]!r}); not running")


def load_state(path: Path) -> dict[str, int]:
    try:
        raw = json.loads(path.read_text())
        return {k: int(v) for k, v in raw.items() if KEY.fullmatch(k)}
    except OSError, ValueError, AttributeError:
        return {}


def save_state(path: Path, state: Mapping[str, int]) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(dict(sorted(state.items())), indent=1))
    os.replace(temporary, path)


def smoke_tarball() -> bytes:
    """An inert npm package whose postinstall prints a line: proves the whole chain works."""
    manifest = {
        "name": "kitsunox-sandbox-smoke",
        "version": "1.0.0",
        "scripts": {"postinstall": "node -e \"console.log('kitsunox smoke')\""},
    }
    files = {
        "package/package.json": json.dumps(manifest).encode(),
        "package/index.js": b"module.exports = 1;\n",
    }
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), 0o644, 0
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(raw.getvalue(), mtime=0)


def smoke(config: Config, keep: Path | None = None) -> int:
    """Run the inert package through the same command as a job; 0 if a result was written.
    With `keep`, the results directory is copied there (owned by the Kitsunox user) for the
    owner's review before any real sample runs (decision 0014's review gate)."""
    data = smoke_tarball()
    key = hashlib.sha256(b"kitsunox-sandbox-smoke:" + data).hexdigest()
    export = config.work_dir / "smoke-export"
    export.mkdir(parents=True, exist_ok=True, mode=0o700)
    (export / f"{key}.tgz").write_bytes(data)
    job = Job(
        key=key,
        package="kitsunox-sandbox-smoke",
        version="1.0.0",
        sha256=hashlib.sha256(data).hexdigest(),
        tarball=export / f"{key}.tgz",
    )
    work = config.work_dir / key
    shutil.rmtree(work, ignore_errors=True)
    for name in [*JOB_DIRS, "input"]:
        (work / name).mkdir(parents=True, mode=0o700)
    try:
        stage_tarball(job, work)
        done = subprocess.run(  # noqa: S603
            docker_command(config, job, work),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=config.timeout_s,
            check=False,
        )
        found = sorted(p.name for p in (work / "results").rglob("*.json"))
        print(f"smoke: docker exited {done.returncode}; result files: {found}")
        if keep is not None and found:
            shutil.rmtree(keep, ignore_errors=True)
            shutil.copytree(work / "results", keep)
            chown_tree(keep, config.owner_uid, config.owner_gid)
            print(f"smoke: result kept for review in {keep}")
        if done.returncode != 0 or not found:
            print(smoke_diagnosis(work, done.stdout, done.stderr))
        return 0 if done.returncode == 0 and found else 1
    finally:
        shutil.rmtree(work, ignore_errors=True)
        shutil.rmtree(export, ignore_errors=True)


def smoke_diagnosis(work: Path, stdout: bytes, stderr: bytes, lines: int = 60) -> str:
    """What a failed smoke run left: every file in its job directories (size and path) and the
    tail of the analyser's output. The smoke package is Kitsunox's own, so this is safe to show."""
    parts = ["smoke: files the job wrote:"]
    for path in sorted(work.rglob("*")):
        if path.is_file() and not path.is_symlink():
            parts.append(f"  {path.stat().st_size:>10}  {path.relative_to(work)}")
    for label, raw in (("stdout", stdout), ("stderr", stderr)):
        tail = raw.decode("utf-8", "replace").strip().splitlines()[-lines:]
        parts.append(f"smoke: analyser {label} (last {len(tail)} lines):")
        parts.extend(f"  {CONTROL.sub('?', line)[:400]}" for line in tail)
    return "\n".join(parts)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    parser.add_argument("--smoke", action="store_true", help="run the inert test package only")
    parser.add_argument("--keep", type=Path, help="with --smoke: copy its results here")
    parser.add_argument("--max-jobs", type=int, default=12, help="jobs per run (default 12)")
    options = parser.parse_args(argv)
    if os.geteuid() != 0:
        print("run as root (the systemd timer does)", file=sys.stderr)
        return 2
    config = Config.load(options.config)
    lock = os.open(LOCK_PATH, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("another run is in progress")
        return 0
    os.umask(0o077)
    check_sandbox_image(config)
    if options.smoke:
        return smoke(config, options.keep)
    state_path = config.work_dir / "state.json"
    attempts = load_state(state_path)
    ran = 0
    for run_id, item in exported_jobs(config):
        if isinstance(item, JobError):
            print(f"{run_id}: refused a job: {item}")
            continue
        job = item
        if (config.results_dir / job.key).exists() or attempts.get(job.key, 0) >= MAX_ATTEMPTS:
            continue
        if ran >= options.max_jobs:
            print(f"cap of {options.max_jobs} jobs reached; the rest wait for the next run")
            break
        ran += 1
        attempts[job.key] = attempts.get(job.key, 0) + 1
        save_state(state_path, attempts)
        try:
            outcome = run_job(config, job, sys.stdout)
        except (JobError, OSError) as error:
            outcome = f"refused: {error}"
            attempts[job.key] = MAX_ATTEMPTS  # a bad tarball doesn't get better
            save_state(state_path, attempts)
        print(f"{run_id} {job.key[:12]} {job.package!r}@{job.version!r}: {outcome}", flush=True)
    print(f"ran {ran} jobs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
