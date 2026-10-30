"""Stage 5 export for package-analysis: cache key, tarball lookup and verification, the export
directory (tarballs, `jobs.json`, README) and the safe-read helpers."""

from __future__ import annotations

import json
import os
import shlex
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest

from conftest import TarEntry, make_tar_gz, sri_sha512
from kitsunox.core.models import ArtifactRef, PackageVersionRef, PublishInfo, VersionSnapshot
from kitsunox.core.run import DataDir
from kitsunox.sandbox import spool as spool_module
from kitsunox.sandbox.models import (
    ANALYSER,
    ANALYSER_DOCS,
    UPSTREAM_SOURCE,
    JobBundle,
    SandboxJob,
)
from kitsunox.sandbox.spool import (
    JOBS_FILE,
    MAX_TARBALL_BYTES,
    README_FILE,
    ExportManifest,
    OversizeFileError,
    TarballIndex,
    UnsafeFileError,
    analysis_args,
    build_job,
    bundle_record_name,
    export_dir,
    export_jobs,
    exported_file,
    exported_jobs,
    job_key,
    key_of,
    load_tarball,
    open_dir,
    read_bundle_record,
    read_regular,
    shell_command,
)
from kitsunox.util.files import atomic_write
from kitsunox.util.hashing import sha256_hex
from kitsunox.util.http import BlobStore, Snapshot, SnapshotEntry, request_key

URL = "https://registry.npmjs.org/kx/-/kx-1.0.0.tgz"
TARBALL = make_tar_gz([TarEntry("package/package.json", b'{"name":"kx"}')])
RUN_ID = "20261029T000000Z-npm"


def snapshot(
    tarball: bytes = TARBALL,
    *,
    url: str = URL,
    integrity: str | None = None,
    name: str = "kx",
    version: str = "1.0.0",
) -> VersionSnapshot:
    return VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name=name, version=version),
        publish=PublishInfo(),
        manifest={"scripts": {"postinstall": "node x.js"}},
        artifact=ArtifactRef(url=url, integrity=integrity or sri_sha512(tarball)),
    )


def job(tarball: bytes = TARBALL, **ref: str) -> SandboxJob:
    return build_job(snapshot(tarball, **ref), sha256_hex(tarball), ("postinstall",))


def entry(data: bytes, *, status: int = 200, size: int | None = None) -> SnapshotEntry:
    return SnapshotEntry(
        url=URL,
        status=status,
        content_type="application/octet-stream",
        sha256=sha256_hex(data),
        size=len(data) if size is None else size,
        fetched_at=datetime(2026, 10, 29, tzinfo=UTC),
    )


@pytest.fixture
def data(tmp_path: Path) -> DataDir:
    return DataDir(tmp_path / "data")


# --- the key --------------------------------------------------------------------------------------


def test_job_key_is_sha256_of_tarball_analyser_and_name() -> None:
    sha = "1" * 64
    assert ANALYSER == "ossf/package-analysis rel-38 dynamic airgapped"
    assert job_key(sha, "kx") == sha256_hex(f"{sha}\n{ANALYSER}\nkx".encode())
    assert job_key(sha, "kx", "other analyser") != job_key(sha, "kx")
    offline = "ossf/package-analysis rel-38 dynamic offline"  # the round-3 jobs'
    assert job_key(sha, "kx", offline) != job_key(sha, "kx")
    assert job_key(sha, "ky") != job_key(sha, "kx")
    assert job_key("2" * 64, "kx") != job_key(sha, "kx")


def test_build_job_fills_the_key_integrity_and_analyser() -> None:
    built = job()
    assert built.ref.name == "kx"
    assert built.tarball_sha256 == sha256_hex(TARBALL)
    assert built.integrity == sri_sha512(TARBALL)
    assert built.hooks == ("postinstall",)
    assert (built.network, built.analyser, built.bundle) == ("airgapped", ANALYSER, None)
    assert (built.install_name, built.package) == (None, "kx")
    assert built.key == key_of(built) == job_key(sha256_hex(TARBALL), "kx")
    assert built.schema_version == 5 and built.unbundled_reason is None
    assert SandboxJob.load_json(built.model_dump_json()) == built


def test_there_is_no_online_mode() -> None:
    """The analysis VM is airgapped (the owner's decision): a job is never anything else."""
    with pytest.raises(TypeError):
        build_job(snapshot(), sha256_hex(TARBALL), (), network="online")  # type: ignore[call-arg]
    for network in ("online", "offline"):
        with pytest.raises(ValueError, match="network"):
            SandboxJob.model_validate(job().model_dump() | {"network": network})


def bundle_summary(**changes: object) -> JobBundle:
    fields: dict[str, object] = {
        "format": "kitsunox-npm-bundle/1",
        "tar_sha256": "a" * 64,
        "dependencies_sha256": "b" * 64,
        "original_sha256": sha256_hex(TARBALL),
        "assumes": {"npm": "11.12.1", "node": "24.15.0"},
        "added": 1,
        "dependencies": ("dep",),
        "top_level": ("dep",),
        "package_json_changes": ("bundleDependencies",),
    }
    return JobBundle.model_validate(fields | changes)


def test_a_bundled_job_is_keyed_by_its_tar_and_dependency_set_not_the_tgz() -> None:
    """gzip output can differ between zlib builds, so a bundle's key is over its
    uncompressed tar, its format and its dependency set; an unbundled job keeps its key."""
    bundle = bundle_summary()
    built = build_job(snapshot(), "c" * 64, ("postinstall",), bundle=bundle)
    assert built.bundle == bundle and built.key == key_of(built) != job().key
    assert SandboxJob.load_json(built.model_dump_json()) == built
    regzipped = build_job(snapshot(), "d" * 64, ("postinstall",), bundle=bundle)
    assert regzipped.key == built.key  # another .tgz of the same tar
    for change in ({"tar_sha256": "e" * 64}, {"dependencies_sha256": "f" * 64}):
        other = build_job(snapshot(), "c" * 64, ("postinstall",), bundle=bundle_summary(**change))
        assert other.key != built.key
    assert bundle_record_name(built) == f"{built.key}.bundle.json"
    assert bundle_record_name(job()) is None


def test_an_unbundled_reason_is_recorded_but_does_not_change_the_key() -> None:
    reason = "incomplete: unresolved-required"
    built = build_job(snapshot(), sha256_hex(TARBALL), ("postinstall",), unbundled_reason=reason)
    assert built.unbundled_reason == reason and built.key == job().key
    with pytest.raises(ValueError, match="unbundled"):
        build_job(snapshot(), "c" * 64, (), bundle=bundle_summary(), unbundled_reason=reason)


def test_a_bundle_is_exported_with_its_record(data: DataDir) -> None:
    bundled = build_job(snapshot(), sha256_hex(TARBALL), ("postinstall",), bundle=bundle_summary())
    record = b'{"format": "kitsunox-npm-bundle/1"}\n'
    with pytest.raises(ValueError, match="record"):
        export_jobs(data, RUN_ID, [(bundled, TARBALL)])
    with pytest.raises(ValueError, match="record"):
        export_jobs(data, RUN_ID, [(job(), TARBALL)], {job().key: record})
    assert export_jobs(data, RUN_ID, [(bundled, TARBALL)], {bundled.key: record}) == {bundled.key}
    directory = export_dir(data, RUN_ID)
    assert (directory / f"{bundled.key}.bundle.json").read_bytes() == record
    assert read_bundle_record(data, RUN_ID, bundled) == record
    assert read_bundle_record(data, RUN_ID, job()) is None
    assert exported_file(data, RUN_ID, bundled) and not exported_file(data, RUN_ID, job())
    (item,) = ExportManifest.load_json((directory / JOBS_FILE).read_bytes()).jobs
    assert item.bundle == bundled.bundle and item.bundle_record == f"{bundled.key}.bundle.json"
    assert item.unbundled_reason is None
    assert exported_jobs(data, RUN_ID) == (bundled,)
    readme = (directory / README_FILE).read_text()
    assert "bundle_record" in readme and "unbundled_reason" in readme


def test_the_tarballs_own_name_is_recorded_only_when_it_differs() -> None:
    same = build_job(snapshot(), sha256_hex(TARBALL), (), install_name="kx")
    assert same.install_name is None and same.key == job().key
    confused = build_job(snapshot(), sha256_hex(TARBALL), (), install_name="helper")
    assert (confused.install_name, confused.package) == ("helper", "helper")
    assert confused.key == key_of(confused) != job().key


def test_versions_with_the_same_tarball_share_a_key() -> None:
    assert job(version="1.0.0").key == job(version="1.0.1").key


# --- safe reads -----------------------------------------------------------------------------------


def test_read_regular_refuses_symlinks_fifos_and_oversize(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.write_bytes(b"12345")
    assert read_regular(plain, 5) == b"12345"
    with pytest.raises(OversizeFileError, match="over"):
        read_regular(plain, 4)
    link = tmp_path / "link"
    link.symlink_to(plain)
    with pytest.raises(UnsafeFileError, match="symlink"):
        read_regular(link, 100)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(UnsafeFileError, match="not a regular file"):
        read_regular(fifo, 100)
    with pytest.raises(UnsafeFileError, match="not a regular file"):
        read_regular(tmp_path, 100)
    with pytest.raises(FileNotFoundError):
        read_regular(tmp_path / "absent", 100)


def test_read_regular_catches_a_file_that_grows_after_fstat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plain = tmp_path / "plain"
    plain.write_bytes(b"123456")
    real_fstat = os.fstat

    def shrunk(fd: int) -> os.stat_result:
        info = real_fstat(fd)
        fields = list(info)
        fields[stat.ST_SIZE] = 1
        return os.stat_result(fields)

    with monkeypatch.context() as patched, pytest.raises(UnsafeFileError, match="over"):
        patched.setattr(os, "fstat", shrunk)
        read_regular(plain, 4)


def test_open_dir_refuses_symlinked_components(tmp_path: Path) -> None:
    (tmp_path / "real" / "inner").mkdir(parents=True)
    (tmp_path / "link").symlink_to(tmp_path / "real")
    with open_dir(tmp_path, "real", "inner") as fd:
        assert stat.S_ISDIR(os.fstat(fd).st_mode)
    with pytest.raises(UnsafeFileError), open_dir(tmp_path, "link", "inner"):
        pass
    (tmp_path / "file").write_text("x")
    with pytest.raises(UnsafeFileError), open_dir(tmp_path, "file"):
        pass
    with pytest.raises(FileNotFoundError), open_dir(tmp_path, "absent"):
        pass


def test_open_dir_passes_on_other_errors(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root ignores directory permissions")
    locked = tmp_path / "locked"
    (locked / "inner").mkdir(parents=True)
    locked.chmod(0)
    try:
        with pytest.raises(PermissionError), open_dir(tmp_path, "locked", "inner"):
            pass
    finally:
        locked.chmod(0o755)


# --- finding and verifying the tarball ------------------------------------------------------------


def test_tarball_index_reads_the_runs_stage_snapshots(tmp_path: Path) -> None:
    Snapshot(entries={request_key(URL, None): entry(TARBALL)}).save(
        tmp_path / "static-snapshot.json"
    )
    index = TarballIndex.for_run(tmp_path)
    assert index.find(snapshot()) == entry(TARBALL)
    assert index.find(snapshot(url=URL + "?other")) is None
    no_artifact = snapshot().model_copy(update={"artifact": None})
    assert index.find(no_artifact) is None
    assert TarballIndex.for_run(tmp_path / "empty").find(snapshot()) is None


def test_tarball_index_ignores_failed_responses() -> None:
    index = TarballIndex({request_key(URL, None): entry(b"gone", status=404)})
    assert index.find(snapshot()) is None


def test_load_tarball_verifies_and_reports_problems(tmp_path: Path) -> None:
    blobs = BlobStore(tmp_path / "blobs")
    assert load_tarball(blobs, entry(TARBALL), snapshot()) == "missing"
    blobs.put(TARBALL)
    assert load_tarball(blobs, entry(TARBALL), snapshot()) == TARBALL
    big = entry(TARBALL, size=MAX_TARBALL_BYTES + 1)
    assert load_tarball(blobs, big, snapshot()) == "oversize"
    wrong = snapshot(integrity=sri_sha512(b"other bytes"))
    assert load_tarball(blobs, entry(TARBALL), wrong) == "integrity"
    no_digest = snapshot().model_copy(update={"artifact": ArtifactRef(url=URL)})
    assert load_tarball(blobs, entry(TARBALL), no_digest) == "integrity"
    no_artifact = snapshot().model_copy(update={"artifact": None})
    assert load_tarball(blobs, entry(TARBALL), no_artifact) == "integrity"


def test_load_tarball_corrupt_blob_is_an_integrity_problem(tmp_path: Path) -> None:
    blobs = BlobStore(tmp_path / "blobs")
    sha = blobs.put(TARBALL)
    path = blobs.root / sha[:2] / f"{sha}.zst"
    path.write_bytes(b"not zstd")
    assert load_tarball(blobs, entry(TARBALL), snapshot()) == "integrity"


def test_load_tarball_a_blob_bigger_than_recorded_is_oversize(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    blobs = BlobStore(tmp_path / "blobs")
    blobs.put(TARBALL)
    monkeypatch.setattr(spool_module, "MAX_TARBALL_BYTES", len(TARBALL) - 1)
    assert load_tarball(blobs, entry(TARBALL, size=1), snapshot()) == "oversize"


# --- the export -----------------------------------------------------------------------------------


def test_export_writes_tarballs_manifest_and_readme(data: DataDir) -> None:
    exported = export_jobs(data, RUN_ID, [(job(), TARBALL)])
    built = job()
    assert exported == {built.key}
    directory = export_dir(data, RUN_ID)
    assert directory == data.root / "sandbox" / "export" / RUN_ID
    assert (directory / f"{built.key}.tgz").read_bytes() == TARBALL
    readme = (directory / README_FILE).read_text()
    assert ANALYSER_DOCS in readme and "argv list" in readme
    assert "-fully-offline" in readme and "-nopull" in readme and "-offline" in readme
    assert "airgapped" in readme and "docker save" in readme and "podman load" in readme
    assert f"{UPSTREAM_SOURCE}/sandboxes/README.md" in readme
    assert 'RESULTS_DIR="$PWD/results/<key>"' in readme
    manifest = ExportManifest.load_json((directory / JOBS_FILE).read_bytes())
    assert (manifest.run_id, manifest.release) == (RUN_ID, "rel-38")
    (item,) = manifest.jobs
    assert (item.ecosystem, item.name, item.version) == ("npm", "kx", "1.0.0")
    assert (item.file, item.key) == (f"{built.key}.tgz", built.key)
    assert (item.sha256, item.hooks) == (sha256_hex(TARBALL), ("postinstall",))
    assert (item.network, item.analyser, item.bundle) == ("airgapped", ANALYSER, None)
    assert manifest.schema_version == 4
    assert (item.bundle_record, item.unbundled_reason) == (None, None)
    assert item.results_dir == f"results/{built.key}"
    assert item.args == analysis_args(built)
    assert item.args[item.args.index("-package") + 1] == "kx"
    assert item.args[item.args.index("-version") + 1] == "1.0.0"
    assert item.args[item.args.index("-local") + 1] == f"{built.key}.tgz"
    assert item.args[item.args.index("-image-tag") + 1] == "rel-38"
    assert item.args[-2:] == ("-nopull", "-offline")
    assert item.command == shell_command(built)
    assert item.job() == built
    assert exported_jobs(data, RUN_ID) == (built,)


def test_no_path_in_the_manifest_names_the_kitsunox_host(data: DataDir) -> None:
    """Round-3 review: absolute host paths made the export useless on a separate VM."""
    export_jobs(data, RUN_ID, [(job(), TARBALL)])
    text = (export_dir(data, RUN_ID) / JOBS_FILE).read_text()
    assert str(data.root) not in text
    readme = (export_dir(data, RUN_ID) / README_FILE).read_text()
    assert str(data.root) not in readme


def test_the_shell_command_runs_from_the_export_directory() -> None:
    built = job()
    command = shell_command(built)
    assert command is not None
    words = shlex.split(command)
    assert words[0] == f"RESULTS_DIR=$PWD/results/{built.key}"
    assert words[1] == "$PACKAGE_ANALYSIS/scripts/run_analysis.sh"
    assert tuple(words[2:]) == analysis_args(built)


def test_untrusted_names_are_quoted_and_control_characters_drop_the_command() -> None:
    odd = job(name="x'; rm -rf ~ #$(id)")
    command = shell_command(odd)
    assert command is not None
    assert shlex.split(command)[2:] == list(analysis_args(odd))
    assert shell_command(job(name="a\nb")) is None
    assert shell_command(job(version="1.0.0\x1b[2J")) is None


def test_every_job_runs_airgapped_with_the_flags_where_run_analysis_reads_them() -> None:
    """`scripts/run_analysis.sh` (rel-38) strips its own -fully-offline and -nointeractive
    wherever they are and passes everything else to `analyze`, whose Go flags include -nopull
    and -offline. Its usage line puts its own flags first, and so does the export."""
    built = job()
    assert analysis_args(built) == (
        "-fully-offline",
        "-nointeractive",
        "-ecosystem",
        "npm",
        "-package",
        "kx",
        "-version",
        "1.0.0",
        "-local",
        f"{built.key}.tgz",
        "-mode",
        "dynamic",
        "-image-tag",
        "rel-38",
        "-nopull",
        "-offline",
    )


def test_the_tarballs_name_is_the_package() -> None:
    confused = build_job(snapshot(), sha256_hex(TARBALL), (), install_name="helper")
    args = analysis_args(confused)
    assert args[args.index("-package") + 1] == "helper"


def test_export_keeps_earlier_jobs_and_is_idempotent(data: DataDir) -> None:
    other = make_tar_gz([TarEntry("package/package.json", b'{"name":"ky"}')])
    first = job()
    second = job(other, name="ky")
    export_jobs(data, RUN_ID, [(first, TARBALL)])
    path = export_dir(data, RUN_ID) / f"{first.key}.tgz"
    before = path.stat().st_mtime_ns
    assert export_jobs(data, RUN_ID, [(second, other), (first, TARBALL)]) == {
        first.key,
        second.key,
    }
    assert path.stat().st_mtime_ns == before  # same bytes: not rewritten
    assert exported_jobs(data, RUN_ID) == tuple(sorted((first, second), key=lambda j: j.key))


def test_export_replaces_a_damaged_tarball(data: DataDir) -> None:
    built = job()
    export_jobs(data, RUN_ID, [(built, TARBALL)])
    path = export_dir(data, RUN_ID) / f"{built.key}.tgz"
    path.write_bytes(b"damaged")
    export_jobs(data, RUN_ID, [(built, TARBALL)])
    assert path.read_bytes() == TARBALL


def test_export_of_nothing_writes_nothing(data: DataDir) -> None:
    assert export_jobs(data, RUN_ID, []) == frozenset()
    assert not (data.root / "sandbox").exists()


def test_export_refuses_bytes_that_are_not_the_jobs(data: DataDir) -> None:
    with pytest.raises(ValueError, match="sha256"):
        export_jobs(data, RUN_ID, [(job(), b"other bytes")])


def test_export_failures_count_as_not_exported(
    data: DataDir, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = atomic_write

    def failing(path: Path, content: bytes) -> None:
        if path.name.endswith(".tgz"):
            raise OSError("disk full")
        real(path, content)

    monkeypatch.setattr("kitsunox.sandbox.spool.atomic_write", failing)
    assert export_jobs(data, RUN_ID, [(job(), TARBALL)]) == frozenset()
    assert exported_jobs(data, RUN_ID) == ()

    def no_manifest(path: Path, content: bytes) -> None:
        if path.name == JOBS_FILE:
            raise OSError("disk full")
        real(path, content)

    monkeypatch.setattr("kitsunox.sandbox.spool.atomic_write", no_manifest)
    assert export_jobs(data, RUN_ID, [(job(), TARBALL)]) == frozenset()


def test_export_directory_that_cannot_be_made(data: DataDir) -> None:
    data.root.mkdir(parents=True)
    (data.root / "sandbox").write_text("a file where the directory goes")
    assert export_jobs(data, RUN_ID, [(job(), TARBALL)]) == frozenset()


def test_export_dir_refuses_odd_run_ids(data: DataDir) -> None:
    for run_id in ("../x", "", ".hidden", "a/b"):
        with pytest.raises(ValueError, match="run id"):
            export_dir(data, run_id)
    assert exported_jobs(data, "../x") == ()


def test_exported_jobs_ignores_damaged_manifests(data: DataDir) -> None:
    assert exported_jobs(data, RUN_ID) == ()
    export_jobs(data, RUN_ID, [(job(), TARBALL)])
    path = export_dir(data, RUN_ID) / JOBS_FILE
    raw = json.loads(path.read_text())
    forged = dict(raw["jobs"][0], key="f" * 64)
    unbuildable = dict(raw["jobs"][0], hooks="not a list")
    raw["jobs"] = [*raw["jobs"], forged]
    path.write_text(json.dumps(raw))
    assert exported_jobs(data, RUN_ID) == (job(),)  # the forged key is ignored
    raw["jobs"] = [unbuildable]
    path.write_text(json.dumps(raw))
    assert exported_jobs(data, RUN_ID) == ()
    raw["run_id"] = "another-run"
    path.write_text(json.dumps(raw))
    assert exported_jobs(data, RUN_ID) == ()
    path.write_text("not json")
    assert exported_jobs(data, RUN_ID) == ()
    path.unlink()
    path.symlink_to(data.root)
    assert exported_jobs(data, RUN_ID) == ()
