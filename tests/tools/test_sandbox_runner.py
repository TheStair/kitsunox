"""The local sandbox runner (tools/sandbox/kitsunox_sandbox_run.py): it only runs jobs that
have exactly the shape Kitsunox exports, and builds a fixed docker command around them."""

import functools
import gzip
import hashlib
import importlib.util
import io
import json
import sys
import tarfile
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from kitsunox.sandbox import spool
from kitsunox.sandbox.models import ANALYSER, ANALYSER_RELEASE

RUNNER = Path(__file__).parents[2] / "tools" / "sandbox" / "kitsunox_sandbox_run.py"
KEY = "ab" * 32


@functools.cache
def runner() -> ModuleType:
    """The runner is a script installed outside the package; load it from its file."""
    spec = importlib.util.spec_from_file_location("kitsunox_sandbox_run", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up here
    spec.loader.exec_module(module)
    return module


def job(**changes: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "ecosystem": "npm",
        "key": KEY,
        "file": f"{KEY}.tgz",
        "results_dir": f"results/{KEY}",
        "analyser": ANALYSER,
        "network": "airgapped",
        "sha256": "cd" * 32,
        "args": [
            *spool.SCRIPT_FLAGS,
            "-ecosystem",
            "npm",
            "-package",
            "evil pkg; rm -rf /",
            "-version",
            "1.0.0",
            "-local",
            f"{KEY}.tgz",
            "-mode",
            "dynamic",
            "-image-tag",
            ANALYSER_RELEASE,
            *spool.AIRGAP_FLAGS,
        ],
    }
    entry.update(changes)
    return entry


def test_the_runner_pins_what_kitsunox_exports() -> None:
    module = runner()
    assert module.ANALYSER == ANALYSER
    assert module.RELEASE == ANALYSER_RELEASE


def test_a_job_with_kitsunox_s_shape_is_accepted(tmp_path: Path) -> None:
    checked = runner().check_job(job(), tmp_path)
    assert (checked.key, checked.package, checked.version) == (KEY, "evil pkg; rm -rf /", "1.0.0")
    assert checked.tarball == tmp_path / f"{KEY}.tgz"


@pytest.mark.parametrize(
    "changes",
    [
        {"key": "../../etc"},
        {"file": "other.tgz"},
        {"results_dir": "elsewhere/x"},
        {"network": "online"},
        {"analyser": "something else"},
        {"args": [*job()["args"][:14], "-offline", "-nopull"]},  # flags reordered
        {"args": [*job()["args"], "-unsafe"]},  # an extra flag
        {"args": [a if a != "-offline" else "-online" for a in job()["args"]]},
        {"args": [a if a != "1.0.0" else "-x" for a in job()["args"]]},  # version as a flag
        {"args": [a if a != "1.0.0" else "1.0.0\n" for a in job()["args"]]},
    ],
)
def test_anything_else_is_refused(tmp_path: Path, changes: dict[str, Any]) -> None:
    module = runner()
    with pytest.raises(module.JobError):
        module.check_job(job(**changes), tmp_path)


def test_the_docker_command_has_no_network_read_only_input_and_limits(tmp_path: Path) -> None:
    module = runner()
    config = module.Config(
        export_dir=tmp_path,
        results_dir=tmp_path / "r",
        work_dir=tmp_path / "w",
        store_dir=tmp_path / "s",
        owner_uid=1000,
        owner_gid=1000,
        analysis_digest="sha256:" + "1" * 64,
        sandbox_image_id="x",
    )
    command = module.docker_command(config, module.check_job(job(), tmp_path), tmp_path / "w")
    joined = " ".join(command)
    assert command[:2] == ["docker", "run"]
    assert "--network none" in joined and command[-1] == "-offline" and "-nopull" in command
    assert f"{tmp_path}/w/input/{KEY}.tgz:/{KEY}.tgz:ro" in command
    assert "--memory" in command and "--pids-limit" in command and "--cpus" in command
    assert f"gcr.io/ossf-malware-analysis/analysis@sha256:{'1' * 64}" in command
    assert "evil pkg; rm -rf /" in command  # one argv element, never a shell word
    shim = command.index("/bin/sh")
    assert command[shim : shim + 5] == [
        "/bin/sh",
        "-c",
        module.PCAP_SHIM,
        "kitsunox-sandbox",
        "analyze",
    ]
    assert "evil" not in module.PCAP_SHIM and command.index("evil pkg; rm -rf /") > shim + 4
    mounts = [command[i + 1] for i, a in enumerate(command) if a == "-v"]
    assert all(m.startswith(str(tmp_path)) for m in mounts)  # nothing else of the host


def test_a_tarball_must_match_its_sha256(tmp_path: Path) -> None:
    module = runner()
    data = b"tarball bytes"
    (tmp_path / f"{KEY}.tgz").write_bytes(data)
    (tmp_path / "w" / "input").mkdir(parents=True)
    good = module.check_job(job(sha256=hashlib.sha256(data).hexdigest()), tmp_path)
    module.stage_tarball(good, tmp_path / "w")
    assert (tmp_path / "w" / "input" / f"{KEY}.tgz").read_bytes() == data
    with pytest.raises(module.JobError):
        module.stage_tarball(module.check_job(job(), tmp_path), tmp_path / "w")


def test_jobs_are_read_from_every_export(tmp_path: Path) -> None:
    module = runner()
    run = tmp_path / "20261101T000000Z-npm"
    run.mkdir()
    (run / "jobs.json").write_text(json.dumps({"jobs": [job(), job(key="zz")]}))
    (tmp_path / "bad name!").mkdir()
    config = module.Config(
        export_dir=tmp_path,
        results_dir=tmp_path,
        work_dir=tmp_path,
        store_dir=tmp_path,
        owner_uid=0,
        owner_gid=0,
        analysis_digest="sha256:" + "1" * 64,
        sandbox_image_id="x",
    )
    found = list(module.exported_jobs(config))
    assert [run_id for run_id, _ in found] == [run.name, run.name]
    assert found[0][1].key == KEY and isinstance(found[1][1], module.JobError)


def test_the_smoke_package_is_inert_and_stable() -> None:
    module = runner()
    data = module.smoke_tarball()
    assert data == module.smoke_tarball()
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(data))) as tar:
        manifest = json.loads(tar.extractfile("package/package.json").read())  # type: ignore[union-attr]
    assert manifest["scripts"] == {"postinstall": "node -e \"console.log('kitsunox smoke')\""}


def test_a_failed_smoke_run_shows_its_files_and_output(tmp_path: Path) -> None:
    module = runner()
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "analyze.log").write_bytes(b"x" * 5)
    shown = module.smoke_diagnosis(tmp_path, b"", b"line one\nfailed: \x1b[31mred\n", lines=1)
    assert "         5  logs/analyze.log" in shown
    assert "analyser stderr (last 1 lines):\n  failed: ?[31mred" in shown
    assert "line one" not in shown
