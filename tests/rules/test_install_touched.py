"""`npm.install-script-changed` v6 and `npm.install-script-code` v4 (round 5) on small, inert
install files (nothing here runs)."""

import json

import pytest

from kitsunox.core.models import (
    Finding,
    PackageVersionRef,
    PublishInfo,
    Severity,
    VersionSnapshot,
)
from kitsunox.ecosystems.npm.install import install_sources
from kitsunox.ecosystems.npm.rules import install_code
from kitsunox.ecosystems.npm.rules.install_code import InstallScriptChanged, InstallScriptCode
from kitsunox.stages.ast import CapabilityCache, CodeChange, code_change

CACHE = CapabilityCache(None)
SNAP = VersionSnapshot(
    ref=PackageVersionRef(ecosystem="npm", name="kx", version="1.0.1"),
    publish=PublishInfo(),
    manifest={},
)


def pkg(hook: str, files: dict[str, bytes]) -> dict[str, bytes]:
    return {"package.json": json.dumps({"scripts": {"postinstall": hook}}).encode(), **files}


def change(new: dict[str, bytes], base: dict[str, bytes] | None) -> CodeChange:
    return code_change(SNAP, new, base, CACHE, install_sources, "1.0.0")


def isc(before: bytes, after: bytes) -> Finding:
    (found,) = InstallScriptChanged().evaluate_code(
        change(pkg("node p.js", {"p.js": after}), pkg("node p.js", {"p.js": before}))
    )
    return found


SPAWN = b'const r = spawnSync("tool", ["--version"])\n'


def test_a_line_the_previous_install_code_had_is_not_touched() -> None:
    """v6: a line the previous install code had, moved or re-indented, doesn't count
    (`@aziron/atlas`, `@znmin/claude-remote-cli`: benign); the same call changed does."""
    moved = b"function check() {\n    " + SPAWN + b"}\ncheck()\n"
    assert isc(SPAWN + b"f(1)\n", moved).severity is Severity.LOW
    assert isc(SPAWN, SPAWN.replace(b"--version", b"--install")).severity is Severity.MEDIUM


def test_a_newly_run_file_made_of_the_old_install_codes_lines_is_not_touched() -> None:
    """v6: a bundle chunk renamed between releases (`@tetsuo-ai/agenc`, `brewtui-bar`)."""
    old = pkg("node a.js", {"a.js": b"import './chunk-1.js'\n", "chunk-1.js": SPAWN})
    new = pkg("node a.js", {"a.js": b"import './chunk-2.js'\n", "chunk-2.js": SPAWN})
    found = InstallScriptChanged().evaluate_code(change(new, old))
    assert [f.severity for f in found] == [Severity.LOW]
    grown = pkg("node a.js", {"a.js": b"import './chunk-2.js'\n", "chunk-2.js": SPAWN + b"eval(x)"})
    (found_grown,) = InstallScriptChanged().evaluate_code(change(grown, old))
    assert found_grown.severity is Severity.MEDIUM


def test_a_url_counts_only_when_who_serves_it_is_new() -> None:
    """v6: the package's own release repository or the registry again is not news; another
    host, another repository owner on a code host, or a host built from a variable is."""
    url = b'const u = "https://github.com/o/r/releases/download/v1.0.0/x.tgz"\n'
    same = b'const u = "https://github.com/o/r/releases/latest/download/x.tgz"\n'
    assert isc(url, same).severity is Severity.LOW
    assert isc(url, url.replace(b"github.com/o/", b"github.com/p/")).severity is Severity.MEDIUM
    assert isc(url, url + b'const m = "https://example.io/x"\n').severity is Severity.MEDIUM
    assert isc(url, url + b"const t = `https://${host}/x.tgz`\n").severity is Severity.MEDIUM
    api = b'get("https://api.github.com/repos/o/r/releases/latest")\n'
    assert isc(api, api.replace(b"latest", b"tags/v2")).severity is Severity.LOW  # owner `o`
    assert isc(api, api.replace(b"repos/o/", b"repos/p/")).severity is Severity.MEDIUM
    ip = b'const u = "http://10.1.2.3/x"\n'
    assert isc(url, url + ip).severity is Severity.MEDIUM


def test_old_tokens_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    """J2 (trade-off, off by default): a match the previous install code had anywhere doesn't
    count even on a changed line (`esoftplay@0.0.196` rewraps its `execSync`)."""
    before = b'execSync("mkdir -p raw")\n'
    after = b'if (ok) {\n  execSync("mkdir -p raw");\n}\n'
    assert isc(before, after).severity is Severity.MEDIUM
    monkeypatch.setattr(install_code, "OLD_TOKENS_COUNT", "never")
    assert isc(before, after).severity is Severity.LOW
    assert isc(before, after + b'exec("curl x")\n').severity is Severity.MEDIUM
    monkeypatch.setattr(install_code, "OLD_TOKENS_COUNT", "minified")
    assert isc(before, after).severity is Severity.MEDIUM  # not a minified line
    wide = b"var a=1;" * 80 + b'execSync("mkdir -p raw");\n'
    assert isc(before, wide).severity is Severity.LOW


@pytest.mark.parametrize(
    ("code", "fires"),
    [
        (b"function dirs(env = process.env) { return env.HOME }\n", False),
        (b"const run = ({ env = process.env, cwd } = {}) => env.CI\n", False),
        (b"function f(\n  a,\n  env = process.env,\n) { return env.X }\n", False),
        (b"send(JSON.stringify(process.env))\n", True),
        (b"function f(env = process.env) {}\nfor (const k of Object.keys(process.env)) g(k)", True),
        (b"spawnSync(cmd, { env: { ...process.env, CI: '1' } })\n", True),
    ],
)
def test_an_environment_taken_as_a_default_parameter_is_not_the_whole_environment(
    code: bytes, fires: bool
) -> None:
    """install-script-code v4: `env = process.env` as a parameter's default is how code takes
    its environment so tests can pass another; harvesting needs the object itself."""
    found = InstallScriptCode().evaluate_code(change(pkg("node p.js", {"p.js": code}), None))
    assert bool(found) is fires, code
