"""`npm.canary-callback`: a tiny package whose loaded or installed code calls a random-id
callback host (inert fixtures: synthetic ids under reserved names; nothing is run)."""

import json

import pytest

from kitsunox.core.models import (
    EvidenceKind,
    PackageVersionRef,
    PublishInfo,
    Severity,
    VersionSnapshot,
)
from kitsunox.ecosystems.npm.rules.artifact import RULES
from kitsunox.ecosystems.npm.rules.canary import MAX_FILES, CanaryCallback, canary_hosts

# A made-up callback id under a reserved domain, shaped like a probe's (letters and digits).
HOST = "q7w2e9r4t1y8u3i6o5p0asdfgh.callback.example"
BEACON = (
    f"const callbackUrl = 'https://{HOST}/marker';\n"
    "try { await fetch(callbackUrl); } catch {}\n"
    "export default function Marker() { return null; }\n"
).encode()
SNAPSHOT = VersionSnapshot(
    ref=PackageVersionRef(ecosystem="npm", name="kx-probe", version="1.0.0"),
    publish=PublishInfo(),
    manifest={},
)


def package(files: dict[str, bytes], manifest: dict[str, object] | None = None) -> dict[str, bytes]:
    meta = {"name": "kx-probe", "version": "1.0.0", "main": "index.js", **(manifest or {})}
    return {"package.json": json.dumps(meta).encode(), **files}


def fire(files: dict[str, bytes]) -> list[str]:
    return [f.explanation for f in CanaryCallback().evaluate_artifact(SNAPSHOT, files)]


def test_a_two_file_import_time_beacon_fires() -> None:
    (finding,) = CanaryCallback().evaluate_artifact(SNAPSHOT, package({"index.js": BEACON}))
    assert finding.severity is Severity.MEDIUM and finding.weight == 3.0
    assert HOST in finding.explanation and "2-file package" in finding.explanation
    (evidence,) = finding.evidence
    assert evidence.kind is EvidenceKind.FILE_SPAN and evidence.path == "index.js"
    assert evidence.line_start == 1 and HOST in (evidence.snippet or "")


def test_the_rule_runs_in_stage_2s_artifact_rules() -> None:
    assert any(rule.id == "npm.canary-callback" for rule in RULES)


def test_an_install_hook_command_and_a_hook_file_fire() -> None:
    hook = package({}, {"scripts": {"preinstall": f"curl -s https://{HOST}/x || true"}})
    (finding,) = CanaryCallback().evaluate_artifact(SNAPSHOT, hook)
    assert finding.evidence[0].path == "package.json:scripts.preinstall"
    assert finding.evidence[0].kind is EvidenceKind.MANIFEST_FIELD
    script = package(
        {"setup.js": f"require('dns').lookup('{HOST}', () => {{}})".encode()},
        {"scripts": {"postinstall": "node setup.js"}},
    )
    assert len(fire(script)) == 1


def test_a_whole_quoted_host_and_a_lookup_command_count() -> None:
    quoted = f"const https = require('https'); https.get({{ hostname: '{HOST}', path: '/' }})"
    assert canary_hosts(quoted) and fire(package({"index.js": quoted.encode()}))
    assert [m.group(0) for m in canary_hosts(f"nslookup {HOST}")] == [f"nslookup {HOST}"]


@pytest.mark.parametrize(
    "text",
    [
        "https://api.example.com/v1",  # a word, not an id
        "https://12345678901234567890.example.com",  # digits only
        "https://abcdefghijklmnopqrstuvwx.example.com",  # letters only (a project slug)
        "https://a1b2c3d4e5.example.com",  # too short
        "'5f3e2a1b9c8d7e6f5a4b.worker.js'",  # a content-hashed file name
        "https://k3j4h5g6f7d8s9a0q1w2.oast.fun/x",  # public OAST: static.exfil-endpoint's
    ],
)
def test_what_is_not_a_canary_host(text: str) -> None:
    assert canary_hosts(text) == []


def test_without_network_use_or_in_a_file_nothing_loads_it_does_not_fire() -> None:
    constant = f"module.exports = {{ url: 'https://{HOST}/' }};\n".encode()
    assert fire(package({"index.js": constant})) == []
    documented = package({"index.js": b"module.exports = 1;\n", "README.md": BEACON})
    assert fire(documented) == []
    tested = package({"index.js": b"module.exports = 1;\n", "test/beacon.test.js": BEACON})
    assert fire(tested) == []


def test_a_package_over_the_file_limit_does_not_fire() -> None:
    filler = {f"lib/f{i}.js": b"module.exports = 1;\n" for i in range(MAX_FILES)}
    assert fire(package({"index.js": BEACON, **filler})) == []
    assert fire({}) == []
