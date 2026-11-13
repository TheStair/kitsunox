"""`static.host-ip-identity`: a bare public IP in a JSON setting, and code that builds a URL
from a scheme variable and reads who runs it.

Fixtures are small, inert snippets in the shape of `@atedone/workspace-context` 0.0.23's
settings and URL builder, with a made-up public address (the documentation ranges are not
global, so they would not fire). Nothing here runs or connects anywhere.
"""

from datetime import UTC, datetime

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
from kitsunox.rules.host_ip import HostIpIdentity, bare_host_ips, identity_urls
from kitsunox.rules.static import RULES
from kitsunox.stages.static import ContentCache, analyse_batch

SNAP = VersionSnapshot(
    ref=PackageVersionRef(ecosystem="npm", name="ws-context", version="0.0.3"),
    publish=PublishInfo(),
    manifest={},
)
PROFILE = b"""{
  "name": "stable",
  "transport": "http",
  "host": "151.0.2.77",
  "port": 8080,
  "pathname": ["workspace", "profile"]
}
"""
BUILDER = b"""'use strict';
const defaultProfile = require('./default-profile.json');
function identity(env) {
  for (const candidate of [Reflect.get(env, 'USER'), Reflect.get(env, 'LOGNAME')]) {
    if (typeof candidate === 'string' && candidate) return candidate;
  }
  return '';
}
function source(profile, env) {
  const authority = profile.port ? `${profile.host}:${profile.port}` : profile.host;
  const url = `${profile.transport}://${authority}/${profile.pathname.join('/')}`;
  const who = identity(env);
  return who ? `${url}?username=${encodeURIComponent(who)}` : url;
}
module.exports = { source };
"""
FILES = {
    "package.json": b'{"name": "ws-context", "main": "index.js"}',
    "lib/default-profile.json": PROFILE,
    "lib/state.js": BUILDER,
}


def _fire(files: dict[str, bytes]) -> list[str]:
    return [f.rule_id for f in HostIpIdentity().evaluate_artifact(SNAP, files)]


def test_fires_on_the_shape_and_shows_both_halves() -> None:
    (finding,) = HostIpIdentity().evaluate_artifact(SNAP, FILES)
    assert finding.severity is Severity.MEDIUM and finding.weight == 3.0
    assert "151.0.2.77" in finding.explanation
    paths = [(e.path, e.line_start) for e in finding.evidence]
    assert paths[0] == ("lib/default-profile.json", 4)
    assert [p for p, _ in paths[1:]] == ["lib/state.js", "lib/state.js"]
    assert "://" in (finding.evidence[1].snippet or "")
    assert "USER" in (finding.evidence[2].snippet or "")


def test_other_identity_reads_and_a_concatenated_scheme_count() -> None:
    code = b"""const os = require('os');
const cfg = require('./cfg.json');
const target = cfg.scheme + '://' + cfg.server + '/p?h=' + os.hostname();
"""
    files = {"cfg.json": b'{"server": "151.0.2.77:9000"}', "index.js": code}
    assert _fire(files) == ["static.host-ip-identity"]
    env = b"const u = `${proto}://${host}/x?u=${process.env.USERNAME}`;\n"
    assert _fire({"c.json": b'{"ip":"151.0.2.77"}', "a.ts": env}) == ["static.host-ip-identity"]


def test_the_address_alone_is_configuration() -> None:
    plain = b"const url = `${profile.transport}://${profile.host}/status`;\n"
    assert _fire({**FILES, "lib/state.js": plain}) == []
    who = b"const who = process.env.USER; const url = 'http://' + host;\n"
    assert _fire({**FILES, "lib/state.js": who}) == []


def test_the_two_halves_of_the_code_must_be_in_one_file() -> None:
    files = {
        "lib/default-profile.json": PROFILE,
        "lib/url.js": b"const url = `${p.transport}://${p.host}`;\n",
        "lib/who.js": b"const who = process.env.USER;\n",
    }
    assert _fire(files) == []


def test_addresses_that_are_not_a_hidden_server() -> None:
    for address in ("10.0.0.5", "127.0.0.1", "8.8.8.8", "1.2.3.4", "999.1.1.1"):
        profile = PROFILE.replace(b"151.0.2.77", address.encode())
        assert _fire({**FILES, "lib/default-profile.json": profile}) == [], address
    url = PROFILE.replace(b'"151.0.2.77"', b'"http://151.0.2.77"')
    assert _fire({**FILES, "lib/default-profile.json": url}) == []  # a URL: hardcoded-ip's


def test_lockfiles_tests_and_commented_code_do_not_count() -> None:
    for path in ("package-lock.json", "test/fixtures/profile.json", "node_modules/x/c.json"):
        assert _fire({path: PROFILE, "lib/state.js": BUILDER}) == [], path
    assert _fire({**FILES, "lib/state.js": b"", "test/state.test.js": BUILDER}) == []
    commented = b"// const url = `${t}://${h}/?u=${process.env.USER}`;\n"
    assert _fire({**FILES, "lib/state.js": commented}) == []


def test_helpers_report_their_halves() -> None:
    assert bare_host_ips(FILES) == [
        ("lib/default-profile.json", 4, "151.0.2.77", '"host": "151.0.2.77"')
    ]
    assert [path for path, *_ in identity_urls(FILES)] == ["lib/state.js"]
    assert bare_host_ips({"big.json": b" " * (300 * 1024) + PROFILE}) == []


def test_stage2_reports_it_on_an_unchanged_release() -> None:
    assert any(r.id == HostIpIdentity.id for r in NPM_ARTIFACT_RULES)
    as_of = datetime(2026, 11, 13, tzinfo=UTC)

    def snapshot(version: str) -> VersionSnapshot:
        return VersionSnapshot(
            ref=PackageVersionRef(ecosystem="npm", name="ws-context", version=version),
            publish=PublishInfo(published_at=as_of),
            manifest={"name": "ws-context", "version": version},
            artifact=ArtifactRef(url=f"https://registry.example/ws-context-{version}.tgz"),
        )

    base, new = snapshot("0.0.2"), snapshot("0.0.3")
    batch = PackageBatch(
        ecosystem="npm",
        name="ws-context",
        base=base,
        versions=(Candidate(change=Change(new=new, previous=base)),),
    )
    out = analyse_batch(
        batch, lambda _: FILES, ContentCache(None, RULES), artifact_rules=NPM_ARTIFACT_RULES
    )
    (version,) = out.versions
    assert [f.rule_id for f in version.findings if f.rule_id == HostIpIdentity.id] == [
        HostIpIdentity.id
    ]
    assert version.history[-1].forwarded
