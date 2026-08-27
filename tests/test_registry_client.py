"""Registry client packument parsing (Claude-owned scaffolding — should pass)."""

from __future__ import annotations

import httpx
import respx

from kitsunox.ingest.registry_client import RegistryClient

_PACKUMENT = {
    "name": "demo",
    "dist-tags": {"latest": "1.1.0"},
    "maintainers": [{"name": "alice"}, {"name": "bob"}],
    "time": {
        "created": "2020-01-01T00:00:00.000Z",
        "1.0.0": "2020-01-01T00:00:00.000Z",
        "1.1.0": "2021-06-01T12:00:00.000Z",
    },
    "versions": {
        "1.0.0": {"dist": {"tarball": "https://r/demo-1.0.0.tgz", "shasum": "aaa"}},
        "1.1.0": {
            "_npmUser": {"name": "bob"},
            "maintainers": [{"name": "alice"}, {"name": "bob"}],
            "dependencies": {"left-pad": "^1.0.0"},
            "scripts": {"postinstall": "node ./install.js", "test": "jest"},
            "dist": {
                "tarball": "https://r/demo-1.1.0.tgz",
                "shasum": "bbb",
                "integrity": "sha512-x",
                "unpackedSize": 4096,
            },
        },
    },
}


@respx.mock
def test_version_meta_parsing(settings):
    respx.get("https://registry.npmjs.org/demo").mock(
        return_value=httpx.Response(200, json=_PACKUMENT)
    )
    with RegistryClient(settings) as client:
        meta = client.version_meta("demo", "1.1.0")

    assert meta.publisher == "bob"
    assert meta.maintainers == ["alice", "bob"]
    assert meta.dependencies == {"left-pad": "^1.0.0"}
    assert meta.install_scripts == {"postinstall": "node ./install.js"}  # 'test' excluded
    assert meta.has_install_script
    assert meta.dist_tarball_url == "https://r/demo-1.1.0.tgz"
    assert meta.unpacked_size == 4096
    assert meta.published_at.year == 2021


@respx.mock
def test_version_timeline_is_chronological(settings):
    respx.get("https://registry.npmjs.org/demo").mock(
        return_value=httpx.Response(200, json=_PACKUMENT)
    )
    with RegistryClient(settings) as client:
        tl = client.version_timeline("demo")
    assert [v for v, _ in tl] == ["1.0.0", "1.1.0"]


@respx.mock
def test_weekly_downloads(settings):
    respx.get("https://api.npmjs.org/downloads/point/last-week/demo").mock(
        return_value=httpx.Response(200, json={"downloads": 12345, "package": "demo"})
    )
    with RegistryClient(settings) as client:
        assert client.weekly_downloads("demo") == 12345
