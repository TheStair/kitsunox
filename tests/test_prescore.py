"""Pre-score router — USER-OWNED. xfail(strict): flips to failure once implemented.

The router must classify events using metadata only. These tests mock the abbreviated
packument endpoint; if your implementation fetches something else, adjust the mocks.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from kitsunox.ingest.changes_feed import ChangeRow
from kitsunox.ingest.registry_client import RegistryClient
from kitsunox.ir import Route

pytestmark = pytest.mark.xfail(reason="USER-OWNED: implement prescore.route()", strict=True)


def _ctx(settings, repo):
    from kitsunox.ingest.prescore import PrescoreContext

    return PrescoreContext(repo=repo, client=RegistryClient(settings))


def _mock_packument(name: str, doc: dict) -> None:
    respx.get(f"https://registry.npmjs.org/{name}").mock(
        return_value=httpx.Response(200, json=doc)
    )


@respx.mock
def test_established_stable_package_is_ignored(settings, repo):
    repo.observe_publish_for_baseline("lodash", maintainers=["jdalton"], version="4.17.20")
    _mock_packument(
        "lodash",
        {
            "name": "lodash",
            "dist-tags": {"latest": "4.17.21"},
            "maintainers": [{"name": "jdalton"}],
            "time": {"4.17.21": "2021-02-20T00:00:00.000Z"},
            "versions": {"4.17.21": {"maintainers": [{"name": "jdalton"}], "dist": {}}},
        },
    )
    from kitsunox.ingest.prescore import route

    row = ChangeRow(seq=1, package_name="lodash", rev="900-x", deleted=False)
    assert route(row, _ctx(settings, repo)).route is Route.IGNORE


@respx.mock
def test_new_package_with_install_script_is_routed(settings, repo):
    _mock_packument(
        "sketchy-new",
        {
            "name": "sketchy-new",
            "dist-tags": {"latest": "1.0.0"},
            "maintainers": [{"name": "nobody"}],
            "time": {"1.0.0": "2026-08-01T00:00:00.000Z"},
            "versions": {
                "1.0.0": {
                    "scripts": {"postinstall": "node ./setup.js"},
                    "maintainers": [{"name": "nobody"}],
                    "dist": {},
                }
            },
        },
    )
    from kitsunox.ingest.prescore import route

    row = ChangeRow(seq=2, package_name="sketchy-new", rev="1-x", deleted=False)
    assert route(row, _ctx(settings, repo)).route in {Route.TIER01, Route.TIER2}


@respx.mock
def test_maintainer_change_is_routed(settings, repo):
    repo.observe_publish_for_baseline("popular-lib", maintainers=["original"], version="2.0.0")
    _mock_packument(
        "popular-lib",
        {
            "name": "popular-lib",
            "dist-tags": {"latest": "2.0.1"},
            "maintainers": [{"name": "original"}, {"name": "attacker"}],
            "time": {"2.0.1": "2026-08-02T00:00:00.000Z"},
            "versions": {"2.0.1": {"maintainers": [{"name": "attacker"}], "dist": {}}},
        },
    )
    from kitsunox.ingest.prescore import route

    row = ChangeRow(seq=3, package_name="popular-lib", rev="40-x", deleted=False)
    res = route(row, _ctx(settings, repo))
    assert res.route in {Route.TIER01, Route.TIER2}
    assert any("maintainer" in r.lower() for r in res.reasons)


@respx.mock
def test_unpublish_is_routed(settings, repo):
    from kitsunox.ingest.prescore import route

    row = ChangeRow(seq=4, package_name="whatever", rev="5-x", deleted=True)
    assert route(row, _ctx(settings, repo)).route in {Route.TIER01, Route.TIER2}
