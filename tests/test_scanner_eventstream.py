"""Scaffold proof: the Tier 0 scanner + IOC path fires on the event-stream incident.

This is the "validate Tier 0 fires on a known incident before moving on" milestone, run
directly against ``scanner.run_tier0`` (no backfill needed). It hits the live npm registry
and OSV.dev — run with ``-m network``.

``event-stream@3.3.6`` was unpublished, so its tarball is gone; the IOC path
(known-malicious-version + malicious ``flatmap-stream`` dependency) must still flag it.
"""

from __future__ import annotations

import pytest

from kitsunox.analysis.scanner import run_tier0
from kitsunox.ingest.registry_client import RegistryClient
from kitsunox.ir import Ecosystem, PackageRef, PublishEvent

pytestmark = pytest.mark.network


def test_tier0_flags_event_stream_3_3_6(settings):
    event = PublishEvent(
        ref=PackageRef(ecosystem=Ecosystem.NPM, name="event-stream"),
        version="3.3.6",
        prev_version="3.3.4",
    )
    with RegistryClient(settings) as client:
        result = run_tier0(event, client=client)

    rule_ids = {f.rule_id for f in result.findings}
    assert result.findings, f"expected >=1 Tier 0 finding, got none (notes={result.notes})"
    assert rule_ids & {
        "tier0.ioc.known_malicious_package",
        "tier0.ioc.malicious_dependency",
    }, rule_ids
    assert result.status == "flagged"


def test_tier0_clean_on_benign_version(settings):
    event = PublishEvent(
        ref=PackageRef(ecosystem=Ecosystem.NPM, name="event-stream"),
        version="3.3.4",
        prev_version="3.3.3",
    )
    with RegistryClient(settings) as client:
        result = run_tier0(event, client=client)

    assert not any(f.rule_id.startswith("tier0.ioc") for f in result.findings), result.findings
