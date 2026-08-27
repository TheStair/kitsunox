"""Repository round-trips (Claude-owned scaffolding — should pass)."""

from __future__ import annotations

from datetime import datetime

from kitsunox.ir import Ecosystem, Finding, PackageRef, PublishEvent, Route, Severity


def test_cursor_roundtrip(repo):
    assert repo.get_cursor() == 0
    repo.set_cursor(4321)
    assert repo.get_cursor() == 4321


def test_publish_event_and_findings(repo):
    event = PublishEvent(
        seq=7,
        ref=PackageRef(ecosystem=Ecosystem.NPM, name="demo"),
        version="1.0.0",
        route=Route.TIER01,
        route_reasons=["new package"],
    )
    eid = repo.record_publish_event(event, source="live")
    repo.add_finding(
        eid,
        Finding(tier=0, rule_id="tier0.ioc.malicious_dependency", severity=Severity.CRITICAL, rationale="x"),
    )
    repo.set_event_tier0(eid, "flagged")

    got = repo.findings_for_event(eid)
    assert len(got) == 1 and got[0].severity is Severity.CRITICAL


def test_baseline_accretes_publishes(repo):
    repo.observe_publish_for_baseline(
        "demo", published_at=datetime(2024, 1, 1), maintainers=["alice"], version="1.0.0"
    )
    repo.observe_publish_for_baseline(
        "demo", published_at=datetime(2024, 1, 11), maintainers=["alice", "bob"], version="1.1.0"
    )
    b = repo.get_baseline("demo")
    assert b.publish_count == 2
    assert b.known_maintainers == ["alice", "bob"]
    assert b.last_version == "1.1.0"
    assert b.publish_cadence_days_median == 10.0


def test_label_lookup_matches_version_and_whole_package(repo):
    repo.add_incident_label("es", "3.3.6", "malicious", source="osv", ref="GHSA-x")
    repo.add_incident_label("worm", None, "malicious", source="openssf")
    assert repo.label_lookup("es", "3.3.6")
    assert not repo.label_lookup("es", "3.3.4")
    assert repo.label_lookup("worm", "9.9.9")  # whole-package label matches any version
