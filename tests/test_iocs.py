"""IOC checker against a fake malicious index (Claude-owned scaffolding — should pass)."""

from __future__ import annotations

from kitsunox.analysis.tier0.iocs import IOCChecker
from kitsunox.threatintel.sync import LabelHit, MaliciousIndex


def _index() -> MaliciousIndex:
    idx = MaliciousIndex()
    idx.add(LabelHit(package_name="flatmap-stream", versions=["0.1.1"], advisory_id="GHSA-x", source="osv"))
    idx.add(LabelHit(package_name="evil-pkg", versions=[], advisory_id="MAL-1", source="openssf"))
    return idx


def test_direct_hit_on_known_malicious_version(settings):
    checker = IOCChecker(_index(), settings=settings, allow_live=False)
    findings = checker.check("evil-pkg", "9.9.9")
    assert [f.rule_id for f in findings] == ["tier0.ioc.known_malicious_package"]
    assert findings[0].severity.value == "critical"


def test_no_hit_for_nonmatching_version(settings):
    checker = IOCChecker(_index(), settings=settings, allow_live=False)
    assert checker.check("flatmap-stream", "0.2.0") == []


def test_malicious_dependency_flagged(settings):
    checker = IOCChecker(_index(), settings=settings, allow_live=False)
    findings = checker.check("event-stream", "3.3.6", dependencies={"flatmap-stream": "0.1.1"})
    assert any(f.rule_id == "tier0.ioc.malicious_dependency" for f in findings)
