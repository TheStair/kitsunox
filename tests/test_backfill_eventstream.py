"""THE GATE — ``kitsunox backfill --incident event-stream`` detects the incident.

USER-OWNED: xfail(strict) until ``eval/backfill.py`` is implemented. Once it passes,
delete the marker — that's the milestone from the plan's verification section.

Hits the live npm registry + OSV.dev — run with ``-m network``.
"""

from __future__ import annotations

import pytest

from kitsunox.eval.backfill import run_backfill
from kitsunox.eval.incidents import get_incident
from kitsunox.ingest.registry_client import RegistryClient

pytestmark = [
    pytest.mark.network,
    pytest.mark.xfail(reason="USER-OWNED: implement eval/backfill.run_backfill()", strict=True),
]


def test_backfill_detects_event_stream(settings, db):
    incident = get_incident("event-stream")
    with RegistryClient(settings) as client:
        report = run_backfill(incident, client=client)

    es_malicious = [
        v for v in report.version_outcomes
        if v.package == "event-stream" and v.version == "3.3.6"
    ]
    assert es_malicious, "3.3.6 not present in the reconstructed timeline"
    assert es_malicious[0].outcome == "detected"
    # detection_rate is over evaluable versions only (tarball-unavailable => 'uneval')
    assert report.detection_rate is None or report.detection_rate > 0
