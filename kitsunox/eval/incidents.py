"""The historical incident set used for detection-rate evaluation.   [USER-OWNED data]

Fill in ``malicious_versions`` / ``prev_good_version`` from OSV + the OpenSSF
malicious-packages mirror (``kitsunox.threatintel``). Where the exact malicious version
list is uncertain, leave it empty and resolve at run time via
``threatintel.osv_query_live(pkg)``.

``load_incident_labels_into_db`` writes these into ``incident_label`` so
``Repository.label_lookup`` can score backfill runs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date


@dataclass
class Incident:
    key: str
    packages: list[str]
    incident_date: date | None
    ghsa_ids: list[str] = field(default_factory=list)
    # (package -> [malicious versions]); empty list => resolve via OSV at run time
    malicious_versions: dict[str, list[str]] = field(default_factory=dict)
    # (package -> last known-good version) — the diff baseline for the scan
    prev_good_version: dict[str, str] = field(default_factory=dict)
    notes: str = ""


# TODO(user): complete versions/dates/GHSA ids. Names + years from the handoff:
INCIDENTS: list[Incident] = [
    Incident(
        key="event-stream",
        packages=["event-stream", "flatmap-stream"],
        incident_date=date(2018, 11, 26),
        ghsa_ids=["GHSA-mh6f-8j2x-4483"],
        malicious_versions={"event-stream": ["3.3.6"], "flatmap-stream": ["0.1.1"]},
        prev_good_version={"event-stream": "3.3.4"},
        notes="malicious `flatmap-stream` dependency added to event-stream@3.3.6",
    ),
    Incident(
        key="ua-parser-js",
        packages=["ua-parser-js"],
        incident_date=date(2021, 10, 22),
        ghsa_ids=["GHSA-pjwm-rvh2-c87w"],
        notes="maintainer account compromise; 0.7.29 / 0.8.0 / 1.0.0 shipped a coin miner + password stealer",
    ),
    Incident(
        key="coa-rc",
        packages=["coa", "rc"],
        incident_date=date(2021, 11, 4),
        notes="near-simultaneous maintainer-account compromise, similar payload to ua-parser-js",
    ),
    Incident(
        key="node-ipc",
        packages=["node-ipc"],
        incident_date=date(2022, 3, 15),
        ghsa_ids=["GHSA-97m3-w2cp-4xx6"],
        notes="protestware; maintainer-introduced destructive payload (10.1.1 / peacenotwar)",
    ),
    Incident(
        key="chalk-debug-2025",
        packages=["chalk", "debug", "ansi-styles", "color-convert", "color-name", "supports-color"],
        incident_date=date(2025, 9, 8),
        notes="Sept 2025 phishing-driven maintainer compromise of Qix packages; wallet-drainer injected",
    ),
    Incident(
        key="shai-hulud",
        packages=[],  # many; resolve from the OpenSSF mirror
        incident_date=date(2025, 9, 15),
        notes="self-propagating worm; credential theft + auto-republish. Resolve package list from mirror.",
    ),
]


def get_incident(key: str) -> Incident:
    for inc in INCIDENTS:
        if inc.key == key:
            return inc
    raise KeyError(key)


def load_incident_labels_into_db(repo) -> int:
    """USER: write INCIDENTS (+ OSV resolution) into ``incident_label``. Return rows written."""
    raise NotImplementedError("TODO(user): persist incident labels — see docstring")
