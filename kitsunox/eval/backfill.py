"""Historical backfill: reconstruct an incident's publishes and run the pipeline on them.

[USER-OWNED body — Claude provides the report shape + a skeleton loop]

For each package in the incident:
  1. fetch the full packument (+ deps.dev history) via ``RegistryClient``
  2. reconstruct the version timeline (``client.version_timeline`` / deps.dev ``publishedAt``)
  3. for each consecutive ``(prev, cur)`` around the incident window, synthesize a
     ``PublishEvent`` (set ``maintainer_delta`` from per-version ``maintainers`` where the
     packument exposes it)
  4. run ``prescore.route`` then ``scanner.run_tier0`` on each synthesized event
  5. compare against ``Repository.label_lookup`` -> detected / missed / could-not-evaluate
     (tarball unavailable)

Persist synthesized events + findings with ``source="backfill"`` so live stats stay clean.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from kitsunox.eval.incidents import Incident
from kitsunox.ingest.registry_client import RegistryClient


@dataclass
class VersionOutcome:
    package: str
    version: str
    route: str | None
    tier0_status: str
    finding_rule_ids: list[str] = field(default_factory=list)
    ground_truth: str | None = None  # "malicious" | "benign_control" | None
    outcome: str = "unknown"  # "detected" | "missed" | "true_negative" | "uneval"


@dataclass
class IncidentReport:
    incident_key: str
    version_outcomes: list[VersionOutcome] = field(default_factory=list)

    @property
    def detected(self) -> int:
        return sum(1 for v in self.version_outcomes if v.outcome == "detected")

    @property
    def missed(self) -> int:
        return sum(1 for v in self.version_outcomes if v.outcome == "missed")

    @property
    def uneval(self) -> int:
        return sum(1 for v in self.version_outcomes if v.outcome == "uneval")

    @property
    def detection_rate(self) -> float | None:
        denom = self.detected + self.missed
        return (self.detected / denom) if denom else None

    def render(self) -> str:
        lines = [f"=== incident: {self.incident_key} ==="]
        for v in self.version_outcomes:
            rules = ",".join(v.finding_rule_ids) or "-"
            lines.append(
                f"  {v.package}@{v.version:12} route={v.route or '-':6} "
                f"t0={v.tier0_status:8} gt={v.ground_truth or '-':16} "
                f"=> {v.outcome:13} [{rules}]"
            )
        rate = self.detection_rate
        lines.append(
            f"  detected={self.detected} missed={self.missed} uneval={self.uneval} "
            f"detection_rate={'n/a' if rate is None else f'{rate:.0%}'}"
        )
        return "\n".join(lines)


def run_backfill(
    incident: Incident,
    *,
    client: RegistryClient | None = None,
    repo=None,
    window_days: int = 30,
) -> IncidentReport:
    """USER: implement. Return a populated ``IncidentReport``."""
    raise NotImplementedError("TODO(user): incident backfill — see module docstring")
