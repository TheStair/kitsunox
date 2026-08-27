"""IOC lookups: is this exact (package, version) known-malicious, and does it pull in a
known-malicious dependency?

Order: local mirror first (fast, offline), then — for the *direct* package only — a live
OSV query as a fallback for packages the mirror doesn't know yet. Dependency checks stay
mirror-only by default (``allow_live_deps=False``): a live query per dependency would mean
dozens of HTTP calls per event and hammer OSV.

Version matching matters. ``eslint-config-prettier`` genuinely had a malware incident, but
only for specific versions — a dependency on ``^10`` that resolves to a clean release is
not a malicious dependency. So:
  - dependency spec is an exact pin to a known-malicious version  -> CRITICAL
  - whole-package malware advisory (no version list)              -> HIGH
  - name has malware history but the spec is a range              -> LOW (verify lockfile)
"""

from __future__ import annotations

import re

import structlog

from kitsunox.config import Settings, get_settings
from kitsunox.ir import Finding, Severity
from kitsunox.threatintel.sync import LabelHit, MaliciousIndex, load_index, osv_query_live

log = structlog.get_logger(__name__)

_EXACT_VERSION_RE = re.compile(r"^\s*v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?\s*$")


def _exact_pin(spec: str) -> str | None:
    """Return the pinned version if ``spec`` is an exact version, else None."""
    m = _EXACT_VERSION_RE.match(spec or "")
    return spec.strip().lstrip("v") if m else None


class IOCChecker:
    def __init__(
        self,
        index: MaliciousIndex | None = None,
        *,
        settings: Settings | None = None,
        allow_live: bool = True,
        allow_live_deps: bool = False,
    ):
        self.settings = settings or get_settings()
        self.index = index if index is not None else load_index(self.settings)
        self.allow_live = allow_live
        self.allow_live_deps = allow_live_deps

    # ---------------------------------------------------------------- direct hit
    def _direct_hits(self, name: str, version: str | None) -> list[LabelHit]:
        hits = self.index.lookup(name, version)
        if hits:
            return hits
        if self.allow_live:
            return [
                h
                for h in osv_query_live(name, version, settings=self.settings)
                if h.is_malware and h.matches_version(version)
            ]
        return []

    def _dep_hits(self, dep_name: str) -> list[LabelHit]:
        hits = [h for h in self.index.lookup(dep_name) if h.is_malware]
        if not hits and self.allow_live_deps:
            hits = [h for h in osv_query_live(dep_name, settings=self.settings) if h.is_malware]
        return hits

    # -------------------------------------------------------------------- check
    def check(
        self, name: str, version: str | None, *, dependencies: dict[str, str] | None = None
    ) -> list[Finding]:
        findings: list[Finding] = []

        for hit in self._direct_hits(name, version):
            findings.append(
                Finding(
                    tier=0,
                    rule_id="tier0.ioc.known_malicious_package",
                    severity=Severity.CRITICAL,
                    rationale=(
                        f"{name}@{version or '*'} matches malicious-package advisory "
                        f"{hit.advisory_id} ({hit.source}). {hit.summary}".strip()
                    ),
                    evidence=f"{hit.advisory_id}: versions={hit.versions or 'unspecified'}",
                )
            )

        for dep_name, spec in (dependencies or {}).items():
            hits = self._dep_hits(dep_name)
            if not hits:
                continue
            findings.append(self._dependency_finding(dep_name, spec, hits))

        return findings

    def _dependency_finding(self, dep_name: str, spec: str, hits: list[LabelHit]) -> Finding:
        pin = _exact_pin(spec)
        bad_versions = sorted({v for h in hits for v in h.versions})
        advisory = hits[0].advisory_id

        if pin and any(pin in h.versions for h in hits):
            sev, rule = Severity.CRITICAL, "tier0.ioc.malicious_dependency"
            why = f"pins {dep_name}@{pin}, a known-malicious version ({advisory})"
        elif any(not h.versions for h in hits):
            sev, rule = Severity.HIGH, "tier0.ioc.malicious_dependency"
            why = f"depends on {dep_name} ({spec}); whole-package malware advisory {advisory}"
        else:
            sev, rule = Severity.LOW, "tier0.ioc.dependency_prior_compromise"
            why = (
                f"{dep_name} ({spec}) has a malware advisory for {bad_versions or 'some versions'} "
                f"({advisory}); verify the resolved/locked version is clean"
            )

        return Finding(
            tier=0,
            rule_id=rule,
            severity=sev,
            rationale=why,
            file_path="package.json",
            evidence=f"{dep_name}@{spec} -> {advisory} (bad: {bad_versions or 'unspecified'})",
        )
