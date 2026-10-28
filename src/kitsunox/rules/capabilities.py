"""Stage 3 rules over capability profiles (ecosystem-agnostic).

Numbers behind the severities, from `day1` (2026-10-28; "updates" are shape-A first releases,
DataDog for malicious): gaining a capability is rare in benign updates and common in malicious
ones.

| Gained in an update | Benign | Malicious |
|---|---|---|
| env-all (the whole environment as a value) | 0.2% | 70.9% |
| dynamic-code | 0.1% | 57.3% |
| network | 0.3% | 57.6% |
| process | 0.2% | 51.2% |

For a new package everything counts as gained (34% of benign new packages "gain" network), so
these rules only look at updates; new packages are covered by what their install scripts run.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from kitsunox.core.models import Evidence, EvidenceKind, Finding, Severity
from kitsunox.core.rules import BaseRule
from kitsunox.lang.javascript import Capability
from kitsunox.stages.ast import CodeChange, Profile

C = Capability
# Gaining one of these alone is worth a look; network together with one of these is the shape of
# exfiltration or a downloader.
STRONG: Final = frozenset({C.ENV_ALL, C.DYNAMIC_CODE})
WITH_NETWORK: Final = frozenset({C.ENV_ALL, C.PROCESS, C.DYNAMIC_CODE})
EVIDENCE_PER_CAPABILITY: Final = 2


def evidence(where: Profile, capabilities: frozenset[Capability]) -> tuple[Evidence, ...]:
    out = []
    for capability in sorted(capabilities):
        for use in where.where(capability)[:EVIDENCE_PER_CAPABILITY]:
            out.append(
                Evidence(
                    kind=EvidenceKind.FILE_SPAN,
                    path=use.path,
                    line_start=use.use.line,
                    line_end=use.use.line,
                    snippet=f"[{capability.value}] {use.use.snippet}",
                )
            )
    return tuple(out)


class CapabilityGained(BaseRule):
    """An update's code can do something the previous version's couldn't."""

    id = "code.capability-gained"
    severity = Severity.LOW
    weight = 1.0
    title = "Code gained capabilities"

    def evaluate_code(self, change: CodeChange) -> Sequence[Finding]:
        if change.before is None:
            return ()
        gained = change.added
        if not gained:
            return ()
        strong = bool(gained & STRONG) or (C.NETWORK in gained and bool(gained & WITH_NETWORK))
        names = ", ".join(sorted(c.value for c in gained))
        return (
            self.finding(
                f"This version's code uses {names}, which the previous version's code did not.",
                *evidence(change.after, gained),
                severity=Severity.MEDIUM if strong else Severity.LOW,
            ),
        )


RULES: Final = (CapabilityGained(),)
