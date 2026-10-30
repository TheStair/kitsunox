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
from kitsunox.lang.javascript import Capability, Use
from kitsunox.stages.ast import CodeChange, Profile

C = Capability
# Gaining one of these alone is worth a look; network together with one of these is the shape of
# exfiltration or a downloader. v2 (2026-10-30): `env-all` alone is no longer MEDIUM. On the
# first VM days it was the commonest sole reason to report (about 170 of 396 MEDIUM-only
# reports: apps that start reading `process.env`), and on `vm-day1` none of the 35 malicious
# samples reported through this rule alone had gained it without `dynamic-code`. Gaining
# `env-all` together with `network` stays MEDIUM (`WITH_NETWORK`).
#
# v3 (2026-10-30): `dynamic-code` alone is MEDIUM only through `eval`. `Function` and `vm` alone
# are LOW: on the live queue they were 85 of the 90 reports this rule made alone through
# `dynamic-code` (`new Function(body)` in template and test helpers, `import vm` for expression
# sandboxes), while all 35 `vm-day1` malicious samples reported through it alone were injected
# `eval(` payloads (`autotel-*`, `awaitly-*`). With `network` they stay MEDIUM.
WITH_NETWORK: Final = frozenset({C.ENV_ALL, C.PROCESS, C.DYNAMIC_CODE})
EVIDENCE_PER_CAPABILITY: Final = 2


def evaluates(use: Use) -> bool:
    """`eval(x)`, or `eval` reached through the global object (`globalThis["eval"]`)."""
    return use.capability is C.DYNAMIC_CODE and (
        use.detail == "eval" or use.detail.endswith("[eval]")
    )


def evidence(where: Profile, capabilities: frozenset[Capability]) -> tuple[Evidence, ...]:
    out = []
    for capability in sorted(capabilities):
        # `eval` first: it is what makes `dynamic-code` alone worth a look.
        uses = sorted(where.where(capability), key=lambda u: not evaluates(u.use))
        for use in uses[:EVIDENCE_PER_CAPABILITY]:
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
    version = 3
    severity = Severity.LOW
    weight = 1.0
    title = "Code gained capabilities"

    def evaluate_code(self, change: CodeChange) -> Sequence[Finding]:
        if change.before is None:
            return ()
        gained = change.added
        if not gained:
            return ()
        evals = C.DYNAMIC_CODE in gained and any(
            evaluates(u.use) for u in change.after.where(C.DYNAMIC_CODE)
        )
        strong = evals or (C.NETWORK in gained and bool(gained & WITH_NETWORK))
        names = ", ".join(sorted(c.value for c in gained))
        return (
            self.finding(
                f"This version's code uses {names}, which the previous version's code did not.",
                *evidence(change.after, gained),
                severity=Severity.MEDIUM if strong else Severity.LOW,
            ),
        )


RULES: Final = (CapabilityGained(),)
