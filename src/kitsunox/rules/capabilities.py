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
from kitsunox.lang.javascript import (
    CONSTRUCTOR_CHAIN,
    FUNCTION_ALIASES,
    GIVEN_LOADER,
    Capability,
    Use,
)
from kitsunox.stages.ast import CodeChange, PathUse, Profile

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
#
# v4 (2026-10-31): after a base whose code used no capability at all (a placeholder release:
# `0.0.0-placeholder`, `1.0.0-reservation.0`), gaining network with another of WITH_NETWORK is
# LOW, as for a new package; `eval` stays MEDIUM. 11 of the live queue's unreviewed reports
# were such first real releases. Making `eval` LOW too cost 18 `vm-day1` malicious samples,
# every one an `eval(` payload after an empty first version (`autotel-*`, `awaitly-*`); this
# way none is lost and one benign sample is no longer reported.
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
    version = 4
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
        combined = C.NETWORK in gained and bool(gained & WITH_NETWORK)
        strong = evals or (combined and bool(change.before.capabilities))
        names = ", ".join(sorted(c.value for c in gained))
        return (
            self.finding(
                f"This version's code uses {names}, which the previous version's code did not.",
                *evidence(change.after, gained),
                severity=Severity.MEDIUM if strong else Severity.LOW,
            ),
        )


def constructs_functions(where: Profile) -> tuple[PathUse, ...]:
    """Uses of the Function constructor reached through `constructor` (`FUNCTION_ALIASES`)."""
    return tuple(u for u in where.where(C.DYNAMIC_CODE) if u.use.detail in FUNCTION_ALIASES)


def strong(use: Use) -> bool:
    """The constructor of a constructor (plain `Function`), or any form in a file that hands it
    `require`, `process` or `module`."""
    return use.detail.startswith(CONSTRUCTOR_CHAIN) or use.detail.endswith(GIVEN_LOADER)


class FunctionConstructor(BaseRule):
    """Code reaches the Function constructor without naming it. It runs built code as `eval`
    does, written so that it reads as neither `eval` nor `Function`. `txnforge` and
    `mock-datas-lib` (2026-11-02) ran a Python dropper through
    `globalThis.constructor.constructor` (split over two variables), and nothing else in
    Stages 2-3 fired. New packages count, since that is where such droppers are published; on
    an update, only a form the previous version's code didn't use.

    MEDIUM for the constructor of a constructor (`x.constructor.constructor`, which is plain
    `Function`: code that isn't hiding names it) and for any form in a file that passes
    `require`, `process` or `module` to a call or names one as a parameter of the built
    function (`(function () {}).constructor("require", body)(require)`). LOW for a function
    literal's constructor otherwise (`Object.getPrototypeOf(async function () {}).constructor`):
    the only way to build an *async* function from text, which code-mode executors and
    expression compilers use. Measurements: `docs/stages/ast.md`."""

    id = "code.function-constructor"
    version = 1
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Reaches the Function constructor through `constructor`"

    def evaluate_code(self, change: CodeChange) -> Sequence[Finding]:
        seen = (
            {u.use.detail for u in constructs_functions(change.before)} if change.before else set()
        )
        found = sorted(
            (u for u in constructs_functions(change.after) if u.use.detail not in seen),
            key=lambda u: not strong(u.use),
        )
        if not found:
            return ()
        medium = strong(found[0].use)
        return (
            self.finding(
                "This version's code takes the Function constructor from "
                + (
                    "an object's `constructor` chain instead of naming `Function`"
                    if found[0].use.detail.startswith(CONSTRUCTOR_CHAIN)
                    else "a function literal's `constructor` (an async or generator function "
                    "built from text)"
                )
                + (
                    ", in a file that hands Node's `require`, `process` or `module` to code"
                    if found[0].use.detail.endswith(GIVEN_LOADER)
                    else ""
                )
                + ": a way to run code built at runtime that searches for `eval` and "
                "`Function` don't find.",
                *(
                    Evidence(
                        kind=EvidenceKind.FILE_SPAN,
                        path=u.path,
                        line_start=u.use.line,
                        line_end=u.use.line,
                        snippet=f"[{u.use.detail}] {u.use.snippet}",
                    )
                    for u in found[:EVIDENCE_PER_CAPABILITY]
                ),
                severity=None if medium else Severity.LOW,
                weight=None if medium else 1.0,
            ),
        )


RULES: Final = (CapabilityGained(), FunctionConstructor())
