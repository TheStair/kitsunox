"""The rule contract shared by every analysis stage.

A rule is small and single-purpose: it looks at one change and returns zero or more findings,
each with evidence a reviewer can check. Rules are deterministic: they read only the change and
the `RuleContext` (never the clock, the network or the environment), so the same input and rule
versions always give the same findings. A rule's `version` is bumped whenever its behaviour
changes, and is recorded on every finding.

Ecosystem-agnostic rules live in `rules/`; rules that read ecosystem concepts (npm `scripts`,
`_npmUser`) live in `ecosystems/<eco>/rules/`.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import ClassVar, Protocol

from kitsunox.core.models import Change, Evidence, Finding, Record, Severity


class RuleContext(Record):
    """Everything a rule may know besides the change itself."""

    as_of: datetime


class Rule(Protocol):
    @property
    def id(self) -> str: ...

    @property
    def version(self) -> int: ...

    def evaluate(self, change: Change, ctx: RuleContext) -> Sequence[Finding]: ...


class BaseRule:
    """Convenience base: subclasses set the class attributes and call `finding()`."""

    id: ClassVar[str]
    version: ClassVar[int] = 1
    severity: ClassVar[Severity]
    weight: ClassVar[float]
    title: ClassVar[str]

    def finding(
        self,
        explanation: str,
        *evidence: Evidence,
        severity: Severity | None = None,
    ) -> Finding:
        return Finding(
            rule_id=self.id,
            rule_version=self.version,
            severity=severity or self.severity,
            weight=self.weight,
            title=self.title,
            explanation=explanation,
            evidence=evidence,
        )


def run_rules(rules: Sequence[Rule], change: Change, ctx: RuleContext) -> tuple[Finding, ...]:
    """All findings, in rule order (then each rule's own order)."""
    return tuple(finding for rule in rules for finding in rule.evaluate(change, ctx))
