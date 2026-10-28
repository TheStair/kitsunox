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

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import ClassVar, Protocol

from kitsunox.core.models import (
    Change,
    Evidence,
    EvidenceKind,
    Finding,
    Record,
    Severity,
    VersionSnapshot,
)
from kitsunox.util.hashing import sha256_hex


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


class FileMatch(Record):
    """One hit of a file rule, without the path: file rules see only content, so their results
    can be cached by content hash and attributed to whichever path and version carry it."""

    rule_id: str
    rule_version: int
    severity: Severity
    weight: float
    title: str
    explanation: str
    line: int
    snippet: str

    def finding(self, path: str) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            rule_version=self.rule_version,
            severity=self.severity,
            weight=self.weight,
            title=self.title,
            explanation=self.explanation,
            evidence=(
                Evidence(
                    kind=EvidenceKind.FILE_SPAN,
                    path=path,
                    line_start=self.line,
                    line_end=self.line,
                    snippet=self.snippet,
                ),
            ),
        )


class FileRule(Protocol):
    """A rule over one file's text. Must be a pure function of the content."""

    @property
    def id(self) -> str: ...

    @property
    def version(self) -> int: ...

    def evaluate_text(self, text: str) -> Sequence[FileMatch]: ...


class ArtifactRule(Protocol):
    """A rule over one version's whole package: its registry metadata and its extracted files.
    Runs where the files are available (Stage 2), e.g. to check one against the other."""

    @property
    def id(self) -> str: ...

    @property
    def version(self) -> int: ...

    def evaluate_artifact(
        self, snapshot: VersionSnapshot, files: Mapping[str, bytes]
    ) -> Sequence[Finding]: ...


def rules_fingerprint(rules: Sequence[FileRule | Rule]) -> str:
    """Identifies a rule set; changes whenever a rule is added, removed or re-versioned."""
    return sha256_hex("\n".join(sorted(f"{r.id}:{r.version}" for r in rules)).encode())[:16]
