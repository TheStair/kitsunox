"""Instructions aimed at an AI coding agent that work against its user (Stage 3).

A package that copies skills or instruction files (`SKILL.md`, `AGENTS.md`, `.cursor/rules`)
into an agent's configuration at install time plants text the agent will follow. The owner
rules such packages benign when the text is what it says (decision 0015, addendum 2026-11-08);
text telling the agent to hide what it does, to ignore its earlier instructions, to switch off
its safeguards, or to send credential files away is the prompt-injection shape, and reports the
version (proposal round 2, S3 guard 3). The text is untrusted data: it is matched, never
followed (`kitsunox.lang.agent_config.hostile_instructions`)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from kitsunox.core.models import Evidence, EvidenceKind, Finding, Severity
from kitsunox.core.rules import BaseRule
from kitsunox.lang.agent_config import TEXT_SUFFIXES, hostile_instructions
from kitsunox.stages.ast import CodeChange

MAX_SHOWN: Final = 3


class HostileInstructions(BaseRule):
    """Agent text the install code may copy (`CodeChange.agent_files`: only when the install
    code names an agent directory) tells the agent to work against the user.

    Added 2026-11-08 (`docs/proposals/precision-round2.md`, S3 guard 3); measured in
    `docs/stages/ast.md`."""

    id = "agent.hostile-instructions"
    severity = Severity.MEDIUM
    weight = 3.0
    title = "Agent instructions work against the user"

    def evaluate_code(self, change: CodeChange) -> Sequence[Finding]:
        found = [
            (path, line, what, text)
            for path, content in sorted(change.agent_files.items())
            if path.lower().endswith(TEXT_SUFFIXES)
            for line, what, text in hostile_instructions(content)
        ]
        if not found:
            return ()
        whats = sorted({what for _, _, what, _ in found})
        paths = sorted({path for path, _, _, _ in found})
        return (
            self.finding(
                f"Agent instructions the install code may copy tell the agent to "
                f"{'; to '.join(whats)}: {', '.join(paths[:MAX_SHOWN])}.",
                *(
                    Evidence(
                        kind=EvidenceKind.FILE_SPAN,
                        path=path,
                        line_start=line,
                        line_end=line,
                        snippet=text,
                    )
                    for path, line, _, text in found[:MAX_SHOWN]
                ),
            ),
        )


RULES: Final = (HostileInstructions(),)
