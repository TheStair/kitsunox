"""Stage 2 file rule: code pushed out of sight by a long run of whitespace on its line.

`hauntview@0.2.9` (live, 2026-11-09, malicious) added one line to its `postinstall.mjs` and to
`dist/cli.js`: 266 tabs, then 12,433 characters of an obfuscated loader (an Ethereum
transaction lookup for its C2 address, an XOR-decoded download, `eval`, a detached
`node -i`). In an editor or a diff viewer the line reads as blank. No other Stage 2 rule saw
it (no literal `eval`, no `_0x` names, shuffled strings full of punctuation) and Stage 3 found
no new capability, so it was reported only because its install script changed.

Formatters and minifiers never write such a line: a minifier removes whitespace, and
indentation that deep (100 or more columns) is generated data or ASCII art, not code. The
rule asks for the run, then code on the same line, and nothing in front of the run but more
code or nothing at all. The thresholds and what is excluded come from live and `vm-day1` data
(`docs/stages/static.md`, `docs/proposals/precision-round4-F.md`).
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import ClassVar, Final

from kitsunox.core.models import Severity
from kitsunox.core.rules import FileMatch
from kitsunox.util.text import collapse_runs


class PaddedCode:
    """A line with a run of at least `MIN_RUN` spaces or tabs, then at least `MIN_CODE`
    characters of code. Not counted:

    - a tail that starts a comment (`//`, `/*`, `*`, `#`, `<!--`) or a markup or table cell
      (`|`, `<`): documentation and tables align with whitespace;
    - a line whose text before the run is open inside a string (an odd count of one quote
      kind): padding inside a literal is data, not hidden code;
    - text with no code punctuation in its first `WINDOW` characters: a `(` or `=`, and a `;`,
      `{`, `)`, `[` or `,` (prose and word lists have none; a string array opening the payload,
      `const _0x38d0=["W1hEQVwF",...`, has `=`, `[` and `,`);
    - indentation that the line before already nearly has (less than `MIN_RUN` deeper): code
      generated with deep nesting grows its indentation a level at a time (`@motir/cli`'s
      compiled JSON-schema validators, 106 spaces), hidden code jumps there from the margin.

    v2 (2026-11-10, round 4 G): shell code counts as code too, a tail that starts by chaining a
    command (`;`, `&&`) or pipes into a shell or `iex` (`; curl -s x | sh` has no `(` or `=`).
    On agent F's scans (every 100/200 run in the verdicted live versions and the `vm-day1`
    samples it read) it adds no match.

    MEDIUM (weight 3), one finding per file: the first such line."""

    id: ClassVar[str] = "static.padded-code"
    version: ClassVar[int] = 2
    severity: ClassVar[Severity] = Severity.MEDIUM
    weight: ClassVar[float] = 3.0
    title: ClassVar[str] = "Code hidden behind a long run of whitespace"
    MIN_RUN: ClassVar[int] = 100
    MIN_CODE: ClassVar[int] = 200
    SHOWN: ClassVar[int] = 160
    WINDOW: ClassVar[int] = 1_000
    # A run starts where the whitespace does (the lookbehind), so a long run is matched once.
    _RUN: ClassVar[re.Pattern[str]] = re.compile(r"(?<![ \t])[ \t]{100,}(?=\S)")
    _NOT_CODE: ClassVar[re.Pattern[str]] = re.compile(r"(?://|/\*|\*|#|<!--|\||<)")
    # v2: shell code has neither `(` nor `=`: a tail that chains a command (`; curl -s x | sh`,
    # `&& ./x`) or pipes into a shell or `iex` is code too.
    _SHELL_CHAIN: ClassVar[re.Pattern[str]] = re.compile(r"(?:;|&&)\s*[\w./$~\"'-]")
    _SHELL_PIPE: ClassVar[re.Pattern[str]] = re.compile(
        r"\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\|\s*iex\b", re.IGNORECASE
    )

    def evaluate_text(self, text: str) -> Sequence[FileMatch]:
        line_start = line_end = code_end = -1
        for match in self._RUN.finditer(text):
            if match.start() > line_end:  # a new line; runs on one long line share its bounds
                line_start = text.rfind("\n", 0, match.start()) + 1
                line_end = text.find("\n", match.end())
                line_end = len(text) if line_end == -1 else line_end
                code_end = line_end
                while code_end > line_start and text[code_end - 1] in " \t\r":
                    code_end -= 1
            length = code_end - match.end()
            if length < self.MIN_CODE:
                continue
            # Only a window of the tail and of the lead is read, so a long line with many runs
            # costs linear time (a 2.4 MB line of 20,000 runs).
            tail = text[match.end() : match.end() + self.WINDOW]
            lead = text[max(line_start, match.start() - self.WINDOW) : match.start()]
            if not self._code(lead, tail):
                continue
            if match.start() == line_start and (
                len(match.group(0)) - _previous_indent(text, line_start) < self.MIN_RUN
            ):
                continue  # deep indentation that grew step by step: generated nested code
            run = match.group(0)
            tabs = run.count("\t")
            kind = "tabs" if tabs == len(run) else "spaces" if not tabs else "spaces and tabs"
            shown = collapse_runs(lead[-40:] + run + tail[: self.SHOWN])
            return [
                FileMatch(
                    rule_id=self.id,
                    rule_version=self.version,
                    severity=self.severity,
                    weight=self.weight,
                    title=self.title,
                    explanation=(
                        f"A line holds {len(run)} {kind}, then {length} characters of "
                        "code: off screen in an editor or a diff, so the code reads as a "
                        "blank line."
                    ),
                    line=text.count("\n", 0, match.start()) + 1,
                    snippet=shown + ("..." if length > self.SHOWN else ""),
                )
            ]
        return []

    def _code(self, lead: str, tail: str) -> bool:
        if self._NOT_CODE.match(tail):
            return False
        if any(lead.count(q) % 2 for q in "\"'`"):
            return False
        if ("(" in tail or "=" in tail) and any(c in tail for c in ";{)[,"):
            return True
        return bool(self._SHELL_CHAIN.match(tail) or self._SHELL_PIPE.search(tail))


MAX_LOOK_BACK: Final = 20  # lines


def _previous_indent(text: str, line_start: int) -> int:
    """The leading spaces and tabs of the nearest non-blank line before the one starting at
    `line_start` (at most `MAX_LOOK_BACK` lines back; 0 if there is none)."""
    end = line_start - 1
    for _ in range(MAX_LOOK_BACK):
        if end <= 0:
            return 0
        start = text.rfind("\n", 0, end) + 1
        line = text[start:end]
        body = line.lstrip(" \t")
        if body.strip():
            return len(line) - len(body)
        end = start - 1
    return 0
