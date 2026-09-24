"""Tier 2 — minimal LLM escalation (docs/Plan.md §4).

Called only for changes whose Tier 0 evidence score crosses the threshold. This module
decides *what to send and how to read the answer*; `evaluate.py` decides *whether to
call it at all*. Keeping that split matters for the cost accounting in §7 — every call
this module makes is a call Tier 0 chose to pay for.

Three constraints shape the design:

**Bounded input.** Only the hunks that actually tripped a rule are sent, with a little
surrounding context, never the whole diff and never the repository. A change can touch
300 files; a Tier 2 prompt should be a few kilobytes. `build_prompt` enforces this and
says plainly when it has truncated.

**Structured output.** The verdict comes back as a validated `Verdict` via
`client.messages.parse`, not as free text to be regex'd. An unparseable verdict is a
failed measurement, not something to guess at.

**Measured cost.** Every call returns its token counts and an estimated dollar figure so
§7 can report what the tiered funnel actually cost, rather than asserting that it is
cheap.

Nothing here runs unless called. Constructing the module makes no network request, and
no API key is read until `review()` is first invoked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from dotenv import load_dotenv
from pydantic import BaseModel, Field

from kitsunox.model import Change, Finding

# Loaded here rather than relying on fetch.py having been imported first — this module
# must work standalone.
load_dotenv()

# Default model. The cost-accounting run in §7 is the right place to decide whether a
# cheaper model holds up on this task — change it here and re-run, don't scatter model
# ids through the codebase.
MODEL = "claude-opus-5"

# USD per million tokens for MODEL. Update alongside MODEL; these two are a pair.
INPUT_COST_PER_MTOK = 5.00
OUTPUT_COST_PER_MTOK = 25.00

# Reasoning depth. Sweeping this low/medium/high against the ground-truth set is a
# cheap experiment and belongs in week 8's cost run — a security verdict on a diff is
# not obviously a task that repays maximum effort.
EFFORT: Literal["low", "medium", "high", "xhigh", "max"] = "high"

MAX_TOKENS = 4096

# Ceiling on the evidence sent. Tier 0 flags a handful of lines; anything approaching
# this means a rule matched a generated file, and sending more would not help the model.
MAX_EVIDENCE_CHARS = 12_000
HUNK_CONTEXT_LINES = 3

SYSTEM_PROMPT = """\
You are reviewing a single change to a source repository for signs of a software supply \
chain attack — malicious code introduced through repository access, CI/build tampering, \
or a compromised or newly-trusted maintainer.

You are given only the parts of the change that a deterministic pre-filter flagged, plus \
why each was flagged. You are not given the rest of the diff or the repository.

Judge the change on the evidence shown. Two failure modes to avoid:

- The pre-filter is pattern-based and fires on plenty of legitimate code. Minified \
bundles, test fixtures, build tooling and vendored dependencies all look alarming to a \
regex. If the flagged code has an ordinary explanation, say benign and say why.
- Absence of evidence in what you were shown is not evidence of absence. If the flagged \
excerpt is genuinely ambiguous without the surrounding code, say suspicious rather than \
guessing either way.

Reserve "malicious" for evidence of intent to harm: exfiltration of secrets or \
credentials, code fetched and executed from an attacker-controlled endpoint, deliberate \
sabotage, or a payload concealed to survive review. Judge the change, not the author.\
"""


class Verdict(BaseModel):
    """The structured response Tier 2 must return."""

    verdict: Literal["malicious", "suspicious", "benign"] = Field(
        description="malicious: evidence of intent to harm. suspicious: genuinely "
        "ambiguous on the evidence shown. benign: an ordinary explanation fits."
    )
    confidence: float = Field(
        ge=0.0, le=1.0, description="Confidence in the verdict, 0.0 to 1.0."
    )
    rationale: str = Field(
        description="Two or three sentences naming the specific evidence that drove the "
        "verdict. Reference the file and what the code does, not the rule that fired."
    )
    decisive_files: list[str] = Field(
        default_factory=list,
        description="Paths of the files the verdict actually turned on. Empty if none "
        "were decisive.",
    )


@dataclass
class Usage:
    """Token and cost accounting for one Tier 2 call."""

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0

    @property
    def cost_usd(self) -> float:
        """Estimated cost. Cached reads bill at roughly a tenth of input rate, which
        matters because the system prompt is identical on every call."""
        billed_input = self.input_tokens + self.cache_read_tokens * 0.1
        return (
            billed_input / 1e6 * INPUT_COST_PER_MTOK
            + self.output_tokens / 1e6 * OUTPUT_COST_PER_MTOK
        )


@dataclass
class Review:
    """A Tier 2 result: the verdict, what it cost, and the prompt that produced it.

    `verdict` is None when the call failed — a failed review must be distinguishable
    from a benign one, or §7's detection rate silently counts errors as clean.
    """

    verdict: Verdict | None
    usage: Usage = field(default_factory=Usage)
    error: str | None = None
    prompt: str = ""

    @property
    def ok(self) -> bool:
        return self.verdict is not None


def _hunks_for(change: Change, findings: list[Finding]) -> list[str]:
    """Extract just the flagged regions of the diff, with a little context.

    Findings carry a file and a line; this pulls the surrounding lines out of that
    file's patch so the model sees the code in situ rather than a bare snippet.
    """
    by_path: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.file_path:
            by_path.setdefault(finding.file_path, []).append(finding)

    files = {f.path: f for f in change.files}
    blocks: list[str] = []

    for path, hits in by_path.items():
        diff = files.get(path)
        if diff is None:
            continue
        if diff.is_binary:
            blocks.append(f"--- {path} (binary file, {diff.change_type}; contents not shown)")
            continue

        lines = diff.patch.split("\n")
        wanted: set[int] = set()
        numbered = list(enumerate(lines))
        # Map finding line numbers back onto patch offsets by walking the patch the same
        # way rules.py did, so the excerpt lands on the line that actually fired.
        offsets = {}
        lineno = 0
        for idx, raw in numbered:
            if raw.startswith("@@"):
                import re

                match = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)", raw)
                if match:
                    lineno = int(match.group(1))
                continue
            if raw.startswith("+") and not raw.startswith("+++"):
                offsets.setdefault(lineno, idx)
                lineno += 1
            elif not raw.startswith("-"):
                lineno += 1

        for hit in hits:
            idx = offsets.get(hit.line) if hit.line is not None else None
            if idx is None:
                continue
            for j in range(idx - HUNK_CONTEXT_LINES, idx + HUNK_CONTEXT_LINES + 1):
                if 0 <= j < len(lines):
                    wanted.add(j)

        if not wanted:
            # No line anchors (path-only findings). Show the head of the patch.
            excerpt = "\n".join(lines[:20])
        else:
            excerpt_lines = []
            previous = None
            for j in sorted(wanted):
                if previous is not None and j > previous + 1:
                    excerpt_lines.append("    ...")
                excerpt_lines.append(lines[j])
                previous = j
            excerpt = "\n".join(excerpt_lines)

        blocks.append(f"--- {path} ({diff.change_type})\n{excerpt}")

    return blocks


def build_prompt(change: Change, findings: list[Finding], *, anonymize: bool = False) -> str:
    """Assemble the bounded Tier 2 prompt.

    Deliberately excludes `change.ground_truth`: Tier 2 must not be told the answer it
    is being measured against.

    `anonymize` additionally withholds the repository and author names. Every incident in
    the ground-truth set is a famous, heavily-documented public attack, so a model can
    recognise `tukaani-project/xz` + `JiaT75` and answer from training data rather than
    from the evidence — in the first Tier 2 run it explicitly cited CVE-2024-3094 by
    number. Anonymising those two fields tests whether the verdict survives on evidence
    alone.

    This is a *partial* control and must be reported as one. File paths and diff contents
    stay, because they are the evidence; `tests/files/bad-3-corrupt_lzma2.xz` is itself
    recognisable. Full de-identification would mean deleting what is being judged.
    """
    lines = [
        f"Repository: {'<redacted>' if anonymize else change.repo}",
        f"Change type: {'pull request' if change.source == 'pr' else 'direct push to default branch'}",
    ]
    if change.pr_number:
        lines.append(f"Pull request: #{change.pr_number}")
    if change.author:
        lines.append(f"Author: {'<redacted>' if anonymize else change.author}")
    if change.author_tenure_days is not None:
        lines.append(
            f"Author history in this repo: first commit {change.author_tenure_days} day(s) "
            f"before this change, {change.author_prior_commits} prior commit(s)"
        )
    if change.source == "pr":
        lines.append(f"Approving reviews: {change.approving_review_count}")
        if change.merged_by:
            lines.append(
                "Merged by: <redacted>" if anonymize else f"Merged by: {change.merged_by}"
            )
    if change.checks_passed is not None:
        lines.append(f"CI checks passed: {change.checks_passed}")
    lines.append(f"Files changed: {len(change.files)}")

    lines.append("\nWhy this change was flagged:")
    for finding in sorted({f.rule_id: f for f in findings}.values(), key=lambda f: f.rule_id):
        where = f" ({finding.file_path})" if finding.file_path else ""
        lines.append(f"- [{finding.severity}] {finding.rule_id}{where}: {finding.rationale}")

    lines.append("\nFlagged code:")
    body = "\n\n".join(_hunks_for(change, findings))
    if len(body) > MAX_EVIDENCE_CHARS:
        body = (
            body[:MAX_EVIDENCE_CHARS]
            + "\n\n[truncated — the flagged regions exceeded the size limit. Judge only "
            "what is shown above, and prefer 'suspicious' over guessing if the truncation "
            "removed something you would have needed.]"
        )
    lines.append(body if body.strip() else "[no extractable diff content — judge on the metadata above]")

    lines.append(
        "\nGive a verdict on this change, with a confidence and a short rationale naming "
        "the specific evidence."
    )
    return "\n".join(lines)


def review(
    change: Change, findings: list[Finding], *, client=None, model: str = MODEL,
    anonymize: bool = False,
) -> Review:
    """Make one Claude call and return a structured verdict plus its cost.

    Never called for a change Tier 0 did not escalate — that decision belongs to
    evaluate.py. Any API failure is captured in `Review.error` rather than raised, so a
    single bad call cannot abort an evaluation run partway through.
    """
    import anthropic

    prompt = build_prompt(change, findings, anonymize=anonymize)

    if client is None:
        # Let the SDK resolve credentials rather than checking one env var: it also
        # accepts ANTHROPIC_AUTH_TOKEN, an `ant auth login` profile, and workload
        # identity federation. Checking only ANTHROPIC_API_KEY would refuse to run on a
        # machine that is perfectly well authenticated.
        try:
            client = anthropic.Anthropic()
        except Exception as exc:  # noqa: BLE001 — surfaced to the caller, never raised
            return Review(
                verdict=None,
                error=f"no Anthropic credentials available ({exc}); no call was attempted.",
                prompt=prompt,
            )

    try:
        response = client.messages.parse(
            model=model,
            max_tokens=MAX_TOKENS,
            thinking={"type": "adaptive"},
            output_config={"effort": EFFORT},
            system=[
                # One breakpoint on the system prompt: it is byte-identical across every
                # change in an evaluation run, so each call after the first reads it from
                # cache at a tenth of the input rate.
                {"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}
            ],
            messages=[{"role": "user", "content": prompt}],
            output_format=Verdict,
        )
    except anthropic.APIStatusError as exc:
        return Review(verdict=None, error=f"{exc.status_code}: {exc.message}", prompt=prompt)
    except anthropic.APIConnectionError as exc:
        return Review(verdict=None, error=f"connection error: {exc}", prompt=prompt)

    usage = Usage(
        input_tokens=getattr(response.usage, "input_tokens", 0) or 0,
        output_tokens=getattr(response.usage, "output_tokens", 0) or 0,
        cache_read_tokens=getattr(response.usage, "cache_read_input_tokens", 0) or 0,
    )

    if response.stop_reason == "refusal":
        return Review(verdict=None, usage=usage, error="model declined to answer", prompt=prompt)

    parsed = getattr(response, "parsed_output", None)
    if parsed is None:
        return Review(
            verdict=None, usage=usage, error="response did not match the Verdict schema",
            prompt=prompt,
        )
    return Review(verdict=parsed, usage=usage, prompt=prompt)
