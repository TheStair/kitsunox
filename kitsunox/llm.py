"""Tier 2 — minimal LLM escalation (docs/Plan.md §4).

Called only for changes whose Tier 0 evidence score crosses the threshold. This module
decides *what to send and how to read the answer*; `evaluate.py` decides *whether to
call it at all*. Keeping that split matters for the cost accounting in §7 — every call
this module makes is a call Tier 0 chose to pay for.

Three constraints shape the design:

**The whole change, annotated.** Tier 0 says *where to look*; Tier 2 reviews the change.
It receives every file's full diff plus the commit message, with the flagged lines marked,
because a hunk cannot be judged without the code around it — and because the pre-filter
misses things. What it does *not* get is the repository: that is Tier 3's job.

**Structured output.** The verdict comes back as a validated `Verdict` via
`client.messages.parse`, not as free text to be regex'd. An unparseable verdict is a
failed measurement, not something to guess at.

**Measured cost.** Every call returns its token counts and an estimated dollar figure so
§7 can report what the tiered funnel actually cost, rather than asserting that it is
cheap. Tier 2 is always exactly one call; only an ambiguous verdict escalates to the
multi-call Tier 3 below.

Nothing here runs unless called. Constructing the module makes no network request, and
no API key is read until `review()` is first invoked.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

from dotenv import load_dotenv
from pydantic import BaseModel, Field

from kitsunox.model import Change, FileDiff, Finding

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

# Ceiling on the diff sent. Tier 2 reviews the whole change, so this is sized for a
# real commit rather than a snippet: ~60KB is roughly 15-20k tokens, a few cents on a
# change that Tier 0 already decided was worth paying for. Flagged files are rendered
# first so that whatever survives truncation is what Tier 0 objected to.
MAX_DIFF_CHARS = 60_000

# Per-file ceiling for files Tier 0 did *not* flag. They are context, and one enormous
# vendored bundle should not crowd out the rest of the change.
PER_FILE_CHARS = 6_000

# Commit messages are short; a runaway one is usually a squashed changelog.
MAX_MESSAGE_CHARS = 4_000

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


def _flagged_lines(diff: FileDiff, hits: list[Finding]) -> set[int]:
    """Patch-text line offsets that tripped a rule, for the `>>>` markers."""
    offsets: dict[int, int] = {}
    lineno = 0
    for idx, raw in enumerate(diff.patch.split("\n")):
        if raw.startswith("@@"):
            match = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)", raw)
            if match:
                lineno = int(match.group(1))
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            offsets.setdefault(lineno, idx)
            lineno += 1
        elif not raw.startswith("-"):
            lineno += 1
    return {offsets[h.line] for h in hits if h.line is not None and h.line in offsets}


def _render_file(diff: FileDiff, hits: list[Finding], budget: int) -> tuple[str, bool]:
    """Render one file's full patch, marking the lines Tier 0 flagged.

    Returns (text, truncated). Markers matter: without them a long diff buries the few
    lines the pre-filter actually objected to.
    """
    header = f"--- {diff.path} ({diff.change_type}, +{diff.additions}/-{diff.deletions})"
    if hits:
        header += "   [flagged: " + ", ".join(sorted({h.rule_id for h in hits})) + "]"
    if diff.is_binary:
        return header + "\n    <binary file; contents not shown>", False
    if not diff.patch:
        return header + "\n    <no diff available>", False

    marked = _flagged_lines(diff, hits)
    lines = diff.patch.split("\n")
    out, truncated, used = [header], False, len(header)
    for idx, raw in enumerate(lines):
        rendered = ("  >>> " if idx in marked else "      ") + raw
        if used + len(rendered) > budget:
            out.append(f"      <... {len(lines) - idx} more lines of this file omitted>")
            truncated = True
            break
        out.append(rendered)
        used += len(rendered) + 1
    return "\n".join(out), truncated


def _render_diff(change: Change, findings: list[Finding]) -> tuple[str, bool]:
    """Render the whole commit, flagged files first.

    Every file is included, not only the flagged ones. Tier 0 says *where to look*; a
    reviewer still needs the code around the hit and the files Tier 0 was silent about —
    in one early run the model explicitly noted it was missing "a sixth unshown file that
    could be the harness", which was true and entirely our doing.

    Ordering by flagged-first means that when a change is too large to send whole, what
    survives truncation is what Tier 0 objected to.
    """
    by_path: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.file_path:
            by_path.setdefault(finding.file_path, []).append(finding)

    ordered = sorted(change.files, key=lambda f: (f.path not in by_path, f.path))
    blocks, truncated, used = [], False, 0

    for diff in ordered:
        remaining = MAX_DIFF_CHARS - used
        if remaining < 400:
            blocks.append(f"<... {len(ordered) - len(blocks)} further files omitted for length>")
            truncated = True
            break
        # Flagged files get a bigger share; unflagged ones are context.
        share = remaining if diff.path in by_path else min(remaining, PER_FILE_CHARS)
        text, cut = _render_file(diff, by_path.get(diff.path, []), share)
        truncated = truncated or cut
        blocks.append(text)
        used += len(text)

    return "\n\n".join(blocks), truncated


def build_prompt(change: Change, findings: list[Finding], *, anonymize: bool = False) -> str:
    """Assemble the Tier 2 prompt: the full change, annotated with what Tier 0 flagged.

    Deliberately excludes `change.ground_truth` and every `Finding.precedent`: Tier 2 is
    measured against that label, and naming the incident a rule was derived from hands it
    the answer.

    `anonymize` additionally withholds the repository and author names. Every incident in
    the ground-truth set is a famous, heavily-documented public attack, so a model can
    recognise `tukaani-project/xz` + `JiaT75` and answer from training data rather than
    from the evidence — in the first Tier 2 run it cited CVE-2024-3094 by number.

    This is a *partial* control and must be reported as one: file paths and diff contents
    stay, because they are the evidence. Full de-identification would mean deleting what
    is being judged.
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

    if change.message.strip():
        label = "Pull request title and body" if change.source == "pr" else "Commit message"
        body = change.message.strip()
        if len(body) > MAX_MESSAGE_CHARS:
            body = body[:MAX_MESSAGE_CHARS] + " [...truncated]"
        lines.append(f"\n{label} (stated intent — check it against what the diff does):")
        lines.append("\n".join("    " + ln for ln in body.split("\n")))

    lines.append("\nWhat the pre-filter flagged, and why:")
    for finding in sorted({f.rule_id: f for f in findings}.values(), key=lambda f: f.rule_id):
        where = f" ({finding.file_path})" if finding.file_path else ""
        lines.append(f"- [{finding.severity}] {finding.rule_id}{where}: {finding.rationale}")

    body, truncated = _render_diff(change, findings)
    lines.append(
        "\nThe complete change follows. Lines the pre-filter objected to are marked "
        "`>>>`; everything else is the surrounding change, included so you can judge the "
        "flagged code in context and notice anything the pre-filter missed.\n"
    )
    lines.append(body if body.strip() else "<no diff content available>")
    if truncated:
        lines.append(
            "\n[This change was too large to include whole. Flagged files were kept in "
            "full and shown first. If the omitted portion is something you would have "
            "needed, say suspicious rather than guessing.]"
        )

    lines.append(
        "\nReview this change. Give a verdict, a confidence, and a short rationale naming "
        "the specific evidence — including anything the pre-filter did not flag, and any "
        "mismatch between what the change says it does and what it actually does."
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
