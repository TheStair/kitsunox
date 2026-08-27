"""Tier 2 — gated LLM reasoning.   [STUB — not built this pass]

Only invoked when Tier 0/1 score exceeds threshold or the pattern is novel/ambiguous.

Planned shape:
  - first-pass triage with a small/cheap model (Claude Haiku 4.5)
  - escalate the residual to a stronger model (Claude Sonnet 5)
  - input: specific diff hunks / install-script content ONLY — never whole files/repos
  - output: structured verdict {malicious|suspicious|benign} + confidence + rationale trace
    (explainability matters for the final presentation)
  - token/cost accounting per event, aggregated for the evaluation write-up

Use the Anthropic SDK (``anthropic`` extra) with structured outputs for the verdict schema.
"""
