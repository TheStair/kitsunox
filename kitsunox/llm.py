"""Tier 2 — minimal LLM escalation. Only called for changes whose Tier 0 score crosses
a threshold (decided by evaluate.py, not here).

Needs:

- A prompt-building function that takes a `Change` + its Tier 0 `Finding`s and builds a
  bounded prompt: only the specific flagged diff hunks and the rule rationales that
  fired — never the whole diff, never the whole repo. Needs a truncation strategy for
  the (hopefully rare) case where even the flagged hunks are too large.

- One Claude API call (single model to start — no Haiku/Sonnet cascade yet) that
  returns a structured verdict: `malicious` / `suspicious` / `benign`, a confidence
  value, and a short rationale explaining which signals drove the call. Use the
  Anthropic SDK's structured output support so the verdict is parseable, not
  free-text.

- Token/cost accounting per call (input/output tokens, estimated $ cost), returned
  alongside the verdict so evaluate.py can aggregate a total for the cost-accounting
  part of the write-up.

- Must not be called at all when Tier 0 doesn't escalate — this module has no business
  logic for deciding *whether* to run, only *what to do* once asked to run.
"""
