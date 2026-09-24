"""Kitsunox — detects source-level software supply chain attacks (malicious commits
and pull requests) using a tiered funnel: cheap deterministic rules (Tier 0) filter
the bulk of changes, and only ambiguous/high-scoring ones are escalated to an LLM
(Tier 2). See docs/Plan.md for the full design and semester schedule.
"""
