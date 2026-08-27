"""Tier 0 — deterministic pre-filters. No LLM. Runs on every routed event.

- ``iocs``       — known-malicious package / dependency lookups (Claude-owned plumbing)
- ``patterns``   — known-bad code constructs in changed files / install scripts (USER-owned)
- ``heuristics`` — new blobs, entropy spikes, new install scripts, dep-pinning loss (USER-owned)
"""
