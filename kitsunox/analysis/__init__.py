"""Analysis tiers.

- ``tarball``      — fetch/unpack/diff published tarballs (Tier 0 input)
- ``tier0``        — deterministic pattern / IOC / heuristic scan (no LLM)
- ``tier1``        — structural / metadata risk scoring (stub this pass)
- ``tier2``        — gated LLM reasoning (stub this pass)
- ``scanner``      — orchestrates Tier 0 over a PublishEvent
"""
