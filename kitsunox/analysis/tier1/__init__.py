"""Tier 1 — structural / metadata risk scoring.   [STUB — not built this pass]

Produces a *risk score*, not a verdict. No LLM. Planned checks:
  - maintainer / account-change detection (highest-signal cheap check)
  - publish-cadence deviation per package (dormant -> sudden publish)
  - version-jump anomaly (patch bump w/ huge diff; major bump w/ tiny diff)
  - dependency-graph diffing (new transitive deps, git/tarball specs, pinning removed)

Much of the raw signal already lands in ``package_baseline`` (see
``kitsunox.db.repo.Repository.observe_publish_for_baseline``) and in the pre-score
reasons; Tier 1 turns those into a calibrated score that gates Tier 2.
"""
