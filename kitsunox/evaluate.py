"""Orchestrates the full evaluation run (docs/Plan.md §7) and produces the report.

Needs:

- The fixed control-sample repo list (psf/requests, pallets/flask, expressjs/express,
  axios/axios) — fetch ~25-40 recent merged PRs from each via
  `fetch.fetch_merged_prs`, each labeled `ground_truth="benign"`.

- Pull the ground-truth incidents from `incidents.py` (already labeled "malicious").

- Run every `Change` (incidents + control sample) through `rules.py` to get a score
  and `Finding`s; for changes whose score crosses the escalation threshold, also run
  `llm.py` and record its verdict.

- Compute and report:
    - detection rate: fraction of the 5 incidents flagged malicious/suspicious
    - false-positive rate: fraction of the control sample flagged
    - cost accounting: total changes seen, how many escalated to Tier 2, total
      tokens/$ spent on Tier 2 calls
    - per-incident detail suitable for the "here's the exact commit and what fired"
      walkthroughs mentioned in the plan (especially xz-utils)

- Write the report to a file (plain JSON and/or Markdown is enough — no dashboard
  needed) and also print a short human-readable summary to stdout.

- Should be runnable in pieces (incidents only, control sample only, or both) so
  Tier 0 tuning (week 5 in the schedule) doesn't require a full run every time.

This is the only module that decides the Tier 0 -> Tier 2 escalation threshold; keep
that decision out of rules.py and llm.py so it's tunable in one place.
"""
