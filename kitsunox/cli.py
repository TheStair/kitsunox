"""Command-line entry point.

Needs a minimal CLI (argparse is enough — no need for a heavier framework at this
scale) that can:

- run the full evaluation (`evaluate.py`) and print/save the report
- optionally scope a run to just the incidents or just the control sample, for faster
  iteration while tuning Tier 0 thresholds
- run a single ad-hoc change through the pipeline given a repo + commit sha or PR
  number, for quick manual sanity checks (e.g. "does this fire on xz-utils")

Should stay thin — all real logic lives in evaluate.py/rules.py/llm.py/fetch.py; this
module just parses arguments and calls into them.
"""
