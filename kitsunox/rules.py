"""Tier 0 — deterministic detection. No LLM. Runs on every `model.Change`.

Needs one rule function per signal (see docs/Plan.md §4 for the full table), each
taking a `Change` and returning zero or more `model.Finding`s:

- CI/workflow tampering: `.github/workflows/*` added or modified.
- Build/install script tampering: `Makefile`, `configure`, `setup.py`, `binding.gyp`,
  `m4/*`, or similar touched.
- Suspicious added file: binary file added, or a file under a path that looks like a
  test fixture but has anomalously high entropy (the xz-utils hiding technique).
- Review bypass: PR merged with zero approving reviews, or merged_by == author.
- Anomalous direct push: a push straight to the default branch by an account that
  doesn't normally push directly (needs some notion of "normal" — even a crude one,
  e.g. compare against the repo's usual merge pattern, is fine for a first pass).
- New-contributor risk: first-time contributor (via GitHub's author_association) whose
  PR touches CI or build files.
- Classic malicious code patterns in diff hunks: `eval`/`exec`, base64-decode feeding
  exec, obfuscated identifiers, secret/credential exfiltration patterns. (Can reuse the
  regex approach from the original npm-registry design — same idea, applied to git diff
  hunks instead of tarball diffs.)

Also needs:

- A scoring/aggregation function that takes a `Change` + all its `Finding`s and
  produces a single score, used by evaluate.py to decide whether to escalate to
  llm.py (Tier 2).
- Every rule must be total (never raise) and must not fetch anything over the network
  — by the time a `Change` reaches this module, all the data it needs should already
  be attached to it.
"""
