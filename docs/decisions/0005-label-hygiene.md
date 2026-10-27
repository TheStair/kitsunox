# 0005: Label hygiene: which OSV matches count as malicious

**Date:** 2026-10-27
**Status:** Accepted
**Affects:** evaluation ground truth (`evaluation/labels.py`, `evaluation/dataset.py`); later,
the Stage 4 known-bad lookup

## Context

The first real 24h run (`20261027T210847Z-npm`, 109,497 changes) matched 29 releases against
OSV `MAL-` records. On inspection, none of them was attacker code:

- **27 were npm's own takedown placeholders**, published by the `npm` account after the
  malicious version had already been removed. Most packages had two: `0.0.1-security` and a
  `0.0.0-stage` stub, published about a minute apart. For example, `paychex-pdftron`'s record
  (MAL-2026-18289, published 2026-10-25) names `99.9.1`, a dependency-confusion version. That
  version was gone before the window opened, but the record's range is "introduced 0", so it
  matched the stubs. In total the run held 41 placeholders, all from the `npm` account.
- **2 were legitimate builds.** `@magda/semantic-indexer-sdk@7.1.0-pr.3888.0` and `.1` were
  published by GitLab CI with trusted publishing. They matched MAL-2025-47009, a September 2025
  record about the Shai-Hulud compromise of earlier versions. The record lists 23 versions
  explicitly, plus an open range covering every version, including future ones.

Counted as malicious, these would have produced a baseline "recall 0/29" for popularity-only,
and later detection rules would have been graded on placeholders.

## Options

1. **Only explicitly listed versions count.** Precise, but 86% of npm MAL records rely on the
   open "introduced 0" range, and many list no versions. Most real shape-B samples would be
   lost.
2. **All matches count (previous behaviour).** Every takedown placeholder and every later build
   of a once-compromised package becomes "malicious".
3. **Open ranges count only for releases published no later than the record, and registry
   placeholders never count.** Listed versions and bounded ranges always count.

## Decision

Option 3.

- An open-ended range is evidence about what existed when the analyst wrote the record. For a
  release published after the record, it is a projection, so the release is excluded as
  `label-projected` rather than labeled either way.
- npm placeholders (`publisher == "npm"` and either `stub: true` or version `0.0.1-security`) are
  excluded as `registry-placeholder`. Requiring the `npm` account matters, because anyone can
  publish a version string like `0.0.1-security`.
- Both are counted in `EvalDataset.excluded`, so the size of each exclusion is visible.

## Consequences

- The first run has **0 malicious samples**, which is the honest result for a single run:
  everything malicious was taken down before the run fetched it.
- Prospective labeling still works. A malicious release recorded at T is published before a
  record written at T+hours, so the open range counts.
- **Remaining risk.** A malicious package re-published by its attacker after the record (same
  name, new version) is excluded rather than labeled. That is a small recall cost in the
  evaluation set, not in the pipeline itself.
- **Possible Stage 1 signal (not decided).** Placeholders mark a confirmed takedown, so they
  could feed a "this name was malicious" signal, for example for typosquat neighbours.
