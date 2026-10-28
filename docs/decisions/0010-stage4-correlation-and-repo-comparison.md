# 0010: Stage 4: what it reads, how it scores, and how releases are compared with git

**Date:** 2026-10-28
**Status:** Accepted
**Builds on:** [0004](0004-git-path-parallel-to-npm.md) (tarball-vs-repo as the join between the
npm and git paths), roadmap open decision 1 (tarball-vs-repo scope)

## Context

Stages 1-3 each flag a version when one of their rules fires at MEDIUM or above. Stage 4 has
three jobs from the architecture: combine weak signals into a score, look things up in outside
knowledge (OSV malware records), and compare a release with its source repository, the signal
for code that was published to npm without passing through git.

Three measurements on `day1` shaped the design:

1. **A score threshold cannot replace the per-stage bars without losing recall.** Counting each
   rule once, "score ≥ 6" alone reports 0.1% of benign updates against 0.9% for the union of
   stage flags, but loses 2 points of recall on malicious updates and 9 on new packages.
2. **Most malicious updates the pipeline missed were never routed to Stages 2-3** (23 of 24 at
   the time), and many carried the same two LOW Stage 1 findings.
3. **Most packages don't ship their sources** (57% of 28 compared benign updates ship only build
   output), and 30% of releases can't be compared at all (the recorded commit was never pushed,
   or the repository is too large).

## Decision

- **Input: every triaged version.** Stage 4 reads `triage.jsonl` and takes Stages 2-3's version
  of the candidates they processed (`ast.jsonl`). Correlating metadata costs nothing, and only
  then can two LOW findings on an unrouted version add up.
- **Report** a version when any finding is MEDIUM or above (so recall is never below Stages 1-3
  together), or when its score reaches `REPORT_SCORE`. The **score** counts each rule once, at its
  largest weight (Stage 2 reports one finding per file), and orders the review queue.
- **Combination rules** are named rules like any other (e.g.
  `npm.combination.revived-with-new-dependency`), so every term of a score is visible.
- **Known-malware lookups** use the OSV `MAL-` label set already synced for evaluation. Only
  records that call *every* version of a dependency malware count (one compromised `chalk`
  release doesn't make `chalk` malware), and only records published by the run's `as_of`.
- **Repository comparison**
  - *Which versions* (the user's choice, from three options): versions any stage flagged, plus
    every update of a watched package, about 500 an hour. Rejected: flagged only (cheap, but can
    only corroborate) and every update with a repository (about 13k archives a day).
  - *No GitHub token, no API.* Refs come from git's smart-HTTP ref advertisement
    (`<repo>.git/info/refs`), contents from `codeload.github.com/<repo>/tar.gz/<commit>`,
    cached by commit through the immutable index. Both go through `HttpFetcher`, so runs replay.
  - *Which commit:* `gitHead` when recorded, else a release tag (`v1.2.3`, `name@1.2.3`, ...).
    The comparison records which was used, since a tag is weaker evidence.
  - *What counts:* a shipped code file that is in the repository at the same path with
    different content; and a shipped code file the repository lacks, in a directory the
    repository has, with no source file there that could have compiled to it. Build output in
    directories git ignores (`dist/`) doesn't count.
  - *Not a gate:* a network failure leaves the version without a comparison; it doesn't fail the
    run or retry. Stage 4 adds evidence; Stage 2 is the stage that must not lose data.
- **Retention** keeps Stage 4's fetches (`correlate-snapshot.json`) with the run, like Stage 2's.

## Consequences

- Unrouted versions can now be reported, but only through Stage 1 findings and combinations of
  them: their code is never read.
- The comparison only helps where a commit can be found. Malicious releases mostly record no
  `gitHead` and have no tag, so the most common case is "no commit for this version", which is
  itself the `npm.provenance.githead-dropped` signal.
- Not attempted: rebuilding packages to compare build output, GitLab and other hosts.
  (`package.json` install hooks and dependency names are compared since the same day.)
