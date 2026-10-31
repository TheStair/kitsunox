# 0016: After-the-fact confirmations are a flag, never a score

**Status:** accepted 2026-10-31 (the owner's decision).

## Context

npm removes malicious packages, usually hours to days after they appear, and replaces each with
an empty `0.0.1-security` "security holding package" published from its own `npm` account. That
publish reaches the registry's changes feed like any other, so Stage 0 already records it. OSV's
`MAL-` records (mirrored from ossf/malicious-packages, synced daily) often follow the same day:
the three packages npm removed after we had reported them all had a record within hours.

Both could be used two ways:

- **as detection**, e.g. a rule that scores a release depending on a removed name, or that
  raises a package once npm removes another of its publisher's;
- **as a check**: mark a version that someone else later called malware, next to our own
  verdict on it.

## Decision

1. **Never a rule or a score.** Kitsunox has to find malware from its own evidence; a takedown
   says nothing the pipeline found, and recall measured with it would no longer measure the
   pipeline. (The existing `npm.dependency.known-malware`, which reads OSV records about a
   *dependency*, predates this and is unchanged.)
2. **A flag, after the fact.** `evaluation/confirmations.py`: `collect` scans each new run's
   `changes.jsonl` for holders and keeps them in `data/takedowns/<ecosystem>.json` (runs are
   pruned after a week; the log is not). The queue reads that log and the newest label set
   fetched by its `as_of`, and attaches to each version the takedowns published after it and
   the OSV records covering it.
3. **Shown where a reviewer acts.** Queued versions carry the flag; versions with a verdict
   that were confirmed since are counted per verdict, and benign or inconclusive ones are listed
   to review again (index.md and the viewer's queue, verdict and entry pages).

## Consequences

- A benign verdict contradicted later is surfaced instead of forgotten; an inconclusive one is
  settled by someone with more evidence (npm sees abuse reports and the account).
- Confirmed malicious verdicts are an outside measure of precision, at no cost: no extra
  requests, a scan of files already on disk (20 s for a week of runs once, under a second a
  tick after that).
- What it can't see: packages npm unpublishes without a holder, takedowns of names whose
  holder publish fell in an ingest gap, and malware nobody else has found yet. Silence is not
  evidence of benign.
