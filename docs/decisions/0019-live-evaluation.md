# 0019: Live evaluation: ledger, two confusion matrices, a review sample and a label hold

**Status:** accepted 2026-11-08 (the owner's decisions on
[proposals/prospective-labeling.md](../proposals/prospective-labeling.md), option B).

## Context

The capstone needs TP / FP / FN / TN counts measured on what the pipeline saw live, not only on
DataDog samples. Labels arrive late (an OSV record a median ~22 h after our capture, up to a
week or more), run outputs are partly pruned after 2 days, and until now nothing joined new
labels with the decisions the pipeline had already made. The proposal measured window A
(10-29 to 11-03) by hand: 34 of 134 OSV-labeled versions reported, precision 2.8%, with 51 of
139 malicious versions labeled only after their run was pruned (26 tarballs lost).

## Decision

The owner's four answers (2026-11-08), binding for the presentation:

1. **Dispute rule: behaviour truth is primary.** A reviewer's verdict on a version, judged by
   what the code does ([0015](0015-reviewer-verdicts.md) addendum), wins over an OSV record
   about the package. The **OSV-truth** matrix (an OSV record wins) is shown alongside, and a
   third, **OSV only** (verdicts ignored), for reference. Missed OSV-labeled versions get the
   same review (`kitsunox live misses`, then `kitsunox live verdict`); a miss nobody has
   adjudicated stays malicious.
2. **Benign delay D = 7 days** for the headline: an unlabeled version is benign only once the
   label set was fetched at least 7 days after its release, provisional (left out, counted)
   before that. Sensitivity rows for D = 3 and 14, and per window the number of labels that
   came later than 3, 7 and 14 days.
3. **Rule freeze 2026-11-12 to 2026-11-19 (window B, `[11-12 00:00Z, 11-19 00:00Z)`; moved to
   2026-11-16..23 by the addendum below).** No
   rule changes in that week. The tooling shows which rule versions scored each version: every
   ledger row carries `rule_id@version` of each finding, the header Stage 4's `stage_version`
   and rule fingerprint, and, when `collect` writes the ledger in the tick that ran the stages,
   the fingerprint of every stage's rule set and the tool version. The report says per window
   whether it is single-version.
4. **The hold is approved**: for 30 days, tarballs of ≤ 64 KB, every reported version's
   tarball (and its diff base), and the review sample's tarballs (~10 GB), in
   `core/retention.py`, with a byte cap and the held bytes logged.

Defaults taken where the owner didn't decide: npm takedowns without an OSV record count as
positives only in a sensitivity row ("behaviour truth + takedowns"); the window-A misses are
adjudicated by review.

## What was built

- `evaluation/ledger.py`: a compact per-version ledger per finished run, kept for good.
- `evaluation/live.py`: the live dataset (every input hashed) and the matrices with Wilson 95%
  intervals, recall by version / OSV record / publisher account, the per-stage funnel, miss
  causes, label timing, rule firing on TP vs FP, and a results log (`data/eval/live/log.jsonl`).
- `evaluation/sample.py`: a daily, label-blind review sample of unreported versions; verdicts on
  sampled or missed versions are recorded with `kitsunox live verdict` as ordinary
  `VerdictRecord`s with **rank 0** (not in a report). No schema change: the viewer already links
  only ranks above 0.
- `collect`: ledgers as runs finish, the hold before every prune, and the daily `live-eval`
  step; one line in the Discord summary.

Definitions of every cell: [evaluation.md](../evaluation.md#live-evaluation-phase-9).

## Consequences

- Nothing here feeds a rule or a score ([0016](0016-after-the-fact-confirmations.md)).
- About 10 GB more disk at steady state (the hold), ~3 MB a day of ledgers.
- Verdicts on sampled versions count in the all-time verdict tally (Discord, viewer); they are
  mostly benign.
- The FN of malware nobody labeled is only bounded (an upper bound from the sample), never a
  point estimate.

## Addendum 2026-11-08: flag-worthy and strict matrices, unverified bounds

Reviewer verdicts now come in four categories ([0015](0015-reviewer-verdicts.md), addendum
"four categories"): malicious, unwanted, benign, unverified (with a reason tag). The owner
decided how each one counts:

- **Headline: flag-worthy** (matrix `behaviour`). Behaviour truth with `malicious` and
  `unwanted` as positives and `benign` as a negative. An OSV record doesn't override a
  reviewer's `unwanted` or `benign`.
- **Strict, malicious only** (matrix `strict`), shown beside it: the same, with `unwanted` a
  negative. A reported unwanted version is an FP here.
- **`unverified` is excluded from both**, counted under "unverified", with bounds:
  - *best case* (`behaviour/best`, `strict/best`): every unverified version is what the
    pipeline decided: reported ones malicious (TP), unreported ones benign (TN);
  - *worst case* (`behaviour/worst`, `strict/worst`): the opposite (FP, FN).

  The owner put this as "all unverified benign vs all malicious". For reported versions,
  which is where nearly every verdict is recorded, the two match. For an unreported one
  (rank 0) they swap, because counting it malicious makes it an FN and lowers recall. Defined
  this way, the two cases bound recall, precision and FP rate together, and each true rate lies
  between them.
- **OSV truth** (`osv`): an OSV record wins; otherwise a seen verdict (malicious or unwanted is
  M, benign B); an `unverified` verdict counts as no verdict, so the version falls back to OSV
  (and is benign once settled without a record). **OSV only** is unchanged (verdicts ignored).
- The sensitivity rows (`behaviour+takedowns`, `behaviour/rescored`, `behaviour/D3`, `/D14`)
  use the flag-worthy headline.
- Each window reports its versions per verdict category and its unverified versions per reason.
  A legacy `inconclusive` verdict (or one in an older dataset) counts as `unverified` with
  reason `none`.
- The review-sample bound counts flag-worthy versions among those whose behaviour was seen
  (malicious, unwanted, benign); it bounds malware alone too.
- The results log's `malicious` / `reported_malicious` / `recall` are the flag-worthy headline;
  new fields `strict_malicious`, `strict_reported` and `unverified` are added. The ledger is
  unchanged.

## Addendum 2026-11-10: the freeze moves to 2026-11-16..23

The owner moved the rule freeze (window B) from `[2026-11-12, 2026-11-19)` to
**`[2026-11-16 00:00Z, 2026-11-23 00:00Z)`**, a Monday to a Monday, to leave a week more for rule
and label work before they get busier; the week after it is for presentation prep and results
analysis (presentation about 2026-11-29). `evaluation/live.py` `DEFAULT_WINDOWS` and the
results viewer follow. Nothing else in the decision changes. One consequence of D = 7: a version
released at the end of window B is benign only once a label set fetched 7 days later exists, so
the full D = 7 matrix for window B is complete on 2026-11-30, a day after the presentation; the
analysis can show D = 7 for versions released through 2026-11-22 (labels fetched by 2026-11-29)
or the D = 3 sensitivity row (complete on 2026-11-26), and says which.


## Addendum 2026-11-15: reports from the package's own OSV record (round 12 P, branch)

Stage 4's `npm.known-malware.self` reports a release when the package's own OSV `MAL-` record
covers it, which is the same OSV data the OSV truth reads. The owner asked that such reports
not grade themselves.

A version the rule alone reports (`LiveSample.self_known_only`) counts as flagged only where a
reviewer verdict (`malicious`, `unwanted`, `benign`) decides its truth:

- It is never flagged in the OSV-truth and OSV-only matrices.
- It is not flagged in the flag-worthy and strict matrices when there is no verdict, since
  their truth then falls back to the same OSV record.
- The `unverified` bounds keep it flagged, because a bound decides from what the pipeline did.
- "Alone" is read from the ledger's rule entries and score, so old ledgers need no change.

Each window reports the count. See
[the proposal](../proposals/self-known-malware-round12-P.md) and `docs/evaluation.md`.

## Addendum 2026-11-23: a fresh unbroken freeze week, 2026-11-25..12-02

The owner's host PC shut down after the tick of 2026-11-19 08:12Z, and collection resumed at
2026-11-23 16:14Z: the freeze week `[2026-11-16, 2026-11-23)` holds 80 runs (2026-11-16 00:33Z
to 11-19 07:44Z, all with the same rule fingerprints: Stage 4 version 28, `2c5cae8034c09bf9`),
about 3⅓ of its 7 days. The four days in between come back only as catch-up runs, whose
versions the live evaluation sets apart (captured more than 6 hours after release), so they
count in no window either way.

The owner chose a fresh unbroken week over topping up the short one with a second segment:

- **Window B** is now **`[2026-11-25 00:00Z, 2026-12-02 00:00Z)`**, still the rule freeze, and
  the results viewer still calls it that. It starts at the first UTC midnight after the
  catch-up reaches the feed head and hourly ticks resume, so its first hours are not recorded
  late.
- **Window B0** keeps the first freeze week, `[2026-11-16, 2026-11-23)`, reported apart. It holds
  the same 80 runs as before; no run has an `as_of` between 11-19 07:44Z and 11-23 16:14Z.
- **The freeze runs until window B ends**: no change to any stage's rules from 2026-11-16 to
  2026-12-02 00:00Z. A change to the evaluation code (like this one) does not touch the
  pipeline's fingerprints, which each ledger records and the analysis checks.
- **D = 7:** the full matrix for window B is complete on 2026-12-09. The analysis shows D = 7 for
  versions released early enough, or the D = 3 sensitivity row (complete 2026-12-05), and says
  which.

`DEFAULT_WINDOWS` in `evaluation/live.py` and the viewer test follow; nothing else changes.
