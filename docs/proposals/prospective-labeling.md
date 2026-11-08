# Proposal: prospective labeling and a live confusion matrix (Phase 9)

> **Status:** implemented 2026-11-08 (option B): `evaluation/ledger.py`, `evaluation/live.py`,
> `evaluation/sample.py`, the hold in `core/retention.py`, and the daily `live-eval` step in
> `collect`; see [evaluation.md](../evaluation.md#live-evaluation-phase-9). Owner decisions
> ([0019](../decisions/0019-live-evaluation.md)): behaviour truth primary with OSV truth
> alongside; D = 7 with 3 / 14 sensitivity; rule freeze 2026-11-12 to 2026-11-19 (window B);
> the 30-day hold approved. Takedowns without OSV count only in a sensitivity row; window-A
> misses are adjudicated by review. Measurements below are read-only, on the VM's `data/` as of
> 2026-11-08 ~16:00Z (label set `20261108T151126Z`, 222,874 npm `MAL-` records). Scripts:
> [Reproducing](#reproducing).

## Summary

- **Goal.** The capstone (presented ~2026-11-29, npm only) needs TP / FP / FN / TN counts that
  hold up to scrutiny, measured on what the pipeline saw **live**, not on DataDog samples. Today
  datasets are built by hand (`eval build`) and nothing joins new labels to the decisions the
  pipeline already made.
- **What live data already says** (runs `20261029T221803Z` to `20261103T035624Z`, the 87 runs
  whose Stage 4 and report finished: 495,833 versions, 1,507 reported under the current scores):
  - **142 versions** (78 OSV records, 33 publisher accounts) we captured before the takedown
    are now covered by an OSV record ("observed", label hygiene of
    [0005](../decisions/0005-label-hygiene.md)). 134 reached Stage 4. **34 were reported:
    live recall 25.4% [95% CI 18.8–33.4]** (shape A 14/74, shape B 20/60). By record it's
    23/73 (31.5%), by publisher account 14/33.
  - This is far below the DataDog numbers (`pipeline+4`: 96.4% A / 69.0% B). The 100 misses:
    35 updates Stage 2 never read (routing), 13 updates over the 16 MB file cap, 41 read with
    no finding (25 are one family, `@goparrot-dashboard/*` 0.0.1 placeholders), 11 with findings
    below the report bar. All 100 are unwatched packages.
  - **Reviewer verdicts** cover all 1,507 reported versions: 41 malicious, 44 inconclusive,
    1,422 benign. Precision is **2.8% [2.1–3.8]**. 8 benign verdicts disagree with OSV, all
    PoC or probe releases judged by behaviour (decision 0015 addendum).
  - **Label timing:** an OSV record appeared a median **21.6 h** after our capture (p75 41 h,
    max 196 h). Our own sync saw it a median 110 h after capture, inflated by the 11-03 to 11-07
    outage. npm's takedown came a median 43 h after capture.
  - **Retention loses evidence.** Pins are decided once, at prune time, from the label set of
    that moment. 51 of the 139 matched versions in pruned runs got their label after the
    prune, so nothing was pinned. 26 of those had a captured tarball, now gone. Of the 86
    captured malicious tarballs, 34 are pinned and on disk, and 2 more are in runs not yet
    pruned. 25 were pinned but their blobs are missing, consistent with the owner's manual
    blob deletion of 11-04.
  - **Takedowns add almost nothing yet.** All 34 taken-down names with a version we captured
    also have an OSV record. The takedowns do confirm 2 versions that hygiene excludes as
    "projected". The 20 taken-down names with no OSV record are mostly platform binaries
    (`*-win32-x64`) we never captured a version of.
- **Proposal (recommended option B).** A daily `live-eval` step in `collect`:
  1. Write a compact per-version **decision ledger** for every finished run. It stays small
     and survives pruning.
  2. Put a deterministic, label-blind **review sample** of unreported versions and a **label
     hold** on small tarballs (≤ 64 KB, 30 days) before the prune can delete them.
  3. Join new OSV records, takedowns and verdicts. Build a versioned `live-*` dataset and
     compute confusion matrices with Wilson intervals per stage, shape and rule set.
  4. Append a results log line, and add one line to the Discord summary.
  Cost: ~10 GB of disk at steady state and a few minutes of CPU a day.
- **What can be shown on 2026-11-25:** window A (10-29 to 11-03, mixed rule sets, benign
  settled at 14+ days) and a frozen-rules window B (about 11-11 to 11-18, benign settled at
  7 days). Expect roughly 250 to 350 labeled malicious versions in total. The FN estimate for
  malware no one has labeled is an upper bound from the review sample, not a point estimate.

## 1. Measurements

### 1.1 Corpus

| | |
|---|---|
| Runs on disk | 95 (`20261029T221803Z` … `20261108T153157Z`), 1,030,439 changes |
| Runs with Stage 4 + report | 87 (to `20261103T035624Z`), 495,833 versions |
| Not finished | 3 runs on 11-03 (stopped by the disk crashes, now pruned, so they will never finish); the 4-day catch-up `20261107T163310Z` (405,710 changes, Stage 4 pending) and later runs |
| Rule sets among the 87 | Stage 4 `stage_version` 7 (`951644acbbdeb3f0` 34 runs, `a8a104b5e5e29a23` 4 runs) and 8 (`4fe66817705f9266` 49 runs). The code is now at Stage 4 version 11, so **no finished run is scored by today's rules** |
| Re-scored runs | 21 (originals in `before-rescore/`). As the ticks wrote them, the 87 reports held 2,773 distinct versions; after re-scoring, 1,507 |

### 1.2 OSV matches

Each change was joined against the newest label set (exact versions or ranges,
`LabelSet.classify`), first run wins:

| Outcome | Versions |
|---|---|
| Name has a record, version not covered | 5,584 |
| npm placeholders (`0.0.1-security`, `0.0.0-stage`), excluded | 460 |
| Projected (open range from an older record), excluded | 7 |
| **Observed malicious** | **142** (78 records, 33 accounts) |
| of which reached Stage 4 | 134 (74 shape A, 60 shape B) |

### 1.3 What each stage decided for the 134

| Stage | A (74) | B (60) | All (134) |
|---|---|---|---|
| Stage 1 rule fired (`rules:`) | 6 | 19 | 25 |
| Stage 1 forwarded (rules or routing) | 30 | 60 | 90 |
| Stage 2 read it | 39 | 60 | 99 |
| Stage 2 had the files | 25 | 58 | 83 |
| Stage 2 flagged | 9 | 10 | 19 |
| Stage 3 flagged | 7 | 11 | 18 |
| **Reported** (score ≥ 6 or MEDIUM+) | **14** | **20** | **34** |

The same 34 versions were reported in the original and the re-scored reports. None of the 34
needed `npm.dependency.known-malware` (the one rule that reads OSV), so the result does not
leak from the labels.

**Why the 100 were missed:**

| Cause | New | Update |
|---|---|---|
| Not read by Stage 2 (no Stage 1 signal, not grown, not watched) | 0 | 35 |
| Stage 2 had no files (declared size over the 16 MB cap; one fetch error) | 0 | 13 |
| Read, no finding | 36 | 5 |
| Read, findings below the report bar | 4 | 7 |

Some of these may be inert. OSV usually labels *every* version of a package (34 of the 78
records are open "all versions" ranges). For example, the 25 `@goparrot-dashboard/*` 0.0.1
releases precede `@goparrot-dashboard/app@0.0.2`, which carried the payload and was reported
HIGH. Under the owner's behaviour rule ([0015](../decisions/0015-reviewer-verdicts.md)
addendum), some of them could be benign. Until they are reviewed, this is unresolved, and
the tarballs needed to settle it are partly gone (1.5).

### 1.4 Label timing

For each of the 78 records, from our first capture of a covered version:

| Interval | n | median | p75 | max |
|---|---|---|---|---|
| npm publish → our capture | 78 | 0.9 h | 1.0 h | 53 h |
| our capture → OSV `published` | 78 | 21.6 h | 40.9 h | 196 h |
| our capture → first label set that had it | 78 | 110 h | 154 h | 205 h |
| our capture → npm takedown | 33 | 42.6 h | 79.1 h | 180 h |

- Negative values appear when a record predates the version. The record was extended later,
  as with `opencode-skills-collection` (record from 10-22, versions 4.1.29–4.1.33 added
  daily) and `@emilgroup/discount-sdk` (`MAL-2026-2074`, from March).
- OSV's `modified` field isn't kept in `LabelSet`, so when a version was *added* to a record is
  only known to within a sync (every 20 h).
- Lags are **censored**: the corpus is 10 days old, so a record later than ~10 days can't have
  been seen yet. The 196 h maximum is a lower bound on the tail.

### 1.5 What retention kept

The 139 matched versions in pruned runs, by whether the package had a record when its run was
pruned (`retention.json` `pruned_at`; prunes on 11-03 16h, 11-04 01h and 11-07 22h):

| Label at prune time | Tarball captured | Pinned | Blob on disk now | Versions |
|---|---|---|---|---|
| no | no | – | – | 25 |
| no | **yes** | **no** | **no (lost)** | **26** |
| yes | no | – | – | 29 |
| yes | yes | yes | yes | 34 |
| yes | yes | yes | **no** | 25 |

The 25 pinned but missing are consistent with the 96 prefix directories deleted by hand on
11-04 (devlog 2026-11-04): 21 were pinned by the prunes before or around the deletion, and 4
were pinned on 11-07 after their blobs were already gone. The current pin rule loses any
version whose label arrives after its run is pruned (2 days on this VM). Here that was 51 of
139 (37%), inflated by the 11-03 to 11-07 outage, when no labels were synced. Malicious tarballs are small:
80 of the 86 captured were ≤ 64 KB, 81 were ≤ 256 KB, and the largest was 1.6 MB
(`@mamans2973/maman`).

Stage outputs (`triage/static/ast/correlate.jsonl`, `report/`) are **not** pruned, so the live
decisions for every run are still there. Replay and re-scoring are not: they need blobs.

### 1.6 Takedowns (`data/takedowns/npm.json`, 233 holders, scanned through `20261108T073127Z`)

- 213 of the 233 names have an OSV record, and 20 don't. We captured no version of any of
  those 20. They include `cc-go-proxy-win32-x64`, `netivri-win32-arm64`, `sqlc-ts-win32-x64`
  and `kr-node-logger`, many of them platform binaries. A takedown is a policy action and
  doesn't prove malware.
- 34 taken-down names had 61 versions captured before the holder. 59 of those are OSV
  observed. 2 are "projected" (`dependencykfeg@25.2.1`, `tailwindcss-visual-kit@1.3.7`), where
  the record is older than the release. For these, the takedown is the evidence that the
  release is malicious too.
- So far, takedowns are a **weak, mostly redundant** label. They are useful in two places:
  resolving "projected" versions, and labeling the delay between capture and the OSV record.

### 1.7 Reviewer verdicts (`data/verdicts/npm.jsonl`)

- 1,633 lines; 1,594 versions (last line wins). 1,502 benign, 51 inconclusive, 41 malicious.
  30 are tagged `probe` (22 malicious, 8 benign). **All were recorded by `claude`. None is by
  the owner.**
- Against the 1,507 reported versions under current scores: each has a verdict. 87 verdicts
  are for versions that re-scoring has since removed from the reports.
- Crossed with OSV and takedowns:

| Verdict | No label | OSV | OSV + takedown |
|---|---|---|---|
| malicious | 15 | 7 | 19 |
| inconclusive | 44 | 0 | 0 |
| benign | 1,414 | 2 | 6 |

- **The 8 disputes** are all PoCs or probes that only act locally: `calculator-preinstall-hook-demo`
  1.0.0 / 1.1.0 / 1.1.1, `@bigdevin55/calculator-install-hook@1.0.0`,
  `@mobile-platform/magnetic-components@0.0.1`, `atlassian-wallboard-plugin1@10.0.88`,
  `service-roles-registry@99.0.1` and `filipt@0.4.0`. In each case the package's *next*
  version is malicious. OSV labels the package; the reviewer judges the version.
- **Independence:** for 19 of the 26 malicious verdicts that OSV confirms, the verdict came
  *after* the OSV record was published. Since 10-31 the queue has shown confirmations, so
  those verdicts aren't independent evidence.
- **Bias:** verdicts exist only for reported versions. They measure precision, never recall.

## 2. The confusion matrix: definitions

**Unit: a version** (`name@version`), counted once, in the first run that recorded it (as
`build_dataset` does). Two coarser views go next to it, because OSV labels packages and
campaigns publish many: **per OSV record** and **per publisher account**.

**Population:** versions that reached Stage 4 in a run whose report is complete. Excluded and
counted: npm placeholders, "projected" matches, and runs that never finished. These runs
are an *operational* loss, shown as their own row and not hidden. Catch-up runs fetched more
than 6 h after publish are reported apart (the 4-day run read packuments after npm had removed
the malware, so its recall cell is survivor-biased).

**Flagged** has two meanings, and both are reported:

- **Reported:** the version is in the run's `report.json` (score ≥ `report_score` or a
  MEDIUM+ finding). This is the headline, since it is what a reviewer sees.
  - Primary: the report as the tick wrote it, scored with that run's recorded `rules` hash.
  - Secondary, recall only: the current report, after any re-score. Precision needs verdicts,
    and the 1,313 originally reported versions that were later re-scored away never got one.
- **Forwarded by stage N:** the stage's own decision (`history[-1]` for that stage), for the
  per-stage funnel (1.3) and pass-through rates.

**Labels:**

| Label | Source | Strength |
|---|---|---|
| Malicious (external) | OSV `MAL-` observed (0005 hygiene), first label set id recorded per version | strong, package-grained |
| Malicious (reviewer) | last verdict `malicious` | strong, version-grained, reported versions only |
| Malicious (weak) | npm takedown after publish, no OSV | weak: policy removals exist |
| Benign | none of the above, no `inconclusive`, and label set fetched ≥ **D** days after publish | presumed |
| Excluded | `inconclusive`; benign younger than D (provisional) | counted |

**Disputes** (OSV malicious, verdict benign) need one rule, applied symmetrically:

- **Primary, "behaviour truth":** the version-level judgement wins, where one exists.
- To be symmetric, the OSV-labeled **misses get the same review** (adjudicated from the ledger,
  the Change, and the tarball if held). Without that, reported OSV versions can be demoted and
  missed ones can't, which biases recall down.
- A miss whose evidence is gone is "unadjudicated" and stays malicious.
- **Sensitivity, "OSV truth":** OSV wins. Both matrices are shown.

**Cells:**

- **TP:** flagged and labeled malicious.
- **FP:** flagged and benign: a benign verdict and no external label (or under behaviour
  truth, a benign verdict even with one).
- **FN:** not flagged and labeled malicious. *Known* FN comes from external labels. The
  *unknown* FN (malware nobody labeled) is bounded from the review sample.
- **TN:** not flagged, no label, past D. Its label noise is bounded from the same sample.

**Intervals:** Wilson 95% for every rate. When a sample finds no positives, the upper bound is
the exact one-sided bound `1 − 0.05^(1/n)` (≈ 3/n).

### What the numbers are today (window A, provisional: D not yet met)

| Matrix | TP | FP | FN | TN | Recall | Precision |
|---|---|---|---|---|---|---|
| Behaviour truth (verdict wins; OSV misses unadjudicated) | 41 | 1,422 | 100 | ≈494,200 | 29.1% [22.2–37.0] | 2.8% [2.1–3.8] |
| OSV truth (OSV wins; verdict-only malicious kept) | 49 | 1,414 | 100 | ≈494,200 | 32.9% [25.9–40.8] | 3.3% [2.5–4.4] |
| OSV only (verdicts ignored) | 34 | – | 100 | – | 25.4% [18.8–33.4] | – |

The benign false-positive rate is ≈0.29% of versions (1,422 / ~495,600). Note that the
numbers mix the three rule sets of 1.1.

## 3. Estimating what nobody reviewed

- **FN, known:** external labels arriving later. By construction, these are only misses that
  someone else found.
- **FN, unknown, and TN label noise:** a **label-blind, deterministic review sample** of
  unreported versions. It is taken daily, *before the prune*, so the tarballs can be held.
  Order is `sha256("live-sample\n" + day + "\n" + ref)` within each stratum, and the first
  n are kept.
  - Strata sizes are measured on 11-02 (118,228 versions, 341 reported).
  - The 11 known misses below the bar fall in U1, and the 36 new packages with no finding
    in U2. The 35 updates that were never read are in U2 or U3.

| Stratum | Size / day | Sample / day | Total by 11-18 |
|---|---|---|---|
| U1 unreported, score > 0 | 12,402 | 20 | ~150 |
| U2 unreported, score 0, new package or install hook, unwatched | 8,763 | 20 | ~150 |
| U3 everything else | 96,722 | 15 | ~100 |

At a base rate near 0.02% (100 known misses in ~495k), a sample this size will usually find
nothing. Its honest output is an **upper bound**: 0 of 150 means ≤ 2.0% of U1 is malware
nobody labeled, at 95%. 0 of 100 means ≤ 3.0% of U3. Each stratum is weighted by its
population. Larger samples tighten this only slowly (n = 600 gives ≤ 0.5%). The proposal
states this limit rather than claiming a point estimate.

**Reviewer reliability:** every verdict so far is Claude's. The owner reviews blind (without
the verdict or the confirmations) all 41 malicious, all 44 inconclusive, and 60 benign drawn
by hash. Report agreement and Cohen's κ. Verdicts recorded after an OSV record or takedown
was visible are flagged `confirmation_seen` and reported apart.

## 4. Design

One daily step, `live-eval`, in `collect` (like the prune, at most every 20 h). It runs after
`labels` and before `prune`. It only reads run outputs, and it never feeds a rule or a score
([0016](../decisions/0016-after-the-fact-confirmations.md) is unchanged).

1. **Ledger** (`data/eval/live/ledger/<run_id>.jsonl.zst`), written once a run's report is
   complete.
   - One row per version entering Stage 4: ref, publish time, publisher, shape, watched,
     tarball URL, size and digest.
   - The decisions: Stage 1 rules and forward, Stage 2 read, files or flag, Stage 3 flag,
     Stage 4 score, reported and rank.
   - The rule ids with versions, and the run's `rules` hash, `stage_version`, watchlist and
     `known_bad` label set id.
   - About 200 B a row before compression, so ~3 MB a day.
   - Backfilled once for the 87 finished runs by streaming their outputs. That takes about
     30 minutes at `nice 19`, under the 4 GB cap.
   - After a re-score, a second ledger row set (`rescored: true`) is added, never replacing
     the original.
2. **Hold** (`data/eval/live/hold.json`). Each day, before the prune, the step adds:
   - tarballs ≤ 64 KB of unwatched versions, and of their diff bases;
   - every reported version's tarball;
   - the day's review sample (section 3);
   each kept for `HOLD_DAYS` = 30. `retention._collect_garbage` treats held digests as
   referenced. When a label arrives for a held version, its blobs move permanently to
   `data/eval/live/tarballs/`, the way `eval/tarballs/` works today. This is a
   `core/retention.py` contract change and is flagged as such: one more set of referenced
   digests, no change to pruning runs.
3. **Join and dataset** (`data/eval/datasets/npm/live-<labels id>.json`). The join reads:
   - the ledger;
   - the newest label set, plus the id of the first label set that covered each version
     (from the 20 h label history on disk);
   - the takedown log;
   - the verdict log, cut at the dataset's `as_of`, with its line count and SHA-256 recorded.

   It writes samples with every label source attached, not just the resolved label. The
   dataset records the sha of every input and the parameters (D, hold, sample sizes).
   Rebuilding from the same inputs gives the same bytes, apart from `built_at`.
4. **Metrics** (`data/eval/reports/npm/live-<id>.json` + `.md`):
   - both confusion matrices;
   - the per-stage funnel;
   - shape A/B, per record and per account;
   - per rule set;
   - rule firing on TP vs FP;
   - the label-lag distribution;
   - the operational-loss row.
5. **Results log**: one JSON line per build in `data/eval/live/log.jsonl`. `collect` never
   edits `docs/`; `docs/evaluation.md` gets rows by hand from the log.
6. **Discord**: one line in the daily summary. For example: "Live eval (labels 11-24): 52 / 190
   malicious reported (27%); +4 newly labeled since yesterday, 1 reported; review sample: 3
   due". Package names are escaped as now.
7. **Missed list**: newly labeled versions that weren't reported go into the queue's
   confirmations section as "missed", for adjudication. This uses the same mechanism as the
   benign-then-confirmed flag of 0016.

**Determinism.** Every input is a file with a recorded hash. The sample order and label
resolution are pure functions. `as_of` is the label set's `fetched_at`, never the clock. Each
row carries the rule versions that produced it.

**Cost.**

| Item | Size |
|---|---|
| Ledger | ~3 MB/day |
| Hold of tarballs ≤ 64 KB | measured 0.59 GB for 2 days of Stage 2 captures (11-01 to 11-02), so ~9 GB at 30 days |
| Reported versions and sample | < 1 GB |
| Dataset and report | tens of MB |

CPU: the ledger is written from outputs the tick just wrote. The nightly join reads ~100 MB of
ledger plus a 36 MB label set: seconds to a minute.

## 5. Options

| Option | What | Gives | Cost / risk |
|---|---|---|---|
| A. Join only | Ledger + nightly join + metrics + log + Discord | Known-FN recall, precision from verdicts, all automatic | No adjudication of misses, no FN bound, evidence keeps being lost (1.5) |
| **B. A + hold + review sample (recommended)** | Also section 3 and the hold | Defensible FN/TN bounds, adjudicable misses, owner-checked verdicts | ~10 GB disk; one retention contract change; ~35 sample reviews a day |
| C. Keep everything 30 days | All tarballs and archives, so old runs can be re-scored | Re-score window A with frozen rules | ~14 GB/day of tarballs + ~30 GB/day archives: doesn't fit the disk ([0006](../decisions/0006-scheduled-collection-and-retention.md), devlog 11-04) |

A smaller variant of B holds tarballs ≤ 256 KB: 81 of 86 malicious instead of 80, at ~39 GB
for 30 days (measured 1.99 GB over 2 days for the 64–256 KB band). That's not worth it.

## 6. What isn't feasible

- **A 30-day benign delay before the presentation.** The oldest version (10-29) settles on
  11-28. Recommended instead:
  - D = 7 days for the headline;
  - a sensitivity table for D = 3, 7 and 14, reporting how many window-A labels arrived after
    each D. By 11-25 window A is 22 to 27 days old, so late arrivals up to ~3 weeks are visible.
- **Re-scoring pruned runs with today's rules.** Archives and most tarballs are gone. Rule
  sets can only be compared on what was held.
- **Recall on the 11-03 to 11-07 gap.** The catch-up run captured packuments after the
  takedowns.
- **True FN for malware nobody else found.** Only an upper bound (section 3).
- **GHSA labels:** not synced. GHSA malware records largely mirror OSV.
- **Precision of the original live reports for re-scored runs:** 1,313 versions were never
  reviewed.

## 7. Timeline and what to present

**Plan to 11-25:**

| Date | Step |
|---|---|
| 11-09 to 11-11 | Build B; backfill the ledger for window A; start the hold and sample |
| ~11-11 | **Rule freeze** (owner's call): no rule changes until 11-18 |
| 11-11 to 11-18 | Window B. From 1.2, expect ~28 observed versions a day, so ~200 malicious and ~700k versions |
| 11-18 to 11-25 | Labels settle (D = 7). Daily review of the sample and the new reports; the owner's blind check |

Window A gives ~140 to 150 malicious versions under mixed rules. Window B gives ~200 under one
rule set. With ~200 positives, a recall near 30% has a 95% interval of about ±6 points.

**What to present:**

1. **The confusion matrix**, behaviour truth and OSV truth side by side, window B (frozen
   rules), with Wilson intervals, the TN label-noise bound and the operational-loss row.
2. **Per-stage funnel** for the labeled malicious versions (table 1.3) and for benign
   pass-through, by shape.
3. **Why misses happen** (the 1.3 cause table), with one worked example of each cause.
4. **Recall by unit**: version / OSV record / publisher account, so a 27-version campaign (`devtest91001`)
   doesn't dominate.
5. **Label timing CDF** (capture → OSV, capture → takedown). This shows the pipeline flagging
   ~a day before the public label for the reported TPs.
6. **Lab vs live**: DataDog `pipeline+4` against live recall, and why they differ (routing,
   size cap, inert first releases).
7. **Reviewer reliability**: owner–Claude agreement (κ), and the confirmation-seen split.
8. **Rule firing on TP vs FP** (which rules earn their noise).

## 8. Open questions for the owner

1. **Dispute rule**: behaviour truth primary (recommended) or OSV truth primary?
2. **D**: 7 days for the headline, with 3/7/14 sensitivity (recommended)? This replaces open
   decision 6 for the capstone.
3. **Rule freeze** for window B: from when, and for how long?
4. **The hold**: ≤ 64 KB, reported versions, and the sample, for 30 days (~10 GB)? Approve the
   `core/retention.py` change.
5. **Review load**: ~35 sample versions a day by Claude, plus the owner's blind check of ~145
   verdicts. Acceptable, or smaller samples with wider bounds?
6. **Takedowns without OSV**: count as weak positives in a sensitivity row only (recommended),
   or ignore?
7. **Adjudicating the 100 window-A misses** with what's left: yes (recommended), or leave them
   all as OSV-labeled?

## Reproducing

The scripts are in `~/kitsunox-scratch/agent-labeling/scripts/` on the VM (outside the
repository). They are read-only on `data/` and are run under `systemd-run --user --scope -p
MemoryMax=4G nice -n 19` with the project venv (`-I`, or `PYTHONPATH=src -P -s` from a
worktree for `join.py`). Intermediate pickles are in `~/kitsunox-scratch/agent-labeling/`.

| Script | Does |
|---|---|
| `join.py` | Streams every run's changes and joins them with the newest label set and the takedown names (~6 min) |
| `stages.py` | Per-stage decisions, capture times and pins for the matches |
| `an2.py`, `stagetab.py`, `fn.py`, `pub.py` | Tables 1.2 and 1.3, miss causes, accounts |
| `timing.py` | Table 1.4 |
| `pins.py`, `pins2.py` | Table 1.5 |
| `tk.py` | Section 1.6 |
| `verd.py`, `vt.py`, `matrix.py` | Section 1.7 and the provisional matrix |
| `strata.py`, `sizes.py`, `msizes.py` | Section 3 strata; tarball sizes for the hold |

If B is built, these become the ledger builder and the `live-eval` step, with tests.
