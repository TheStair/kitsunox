# Evaluation

> **Status (2026-10-27):** OSV labels; datasets built from our own ingest runs; DataDog malware
> samples imported as encrypted data ([0007](decisions/0007-datadog-samples-and-follow-on-releases.md));
> baseline and Stage 1 predictors. **2026-11-08:** live evaluation (Phase 9, below).

## How to run

```sh
uv run kitsunox labels sync                  # OSV MAL- records for npm (~220 MB download)
uv run kitsunox eval build <name>            # join all recorded runs with the newest labels
uv run kitsunox samples datadog --intent 2000   # DataDog npm samples (~5 GB, kept encrypted)
uv run kitsunox eval run <name> --predictor stage1-rules   # or stage1, popularity-only, forward-all
```

- **Labels** (`evaluation/labels.py`): every OSV `MAL-` record for npm, reduced to
  `{package → (id, published, versions, ranges)}` and saved under
  `data/labels/npm/<id>.json`. Withdrawn records are dropped. Matching is exact: explicit version
  lists, or SEMVER ranges (`introduced`/`fixed`/`last_affected`). The parser is fuzzed.
- **Dataset** (`evaluation/dataset.py`): every `Change` from recorded runs is matched
  against the labels.
  - **Malicious samples:** releases a record *observes*: the version is listed explicitly, or
    falls in a bounded range, or falls in an open-ended range ("all versions") and was published
    no later than the record. See [0005](decisions/0005-label-hygiene.md).
  - **Excluded, counted in `excluded`:**
    - `registry-placeholder`: npm's own takedown stubs (`0.0.1-security`, `0.0.0-stage`,
      published by the `npm` account). OSV's open ranges match them, but they hold no attacker
      code.
    - `label-projected`: matched only by an open range from a record published *before* the
      release. That is a guess about the future, not evidence.
  - **Benign samples:** a deterministic stratified sample, N per (shape, watched) stratum,
    ordered by a hash of (dataset name, release). They are *settled* only once the label set is
    ≥30 days newer than the release, and *provisional* until then. `population` records each
    stratum's real size before sampling.
  - **Bookkeeping:** a release seen in several runs counts once (earliest run). Datasets record
    the label set's id and SHA-256. Rebuilding gives identical samples; only `built_at` changes.
- **Metrics** (`evaluation/metrics.py`):
  - A `Predictor` decides forward/clear for each change. Each report cell is
    `label/shape[/provisional]` with total, forwarded and rate (recall for malicious,
    pass-through for benign). The `*/all` rollups use settled samples only.
  - **Re-weighted pass-through:** strata are sampled equally, so the raw benign rate is biased
    towards whichever stratum is smaller in reality (watched packages). Reports also give
    `weighted_pass_through`: each stratum's sample rate weighted by its population. In the first
    run the raw popularity-only rate was 50.0% and the weighted one 13.5%.
  - **Baselines:** `forward-all` (upper bound on recall) and `popularity-only` (the watchlist
    half of the forward policy, with no detection). Stage 1 will plug in as another predictor.

### Why malicious samples will be scarce at first

npm replaces malicious versions with a placeholder (`0.0.1-security`, and in the 2026-10-27 run
also `0.0.0-stage`), usually within hours. A malicious release only becomes a sample if an ingest
run recorded its packument **before** the takedown. The dataset therefore grows with regular ingest runs ("prospective labeling"). OSV
publishes about 20 new npm `MAL-` records a day (141 in the week to 2026-10-27).

The OSV npm export on 2026-10-27 had 222,848 `MAL-` records. 86% mark every version of the
package as malicious, which in practice means a brand-new malicious package (shape B).

## What we measure

For every run on the evaluation set, per stage and overall:

| Metric | Definition | Why |
|---|---|---|
| **Recall (known-bad)** | malicious changes forwarded past stage N ÷ malicious changes entering it | Missing an attack is the worst outcome |
| **Pass-through rate (benign)** | benign changes forwarded past stage N ÷ benign changes entering it | Controls cost of later stages and reviewer load |
| **Final flag rate (benign)** | benign changes in the final report ÷ all benign | The false-positive rate a reviewer actually sees |
| **Rule firing profile** | per rule: fires on bad, fires on benign | Finds noisy or dead rules to remove (CLAUDE.md "quality over volume") |

Recall is reported **separately for shape A (compromised existing package) and shape B (new
malicious package)** ([threat-model.md](threat-model.md#two-attack-shapes)). Public datasets are
dominated by shape B, so a single recall number would mostly measure typosquat detection.

## Live evaluation (Phase 9)

Datasets built with `eval build` and the DataDog samples measure rules in the lab. Live
evaluation measures what the pipeline decided **at the time**, on every version it saw, against
labels that arrive days later: OSV `MAL-` records, npm takedowns and reviewer verdicts. The design
is [proposals/prospective-labeling.md](proposals/prospective-labeling.md) (option B) and the
owner's decisions are [0019](decisions/0019-live-evaluation.md).

```sh
uv run kitsunox live ledger                       # backfill: a ledger for every finished run
uv run kitsunox live eval                         # dataset + matrices -> data/eval/live/reports/
uv run kitsunox live misses                       # labeled-malicious versions not reported
uv run kitsunox live sample                       # draw due daily samples, list the newest
uv run kitsunox live verdict <run_id> <name> <version> benign --by claude   # sampled / missed
```

### The decision ledger (`evaluation/ledger.py`)

Run outputs are large and partly pruned, so each finished run (Stage 4 and its report complete)
is boiled down once to `data/eval/live/ledger/<run_id>.jsonl.zst`, kept for good (~90 KB for an
hourly run of ~2,200 versions). Its first line is a header: the run, `as_of`, Stage 4's
`stage_version` and rule fingerprint (`correlate.json`), the report bar, the label set and
watchlist Stage 4 used, the SHA-256 of every file read, and, when `collect` wrote it in the tick
that ran the stages, the rule fingerprint of every stage and the tool version (`pipeline`; a
backfill can't know them, so it is empty). Then one row per version that entered Stage 4:

| Field | Meaning |
|---|---|
| `name`, `version`, `published_at`, `publisher`, `previous` | The release; `previous` empty = a new package (shape B) |
| `watched`, `hook`, `placeholder`, `declared_size` | On the watchlist; declares an install hook; the registry's own stand-in |
| `s1`, `s1_forwarded` | Stage 1's route: `rules`, `watched`, `new`, `hook`, `grown`, `size-unknown`, `small` (2026-11-08), `none` |
| `s2`, `s3` | Stages 2 and 3: `unread`, `no-files` (size cap or fetch error), `clear`, `flagged` |
| `score`, `forwarded`, `rank` | Stage 4's score and decision; the rank in the run's report (empty: not reported) |
| `rules` | `rule_id@version:severity` of every finding above INFO |
| `tarball`, `tarball_size`, `base_tarball`, `base_tarball_size` | SHA-256 and size of the tarballs Stage 2 captured |

A re-scored run (`kitsunox rescore`) is ledgered as the tick scored it (`before-rescore/`); its
current outputs go to `<run_id>.rescored.jsonl.zst`, used only for a secondary recall figure.
The ledger streams `correlate.jsonl` a line at a time and is a pure function of the run's files.

### The live dataset and the matrices (`evaluation/live.py`)

`kitsunox live eval` (and `collect`, daily) joins the ledgers with the newest label set and
writes `data/eval/live/datasets/live-<labels id>.jsonl.zst`: a header with the SHA-256 of every
input (the label set and every earlier one, the takedown log, the verdict lines used, every
ledger), the runs with their rule fingerprints, and the runs that never finished; then one row
per version with every label source attached. `as_of` is the label set's `fetched_at`; verdicts
recorded after it are not used. Rebuilding from the same files gives the same bytes. The
report goes to `data/eval/live/reports/live-<id>.json` and `.md`, and a line to
`data/eval/live/log.jsonl` (`collect` never edits `docs/`).

**Population.** Each version that entered Stage 4 in a finished run, once, in the first run
that recorded it. A **window** is the runs whose `as_of` falls in `[start, end)`: A is
2026-10-29 to 2026-11-04, B (the rule freeze, [0019](decisions/0019-live-evaluation.md)) is
2026-11-12 to 2026-11-19. `all` is every window together. A version captured more than 6 hours
after its release (the first VM run's 24-hour window, the 4-day catch-up of 11-07) is counted
in a separate `catch-up` group, not in any window: npm may already have removed the malware, so
its recall is survivor-biased.

**Flagged** = in the run's report as the tick wrote it (`before-rescore/` for a re-scored run).
The row "flagged = current report" uses the report after re-scores, for recall.

**Truth** for a version, in this order (`live.truth`). Verdicts come in four categories
([0015](decisions/0015-reviewer-verdicts.md), addendum "four categories"); how each counts is
the owner's ([0019](decisions/0019-live-evaluation.md), addendum):

| | Flag-worthy (headline, `behaviour`) | Strict (`strict`) | OSV truth | OSV only |
|---|---|---|---|---|
| npm placeholder (`0.0.1-security`, `0.0.0-stage`) | excluded | excluded | excluded | excluded |
| verdict `malicious` | malicious | malicious | malicious | ignored |
| verdict `unwanted` | malicious (an OSV record doesn't change it) | benign (an OSV record doesn't change it) | malicious | ignored |
| verdict `benign` | benign (an OSV record doesn't change it) | benign | used only without an OSV record | ignored |
| verdict `unverified` (and legacy `inconclusive`) | excluded (bounded below) | excluded (bounded below) | as no verdict: the rows below | ignored |
| OSV record *observes* it ([0005](decisions/0005-label-hygiene.md)) | malicious | malicious | malicious | malicious |
| OSV record only *projects* onto it | excluded | excluded | excluded | excluded |
| npm takedown after it, no OSV | benign (malicious in the "+ takedowns" row) | same | same | same |
| none of these, released ≥ D days before `as_of` | benign | benign | benign | benign |
| none of these, younger | excluded (provisional) | same | same | same |

**Cells.** TP = flagged and malicious; FP = flagged and benign (`fp_unreviewed`: of those, how
many have no verdict, so they are *presumed* benign); FN = not flagged and malicious; TN = not
flagged and benign. Recall = TP / (TP + FN), precision = TP / (TP + FP), FP rate = FP / (FP +
TN), each with a Wilson 95% interval. Excluded versions are counted by reason.

**Unverified bounds.** The flag-worthy and strict matrices each have a best case
(`behaviour/best`, `strict/best`) and a worst case (`/worst`) that put the unverified versions
back: best = the pipeline was right about each one (reported → TP, unreported → TN), worst =
it was wrong about each one (reported → FP, unreported → FN). For reported versions, where
nearly all verdicts are, that is "all unverified malicious" vs "all benign". Each true recall,
precision and FP rate lies between the two. The sensitivity rows (`+ takedowns`, `rescored`, D
= 3 and 14) use the flag-worthy headline. Each window also counts its versions per verdict
category, and its unverified ones per reason (`none` for legacy records).

**Also per window:** the matrix by shape (A = update, B = new package); recall by **OSV record**
(a record counts as caught if any of its malicious versions was reported) and by **publisher
account**; the D = 3 and 14 rows and how many OSV labels came more than 3 / 7 / 14 days after
the release; the **funnel** (entered, Stage 1 rule, Stage 1 forwarded, Stage 2 read, had files,
flagged, Stage 3 flagged, reported) for malicious and benign versions; **why each miss
happened** (not read by Stage 2; Stage 2 had no files; read with no finding; findings below the
report bar), by new package or update; **rule firing** on TP vs FP; how many verdicts were
recorded after an OSV record or takedown was public; and the **rule sets** that scored it (Stage
4 fingerprints, full fingerprints where recorded, rules seen with more than one version, and
whether the window is single-version). **Label timing**, per OSV record from its earliest
capture: publish → capture, capture → OSV `published`, capture → the first of our label sets
that had it, capture → npm takedown (n, median, p75, max hours).

### The review sample (`evaluation/sample.py`)

External labels only find the misses someone else found. To bound the rest, each finished day
gets a **label-blind** sample of its unreported versions, written once to
`data/eval/live/sample/<day>.json` with a Markdown review list. Within each stratum, versions
are ordered by `sha256("live-sample\n" + day + "\n" + "npm:name@version")` and the first n
are kept; nothing about labels, verdicts or the clock is read. A day is sampled once no run of
it can still finish.

| Stratum | Unreported versions | Per day |
|---|---|---|
| U1 | score > 0 | 20 |
| U2 | score 0, a new package or an install hook, not watched | 20 |
| U3 | everything else | 15 |

A reviewer records verdicts with `kitsunox live verdict RUN_ID NAME VERSION VERDICT`: the same
`VerdictRecord` as `kitsunox verdict`, built from the ledger row, with **rank 0** (the version is
in no report). The same command adjudicates the misses `kitsunox live misses` lists. The live
report then gives, per window (by sample day) and per stratum, the reviewed versions (those with
a malicious, unwanted or benign verdict; unverified ones don't count) found flag-worthy
(malicious or unwanted, both shown), a 95% upper bound on that share (Wilson; the exact
`1 − 0.05^(1/n)` when none was), and the population-weighted bound on unlabeled flag-worthy
versions among unreported ones (it bounds malware alone too). With a
base rate near 0.02% the sample will usually find nothing: the honest output is a bound, not a
point estimate.

### The label hold (`core/retention.py`)

Labels come a median ~22 h after our capture, but runs are pruned after 2 days. Before every
prune, `data/eval/live/hold.json` is updated: every captured tarball ≤ 64 KB (80 of the 86
malicious tarballs captured in window A were), every reported version's tarball and diff base,
and the review sample's tarballs, each held 30 days past its run; versions live evaluation has
labeled malicious are held for good. The cap is 15 GB (the owner approved ~10 GB). See
[0006](decisions/0006-scheduled-collection-and-retention.md#addendum-2026-11-08-a-30-day-label-hold).

### Window A, provisional (2026-11-08)

Label set `20261108T151126Z`; 87 finished runs of 10-29 to 11-03 plus the 4-day catch-up
`20261107T163310Z`; built with `kitsunox live eval` into a scratch directory. **Provisional**:
with D = 7 only versions released by 11-01 15:11Z are settled benign (144,239 versions of
window A are still provisional), the misses are not adjudicated yet, and the runs were scored
by six Stage 4 rule sets (`stage_version` 5 to 8), so this is not a single-version window.

| Window A | TP | FP | FN | TN | Recall | Precision | FP rate |
|---|---|---|---|---|---|---|---|
| Behaviour truth (headline) | 37 | 1,899 | 94 | 224,444 | 28.2% [21.2–36.5] | 1.9% [1.4–2.6] | 0.8% |
| OSV truth | 44 | 1,892 | 94 | 224,444 | 31.9% [24.7–40.1] | 2.3% [1.7–3.0] | 0.8% |
| OSV only | 30 | 1,491 | 94 | 224,448 | 24.2% [17.5–32.4] | 2.0% [1.4–2.8] | 0.7% |
| Flagged = current report (re-scores) | 37 | 1,140 | 94 | 225,203 | 28.2% | 3.1% [2.3–4.3] | 0.5% |

- 758 of the 1,899 FPs have no verdict: versions the tick reported that a re-score later
  removed, so nobody reviewed them; they are presumed benign. All 1,141 reviewed FPs are
  benign verdicts.
- By shape: A (updates) 10 / 64 = 15.6% [8.7–26.4]; B (new packages) 27 / 67 = 40.3%
  [29.4–52.3]. By OSV record 25.4% [16.5–36.9]; by publisher account 55.8% [41.1–69.6].
- Misses (94): 35 updates Stage 2 never read, 10 updates without files (size cap), 39 read with
  no finding (36 new packages, mostly the `@goparrot-dashboard/*` 0.0.1 family), 10 with
  findings below the bar. None is a watched package.
- Takedowns as weak positives change nothing (every takedown we captured has an OSV record).
- 14 malicious versions were captured more than 6 h after release (catch-up group: 6 TP,
  8 FN), and 3 runs of 11-03 never finished (63,452 changes): the operational loss.
- Label timing per OSV record (75): capture → OSV `published` median 21.6 h (p75 41.9, max
  195.8); capture → npm takedown median 42.8 h (31 records).
- The proposal's hand count (34 / 134 reported) differs because the first VM run's versions
  published over 6 h before capture are now in the catch-up group and verdicts decide
  disputes.

## Data sources

### Known-bad

| Source | Gives | Code included? | Notes |
|---|---|---|---|
| [`ossf/malicious-packages`](https://github.com/ossf/malicious-packages) / OSV `MAL-` | Labels: package, affected versions, source, date | No | Thousands of npm records, still growing in 2026. Mostly shape B |
| GitHub Advisory DB, `type=malware` | Labels | No | Overlaps with OSV |
| [DataDog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) | **Actual tarballs**, encrypted zips (password `infected`) | Yes | Third-party analysis counted ~3,600 npm samples. Mostly shape B. Check the license before use |
| Backstabber's Knife Collection | Tarballs (academic) | Yes | Access on request. Older samples |
| **Our own cache (prospective)** | Tarballs of recent changes we later see appear in `MAL-`/GHSA | Yes | The only reliable source of *recent* shape-A samples with a benign previous version. See below |

**Shape-A samples are the scarce part.** A compromise is only diffable if we have the malicious
version *and* the benign version before it. Registries remove malicious versions quickly. Plan:

1. **Curated incident set (small, hand-labeled):** public compromises where both versions can
   still be obtained as data, e.g. from the DataDog dataset or researcher archives. Candidates to
   check include historical compromises (event-stream, ua-parser-js, coa/rc) and the 2025–2026
   account-takeover and worm incidents. **Which of these are actually still obtainable has not
   been checked yet.**
2. **Prospective labeling:** Stage 0 caches packuments for every change, and tarballs for every
   change forwarded past Stage 1 (plus a random benign sample). A nightly job joins the cache
   against new `MAL-`/GHSA records. Matches become labeled shape-A or shape-B samples, complete
   with the prior version. This grows the dataset with exactly the kind of recent attacks the
   project targets.
3. **Synthetic shape-A cases (clearly labeled as synthetic):** take a real benign release and
   inject a known-bad pattern taken from a real sample (install hook + exfil snippet) to create
   a "compromised" next version. Useful for unit-level recall, but reported separately and never
   mixed into real-world recall.

### Benign

A stratified random sample of recent changes from the `_changes` feed, by popularity bucket
(top 1k / 1k–10k / 10k–100k / long tail) and by new-package vs. new-version. A change counts as
benign if, **30 days after publish**, it's still on the registry and has no `MAL-`/GHSA record.
That's an imperfect label, so we'll hand-review a small subset of flagged "benign" items to
estimate label noise.

Target sizes for the first iteration: ~500 known-bad (with as many shape A as we can get) and
~5,000 benign. Larger once prospective labeling is running.

## Safe handling

- Malicious samples live only under `data/eval/` (gitignored), stored **as distributed**
  (encrypted zips stay encrypted at rest).
- Decryption and extraction go through the same `ArtifactTree` safe-extractor the pipeline uses:
  no execution, path-traversal and bomb guards. Extraction targets a temp directory that is
  deleted after the run, or happens in memory.
- No `npm`, `node`, or `npx` on the host, ever. Dynamic analysis of samples happens only in the
  Stage 5 sandbox once it's designed and reviewed.
- `tests/fixtures/` holds **only hand-written, inert snippets** that mimic patterns (e.g. a
  `package.json` with a `postinstall` pointing at a file, a string that is a long base64 blob).
  Never real malware.
- Antivirus (macOS XProtect on the laptop; none on the Linux VM by default) may quarantine extracted samples. That's expected. Don't
  disable it. Keep samples encrypted at rest.
- The eval manifest (sample IDs, labels, source, hashes) is a small JSON/CSV committed under
  `docs/` or `tests/`. The samples themselves are never committed.

## Results log

| Date | Commit | Dataset | Stage | Recall A | Recall B | Pass-through (benign) | Notes |
|---|---|---|---|---|---|---|---|
| 2026-10-27 | Phase 3 label fixes | `first-24h` (1 run, 24h, 109,497 changes; 0 malicious, 1,500 benign, all provisional) | baseline `forward-all` | n/a | n/a | 100% | No malicious samples survive label hygiene: 41 takedown placeholders and 2 projected matches excluded |
| 2026-10-27 | Stage 1 | `day1` (4 runs; 1,500 benign; DataDog 965 A + 905 B first releases, 481 A + 1,093 B follow-ons) | `stage1-rules` | **80.1%** (follow-on 2.7%) | **58.2%** (follow-on 21.7%) | **0.6%** weighted | DataDog recall (GuardDog-biased). `npm.publisher.unfamiliar` downgraded to LOW: 2.6% → 0.6% pass-through, A recall 81.1% → 80.1% |
| 2026-10-27 | Stage 1 | `day1` | `stage1` (rules + watched) | 85.6% (21.8%) | 58.2% (23.1%) | 14.5% weighted | Watched packages dominate pass-through |
| 2026-10-27 | Stage 2 | `day1` | `stage2-rules`, first set | 19.5% (31.0%) | 74.4% (67.7%) | 11.5% weighted | 2 MB file cap; 698/965 A samples had a larger new file |
| 2026-10-27 | Stage 2 | `day1` | `stage2-rules`, tuned | **71.5%** (84.0%) | **49.9%** (50.7%) | **1.0%** weighted | 16 MB cap; five rules MEDIUM → LOW. Base gone for 1,542 samples (follow-on numbers optimistic) |
| 2026-10-27 | Stage 2 | `day1` | `stage1+2-rules` (either) | **91.4%** (85.4%) | **66.1%** (55.6%) | **1.5%** weighted | Assumes Stage 2 sees every release, not only Stage 1's forwards. See [stages/static.md](stages/static.md#results) |
| 2026-10-27 | Stage 1 routing | `day1` | `stage1` (rules, watched, new, grown ≥ 64 KiB) | 93.0% (59.0%) | 100% (26.9%) | 25.8% weighted | Not flags: what Stage 2 reads. Decision 0008 |
| 2026-10-27 | Stage 1+2 | `day1` | **`pipeline`** (end to end) | **86.0%** (38.0%) | **66.0%** (22.5%) | **0.9%** weighted | Hybrid routing, 16 MB cap, `exfil-endpoint` v1. Simulation predicted it exactly |
| 2026-10-27 | Stage 1+2 | `day1` | **`pipeline`**, `exfil-endpoint` v2 | **86.0%** (38.0%) | **66.0%** (22.5%) | **0.7%** weighted | Webhook ids required, `requestbin.`; recall unchanged |
| 2026-10-28 | Stage 3 | `day1` | `stage3-rules` | **80.6%** (90.4%) | 33.7% (34.4%) | **0.2%** weighted | Capability gained + install-script code. Follow-ons optimistic (base gone) |
| 2026-10-28 | Stage 1+2+3 | `day1` | **`pipeline+3`** (end to end) | **89.7%** (38.7%) | **66.0%** (22.8%) | **0.8%** weighted | +3.7 pts on A vs `pipeline` |
| 2026-10-28 | Stage 1-4 | `day1` | **`pipeline+4`** (what is reported) | **91.1%** (38.7%) | **66.5%** (22.9%) | **0.9%** weighted | Stage 4 over every triaged version; report on MEDIUM+ or score ≥ 6. See [stages/correlate.md](stages/correlate.md#evaluation) |
| 2026-10-28 | Stage 4 | `day1` | `pipeline+4` + install hooks / dependencies vs the repo's `package.json` | **91.2%** (39.7%) | 66.5% (22.9%) | 0.9% weighted | Hooks: 53/57 malicious, 0/121 benign among comparable updates (2026-10-29, `repo.compared` v2: 51/55, 0/116) |
| 2026-10-29 | Stage 2 | `vm-day1` (1,000 A + 500 B benign, provisional; DataDog 3,444) | `stage2-rules`, `exfil-endpoint` v2 | 71.5% (84.0%) | 49.9% (50.7%) | 0.8% weighted (11 of 1,500) | Baseline on the VM's first day |
| 2026-10-30 | Stage 2 | `vm-day1` | `stage2-rules` + `static.encoded-url`, `static.function-require` (both MEDIUM 3) | 71.6% (84.0%) | **52.4%** (53.9%) | 0.8% weighted (no benign added) | +58 malicious samples (+1 A, +22 B, +35 B follow-on), **0 benign added, 0 lost**. A URL hidden as a whole base64/hex literal, and `new Function("require", body)`: what the `chai-as-*` / pino-clone family does with its second stage ([stages/static.md](stages/static.md)) |
| 2026-10-30 | Stage 1-3 | `vm-day1` | `pipeline+3` with the two rules above (analyst's run) | 89.4% (29.5%) | **67.6%** (22.8%) | 0.8% weighted (A 0.5%, B 2.8% provisional; unchanged) | Before: B 66.0%. +15 B end to end |
| 2026-10-30 | Stage 2 | `vm-day1` | `stage2-rules`, `exfil-endpoint` v3 + `webhook-placeholder` | 71.5% (84.0%) | 49.9% (50.7%) | 0.8% weighted | Same flags as v2 (0 differences). v3 alone lost 43 B samples (42 end to end, a `chai-as-*` family caught only via a Slack placeholder) for 1 benign: placeholders kept at MEDIUM under their own id instead |
| 2026-10-29 | Stage 1-4 | `vm-day1` (1,000 A + 500 B benign; DataDog) | `pipeline+4` before dependency reputation | 90.8% (29.5%) | 63.1% (22.9%) | 1.1% weighted | Baseline for the row below, same code otherwise. **Caveat (found 2026-10-30):** this and the next row ran while Stage 2 briefly had `exfil-endpoint` v3 without `webhook-placeholder`, which drops a `chai-*` family of ~31 B samples; the dependency rules' own gain is +1 A / +12 B, and the 67.8% B two rows down is with Stage 2 restored |
| 2026-10-29 | Stage 4 | `vm-day1` | `pipeline+4` + `npm.dependency.fresh-foreign` / `name-embeds-popular` | **90.9%** (29.5%) | **64.4%** (22.9%) | **1.1%** weighted (same 21 benign samples) | +1 A (`@mastra/node-audio@0.1.8`), +12 B (tea.xyz farm, `bipyruss`); 118 of the 119 `easy-day-js` samples gain a second MEDIUM reason. Benign: fresh-foreign 0/1,500, name-embeds 2 (not reported). See [stages/correlate.md](stages/correlate.md#evaluation) |
| 2026-10-29 | Stage 4 | `vm-day1` | `pipeline+4`, dependency review fixes (`STAGE_VERSION` 5, both dependency rules v2; rules `ec80d6148db6f04f`, watchlist and labels `20261029T221803Z`) | 90.9% (29.5%) | **67.8%** (22.9%) | 1.1% weighted (22 benign: +`@zerodot/discord@1.0.0`, B) | +31 B and the benign one are **not** from this change: none of the 32 gets a dependency-rule finding (checked offline); they come from the concurrent Stage 2 `exfil-endpoint` v3 / `webhook-placeholder` change (`chai-*` family), which the previous row's run predates. No sample lost. Dependency lookups: 173 names, 172 found, 1 missing, 0 failed; packuments now pinned under `data/eval/dependencies/` (172), so re-runs are offline |
| 2026-10-30 | Stage 1-4 | `vm-day1` | `pipeline+4`, every update with an install hook routed to Stages 2-3, `npm.install-hook` v2 (version-only command changes), `npm.install-script-changed`, diff base 2 (also the `chai-*` rules, added since the last row) | **96.4%** (**71.7%**) | **69.0%** (**55.3%**) | 1.4% weighted (A 1.0%, B 2.8%; 24 benign, was 22) | 1,905 -> 2,527 forwarded. Gained 611 malicious updates with an install hook (worm follow-ons whose hook was unchanged, so Stage 1 never sent their code on), 10 new packages (the `chai-*` rules), 2 benign (`glimmervoid` prereleases, a `bot${token}` Telegram reference). Lost `shoal-cli@0.4.3`: its only catch was a `console.log` banner whose version string changed |
| 2026-10-30 | Stage 1-4 | `vm-day1` | `pipeline+4`, precision pass: Stage 2 not-new and docs-only matches LOW, `code.capability-gained` v2, constant code (extractor v2), downgrade v2 + `WEAK_ALONE`, `install-script-not-in-repo` v3, inline install code | 2,496 malicious (72.5%; was 2,503) | (see left) | 20 of 1,500 benign (was 24) | -8 malicious, all follow-on releases whose series' first malicious release is still reported (`esoftplay` x5, `base_parts_ai`, `healcode-client`, `jio-payment-sdk`); +1 (`tnactgfds@0.30.5`). Live, same window: 1,769 -> 1,160 reported (-34%) |
| 2026-10-30 | Stage 1-4 | `vm-day1` | `pipeline+4`, second precision pass: `code.capability-gained` v3 (`dynamic-code` alone MEDIUM only via `eval`), extractor v3, hashed chunks, `install-script-changed` v2 (line endings); then simulated on that run's findings: LOW cap 3, docs-only matches LOW for every static rule, `non-registry` v2 | 2,494 malicious (72.4%; was 2,496) | (see left) | 18 of 1,500 benign (was 20) | -2 malicious, both caught only by the CRLF artefact ("+0 -0 lines"): `@pixui-dev/pxw@0.1.23` and `securegate-cli-tool@2.1.4`, follow-on releases whose install script is unchanged but for line endings; their earlier releases aren't in the set. The LOW cap, docs and non-registry changes lose none on top. Live: of 1,761 unreviewed versions, 1,078 still reported before this pass, about 845 after |
| 2026-10-31 | Stage 1-4 | `vm-day1` | `pipeline+4` with everything above, plus install code that follows the files a hook loads (`npm.install-script-code` v2) | **2,506 malicious (72.8%; was 2,494)** | (see left) | 19 of 1,500 benign | +12 malicious through followed files (`@emilgroup/*` SDKs, `free-anthropic-claude`, `github-badge-bot`, `aicp-tracker`, `@speedshop/sdk-api`, `string-setup-helper`), none lost; +1 benign (`domain-driver@0.8.2`). 117 malicious and 4 benign samples' install-code findings changed |
| 2026-10-31 | Stage 0-4 | `vm-day1` | `pipeline+4`, third precision pass: `install-script-changed` v3 (a loaded file counts only when it adds a risky use), `exfil-endpoint` v4 (written Telegram placeholders), Vite hashes in `unhashed`, `capability-gained` v4 (placeholder bases), diff base 3 (platform builds) | 2,503 malicious (was 2,506) | (see left) | 4 fewer benign reported | -3 malicious, all `aicp-tracker` (1.0.1, 1.1.7, 1.3.4), whose loaded files changed without a risky line; the family is still reported through 1.0.7. Benign: `domain-driver@0.8.2`, `@mastra/e2b`, two `glimmervoid` releases. A first try of `capability-gained` v4 that made `eval` LOW too cost 18 malicious (`autotel-*`, `awaitly-*`) and was narrowed. Diff base 3 changes no `vm-day1` sample |
| 2026-10-31 | Stage 2-4 | `vm-day1` | `pipeline+4`, `binding.gyp` actions and command expansions as install code, extractor v4 (`process.getBuiltinModule`, `Reflect.get(process, 'env')`), every base chunk of a name compared | 2,506 malicious (was 2,503) | (see left) | benign unchanged | +3 malicious, all `awaitly-visualizer` (2.0.2, 13.0.1, 22.0.2), run at install only through `binding.gyp` |
| 2026-10-31 | Stage 1-4 | `vm-day1` | `pipeline+4`, `publish-method.downgrade` v3 (LOW on a prerelease) | 2,506 malicious (unchanged) | (see left) | benign unchanged | The rule fires on 149 malicious samples, none a prerelease. Live: 77 of 101 queue versions reported by it alone were prereleases |
| 2026-10-31 | Stage 2-4 | `vm-day1` | `pipeline+4`, Stage 2 compares a file with no counterpart against all of the base's code (`BaseFiles.anywhere`) | 2,505 malicious (was 2,506) | (see left) | benign unchanged | -1: `esoftplay@0.0.248` moved its Telegram code into new files; 8 of the family's 22 samples still reported. Live estimate: 27 of 46 queued exfil-endpoint reports with a base cleared |
| 2026-10-31 | Stage 3 | `vm-day1` | `pipeline+4`, `install-script-changed` counting a hook's own file only when its change adds a risky line (not adopted) | 2,497 malicious (was 2,506) | (see left) | benign unchanged | -9: 8 `esoftplay` releases and `fooobar@1.0.14` edit an existing hook file without a new risky import. Dropped |
| 2026-10-31 | Stage 3 | `vm-day1` | `pipeline+4`, `npm.install-script-obfuscated` (HIGH, weight 4: a file `npm install` runs is obfuscated; on updates only new or changed ones) | 2,505 malicious (unchanged) | (see left) | benign unchanged (0 of 1,500 fire) | Fires on 96 malicious samples (72 updates, 24 new; the `@antv/*` Shai-Hulud wave's obfuscated `bundle.js`), all reported already: it raises their rank, not recall. Live estimate from report evidence: 3 queue versions (`motionchart-cli` 1.0.3 and 1.0.4, inconclusive; `@routinecrew/routinecode`, benign) |
| 2026-10-31 | Stage 4 | `vm-day1` | `pipeline+4`, `npm.dependency.known-malware` v2: a specifier only npm's `0.0.1-security` holder satisfies is LOW (weight 1) | 2,505 malicious (unchanged) | (see left) | benign unchanged | Skipping such dependencies outright was tried first: also no reporting change, but 6 of the rule's 12 malicious samples (a tailwind-icon campaign, `vite-support-kit`, all `fs: ^0.0.1-security`) lost the finding, so it stays as LOW. Live: clears 3 of the rule's 4 false positives (`modulus-security`, `modulus-firewall`, `victor-nest-resource`) |
| 2026-11-01 | Stage 3 | `vm-day1` | `pipeline+4`, `npm.install-script-obfuscated` v2 (also javascript-obfuscator's string-array rotation prologue, for renamed identifiers) | 2,505 malicious (unchanged) | (see left) | benign unchanged (0 fire) | Fires on 100 malicious samples (was 96: `analytics-browser`, `qdrant-js`, `react-native-country-select`, `tailwin`). Live: catches `sino-bc-cli`'s renamed-identifier bundle |
| 2026-11-01 | Stage 4 | `vm-day1` + live verdicts | `WEAK_ALONE` += `code.capability-gained`, `static.webhook-placeholder` (simulated over the eval dump and the current reports of every verdict) | 2,505 malicious (unchanged) | (see left) | benign unchanged | Live: 888 -> 825 benign verdicts still reported (-63), 27 / 27 malicious and 18 / 18 inconclusive kept. Last 26 ticks before it: 324 of 96,550 versions reported, 307 benign, 16 malicious |
| 2026-11-01 | Stage 4 | `vm-day1` | `npm.dependency.known-malware` v3: a UPM package's `com.unity.*` dependency is LOW | 2,505 malicious (unchanged: no sample has such a dependency) | (see left) | benign unchanged | Live: 41 `net.dreditor.*` releases in the 03:12 tick (all HIGH through `com.unity.ugui` and others) and `com.hidano.shadow-only-shader`; with v2, all four live false-positive kinds of the rule are LOW |
| 2026-11-01 | Stage 2 | captured tarballs | `static.known-signature` v1 (9 signatures from our malicious verdicts) | every captured family member matches | (see left) | 0 of 814 benign and 26 inconclusive verdicts except `calculator-preinstall-hook-demo@1.1.1` (same author's webhook); 1 of 6,004 other captured tarballs (`dependencykfeg@25.1.9`, an unreported release of a confirmed family) | Not measured on `vm-day1`: signatures from our own verdicts would only find what they were taken from there. Recall is prospective |
| 2026-11-04 | Stage 4 | `vm-day1` | `pipeline+4` (2,507 malicious reported) with a per-sample dump, for `repo.established-match` clearing install code (decision 0017) | -1 malicious if the clearing is on (2,507 → 2,506): `gina@0.7.1`, whose code is in `gina-io/gina` (2013, 11 stars, commit on the default branch) | (see left) | benign unchanged (3 same-shape benign have 0-star repositories) | Live: would clear 33 of 1,231 reported versions with a GitHub repository, 20 of 20 reviewed benign. Off (`CLEAR_ESTABLISHED = False`) until the owner decides; the finding is reviewer evidence |
| 2026-11-06 | Stage 4 | `vm-day1` | `pipeline+4` with commit history and the API (decision 0018) | 2,507 → 2,507 reported; `CLEAR_HISTORY` on: 2,506 (−`gina@0.7.1`) | (see left) | 14 → 14 (15 before the monorepo exception for version-only tags) | `no-new-commits` 60 malicious / 0 benign, `commit-after-release` 13 / 0, all already reported. Live: the clearing would remove 78 of 1,507 reports (60 reviewed benign, 0 reviewed malicious). Off (`CLEAR_HISTORY = False`) until the owner decides |
| 2026-11-08 | Stage 1 | `vm-day1` + live verdicts | `publish-method.downgrade` v4 (full weight only with a co-signal or, watched, a dropped `gitHead`), `dependency.non-registry` v3 (protocols npm can't fetch), `version.suspicious` v3 (date-shaped majors); [proposal](proposals/stage1-precision.md) | 254 / 254 affected samples still reported by `pipeline+4` (real code, also with watchlist popularity): all cells unchanged | (see left) | benign unchanged | Live, 87 runs (Oct 28 - Nov 3, every report reviewed): downgrade -74 (73 benign, 1 inconclusive), non-registry -6, version -4 reported versions; 41 / 41 malicious kept. 4-day run of Nov 7 (unreviewed): `version.suspicious` alone -316 (314 `@haybarn/*`). 0 of 53,389 OSV malware versions has a date-shaped major |
| 2026-11-08 | Stage 4 | `vm-day1` + live verdicts | `revived-with-new-dependency` v2 (LOW when the previous publisher returns with no maintainer added) on top of the Stage 1 row above | 254 / 254 affected samples still reported (all cells unchanged); 4 of the rule's 36 malicious samples get the LOW form and stay reported through other signals | (see left) | benign unchanged | Live, 87 runs: -74 reported versions (all benign). With the Stage 1 row: 1,371 → 1,213 reported (157 benign, 1 inconclusive fewer), 1,011 → 868 packages; 41 / 41 malicious kept. 4-day run of Nov 7: 1,438 → 994 |
| 2026-11-08 | Stage 4 | `vm-day1` + every recorded live run (10-28 22:18Z to 11-08 15:32Z) | `npm.dependency.missing` v1 (MEDIUM 3: an added dependency was 404 when the run looked it up, under a name unrelated to the release's; siblings INFO), `STAGE_VERSION` 12 | DataDog unchanged: fires on 1 of 3,444 (`@financials/using-dep-conf@1.0.0`, already reported); no DataDog dependency was first published after its dependent, so the set can't show the pattern | (see left) | 0 of 1,500 benign fire | Live, simulated on each run's recorded 404s: 121 releases with a 404 dependency (~11/day), 35 MEDIUM. **+16 campaign wrappers reported** (Tailwind/Animate.css template; 5 with OSV `MAL-` records, 1 malicious + 3 unverified verdicts; 0 before), +15 other reports (~1.4/day, unreviewed, private or unpublished names), 4 benign already reported; nothing lost. Not caught: 4 wrappers that require the payload without declaring it. See [stages/correlate.md](stages/correlate.md#missing-dependencies-npmdependencymissing-stage-version-12) |
| 2026-11-08 | Stage 1 | `vm-day1` + live verdicts | `version.suspicious` v4 (year major with a month-day minor, or 0 in `as_of`'s year; `YYMM` major), `dependency.non-registry` v4 (SheetJS's CDN LOW); [round 2](proposals/precision-round2.md) F5, F6b | the 21 malicious samples at risk through the two rules all still reported by `pipeline+4` (real code) | (see left) | benign unchanged | Live, real rules on the proposal's 3,032 reported versions (2,208 reported today): F5 -46, F6b -50, all benign, 0 positives lost; on all 3,211 with a verdict: -68, -53. F5 narrowed from the proposal (minor 0 only in `as_of`'s year): "minor 0 in any year" exempts 15 OSV malware versions (`2000.0.0`, `1999.0.1`, ...); as built, 0 of 53,389 |
| 2026-11-08 | Stage 4 (+ Stage 3 signal) | `vm-day1` + live verdicts | `revived-with-new-dependency` v3 (LOW with provenance; F7); `npm.install-build-tool` (Stage 3 INFO) explains `npm.install-hook` (LOW; F2), `STAGE_VERSION` 13; [round 2](proposals/precision-round2.md) | F7's 1 at-risk sample still reported; F2: none of the 433 samples reported only through install rules has build-tool-only hooks, and the 4 other malicious samples with such hooks are decided as before by `pipeline+4` (1 reported, 3 not either way) | (see left) | benign unchanged | Live, real code on the proposal's 3,032 reported versions: F7 -65 (65 packages), F2 -7 where the tarball was captured (-12 if the 5 without one have no `binding.gyp`), all benign, 0 positives lost; on all 3,211: -69, -8 (-13) |
| 2026-11-08 | Stage 2 | `vm-day1` + live verdicts | `exfil-endpoint` v6 (placeholder tunnel labels, a host among 2+ other non-endpoint domain literals: LOW; F3c, F3b), `hardcoded-ip` v3 (markup, tables, lockfiles, notices, `*.test.js`, `package.json` metadata URLs: LOW; F4b); [round 2](proposals/precision-round2.md) | the 65 malicious samples at risk through the two rules all still reported by `pipeline+4` (real code) | (see left) | benign unchanged | Live, real code (stored findings judged again on the captured tarball): F3b+F3c -43 (17 packages; simulated 33), F4b -12; with the rules on stored snippets where no tarball: -60, -20. All benign, 0 positives lost. **Round 2 together** (F5, F6b, F7, F2, F3b+F3c, F4b) on the proposal's 3,032: 2,208 → 1,985 reported (-223, 153 packages, all benign; precision 5.8% → 6.4%), with the snippet proxies -253 (6.5%; proposal: -227, 6.5%). On all 3,211 with a verdict: 2,371 → 2,109 (-262), 136 positives kept |
| 2026-11-08 | Stage 0 | live verdicts + `vm-day1` + DataDog | diff base 5 (a prerelease named by a commit id is diffed against the latest earlier publish on its line; [round 2](proposals/precision-round2.md) F8), `DIFF_BASE` 5, recorded per run | DataDog: 0 of 3,444 samples on a commit line; `vm-day1`: 94 on one, all benign (0 malicious) | (see left) | benign: see notes | Live verdicts, `pipeline+4` with today's code on both bases: 199 of the 242 commit-line reports get a new base; reported 21 → 3, **-18 benign** (7 packages), 0 positives on a commit line (0 of 137). The proposal's ~135 was mostly `@astryxdesign/cli` (119), whose reports came from an unreadable base over 16 MiB, already fixed by `d46ef27`. Six unpruned runs: base 5 changes 2,846 of 4,859 commit-line changes, 0 reported with it. Replay of two unpruned runs (diff base 4): identical |
| 2026-11-08 | Stage 4 (+ Stage 3 signal) | `vm-day1` (all 433 samples reported only through install rules) + live verdicts | `npm.install-explained` (Stage 3 INFO: S1 platform-binary launcher, S2 own-release download with a checksum, S3 agent-skill copier with the owner's three guards) explains `npm.install-hook`, `-script-changed`, `-script-code` (LOW), `STAGE_VERSION` 14; `agent.hostile-instructions` (Stage 3 MEDIUM); [round 2](proposals/precision-round2.md) S1-S3 | **0 of 433 explained** (real code, every sample; the proposal had checked 149), 0 hostile; only `@nx/key@3.2.0` has 2+ platform builds (refused: `env-all`, network off the registry) | (see left) | benign unchanged | Live, the 3,244 reported verdicts (2,107 reported with today's code), signal on the 738 captured tarballs of the 1,442 versions with an install finding, real `explained` + `decide`: **2,107 → 2,022 (-85: S1 36, S2 34, S3 15; 70 packages), all benign**; 0 malicious, unwanted or unverified lost; precision (malicious + unwanted) 4.23% → 4.41%. `agent.hostile-instructions` fires on none of them (2 benign quoting the attack before its quote/discussion guards). Measured on the stored diff base (4): a few commit-line versions among the 85 may also be among F8's 18 |
| 2026-11-08 | Stage 3 | `vm-day1` + live runs | `code.function-constructor` v1, extractor v5 (the Function constructor through `constructor`: MEDIUM for `x.constructor.constructor` or with `require`/`process`/`module` handed over, LOW for a function literal's otherwise) | unchanged: fires on 4 of 3,443 malicious, all LOW, each already reported or not routed (from a Stage 3 dump of every sample; `pipeline+4` itself ran out of memory at 8 GB in the scratch copy) | (see left) | 2 of 1,500 benign fire, both LOW: no benign sample reported | Live: `txnforge@1.0.4` and `mock-datas-lib@1.0.1` (adjudicated malicious, score 0) now MEDIUM; 3 unreviewed new catches (`jmrwd-gjdob-util`, `smfos-bskdz-util`, `tsbwt-hawsi-util` @1.0.1). No other Stage 3 finding changes on 42 reviewed malicious versions. Benign: ~3 extra reports a day (≤ 8), 0 from the constructor-chain form. See [stages/ast.md](stages/ast.md) |
| 2026-11-08 | Stage 3 | `vm-day1` + live runs | `npm.undeclared-package` v1 (INFO, weight 0), extractor v6 (packages loaded by name; `.d.cts`/`.d.mts` skipped) | unchanged (INFO reports nothing): fires on 758 of 3,443 malicious | (see left) | 64 of 1,500 benign fire; none reported | As MEDIUM it would have added 700-1,150 benign reports a day (live, 32,272 versions); the narrowest variant (undeclared, not a devDependency, not in test/template paths, and missing from npm) 8-47 a day, but it needs Stage 4's registry lookup. `tailwind-animate-engine@1.0.6` gets the INFO finding and stays unreported. See [stages/ast.md](stages/ast.md) |
| 2026-11-08 | Stage 2 | Baileys corpus + live runs | `static.channel-follow` (MEDIUM 3, "unwanted"; in `ALWAYS_NEW`); [proposal](proposals/prefreeze-recall.md) | `vm-day1`: +1 B follow-on (`violetics`) | (see left) | `vm-day1` benign unchanged | Corpus: 26 / 26 hidden auto-follow forks, 4 / 4 disclosed ones, 1 of 23 benign (`@yshtxxproject`, same code as a ruled fork). Live misses: +2 (`@sakataa/baileys@2.0.0`, `@axo_cuy/baileyss@3.0.1`). Live, 4.6 days: +11 reported, all default-on forks (unwanted; 0 FP headline, 11 strict) |
| 2026-11-08 | Stage 2 | live runs | `static.shell-startup` (`hook`, `inject` MEDIUM 3; `shell`, `code` LOW 1) | `vm-day1`: no sample changes | (see left) | `vm-day1` benign unchanged | Live misses: +2 (`@atedone/workspace-context` 0.0.12, 0.0.18; with small-update routing). Live, 4.6 days (1,421 versions with a match): +1 reported (`@heyvamz/carry`, completion installer); as MEDIUM, `shell` and `code` would add ~8 and ~2 a day |
| 2026-11-08 | Stage 1-3 | `vm-day1` | `pipeline+3`, updates ≤ 64 KiB routed (`small update`) plus `static.channel-follow` and `static.shell-startup`; before at `30b728d` (`pipeline+4` didn't fit the 4 GB cap) | 920 / 965 (393 / 481) unchanged | 612 / 905 (**606 → 669** / 1,093) | 13 of 1,500 before and after | +62 B follow-ons from the routing (existing rules), +1 from `channel-follow`; 0 lost. Live: +16.2k versions/day read, +0.14 GB/day, 2 of 6,436 sampled small updates reported (~5/day, both look benign) |
| 2026-11-08 | Stage 3 + Stage 4 | `vm-day1` (per-sample dump) + 8 unpruned live runs (29.2 h, 29,470 versions) + live verdicts | `npm.undeclared-package` v2 (INFO; extractor v7: at module load, from the entry points and the files they load) and `npm.undeclared.missing` v1 (MEDIUM 3: such a name was 404 at Stage 4's lookup; own scope, watched and siblings never asked; STAGE_VERSION 15) | `vm-day1`: unchanged (2 malicious get the finding, `react-tmedia@2.1.4`, `tailwind-state@1.0.3`, both reported already) | (see left) | `vm-day1`: 0 of 1,500 benign | Live: +1 benign report in 29.2 h (~0.8/day: `@ohos-ports/cms-components`, 21 `@smallstack/*` names npm lacks); v2 INFO on 204 versions (v1: 993). Recall: `tailwind-animate-engine@1.0.6` (+3 identical-manifest wrappers, tarballs gone; all unverified). 0 of 56 reviewed positives with tarballs changed. See [stages/correlate.md](stages/correlate.md#undeclared-and-missing-npmundeclaredmissing-stage-version-15) |
| 2026-11-08 | Stage 2 | Baileys corpus + verdict tarballs (1,522) + live tarballs (35,544) + `vm-day1` | `static.known-signature` v3: KX-0008/0009/0011 (Baileys channel follows) retired for `static.channel-follow` | unchanged | (see left) | unchanged | Every KX match also has a non-demoted `channel-follow` match: 16/16, 2/2, 1/1; 0 signature-only. Reported forks stay reported, HIGH -> MEDIUM, score -6. See [stages/static.md](stages/static.md) |
| 2026-11-09 | Stage 3 | live verdicts (750 with the rule) + `vm-day1` (629 malicious samples it fires on) | `npm.install-script-changed` v4: LOW when every changed install file differs only in volatile strings (versions, digests, dates, integrity; same URL hosts) or printed text | `vm-day1`: all 629 stay MEDIUM, no report changes | (see left) | live: 64 fewer benign reports (27 packages) | Live, today's other findings and Stage 4's `explained`/`decide`: 655 of the 750 reported → 591 (−64 benign: 50 volatile, 14 printed); 0 of 6 malicious, 3 unwanted, 27 unverified lost. Not built: comments/formatting only (−8, loses `hyrox@0.1.6`, unverified), any string-literal change (−27, loses 8 `vm-day1` samples). See [stages/ast.md](stages/ast.md) |
| 2026-11-09 | Stage 3 | `vm-day1` (per-sample scan of every sample; today's `pipeline+4` per sample for the candidates) + 12 fully captured live runs (33.2 h, 35,734 versions) + live verdicts (108 positives, 1,428 benign with tarballs) | `npm.load-fingerprint` v1 (MEDIUM 3; extractor v8, `lang/at_load.py`): a loaded file reads two of `os.hostname()`/`userInfo()`/`networkInterfaces()`/`homedir()` in code that runs at load, the loaded files use the network; not a `bin` target; on updates only if the base didn't | 0 shape-A samples fire | **+2 new packages** (`@twilio-client/twilio-client@0.0.1`, `safe-chain-test@1.0.0`), **+40 follow-ons** (32 `blocks-nextjs`); fires on 310 malicious, 268 reported already | `vm-day1`: 0 of 1,500 benign fire | Live: 4 newly reported in 33.2 h (~2.9/day, all look benign: `dsh-session-gallery`, two `@saccolabs/*-mcp`, `chatbotx-mcp`); 1 true positive already reported (`archetype-index-sdk`, score 5 → 8). Reviewed: 3 positives and 1 benign fire, all reported already; 0 reviewed benign newly reported. The text form without "at load" fired on 33-73 unreported live versions a day; a command, write or detached spawn at load was measured and not built. See [stages/ast.md](stages/ast.md#load-time-payloads-npmload-fingerprint-extractor-v8) |
| 2026-11-09 | Stage 3 | `vm-day1` (per-sample scan of every sample; `pipeline+4` per sample for the candidates) + 13 fully captured live runs (33.7 h, 37,154 versions) + live verdicts (108 positives, 1,434 benign with tarballs) + 35 live misses with a tarball | `npm.publish-at-load` v1 (MEDIUM 3; extractor v9, `lang.at_load.commands`): a command that runs at load (an `exec`/`spawn`/`execa` call or a same-file wrapper, reached at load) in the loaded files (not a `bin` target) or the install code publishes to npm; on updates only if the base didn't | 28 shape-A samples fire, all reported already | **+46 new packages** (the `*_z3n` self-publishing spam; each now score 5); fires on 105 malicious, 59 reported already (`@emilgroup/*` worm and 18 others through the install rules) | `vm-day1`: 0 of 1,452 benign fire | Live: 0 of 37,154 versions fire (0 a day); reviewed: 0 benign, 0 positives fire (none publishes); 0 of 35 live misses. Not built: publish or token text in a loaded or install file (181 unreported live versions, ~129 a day), a publish string that runs at load in any use (2 live, 5 reviewed benign: help text), token + registry `PUT` at load (fires on nothing). See [stages/ast.md](stages/ast.md#self-publishing-at-load-or-install-npmpublish-at-load-extractor-v9) |
| 2026-11-09 | Stage 3 | `vm-day1` (the 433 malicious samples reported only through install rules, per sample) + 18 live runs (17 fully captured, 38 h, plus the 4-day catch-up run; 479 versions whose install code names an agent directory) + live verdicts (202 such versions with a tarball) | `npm.install-explained` v2: S3 (agent-skill copier) only for copies into the project: no home-directory reference in the install code or hook line, no package loaded by name (decision 0015, addendum 2026-11-09); `npm.install-agent-user-wide` (INFO, weight 0) notes the home reference | 433 / 433 unchanged: S3 explained none before or after; the note fires on 1 (`aicp-tracker@1.0.7`, reported through its network and process install code) | (see left) | `vm-day1` benign unchanged | Live: S3 explained 69 versions (30 packages), v2 keeps 23; 43 user-wide and 3 undetermined (`@doist/todoist-cli`) lose it. Reports: **+0** in the 38 fully captured hours, **+7** in the catch-up run (all reviewed benign). Reviewed: **16 benign versions reported again** (14 user-wide copiers to relabel unwanted, 2 that only mention home); 0 positives change (none was S3). See [stages/ast.md](stages/ast.md#s3-v2-copies-into-the-project-only-2026-11-09) |
| 2026-11-09 | Stages 2-4 (precision round 3) | all 3,716 verdicted live versions, Stages 1-4 replayed per version with the real code (2,975 recomputed on their tarballs) + `vm-day1` (`pipeline+4` per sample on all 3,444 malicious samples, repository comparison off; the 1,312 a fix could touch re-run with the fix) | `static.exfil-endpoint` v7 (X1-X4: core-js's cited paste, `*.host` patterns, separated domain lists, OAST placeholder labels), `static.hardcoded-ip` v4 (X5: example addresses LOW, AliDNS/DNSPod/114DNS resolvers), `npm.install-build-tool` v2 (X6: `node-addon-api`/`nan` header lookups in `binding.gyp`), `npm.dependency.fresh-foreign` v3 (X7: LOW on a prerelease) | `vm-day1`: 1,309 of the 1,312 at risk reported before and after, **0 lost** (2,708 of 3,444 overall) | (see left) | live: 1,834 → 1,787 reported, **-47 benign** (46 packages, 3.1% of 1,533); 0 malicious, unwanted or unverified lost, and no positive's touched finding changes; precision 15.02% → 15.42% | [precision round 3](proposals/precision-round3.md). Rejected with numbers: Telegram tokens not written out (encoded in `github-badge-bot`, `foundry-toolkit`), echo-only hooks (4 DataDog PoCs), a narrower downgrade co-signal (`@hithink-tech/hithink-finance-cli`, unwanted), revived with popular deps (`xrpl@2.14.2`) |
| 2026-11-10 | Stages 1-4 (precision round 4, agents A-G) | all 3,716 verdicted live versions, Stages 1-4 replayed per version with the real code (today's verdicts) + `vm-day1` (`pipeline+4` per sample on every sample a change could touch) | D: `static.exfil-endpoint` v8 (Telegram wrappers whose file collects nothing), `static.hardcoded-ip` v5, `static.function-require` v2; C: `npm.dependency.non-registry` v5 (source vouched for by the previous release), `npm.dependency.fresh-foreign` v4 (watched scope); A: `npm.install-persistence`, `static.channel-tagging`, `npm.install-script-code` v3 (hidden code), `npm.install-script-changed` v5 (content-aware, **trade-off**), spawned scripts; E: `npm.install-explained` v3 (S5 inert install code, cargo-dist); B: `npm.install-build-tool` v3, `npm.install-inert`; F: `static.padded-code`; G: `npm.install-script-loader`, `npm.install-script-exfil`, script masking, scripts started by scripts, Windows hook paths | `vm-day1`: **+21** (17 `static.padded-code`, e.g. the `@gluestack-ui`/`@react-native-aria` compromise; 4 install-script rules), **-6** accepted (`esoftplay` follow-ons whose unchanged `bin/cli.js` the install hook never runs; A's v5) | (see left) | live: 1,787 → 1,428 reported; **benign 1,486 → 1,112 (-25%)**; positives: `tmailcli@0.1.5` (unwanted, Go binary) lost, `hyrox@0.1.6` (unverified) lost, 2 unwanted + 1 unverified gained; precision 15.42% → 20.46% (unwanted also rose 224 → 239 through re-reviews) | proposals `precision-round4-{A..G}.md`. Owner rejected D6 (obfuscation in hashed `assets/`), R1 (revived with popular deps: `vant`), E3 (inline `node -e` on updates: `shoal-cli`); `CLEAR_*` stay off; patchers stay reported |
| 2026-11-10 | Stages 1-4 (precision round 5, agents H-L) | all 3,716 verdicted live versions, Stages 1-4 replayed per version with the real code (agent K's corrected harness: the run's watchlist, known-malware regenerated; today's verdicts), full replay of final main `7af2e32` + `vm-day1` (`pipeline+4` per sample on every sample a change could touch) | K: `npm.dependency.non-registry` v6, `npm.provenance.githead-dropped` v2; L: `static.obfuscated` v2 (Emscripten glue), `static.exfil-endpoint` v9, `static.hardcoded-ip` v6, test-named files not loaded by hooks or entry points; J: `npm.install-script-changed` v6 (lines the previous install code already ran), `npm.install-script-code` v4, `npm.install-persistence` v2; H: `npm.install-explained` v4 (S6 own-binary downloads that run nothing fetched); I: `binding.gyp` parser (recall fix), `npm.install-build-tool` v4 | `vm-day1`: 0 lost, 0 gained | (see left) | live: 1,413 → 1,348 reported; **benign 1,087 → 1,022** (K -11, L -17, J -14, H -16, I -7 net); 0 positives or unverified changed; precision 21.40% → 22.46%. Rounds 4 + 5 with today's verdicts: benign 1,463 → 1,022 (-30%), precision 16.73% → 22.46%; `esoftplay@0.0.269-beta96052d3` (re-reviewed malicious; follow-on, lost to round 4's accepted v5) | proposals `precision-round5-{H..L}.md`. Owner rejected L4 (16 KiB Telegram window) and J2 (loses `gina@0.7.1`) |
| 2026-10-27 | Stage 1 | `day1` | baseline `popularity-only` | 21.8% | 0.0% | 13.9% weighted | |
| 2026-10-27 | Phase 3 label fixes | `first-24h` | baseline `popularity-only` | n/a | n/a | 13.5% weighted (A 14.0%, B 0%; raw sample 33.3%) | 14,743 of 105,350 shape-A releases are watched. Before the fixes, this row read "recall 0/29", every one a label artifact |
