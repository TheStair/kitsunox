# Evaluation

> **Status (2026-10-27):** OSV labels; datasets built from our own ingest runs; DataDog malware
> samples imported as encrypted data ([0007](decisions/0007-datadog-samples-and-follow-on-releases.md));
> baseline and Stage 1 predictors.

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
| 2026-10-27 | Stage 1 | `day1` | baseline `popularity-only` | 21.8% | 0.0% | 13.9% weighted | |
| 2026-10-27 | Phase 3 label fixes | `first-24h` | baseline `popularity-only` | n/a | n/a | 13.5% weighted (A 14.0%, B 0%; raw sample 33.3%) | 14,743 of 105,350 shape-A releases are watched. Before the fixes, this row read "recall 0/29", every one a label artifact |
