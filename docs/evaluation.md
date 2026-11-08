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
| `s1`, `s1_forwarded` | Stage 1's route: `rules`, `watched`, `new`, `hook`, `grown`, `size-unknown`, `none` |
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

**Truth** for a version, in this order (`live.truth`):

| | Behaviour truth (headline) | OSV truth | OSV only |
|---|---|---|---|
| npm placeholder (`0.0.1-security`, `0.0.0-stage`) | excluded | excluded | excluded |
| verdict `malicious` / `benign` | malicious / benign | used only without an OSV record | ignored |
| verdict `inconclusive` | excluded unless OSV | excluded unless OSV | ignored |
| OSV record *observes* it ([0005](decisions/0005-label-hygiene.md)) | malicious | malicious | malicious |
| OSV record only *projects* onto it | excluded | excluded | excluded |
| npm takedown after it, no OSV | benign (malicious in the "+ takedowns" row) | same | same |
| none of these, released ≥ D days before `as_of` | benign | benign | benign |
| none of these, younger | excluded (provisional) | same | same |

**Cells.** TP = flagged and malicious; FP = flagged and benign (`fp_unreviewed`: of those, how
many have no verdict, so they are *presumed* benign); FN = not flagged and malicious; TN = not
flagged and benign. Recall = TP / (TP + FN), precision = TP / (TP + FP), FP rate = FP / (FP +
TN), each with a Wilson 95% interval. Excluded versions are counted by reason.

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
| 2026-10-27 | Stage 1 | `day1` | baseline `popularity-only` | 21.8% | 0.0% | 13.9% weighted | |
| 2026-10-27 | Phase 3 label fixes | `first-24h` | baseline `popularity-only` | n/a | n/a | 13.5% weighted (A 14.0%, B 0%; raw sample 33.3%) | 14,743 of 105,350 shape-A releases are watched. Before the fixes, this row read "recall 0/29", every one a label artifact |
