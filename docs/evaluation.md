# Evaluation

> **Status:** light harness implemented (2026-10-27): OSV labels, datasets built from our own
> ingest runs, and baseline predictors. Malware tarballs (DataDog dataset) are deferred by
> decision, so code-level stages can't yet be measured on real attacks.

## How to run

```sh
uv run kitsunox labels sync                  # OSV MAL- records for npm (~220 MB download)
uv run kitsunox eval build <name>            # join all recorded runs with the newest labels
uv run kitsunox eval run <name> --predictor popularity-only   # or forward-all
```

- **Labels** (`evaluation/labels.py`): every OSV `MAL-` record for npm, reduced to
  `{package → (id, published, versions, ranges)}` and saved under
  `data/labels/npm/<id>.json`. Withdrawn records are dropped. Matching is exact: explicit version
  lists, or SEMVER ranges (`introduced`/`fixed`/`last_affected`). The parser is fuzzed.
- **Dataset** (`evaluation/dataset.py`): every `Change` from recorded runs is matched
  against the labels.
  - **Malicious samples:** releases covered by a record.
  - **Benign samples:** a deterministic stratified sample, N per (shape, watched) stratum,
    ordered by a hash of (dataset name, release). They are *settled* only once the label set is
    ≥30 days newer than the release, and *provisional* until then.
  - **Bookkeeping:** a release seen in several runs counts once (earliest run). Datasets record
    the label set's id and SHA-256.
- **Metrics** (`evaluation/metrics.py`):
  - A `Predictor` decides forward/clear for each change. Each report cell is
    `label/shape[/provisional]` with total, forwarded and rate (recall for malicious,
    pass-through for benign). The `*/all` rollups use settled samples only.
  - **Baselines:** `forward-all` (upper bound on recall) and `popularity-only` (the watchlist
    half of the forward policy, with no detection). Stage 1 will plug in as another predictor.

### Why malicious samples will be scarce at first

npm replaces malicious versions with a `0.0.1-security` placeholder, usually within hours. A
malicious release only becomes a sample if an ingest run recorded its packument **before** the
takedown. The dataset therefore grows with regular ingest runs ("prospective labeling"). OSV
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
- macOS XProtect or other antivirus may quarantine extracted samples. That's expected. Don't
  disable it. Keep samples encrypted at rest.
- The eval manifest (sample IDs, labels, source, hashes) is a small JSON/CSV committed under
  `docs/` or `tests/`. The samples themselves are never committed.

## Results log

| Date | Commit | Dataset | Stage | Recall A | Recall B | Pass-through (benign) | Notes |
|---|---|---|---|---|---|---|---|
| (none yet) | | | | | | | |
