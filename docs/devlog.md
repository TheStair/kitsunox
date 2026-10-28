# Kitsunox dev log

Reverse-chronological. Newest entry first.

## 2026-10-28: Metadata-vs-tarball rules, and surviving network failures

**Stage(s):** Stage 2 (npm artifact rules), Stage 0 and `collect` (resilience)
**Context:** The user asked for a rule closing the "declared size is publisher-controlled" gap
from [0008](decisions/0008-stage2-routing-and-tarball-capture.md). Then they asked for
protection against network drops, choosing that over renting cloud compute. From Stage 5 on,
the whole pipeline is planned to move into a VM on their desktop.

### Decisions
- **Compare metadata with the tarball, two rules** (`ecosystems/npm/rules/artifact.py`):
  `hidden-install-script` (HIGH: an install hook the registry metadata doesn't show; npm runs
  the tarball's) and `size-mismatch` (MEDIUM: files bigger than `dist.unpackedSize`). The first
  is the documented "manifest confusion" weakness, found while looking at the size question.
- **Flag understated sizes only.** Overstating doesn't help an attacker, and the two-sided
  version fired on 236 DataDog samples, all from files missing in the dataset's zips.
- **Network failures are retried, not skipped** ([0009](decisions/0009-network-failure-handling.md)):
  - `TransientFetchError`, a retry list in the checkpoint, and an outage threshold that
    writes nothing.
  - Stage 1–2 catch-up for recent runs.
  - A chain gap of 7 days instead of 48 hours.
- **Not cloud, for now:** resilience is needed anyway, and the sandbox may break providers'
  terms. The planned VM host is recorded in the roadmap.

### Challenges
- **Stage 0 turned network failures into permanent data loss.** Found by reading the error
  path while answering the user's question. A failed packument fetch was a "skipped package",
  and the checkpoint moved past it.
  - **Resolution / why it worked:** transient skips are carried in the checkpoint and fetched
    over their original window next run. Tested by `test_network_skips_are_retried_by_the_next_run`
    (offline package, then back online) and `test_an_outage_writes_nothing`.
- **The size rule can't catch the evasion it was asked for, in full.** A version that
  understates its growth below 64 KiB is never downloaded, so no post-download check sees it.
  The rule covers routed versions only. Recorded as a limit, with an untried idea: the
  tarball's `Content-Length`, which the publisher doesn't declare.

### Evaluation snapshot
- Artifact rules on `day1`: 0 of 1,468 benign samples flagged. On live data (1,069 versions)
  declared and real sizes matched exactly every time. No malicious sample hid an install
  script, so there is no recall evidence either way: these rules guard against evasions the
  dataset doesn't contain.

### Open questions / next steps
- `Content-Length` (HEAD request) as a publisher-independent growth signal for routing.
- Stage 3 (capabilities) has started; see the next entry.

## 2026-10-27: Hybrid routing to Stage 2, tarball capture in `collect`

**Stage(s):** Stage 1 forward policy, Stage 2 pipeline wiring, retention
**Context:** Stage 2 only adds recall if it reads code Stage 1 has no reason to forward. The
user chose a hybrid between "behind the Stage 1 gate" and "every release". See
[0008](decisions/0008-stage2-routing-and-tarball-capture.md).

### Decisions
- **Route by size growth, not by small size.** I had proposed adding updates *below* a size
  limit. Simulating from the saved per-sample eval results showed that adds nothing under 5 MB:
  malicious updates are large because the payload is added code. A growth of ≥ 64 KiB in
  declared unpacked size routes 71% of malicious updates and 8.3% of benign ones.
- **16 MB download cap per version.** About 10x less volume for 0.3 points of recall.
- **Keep watched packages routed** even though DataDog shows little gain from them: its
  samples are mostly unpopular packages, while popular-package takeovers are the
  highest-impact attacks.
- **Run Stages 1 and 2 inside the hourly `collect`.** Malicious tarballs are deleted quickly,
  so they must be fetched in the same tick.

### Challenges
- **Retention would never have deleted a tarball.** Garbage collection treated every
  immutable-index entry as a live reference, and tarballs are fetched as immutable. Found while
  checking how captured tarballs would be pruned, before the hourly agent picked up the change.
  - **Resolution:** the index is now a cache: entries whose blob no run references are deleted
    first, then the blobs. Pruning pins OSV-named packages' tarballs from `static-snapshot.json`.
  - **Why it worked:** `test_tarballs_follow_retention` (labeled and unlabeled cases).
- **Live false positives.** The first live Stage 2 run flagged 6 versions, all benign. Two were
  rule bugs: a Slack webhook placeholder in docs, and `requestbin` inside the identifier
  `OscoreRequestBinding`. `exfil-endpoint` v2 requires a webhook id and a dot after `requestbin`.
  - **Why it worked:** `pipeline` benign pass-through 0.9% → 0.7%, recall unchanged.

### Evaluation snapshot
- End to end (`pipeline`, `day1`): A 86.0%, B 66.0%, benign 0.9% weighted. Before (Stage 1
  rules alone): 80.1% / 58.2% / 0.6%. The old gate would have given 83.5% / 58.2% / 1.0%.
- Simulation and real run agreed to the decimal, so the per-sample reports are a reliable,
  fast way to compare routings.

### Open questions / next steps
- Disk: about 14 GB/day of tarballs, about 100 GB at steady state (263 GB free).
- `dist.unpackedSize` is publisher-declared; compare it with the real size after download.
- Content-cache hit rate across hourly runs is still unmeasured.
- Next stage: Stage 3 (AST capabilities), after asking.

## 2026-10-27: Stage 2 static heuristics, first evaluation and tuning

**Stage(s):** Stage 2 static diff heuristics
**Context:** Stage 1 misses 42% of first-release malicious packages (shape B) because their
metadata looks normal. Stage 2 reads the code each release adds, with regular expressions only.

### Decisions
- **Analyse new file contents, not diffs of lines.** Every content (by SHA-256) that is in a
  version of the batch but not in the base is analysed once and cached on disk by content and
  rule fingerprint. Alternative: line diffs per file. Rejected because payloads are often
  appended to bundled files, and a whole-file rule result is cacheable across packages.
- **Evaluate with the DataDog files decrypted in memory only.** The package files are read from
  the encrypted zip with `include="/package/"` and never written out.
- **Five rules downgraded MEDIUM → LOW** (`npm-publish`, `dynamic-code`, `encoded-blob`,
  `env-harvest`, `sensitive-path`). Each fired on 1–8% of benign releases, close to its rate on
  malicious ones. Kept as LOW evidence for Stage 4 combination scoring instead of being
  removed: together they may still separate the classes.
- **File cap 2 MB → 16 MB.** See below.

### Challenges
- **First run: 19.5% recall on shape A.** Per-sample inspection showed 698 of 965 shape-A
  samples had a new file over the 2 MB cap: the payload is appended to an existing large
  bundle, so the file was skipped.
  - **Resolution:** cap raised to 16 MB (Shai-Hulud's payload is ~10 MB).
  - **Why it worked:** A recall 19.5% → 71.5% on the same dataset.
- **Benign pass-through 11.5%.** Per-rule counts: `npm-publish` alone hit 6.4% / 8.0% of
  benign A / B (release tooling mentions `NPM_TOKEN`).
  - **Resolution:** the five downgrades above.
  - **Why it worked:** 11.5% → 1.0%. Cost: B recall 74.4% → 49.9%.
- **A 95 MB zip member aborted a 17-minute evaluation**, and a cache temp-file race crashed
  another. Fixed with `skip_oversize`, a per-sample catch-all that counts errors in `notes`,
  and a shared `util/files.atomic_write`. See [validation.md](validation.md).
- **Follow-on numbers are inflated.** Stage 2 gets 84% on shape-A follow-ons vs Stage 1's 2.7%,
  but mostly because the malicious base is gone from npm (1,542 samples), so all files count
  as new. Recorded as optimistic, not as a win.

### Evaluation snapshot
- `stage2-rules`: A 19.5% → 71.5%, B 74.4% → 49.9%; benign 11.5% → 1.0%.
- `stage1+2-rules` (either stage): A 91.4%, B 66.1%, benign 1.5%, vs Stage 1 alone 80.1% /
  58.2% / 0.6%.

### Open questions / next steps
- **The union number assumes Stage 2 sees every release.** Behind the Stage 1 gate, the
  samples only Stage 2 catches are mostly dropped first (unwatched, no metadata signal).
  Running it on everything means ~109k tarballs a day (mean 2.1 MB, median 62 KB in the eval
  store). Needs a decision with the user: gated, all releases, or all new packages plus gated
  updates, possibly with a size cap from `dist.unpackedSize`.
- Pipeline command over `batches.jsonl`, tarball capture in `collect`, content-cache hit rate.
- Evaluation is slow (~37 min per predictor; pure-Python ZipCrypto under the GIL).

## 2026-10-27: Burst handling between Stage 1 and Stage 2

**Stage(s):** Stage 1 output contract, Stage 2 design
**Context:** Stage 1 forwards ~15k versions a day, 96% only because the package is watched.
The user chose to handle bursty packages (option 1 of three; the other two were deprioritising
prereleases and raising the popularity bar).

### Decisions
- **Batch per package per run, but never reduce a batch to its newest version.** My first
  description of option 1 ("analyse the latest, diffed against the last analysed version")
  was wrong: a malicious version reverted within the burst would never be inspected. The
  corrected contract (`PackageBatch`, [stages/triage.md](stages/triage.md)) is that Stage 2
  analyses every distinct file content in any version of the batch, once.
- **Content-hash analysis cache across runs** for Stage 2, keyed on content SHA-256 plus rule
  versions. It is deterministic because analysis is pure.

### Challenges
- **The estimated saving didn't hold.** I had estimated ~5k packages a day. That is true for
  daily batching (5,634), but at the hourly collection cadence bursts spread across hours: the
  simulation gives ~11,800 batches (−20%). The content cache is where the real saving should
  come from. It is unmeasured until Stage 2 downloads tarballs.

### Open questions / next steps
- Measure distinct-content ratios once tarballs are fetched (Stage 2).

## 2026-10-27: Stage 1 metadata triage, DataDog samples, and the stub bug

**Stage(s):** Stage 1 (new), evaluation, plus one Stage 0 fix (flagged below)
**Context:** The user approved Stage 1. With 0 prospective malicious samples, they also approved
downloading malware as long as it is only executed in the sandbox
([0007](decisions/0007-datadog-samples-and-follow-on-releases.md)).

### Decisions
- **Rule contract** (`core/rules.py`): `evaluate(change, ctx)`, with `RuleContext` holding only
  `as_of`. Rule versions are recorded on findings.
- **Forward policy:** MEDIUM or above, or a watched package. LOW findings only score.
- **DataDog samples as metadata only:** the zips stay encrypted; only `package_info` (the
  captured packument) is decrypted, in memory. It goes through the same `Packument` parser as
  Stage 0.
- **Follow-on releases in their own cell.** Recall measured against a malicious diff base is
  meaningless for change-based rules.

### Challenges
- **A Stage 0 bug found through Stage 1's numbers.** The install-hook rule fired on 0 of 4,124
  new packages. 98% of them were npm staged-publishing stubs (`0.0.0-stage`), and real first
  releases diffed against those stubs.
  - **Resolution:** the npm `Packument` skips stubs as a diff base (tool 0.2.0); evaluation
    rebases old runs. This touches Stage 0 inside a Stage 1 task. It is a correctness fix in
    the npm adapter with no contract change, and is flagged here and in
    [validation.md](validation.md).
  - **Trap avoided:** skipping stub *releases* outright would let an attacker hide a release
    by setting `"stub": true` in package.json. Stubs are still emitted.
- **Shape-A recall looked like 55%.** Splitting by whether the previous version was also
  malicious gave 81% on first releases and 3% on follow-ons. Most "misses" were the 2nd–nth
  versions of the same worm wave (Shai-Hulud, 2025-09/11).
- **One rule was most of the noise.** `npm.publisher.unfamiliar` caused ~90% of benign forwards
  for 10 unique catches. Downgraded to LOW: pass-through went from 2.6% to 0.6%, and A recall
  from 81.1% to 80.1%.
- **Smaller tunings:** CalVer exempted from `npm.version.suspicious`; `workspace:` specs
  treated as registry specs.

### Evaluation snapshot
- `stage1-rules` on `day1`, first releases: recall A **80.1%**, B **58.2%**; benign
  pass-through **0.6%** (weighted; labels provisional).
- `stage1` (with watched packages): A 85.6%, B 58.2%, pass-through 14.5%.
- Baseline `popularity-only`: A 21.8%, B 0%, pass-through 13.9%.

### Open questions / next steps
- **42% of shape-B first releases have no metadata signal** (payload runs on import), so Stage
  2 is needed.
- **Tarball capture at ingest** for forwarded changes, before npm removes them.
- **The DataDog bias** towards GuardDog-detectable patterns needs checking against prospective
  samples.
- **Watched-package forwarding is 96% of Stage 1's output** (14.7k/day). Is that budget right
  for Stage 2?

## 2026-10-27: Hourly chained collection and retention (Phase 9 started)

**Stage(s):** Stage 0 orchestration (`core/run.py`, `core/retention.py`, `collect.py`, CLI)
**Context:** The first 24h run found no malicious samples, because everything malicious was
removed before the run fetched it. The user chose hourly collection with retention, ahead of
Stage 1, so samples accumulate while Stage 1 is built.

### Decisions
- **`kitsunox collect` under launchd, hourly**:
  - The watchlist is refreshed weekly and labels daily. Both are best-effort: a failure is
    logged and the previous one is kept.
  - Each tick records one chained ingest run. A failed ingest fails the tick and leaves the
    checkpoint where it was.
  - Pruning runs daily. See [0006](decisions/0006-scheduled-collection-and-retention.md).
- **Chained runs instead of fixed 24h windows.** The checkpoint now records the previous run's
  id and `as_of`. The next window starts 15 minutes before that, and coverage holds because
  the feed ranges are contiguous. Alternatives were a fixed 1h window (it loses releases whose
  feed entry lands after the run that should have seen them) and a 24h window every hour
  (re-emits every release 24 times).
- **7-day retention, not 30** (roadmap decision 5, resolved). Datasets need only the
  `Change` records, which are kept forever and compressed. Raw packuments are pinned only for
  packages named in OSV records.
- **A data-directory lock** (`flock`), because pruning deletes unreferenced blobs and a
  recording run's blobs aren't referenced yet.

### Challenges
- **A coverage false alarm in the design.** The coverage estimate of an hourly run (1st
  percentile of last-modified times) always falls just after the window start once the window
  overlaps the previous run. Every tick would have warned. **Resolution:** chained runs are
  covered by contiguity of the feed, recorded as `chained_from` in the manifest.
- **Crash-safety of pruning.** If the process died after compressing `changes.jsonl` but before
  writing `retention.json`, the retry would have found no plain `changes.jsonl` and pinned
  nothing. Caught while writing the code. **Resolution:** read through `changes_file()`, and
  write the marker last. Test: `test_crash_after_compressing_still_pins`.
- **Each step closes its HTTP client**, so a single injected client failed after the first
  step in tests. `collect` now takes a client factory.

### Evaluation snapshot
- First real tick (foreground): 70 minutes of feed, 3,502 packages, 4,704 changes, 2m23s,
  chained from the 24h run, replay identical. First launchd tick: 178 packages in 9s, exit 0,
  no macOS privacy (TCC) problems from running inside `~/Documents`.

### Open questions / next steps
- **Tarballs are not captured at ingest**, so malicious samples will have metadata but no code.
  That needs solving with the forward policy (Stage 1/2).
- **Dataset rebuilds are still manual** (`eval build`). They could join `collect` once Stage 1
  has a predictor worth tracking.
- Next: Phase 4, Stage 1.

## 2026-10-27: Phase 3 (light) evaluation harness, and the first real 24h run

**Stage(s):** evaluation harness (`evaluation/`), Stage 0 at full scale
**Context:** Build the light harness chosen by the user: OSV labels, datasets from our own runs,
and baselines, with no malware tarballs. Then run the whole chain for real over 24 hours. Harness
code: `b325b72`. Label fixes: the commit after it.

### Decisions
- **Ground truth comes from our own runs** (prospective labeling), not from downloaded malware.
  A release becomes a sample only if we recorded it, so samples always have the metadata the
  pipeline actually sees.
- **Label hygiene** ([0005](decisions/0005-label-hygiene.md)): npm takedown placeholders are
  never malicious. An open-ended OSV range counts only for releases published no later than the
  record.
- **Re-weighted pass-through:** benign strata are sampled equally (500 each) but differ hugely
  in size, so reports weight each stratum's rate by its population.

### Challenges
- **Every "malicious" match in the first run was a label artifact.** The run matched 29
  releases. 27 were npm placeholder stubs (`0.0.1-security`, `0.0.0-stage`, published by the
  `npm` account) matched by "all versions" ranges. 2 were legitimate GitLab-CI trusted-publisher
  builds of `@magda/semantic-indexer-sdk`, matched by a 2025 Shai-Hulud record. Found by reading
  the 29 samples before writing up the numbers.
  - **Resolution:** exclude placeholders and open-range projections, counting both
    (`excluded: {registry-placeholder: 41, label-projected: 2}`). Tests:
    `test_placeholders_and_projected_labels_are_excluded`,
    `test_open_ranges_only_observe_earlier_releases`, `test_security_placeholder`.
  - **Why it worked:** 0 malicious samples remain. That is correct for a single run: every
    malicious package in the window was taken down before the run fetched its packument.
- **Popularity-only pass-through read 50.0%, which was meaningless.** It is exactly the share
  of watched samples, because the sampler takes 500 per stratum.
  - **Resolution:** record stratum populations and weight by them. The population had 14,743
    watched and 90,607 unwatched shape-A releases, so the weighted rate is **13.5%**
    (A: 14.0%, B: 0%).
  - **Why it worked:** checked by hand against the population counts, and by
    `test_pass_through_is_reweighted_to_population`.
- **Dataset rebuilds were not byte-identical**, because `built_at` is the current time. The
  samples are identical, so this was left as provenance metadata and documented.

### Evaluation snapshot
- Run `20261027T210847Z-npm` (offline replay identical, 7.4 min): 24h window, feed `(139752494, 140152494]`, 63,143 packages,
  109,497 changes, 0 skipped, 0 popularity failures. Window covered: the feed start estimate is
  2026-10-26T14:28Z, 6.7h before the window start.
- Timing: watchlist 12.2 min (63,172 packages); labels sync 14 s (222,516 records, 222,515
  packages); 24h ingest 46.5 min (~23 packages/s). Disk: blobs 5.5 GB, runs 792 MB.
- Baselines on `first-24h` (benign labels all provisional, since labels are less than 30 days
  newer): forward-all 100% pass-through; popularity-only 13.5% weighted. Recall is n/a with no
  malicious samples.

### Open questions / next steps
- **Malicious samples need repeated ingest runs** to catch releases before takedown. A scheduled
  hourly run (launchd) needs the user's go-ahead.
- **Blob store growth:** 5.5 GB per day of packuments. This needs a retention policy before
  scheduling.
- **Next:** Phase 4, Stage 1 metadata triage. Ask before starting.

## 2026-10-27: Scope correction: git-commit path planned alongside npm

**Stage(s):** architecture (no code)
**Context:** The user pointed out that they had intended a git-first pipeline (commits → filter →
full repo → compare to npm). The npm-only focus came from my recommendation in
[0002](decisions/0002-data-sources.md), which was approved in a bundle of recommendations. The
git-first option was never presented as an explicit choice.

### Decisions
- **Parallel paths** (user's proposal): keep the npm registry path, and add a path that watches
  commits on the GitHub/GitLab repos of popular npm packages. Releases are joined to repos for
  tarball-vs-repo comparison. See [0004](decisions/0004-git-path-parallel-to-npm.md).
- **Order:** finish the npm workflow first, then build the git path (roadmap 8b).

### Challenges
- **Scope drift from a bundled recommendation**: a direction-setting choice (which source drives
  the pipeline) was accepted without its alternative being visible. **Resolution:** from now on,
  such choices are presented as explicit options with what they exclude.

### Open questions / next steps
- Git phase: polling budget vs. GH Archive, a GitHub token, GitLab coverage.
- Next: Phase 3 (evaluation harness) scope.

## 2026-10-27: Validation pass on Stage 0: fuzzing, live cross-checks, 6 fixes

**Stage(s):** Stage 0 ingest and foundations (`util/`, `core/`, `ecosystems/npm/`)
**Context:** Before building the evaluation harness, the user asked to test and validate what
exists. Full report: [validation.md](validation.md). Also in this session: schema versions on
persisted records (`6b027a1`, see architecture.md).

### Decisions
- **Property-based fuzzing with Hypothesis, deterministic by default** (`derandomize=True`), so
  the normal test run stays reproducible. An `explore` profile with random seeds and 20k
  examples is used for validation passes.
- **Differential testing for semver** against the `semver` library, as an independent oracle
  instead of hand-picked cases.
- **Live validation against independent sources:** ecosyste.ms (releases) for completeness and
  deps.dev for field accuracy. Neither is used in the pipeline itself, which keeps the check
  independent.
- **Lenient tar reading + anomaly flag** instead of strict reading. Analysis must see everything
  any installer might extract. The disagreement between readers is itself evidence.
- **Catch-all per-package error handling in Stage 0**, recorded as `UNEXPECTED ...` in
  `skipped.jsonl`. Normally a broad `except` hides bugs, but here the alternative is an attacker
  being able to halt the scanner with one malformed package. Visibility comes from
  `skipped.jsonl`.

### Challenges
- **Tar parser differential (high severity):** a malicious file after an end-of-archive marker,
  an invalid header, or a zero block was invisible to analysis. Confirmed with crafted archives
  and fixed (F1 in validation.md).
- **Run-wide crash from one packument (high severity):** `"maintainers": 1.0` raised
  `TypeError`. Found by fuzzing, though at first it surfaced only intermittently: the failing
  example had been found by the random-seed run and saved to Hypothesis's database, and the
  deterministic run then replayed it. Fixed (F4).
- **Completeness check looked catastrophic at first:** 823 of 1,015 independently listed
  releases were "absent".
  - **Resolution:** the feed range covered only ~31 minutes of the 3-hour window. Within the
    covered time, 148 of 149 releases were found.
  - **Why this matters:** it revealed that nothing checked coverage (F6, fixed), and that the
    "2h window" smoke runs earlier today had really covered ~12–25 minutes. Their throughput
    numbers are still valid. Their coverage claims weren't.
- **Feed start estimate:** the minimum last-modified time (18:36) badly overstated coverage. The
  1st percentile (19:52) matched the measured start, so that's what is used.
- **Truncated gzip (F2), drive letter after strip (F3, found by deep fuzzing), and HTTP error
  handling (F5)** were smaller fixes.

### Evaluation snapshot
- Not a detection evaluation. Implementation quality, before → after:
  - Tests: 106 → 140.
  - Branch coverage: 94% → 96%.
  - Fuzz failures: 4 distinct bugs → 0 over 240k random cases.
  - Live feed completeness: 99.3% (148/149).
  - Publish-time accuracy: 127/127.
  - Provenance: 127/127 after checking the 2 disagreements against npm (deps.dev lag).

### Open questions / next steps
- **npm feed omissions** (1 in 149 observed; the true rate is unknown). Measure over a larger
  sample, then decide whether to add a supplementary discovery sweep, e.g. periodically
  re-checking ecosyste.ms recent releases against our runs.
- Make the live cross-checks a repeatable `kitsunox validate` command.
- Provenance is the registry's claim, not a verified Sigstore bundle. Decide whether
  verification is worth it for Stage 1.
- Then Phase 3, the evaluation harness.

## 2026-10-27: Popularity: per-change lookups abandoned for a weekly watchlist

**Stage(s):** Stage 0 ingest (popularity enrichment). Closes Phase 2.
**Context:** Stage 1's forward policy needs "is this package popular?" for every change to an
existing package. The plan (roadmap decision 3) was per-change lookups against the npm downloads
API, with a ≥1k weekly or ≥10 dependents cutoff. Full write-up:
[decision 0003](decisions/0003-popularity-watchlist.md).

### Decisions
- **Weekly watchlist from packages.ecosyste.ms** (user-approved): packages ranked by last-month
  downloads, paged until below the cutoff, saved as a small JSON list. Runs record the list's
  id and SHA-256, and replay verifies it. Per-change API lookups are kept as `--popularity api`.
- **Cutoff raised to 10k weekly** (user-approved): ≥43k monthly on the watchlist.
- **Dependents dropped as a criterion for now**: deps.dev only has them via a per-version
  `v3alpha` endpoint. Counts are stored in the watchlist for later.
- **Per-host request pacing in `HttpFetcher`** (`set_min_interval`): generic, so any throttled
  API can use it. Replays and cache hits are never paced.
- **Download counts for a closed period are cached across runs** (immutable), since they're
  final.

### Challenges
- **The npm downloads API throttles hard**: `429` with `retry-after: 0`. The first live run with
  8 threads had 64 of ~1,100 lookups fail after retries, and took 3m22s vs 34s without
  popularity.
  - **Resolution:** a burst test showed sequential requests (~2.4/s) never got a 429 while two
    parallel ones did almost at once, so requests are paced at 0.5 s. The next run had 0
    failures.
  - **Why it wasn't enough:** 88% of changed existing packages were scoped (946 of 1,075), and
    scoped names can't use bulk lookups. That run took 8.5 minutes, which is ~12h for a full day.
- **The planned 1k cutoff was far too low**: 57% of changed existing packages clear it (20% at
  10k, 8% at 100k).
- **ecosyste.ms pages are huge**: ~100–200 MB per 1,000 packages, with no field selection.
  gzip transfer is ~8× smaller. Raw pages go to a temporary blob store and are discarded.
- **Old run files no longer load** after the `Popularity` model changed: models forbid unknown
  fields, so scratch runs recorded earlier fail validation. No real data was affected, but
  records have **no schema version**. This needs fixing before data accumulates.

### Evaluation snapshot
- Watchlist vs API weekly counts on 1,638 packages: 92.2% agreement. The watchlist caught 221 of
  296 packages that the API showed at ≥10k/week (75%). Its misses are mostly fast risers or
  spikes. Mitigated by Stage 1 forwarding anything flagged; not yet measured against attacks.
- Ingest with watchlist: 38 s per ~1,250 packages (vs 8.5 min API mode), replay identical.

### Removed / abandoned
- **Per-change downloads-API popularity as the default**: ~12h/day of paced requests for a full
  day of npm. Kept as an opt-in mode.

### Open questions / next steps
- Add a schema version to persisted records (`Change`, `RunManifest`, `Watchlist`).
- Consider a bulk downloads-API top-up for unscoped packages to catch fast risers.
- Phase 3: evaluation harness.

## 2026-10-27: Phase 2, Stage 0 ingest with record/replay

**Stage(s):** Stage 0 ingest, plus core and util foundations
**Context:** Build the foundation every later stage depends on: data models, a fetch layer that
makes runs reproducible, a safe way to open untrusted tarballs, and the npm adapter. See
[stages/ingest.md](stages/ingest.md).

### Decisions
- **Snapshot fetcher instead of a plain HTTP cache** (`util/http.py`): each run records request
  key → content hash in `snapshot.json`; replay mode answers only from it and fails on a miss.
  A TTL cache was rejected because it gives "probably the same" inputs, not provably the same.
  Integrity-pinned responses (tarballs) are also indexed across runs, so they're downloaded once.
- **In-memory tarball extraction** (`util/archive.py`): no files written means no path-traversal
  or symlink attack surface on the host. Links, devices, FIFOs and unsafe paths are *reported*,
  not silently dropped, because a symlink to `~/.npmrc` inside a tarball is itself a signal.
  Trailing gzip data is rejected, since tools disagree on how to read it.
- **Previous version = highest lower semver published earlier**, falling back to publish order.
  This diffs backports against their own release line (tested: `1.1.1` after `2.0.0` → `1.1.0`).
- **Ecosystem contract uses feed positions, not time**: the npm feed has no timestamps, so
  `list_changes(since, until)` works in sequence numbers and the publish-time window is applied
  to packument `time` entries. This differs from the Phase 1 sketch; architecture.md is updated.
- **Rule/Stage contracts deferred to Stage 1**: there's no consumer yet, and guessing them now
  would mean revising them later.
- **No popularity yet**: deferred within Phase 2, because it isn't needed until the Stage 1
  forward policy.

### Challenges
- **Packument storage blew up**: the first live run stored **1.4 GB for 1,208 packages**, because
  packages with long version histories have multi-MB packuments. At ~100k packages a day that
  would be ~140 GB/day.
  - **Resolution:** zstd-compress blobs (stdlib `compression.zstd`, Python 3.14), still keyed by
    the hash of the uncompressed bytes.
  - **Why it worked:** the second live run stored **119 MB for 1,068 packages** (≈10× smaller),
    and the replay was still byte-identical. The abbreviated packument was considered and
    rejected: it lacks the per-version `time` map and `_npmUser`.
- **Extractor false positive on real tarballs**: a real package's tarball had a bare `package`
  directory entry, which was reported as an "unsafe path".
  - **Resolution:** skip directory entries before path validation. Directories are implied by
    file paths anyway.
- **Monorepo repository URLs** (`github.com/o/repo/sub/pkg.git`) weren't normalized.
  - **Resolution:** drop the sub-path. Covered by a parametrized test.
- **FIFO reported as "device"**: Python's `tarfile.isdev()` is also true for FIFOs. Caught by
  `test_unsafe_and_special_entries_are_reported_not_extracted`; fixed by checking FIFO first.

### Evaluation snapshot
- No detection yet, so no recall/FP numbers. Ingest health on two live runs: 0 skipped packages,
  59 of 60 random tarballs extracted cleanly (1 was a 404, removed after publish), replay
  identical both times.
- Live observations (one 2h sample of 1,821 changes, worth re-measuring):
  - 40% of new versions use trusted publishing and 34% carry provenance.
  - 2.5% are brand-new packages.
  - 1.6% have install scripts.
  - No trusted → manual publish downgrades were seen.

### Open questions / next steps
- Popularity enrichment (downloads API bulk for unscoped names; deps.dev for dependents).
- Blob retention policy (roadmap decision 5).
- Cross-run dedupe of changes re-emitted when a package is touched again.
- Measure npm read rate limits at full-day volume (only ~35 packages/s tried so far, with no 429s).
- Then Phase 3: the evaluation harness.

## 2026-10-27: Planning: threat model, architecture, data sources, evaluation

**Stage(s):** all (design only, no pipeline code)
**Context:** With the scaffold in place, we drafted the Phase 1 planning docs and settled the
four decisions that block Phase 2: [threat-model.md](threat-model.md),
[architecture.md](architecture.md), [evaluation.md](evaluation.md), [roadmap.md](roadmap.md),
and [decisions/0002-data-sources.md](decisions/0002-data-sources.md).

### Decisions
- **Discovery via the npm replication `_changes` feed + full packuments**: GitHub-based discovery
  was rejected because the main attack path (publishing straight to the registry) never touches
  git. Third-party aggregators (deps.dev, ecosyste.ms) were rejected for discovery because of
  lag; commercial feeds because they aren't independent or reproducible. GitHub, deps.dev and
  OSV stay in supporting roles. See [0002](decisions/0002-data-sources.md).
- **Split attacks into shape A (compromised existing package) and shape B (new malicious
  package)**: they need different signals (delta vs. absolute + name similarity). Recall is
  reported per shape so typosquat-heavy public datasets can't hide weak shape-A recall.
- **Publish-method change as a planned Stage 1 signal**: packuments now expose
  `_npmUser.trustedPublisher`, `approver`, and `dist.attestations`. A version published
  manually where earlier ones came through OIDC trusted publishing is cheap to detect. Expected
  to be high-precision, but **unproven until measured**. Provenance alone is not treated as an
  all-clear, since a hijacked CI workflow produces valid attestations.
- **Determinism by snapshot + pure analysis**: all fetches go through a caching client into a
  content-addressed snapshot; stages 1–4 never read the clock and use an explicit `as_of`.
- **Run ledger**: stages record cleared items instead of dropping them, so per-stage recall and
  pass-through can be computed.
- **Eval harness before any detection stage** (roadmap Phase 3), so every rule lands with numbers.
- **User decisions (all accepted as recommended):**
  1. Tarball-vs-repo: three checks (manifest, tarball-only JS, changed shared files) against the
     GitHub repo at `gitHead`/tag, with a build-output allow-list. Rebuilding packages is out of
     scope.
  2. "Recent" = versions published in `[as_of − 24h, as_of]`, with `as_of` explicit.
  3. Coverage: all changes through Stage 1. Tarball stages get packages above a popularity
     cutoff (start ≥1k weekly downloads or ≥10 dependents) **or** anything Stage 1 flagged.
  4. Reports: `report.json` canonical, Markdown per candidate + `index.md` rendered from it.

### Challenges
- **The npm replication API changed in 2025**: the old CouchDB `_changes` endpoint was retired
  on 2025-05-29. The new `replicate.npmjs.com/registry/_changes` has no `include_docs` and no
  streaming. Older tooling and many blog posts still describe the old API.
  - **Resolution:** probed the new endpoint live. Root `update_seq` ≈ 140.1M; a 20k-seq page
    held ~6,000 packages, covering ≈80 minutes. Designed Stage 0 around name-only changes plus a
    packument fetch per package (~100k/day).
  - **Why it worked:** verified directly against the live API, not just docs. The volume figure
    is a single sample and needs re-measuring in Phase 2.
- **Shape-A evaluation samples are scarce**: public datasets are mostly new malicious packages,
  and registries remove malicious versions fast, so the "previous benign + malicious" pair is
  rarely available.
  - **Resolution (planned):** a small curated incident set; **prospective labeling** (cache what
    we ingest, then join later against new `MAL-` records); synthetic injected cases reported
    separately. Unproven until Phase 3/9.

### Open questions / next steps
- Benign-label delay (proposed: 30 days) is still open.
- Which historical compromise samples are actually obtainable has not been checked.
- DataDog dataset license and current npm sample count need confirming before use.
- Real read rate limits for `registry.npmjs.org` at ~100k packuments/day: measure in Phase 2.
- Next: Phase 2, which covers `core/` models and interfaces, the caching HTTP client, the safe
  extractor, and the npm adapter for Stage 0. Ask before starting.

## 2026-10-27: Fresh start and project scaffold

**Stage(s):** none yet (project setup)
**Context:** Kitsunox is being rewritten from scratch as a master's capstone in Cybersecurity
Engineering. The goal is a deterministic, explainable pipeline that flags likely supply chain
attacks in recent npm releases. This session set up the repo and toolchain so later stages have a
working base with lint, type-check and test gates from day one.

### Decisions
- **Fresh rewrite, no code reuse from earlier attempts**: the project needs to be explainable and
  reproducible end to end for the capstone defense. Starting clean means every design choice is
  deliberate and documented here, instead of inherited. The README dropped the earlier "AI
  powered" framing: the pipeline is deterministic, and an LLM stage is an optional future
  extension.
- **Tooling stack**: Python 3.14 via uv, pydantic v2 for inter-stage records, mypy `--strict`
  added to the done gate, ruff including bandit (`S`) rules, network tests opt-in. Full rationale
  is in [decisions/0001-tooling-stack.md](decisions/0001-tooling-stack.md).
  - 3.15 was considered and declined for now: it's a few weeks old, and native wheels
    (pydantic-core, tree-sitter) tend to lag.
- **Scaffold before the planning docs**: CLAUDE.md lists scaffolding last, after the threat
  model, architecture and roadmap. We reordered so the "done" gate (ruff, mypy, pytest) exists
  before any real code is written. The planning docs are the next deliverable. No pipeline code
  was written.
- **Repo hygiene**: `data/` is gitignored before any downloads exist, so malicious samples can't
  be committed by accident. `CLAUDE.md` moved from `.claude/` (gitignored) to the repo root so
  the project instructions are version-controlled.

### Challenges
- **uv wasn't installed**: installed with Homebrew (uv 0.13.6). uv fetched CPython 3.14.10.

### Open questions / next steps
- Draft `docs/threat-model.md`, `docs/architecture.md` (Mermaid pipeline diagram) and
  `docs/roadmap.md`.
- Compare data sources for "recent npm changes" (registry changes feed, GitHub API, others) and
  recommend one.
- Propose the labeled evaluation set (OSV `MAL-` advisories, public malicious-package datasets,
  benign recent changes) and how to store it inertly.
- Decisions for the user:
  - Scope of tarball-vs-repo diffing.
  - How "recent" is defined.
  - All of npm vs. a popularity cutoff.
  - Report format.
