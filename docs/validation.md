# Validation report

What has been checked about the implemented code (Stage 0 ingest and its foundations), how, and
with what result. Re-run these checks after significant changes and add a new dated section;
don't edit old ones.

## 2026-10-27: Stage 0 and foundations

**Commit under test:** the commit that adds this file (parent `6b027a1`).
**Scope:** `util/archive.py`, `util/http.py`, `util/hashing.py`, `util/schema.py`,
`ecosystems/npm/*`, `stages/ingest.py`, `core/*`, `cli.py`.

### Summary

| Check | Method | Result |
|---|---|---|
| Unit and integration tests | `uv run pytest` | 140 passed (was 106 before this pass) |
| Branch coverage | `uv run pytest --cov` | **96%** (was 94%); CLI 46% → 69%; floor set at 90% |
| Extractor safety properties | Hypothesis, 20,000 random cases per property | **3 bugs found and fixed** (below); clean after |
| Packument parser robustness | Hypothesis, hostile JSON | **1 bug found and fixed** (run-wide crash) |
| Semver ordering | Differential test vs. the `semver` library | Agrees on all generated cases |
| Feed completeness | Live run vs. ecosyste.ms independent release list | **99.3%** (148/149) within covered time; the miss is npm's feed |
| Window coverage | Live runs, feed probes | **Gap found**: no check existed; added one |
| Field accuracy | Live run vs. deps.dev | Publish times 127/127 exact; provenance 125/127, the 2 differences are deps.dev lag |
| Previous-version invariants | All 4,612 changes of a live run | 0 time-order violations; 4 documented fallbacks |
| Determinism | `ingest replay` on every live run | Byte-identical every time |

### Findings and fixes

**F1. Tar parser differential: entries hidden from analysis.** *Severity: high (detection
bypass).*
- **Found by:** reading the extractor and then a crafted-archive probe.
- **What happened:** Python's `tarfile` in strict mode stops at an end-of-archive marker, an
  invalid header block, or a single zero block. Lenient readers continue past these. A malicious
  file placed after any of them was invisible to Kitsunox. Confirmed for all three placements.
- **Fix:** extract in lenient mode (`ignore_zeros=True`), so every entry any reader could find is
  analyzed. Compare with a strict count, and add an `anomalies` entry to `ArtifactTree` when they
  differ or non-zero bytes trail the last entry. `npm pack` produces neither, so the anomaly is
  also a detection signal for Stage 2.
- **Tests:**
  `test_entries_hidden_from_strict_readers_are_extracted_and_flagged[after-eof-marker|after-garbage-header|after-zero-block]`
  and `test_trailing_non_zero_bytes_are_flagged`.

**F2. Truncated gzip accepted.** *Severity: medium.*
- **What happened:** `zlib` returns partial output for a cut-off stream without raising, so
  partial archives were analyzed as if complete.
- **Fix:** require `decompressor.eof`.
- **Test:** `test_truncated_gzip_is_rejected`.

**F3. Drive letter exposed by stripping.** *Severity: low (nothing is written to disk today).*
- **Found by:** the deep fuzzing run. `package/C:/Windows/x` passed path validation because the
  check ran before the `package/` prefix was stripped, and came out as `C:/Windows/x`.
- **Fix:** validate after stripping.
- **Test:** `test_safe_relative_path[package/C:/Windows/x.js-None]`.

**F4. One hostile packument crashed the whole ingest run.** *Severity: high (scanner
denial-of-service).*
- **Found by:** fuzzing. `"maintainers": 1.0` (or `true`) raised `TypeError` in `publish_info`.
  Stage 0 only caught expected error types, so publishing one malformed package would have
  blinded the scanner to every other change in the window.
- **Fix:**
  - Type-check `maintainers` before iterating.
  - Defense in depth: Stage 0 now catches *any* per-package exception and records it in
    `skipped.jsonl` as `UNEXPECTED <type>: ...`, so a parser bug costs one package, visibly.
- **Tests:** `test_non_list_maintainers_are_ignored`, `test_failures_are_recorded_not_dropped`.

**F5. Non-HTTPS redirects and non-transport HTTP errors.** *Severity: low.*
- **Found by:** review.
- **What happened:**
  - Redirects were followed to any scheme.
  - `httpx.DecodingError` and `TooManyRedirects` weren't converted to `FetchError`, so they would
    have escaped per-package handling.
- **Fix:** refuse non-HTTPS final URLs, and wrap all `httpx.HTTPError`s.
- **Tests:** `test_redirect_to_plain_http_is_refused`,
  `test_non_transport_http_errors_become_fetch_errors`.

**F6. No check that the feed range covers the window.** *Severity: medium (silent recall loss).*
- **Found by:** the completeness validation itself. A 3-hour window with a 6,000-position range
  covered only ~31 minutes, and nothing said so.
- **Fix:** each package's last-modified time is collected. The **1st percentile** estimates
  where the range starts, and runs record `feed_start_estimate` and `window_covered`. The CLI
  warns when it's not covered.
  - The minimum is not used: some packages reach the feed long after they last changed, which
    made the minimum (18:36) far earlier than the measured coverage start (~19:52, matching the
    1st percentile).
- **Default lookback checked:** probing the feed at several offsets shows 400k positions ≈ 31h
  at current rates (~12–15k positions/hour), a ~30% margin over 24h.
- **Tests:** `test_window_coverage_from_earliest_modification[covered|gap]`,
  `test_feed_start_estimate_ignores_lagging_outliers`.

### Known limits confirmed, not fixed

- **npm's replication feed omits some publishes.**
  - `@kushalkhemka/opensec-pi-subagents@0.20.10` (published 19:54:53Z) was never in the feed,
    either in our range or in later entries, and a `doc_ids` query for it returned nothing 35+
    minutes later. The same query works for packages that are in the feed.
  - One miss in 149 releases (0.7%) is a small sample; the true rate needs more measurement.
  - A supplementary discovery source may be needed (open question in the devlog).
- **Provenance is taken from the registry's claim** (`dist.attestations`). The Sigstore bundle is
  not verified. npm is the source of record, so this is acceptable for a triage signal, but it
  isn't proof.
- **Previous-version fallback:** a release lower than everything before it (e.g.
  `0.0.0-nightly` after `0.0.1`) is diffed against the most recent earlier release. 4 of 4,612
  changes in the sample, all nightly/canary builds.
- **ecosyste.ms** lags the registry by minutes to hours, so it's useful for validation but not
  as a primary source.

### How to reproduce

```sh
uv run pytest --cov                                      # tests + coverage floor
HYPOTHESIS_PROFILE=explore uv run pytest -p no:cacheprovider \
  tests/util/test_archive_fuzz.py tests/ecosystems/npm/test_npm_fuzz.py   # ~4 min
uv run pytest -m network                                 # live record + replay
```

The completeness, field-accuracy and feed-rate checks were one-off scripts run against a live
ingest. Their method is described above. Turning them into a repeatable
`kitsunox validate` command is listed as a next step.

## 2026-10-27 (later): first full 24h run and label audit

Run `20261027T210847Z-npm`: 24h window, feed `(139752494, 140152494]`, 63,143 packages,
109,497 changes.

| Check | Result |
|---|---|
| Offline replay of the full run | **identical** (`changes.jsonl` sha256 `156daffb0e06…`), 7m24s, CPU-bound, no network |
| Window coverage | covered: the feed start estimate (2026-10-26T14:28Z) is 6.7h before the window start |
| Per-package failures | 0 skipped, 0 popularity lookup failures |
| Dataset rebuild determinism | samples identical across rebuilds; only `built_at` differs |
| Manual audit of all 29 OSV matches | **29 of 29 were label artifacts**: 27 npm takedown placeholders, 2 legitimate builds matched by an open-ended 2025 range. Fixed by [0005](decisions/0005-label-hygiene.md). 0 malicious samples remain |
| Benign pass-through estimator | the raw stratified rate (50%) was biased; now population-weighted (13.5%) |

Lesson: OSV "all versions" ranges are not release-level ground truth. Any future label source
gets the same manual audit of its first matches before its numbers are trusted.

## 2026-10-27 (evening): Stage 1 and the staged-publishing stub bug

| Check | Result |
|---|---|
| Rule firing profile on 109k real changes | `npm.install-hook` fired on **0** of 4,124 "new packages". Implausible, and the cause was a Stage 0 bug |
| Stub bug | 4,060 of the 4,124 new packages (98%) were npm staged-publishing placeholders (`0.0.0-stage`, `stub: true`). A package's first real release then diffed against the stub and was counted as shape A. Fixed in tool 0.2.0 (`Packument.previous_version` skips stubs; stubs are still emitted, because the flag is publisher-controlled). Test: `test_stub_is_never_a_diff_base` |
| DataDog import | 3,444 samples (1,446 A, 1,998 B), 4 failures (2 without `package_info`, 2 registry placeholders), all recorded with reasons |
| Follow-on releases | 481 of 1,446 A samples diffed against an also-malicious previous version. Recall on them is 2.7% vs 81% on first releases, so they're reported separately |
| Rule precision | `npm.publisher.unfamiliar` fired on 2.57% of benign releases for 10 unique catches → downgraded to LOW |

Replays of runs recorded with tool 0.1.0 will no longer match under 0.2.0. This is expected:
Stage 0's output changed. Their `manifest.tool_version` records which code produced them.

## 2026-10-27 (night): Stage 2 static heuristics

| Check | Result |
|---|---|
| Hostile archives | One DataDog zip held a 95 MB binary (`@42ailab-42plugin-linux-arm64`), which aborted the first evaluation. `extract_zip(skip_oversize=True)` now skips such members, and the Stage 2 predictor counts any per-sample exception in `notes` instead of aborting |
| Concurrent cache writes | Two threads wrote the same cache entry through one temp name (`id()` of the shared `()` result) and one `replace` failed. Fixed by the shared `util/files.atomic_write` (pid + thread in the temp name) |
| File-size cap | At 2 MB, 698 of 965 shape-A samples had an unanalysed new file; A recall was 19.5%. At 16 MB: 71.5% |
| Rule precision | Five rules fired on 1–8% of benign releases at near-equal rates on malicious ones; downgraded to LOW. Benign pass-through 11.5% → 1.0% |
| Data gaps | Base tarball unavailable for 1,542 samples (treated as all-new), sample files unavailable for 32 |
| Runtime | ~37 min per predictor over `day1`. ZipCrypto decryption is pure Python and holds the GIL, so the 8 threads barely help |
| Retention of tarballs | The immutable index counted as a GC reference, so captured tarballs would never have been deleted (~14 GB/day). Now index entries without a run reference are deleted with their blobs, and pruning pins OSV-named packages' tarballs from `static-snapshot.json`. Test: `test_tarballs_follow_retention` |
| Live Stage 2 | Run `20261028T004851Z-npm`: 1,243 versions in 2 min 20 s, 794 MB downloaded, 6 flagged, all benign on inspection. Two false-positive patterns fixed in `exfil-endpoint` v2 |
| End to end | `pipeline` on `day1`: 86.0% / 66.0% / 0.9% benign, equal to the simulation from saved per-sample results |

## 2026-10-28: Network-failure handling and artifact rules

| Check | Result |
|---|---|
| Network skip, then back online | Retried by the next chained run over the first run's window; replay identical (`test_network_skips_are_retried_by_the_next_run`) |
| Outage (> 20% of packages failing on the network) | `IngestDegradedError`: no run, no checkpoint change (`test_an_outage_writes_nothing`) |
| Registry unreachable during `collect` | Logged as OFFLINE, nothing written (`test_offline_tick_writes_nothing`) |
| Stage 2 crashed for a run | Redone by the next tick (`test_unfinished_stages_are_caught_up`) |
| Declared vs real unpacked size, 1,069 live versions | Exact match in all |
| Artifact rules on `day1` benign | 0 of 1,468 flagged |


## 2026-10-28 (afternoon): Stage 3 live, cache damage, Stage 4

| Check | Result |
|---|---|
| Stage 3 on `20261028T031447Z-npm`, before / after comparing with `change.previous` | 44 / 7 versions flagged of 1,233 read (37 were new packages behind a `0.0.0-stage` placeholder) |
| Content cache, HTTP index and AST cache scanned for undecodable files | 1 damaged of 1.73M (a TLS record + the intended `[]`); readers now treat damage as a miss, `atomic_write` reads back |
| Eval refactor (shared findings collector) | `pipeline+3` re-derived exactly from the dump: 89.7% / 66.0%, benign 0.9% / 1.2% |
| Repo comparison, `day1` (965 malicious, 300 benign updates) | comparable 5.9% / 40%; flagged 49 of 57 / 9 of 121 compared; 43 of the 49 already flagged by Stages 1-3 |
| Stage 4 known-malware lookup by name alone | 11 benign new packages hit (`axios`, `chalk`, `debug`); whole-package records only: 0 |


## 2026-10-29: First live Stage 4 run

| Check | Result |
|---|---|
| Catch-up of `20261027T210847Z-npm` (109,497 versions) from Stage 3 | No failure; Stage 3 ~3.7 h, Stage 4 ~7.5 h; 5,637 versions compared with their repository; 1,759 reported (1.6%: 468 HIGH, 1,231 MEDIUM, 60 on score) |
| Fetch volume of that Stage 4 | 2,142 GitHub archives, 31 GB (estimate was 5–15 GB/day); 1,634 ref advertisements, 0.3 GB |
| `npm.repo.install-script-not-in-repo` live hits | 43 (16 packages), all compared with a monorepo's root manifest. With `repo.compared` v2: 13 packages match their own manifest's hooks, 1 not comparable, 2 still fire accurately (`bun`, `@kilocode/cli`: hooks added by release scripts) |
| Repo comparison re-measured with v2 (`day1`, same samples) | compared 55 / 116; hooks 51 / 0; code 48 / 3; dependencies 7 / 2 (v1: 57 / 121; 53 / 0; 49 / 9; 30 / 14) |


## 2026-10-30: First VM day (4 vCPUs, 30 GB RAM)

Run `20261029T221803Z-npm`, a 24-hour catch-up window, timed from its files and
`journalctl --user -u kitsunox-collect`; memory sampled every 30 s
(`ps -o rss`, `free -m`).

| Check | Result |
|---|---|
| First tick, Stage 0 | Watchlist 36 min (63,563 packages), labels 12 s (222,568 records), ingest 43 min: 110,084 changes, 0 skipped |
| Stages 1-3 on 110,084 versions | Stage 1 under 1 min; Stage 2 71 min; Stage 3 85 min (the laptop: Stage 3 ~3.7 h on 109,497) |
| Stage 4, holding the run in memory | OOM-killed after 3 h 09 min at 21.6 GB anon RSS (kernel log) |
| Stage 4 input streamed (`RunVersions`, `LineFile`), alone | Index 12 s, one pass 22 s, 0.12 GB peak RSS |
| Stage 4 resumed, streamed, archives not yet slotted | 3 h 07 min with every archive already cached by the killed attempt; 18.5 GB peak RSS; 6,739 compared with their repository, 984 reported (0.9%: 336 HIGH, 590 MEDIUM, 58 LOW), 2,202 GitHub requests, 0 failed; 628 dependency names looked up |
| What makes a reported version HIGH | `static.exfil-endpoint` alone 128, `npm.publish-method.downgrade` alone 125, install hook with or without `install-script-not-in-repo` 80 |
| `npm.dependency.known-malware` live | 1 hit: `victor-nest-resource` adds `fs`, `child_process`, `path`, `util` (OSV lists npm's `fs` and `http` as malware). On `vm-day1`, 20 malicious samples and 2 benign add a dependency named like a Node built-in; kept |
| `npm.publish-method.downgrade` with the publisher's history (packuments) | 120 of 127 live hits: that account had published the package by hand before; 57 since the package's first CI release. That second reading as a filter would lose 7 of 149 malicious samples (`axios@1.14.1`, five `@nx/*`, `synckit`); not adopted |
| `static.exfil-endpoint` forms on `vm-day1` (1,176 malicious, 5 benign samples) | Telegram only with a literal bot token and tunnels only as a concrete host would drop 30 malicious (29 caught by nothing else) and 4 benign; not adopted. ngrok region hosts only: 9 live reported versions, but 11 malicious samples (`stage2-rules` 2,169 -> 2,158 forwarded; the first scan missed 2-letter labels); not adopted |
| Stage 5 bundles for the run's reported versions with install hooks (154; 78 more not captured) | Bundle format 2, 4 workers: 123 offline-installable (102 complete, 25 without dependencies, 4 of the complete predict network); 12 incomplete only because one dependency file was over 64 MiB (native CLIs: bun, opencode, `@square/cli`). After letting a file take the unpacked cap: **135 of 154 (87.7%)**; still out: 10 over a cap (8 unpacked, `@opencode/cli` x6), 4 with an unresolved dependency (2 not on the registry, 1 a remote URL, 1 for another platform), 1 with a dependency shrinkwrap. p50 / p90 / max: 127 / 230 / 642 packages, 14 / 63 / 126 MB `.tgz`, 10 / 24 / 45 s; 2.8 GB fetched once for all 154; 4.3 GB peak RSS |
| Ticks after the catch-up (bounded Stage 4: archive and packument slots) | 11:30-12:13 UTC, 23,807 changes: 43 min, 196 to review, available memory never under 20.7 GB of 30.7 (old code: 5.5 GB); systemd cgroup peak 16 GB, page cache included. Hourly ticks of ~5,000 changes since: 8-10 min, cgroup peak 6-7 GB. The queue held 1,119 packages (1,568 versions) from 7 runs at 14:43 |

## 2026-11-08: Streaming steps 1-2 (`collect`, retention, Stage 0 digest)

`docs/proposals/streaming-stages.md` steps 1 and 2, measured from a worktree against the live
`data/` read-only (copies for anything that writes), each job under
`systemd-run --user --scope -p MemoryMax=4G` (6G for the digest). Peak RSS is
`getrusage(RUSAGE_SELF).ru_maxrss`.

| Check | Result |
|---|---|
| `prune` on a hard-linked copy of the 4-day run `20261107T163310Z-npm` (405,710 changes, 2.94 GB `changes.jsonl`), with the newest label set (222,873 names) | 41 s; **1.19 GB peak RSS**, of which 0.74 GB is the label set, loaded before pruning (the old code: ~16 GB, estimated in the proposal, not run); 1,983 entries pinned; `.zst` 209.6 MB; decompressed SHA-256 equals the original's |
| `prune` on a copy of the hourly `20261108T153157Z-npm` (1,598 changes), new code vs. the old | `retention.json` byte-identical; `.zst` 1,146,488 vs. 1,146,134 B (streamed frames); both decompress to the original |
| `collect._resume_from`'s Stage 2 retry check on the 4-day run's `static.jsonl` (1.67 GB, 42,719 batches) | Streamed: no line holds the `WILL_RETRY` text, so nothing is parsed; ~1 s, **86 MB peak RSS** (the old check read the file and split it into lines first: ~3.3 GB before parsing, from the proposal's sizes) |
| `collect.run_stages` dropping each stage's result after counting | Not measured live (it needs a whole tick); the existing `tests/test_collect.py` log-line checks pass unchanged. The proposal's model puts the saving at the earlier stages' results: ~13-21 GB held when Stage 3 started on the 4-day run |
| `changes_digest` over the 4-day run's `changes.jsonl`, each line parsed into a `Change` and fed to the function one at a time | 405,710 changes; equals the manifest's `changes_sha256` (`00652635...`); 36 s; **128 MB peak RSS** (the joined string: ~18 GB, estimated in the proposal) |
| `kitsunox ingest replay` (worktree code; read-only, no lock) | `20261108T153157Z-npm` (1,598 changes): identical, 12 s, 0.55 GB peak RSS. `20261107T222723Z-npm` (16,589 changes): identical, 94 s, 1.04 GB peak RSS |
| `ingest replay` of the 4-day run | Not run: the replay still holds every `Change` (~13 GB) until step 4 |
