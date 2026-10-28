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
