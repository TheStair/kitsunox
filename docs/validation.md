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
