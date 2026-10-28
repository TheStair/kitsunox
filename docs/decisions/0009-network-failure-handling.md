# 0009: Surviving network failures and downtime

**Date:** 2026-10-28
**Status:** Accepted
**Revises:** the 48-hour gap in [0006](0006-scheduled-collection-and-retention.md)

## Context

Collection runs hourly on a laptop that sometimes sleeps, travels and changes networks. From
Stage 5 on, the plan is to move the whole pipeline into a VM on the user's desktop; collection
must cope either way. The alternative was renting a cloud machine. It was rejected for now:
outages happen there too, and the sandbox may break providers' terms. Reviewing the code showed
three ways a disconnect lost data silently:

1. **Stage 0 treated a network failure like a deleted package.** A package whose packument
   fetch failed was recorded in `skipped.jsonl` and the run succeeded. The checkpoint then moved
   past it, so a ten-minute outage could drop hundreds of packages from the record for good.
2. **Stage 2 never retried a failed tarball download.** Malicious tarballs are deleted within
   hours, so these failures matter most.
3. **A gap over 48 hours** (machine off) fell back to a 24-hour window and lost the rest.

## Decision

- **Transient vs. permanent failures.** `HttpFetcher` raises `TransientFetchError` (a
  `FetchError`) when retries run out on connection errors or retryable statuses (429, 5xx).
  A 404 or a malformed body is still a plain failure.
- **Stage 0 retry list.** Skips caused by `TransientFetchError` are marked `transient`. The
  checkpoint carries them as `RetryItem`s (name, feed position, window start). The next chained
  run fetches them again over a window reaching back to when they were missed. The manifest
  records the retried items, so the run still replays exactly. Items older than
  `MAX_CHAIN_GAP` expire.
- **Outage threshold.** If more than 20% of a run's packages (with at least 20 packages) fail
  on the network, `record_ingest` raises `IngestDegradedError` before writing anything. The
  checkpoint stays put, and the next tick covers the whole range.
- **Offline ticks.** `collect` logs `ingest: OFFLINE or outage, nothing written` and stops.
  No run, no checkpoint change.
- **Stage 1–2 catch-up.** Each tick first redoes runs from the last 48 hours whose
  `static.jsonl` is missing (stages crashed or never ran) or that have a version or base marked
  `unavailable, will retry`. Already-fetched tarballs come from the immutable index and results
  from the content cache, so a redo only fetches what failed.
- **`MAX_CHAIN_GAP`: 48 hours → 7 days**, equal to retention. After a long weekend offline, the
  first tick catches up the whole gap; that one tick is large (about 5 GB of packuments a day of
  gap) but loses nothing still listed on the registry.

## Consequences

- Versions published and deleted while the machine was offline are still lost: no client-side
  design can recover those. The 15-minute chain overlap and hourly cadence keep the window small
  while online.
- A run's `skipped_count` now includes transient skips, which are reported separately
  (`transient_skipped`) and retried.
- A long catch-up tick holds the data-directory lock for its duration; the ticks it overlaps
  skip quietly and are covered by chaining.
- Tests: `test_network_skips_are_retried_by_the_next_run`, `test_an_outage_writes_nothing`,
  `test_stale_retries_expire`, `test_offline_tick_writes_nothing`,
  `test_unfinished_stages_are_caught_up`, `test_network_failures_are_marked_for_retry`.
