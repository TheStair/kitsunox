# 0010: Stage 4: what it reads, how it scores, and how releases are compared with git

**Date:** 2026-10-28
**Status:** Accepted
**Builds on:** [0004](0004-git-path-parallel-to-npm.md) (tarball-vs-repo as the join between the
npm and git paths), roadmap open decision 1 (tarball-vs-repo scope)

## Context

Stages 1-3 each flag a version when one of their rules fires at MEDIUM or above. Stage 4 has
three jobs from the architecture: combine weak signals into a score, look things up in outside
knowledge (OSV malware records), and compare a release with its source repository, the signal
for code that was published to npm without passing through git.

Three measurements on `day1` shaped the design:

1. **A score threshold cannot replace the per-stage bars without losing recall.** Counting each
   rule once, "score ≥ 6" alone reports 0.1% of benign updates against 0.9% for the union of
   stage flags, but loses 2 points of recall on malicious updates and 9 on new packages.
2. **Most malicious updates the pipeline missed were never routed to Stages 2-3** (23 of 24 at
   the time), and many carried the same two LOW Stage 1 findings.
3. **Most packages don't ship their sources** (57% of 28 compared benign updates ship only build
   output), and 30% of releases can't be compared at all (the recorded commit was never pushed,
   or the repository is too large).

## Decision

- **Input: every triaged version.** Stage 4 reads `triage.jsonl` and takes Stages 2-3's version
  of the candidates they processed (`ast.jsonl`). Correlating metadata costs nothing, and only
  then can two LOW findings on an unrouted version add up.
- **Report** a version when any finding is MEDIUM or above (so recall is never below Stages 1-3
  together), or when its score reaches `REPORT_SCORE`. The **score** counts each rule once, at its
  largest weight (Stage 2 reports one finding per file), and orders the review queue.
- **Combination rules** are named rules like any other (e.g.
  `npm.combination.revived-with-new-dependency`), so every term of a score is visible.
- **Known-malware lookups** use the OSV `MAL-` label set already synced for evaluation. Only
  records that call *every* version of a dependency malware count (one compromised `chalk`
  release doesn't make `chalk` malware), and only records published by the run's `as_of`.
- **Repository comparison**
  - *Which versions* (the user's choice, from three options): versions any stage flagged, plus
    every update of a watched package, about 500 an hour. Rejected: flagged only (cheap, but can
    only corroborate) and every update with a repository (about 13k archives a day).
  - *No GitHub token, no API.* Refs come from git's smart-HTTP ref advertisement
    (`<repo>.git/info/refs`), contents from `codeload.github.com/<repo>/tar.gz/<commit>`,
    cached by commit through the immutable index. Both go through `HttpFetcher`, so runs replay.
  - *Which commit:* `gitHead` when recorded, else a release tag (`v1.2.3`, `name@1.2.3`, ...).
    The comparison records which was used, since a tag is weaker evidence.
  - *What counts:* a shipped code file that is in the repository at the same path with
    different content; and a shipped code file the repository lacks, in a directory the
    repository has, with no source file there that could have compiled to it. Build output in
    directories git ignores (`dist/`) doesn't count.
  - *Not a gate:* a network failure leaves the version without a comparison; it doesn't fail the
    run or retry. Stage 4 adds evidence; Stage 2 is the stage that must not lose data.
- **Retention** keeps Stage 4's fetches (`correlate-snapshot.json`) with the run, like Stage 2's.

## Consequences

- Unrouted versions can now be reported, but only through Stage 1 findings and combinations of
  them: their code is never read.
- The comparison only helps where a commit can be found. Malicious releases mostly record no
  `gitHead` and have no tag, so the most common case is "no commit for this version", which is
  itself the `npm.provenance.githead-dropped` signal.
- Not attempted: rebuilding packages to compare build output, GitLab and other hosts.
  (`package.json` install hooks and dependency names are compared since the same day.)

## Addendum (2026-10-29): network failures are retried

The "not a gate" bullet above said a network failure leaves the version uncompared and is not
retried. That contradicted [0009](0009-network-failure-handling.md) (network failures are
retried, never silently skipped), and `repo_lookup` also labelled every `FetchError` as
"network", including permanent ones such as a malformed ref advertisement.

- **Transient vs. permanent**, as in Stages 0 and 2: only `TransientFetchError` (the fetcher's
  attempts ran out on connection errors or 429/5xx) marks a comparison `transient`; a 404, size
  limit or malformed response is permanent.
- **In-stage retry passes:** after the first pass, the transient lookups run again, at most
  `RETRY_PASSES` (2) times, stopping when a pass recovers none, so a small outage costs one
  extra pass, not two (a large one gets no retry pass; see the outage guard below). No extra
  sleeping; requests keep the fetcher's own back-off. Retried fetches go through the same
  `HttpFetcher`, so they are recorded and the run replays.
- **Visible when it still fails:** the decision reason gets `NETWORK_UNCOMPARED`,
  `repo_network_failures` counts it, and `correlate.json` records `repo_network`
  (lookups, first-pass failures, passes run, whether retrying was skipped, still failing).
- **Rejected:** redoing Stage 4 on the next tick, like Stage 2's catch-up. It would need
  `collect` to treat a network-marked `correlate.jsonl` as unfinished; possible later, but
  Stage 4 is still not a gate, and repeating a whole run's comparisons for a few versions
  costs more than it recovers. Retrying immediately inside `repo_lookup` was also rejected: it
  gives the network no time to recover, while a pass after the whole run does.
- **Outage cost (review, same day):** a failed refs request is never cached, so every version
  of a repository paid the fetcher's whole back-off (1+2+4+8 s plus connect timeouts) in the
  first pass and again in the retry. At ~500 lookups an hour on 8 workers, a GitHub outage
  would have made Stage 4 take 0.5-2.3 h, longer than the hourly tick. Two changes:
  - `RepoMemory` remembers, for one pass and across worker threads, a repository whose
    request failed on the network; its other versions fail fast as transient. The lookup's
    `new_pass()` clears it before each retry pass, so retries still go to the network. The
    first pass now pays the back-off once per repository, not once per version.
  - **Outage guard:** if at least half the lookups (`OUTAGE_SHARE`) and at least 20
    (`OUTAGE_MIN`) failed on the network in the first pass, no retry pass runs, and
    `correlate.json` records `repo_network.retry_skipped: "outage"`. Count-based, not a time
    budget: analysis never reads the clock. Rejected: a host-wide circuit breaker (fail
    everything after K failures to `github.com`); it would cut the first pass further but
    turns one bad repository into a run-wide skip. Still open if outages prove common.
  - `HttpFetcher` now caps a server's `Retry-After` at `max_delay` (60 s); before, a large
    value stalled a worker for as long as the server asked.
  - `correlate.json` gains `stage_version` (`STAGE_VERSION` = 2): the rules fingerprint covers
    only rule ids and versions, and none of the rules changed, so it could not tell this
    output from earlier output.
- **Replay:** retried fetches that succeed are recorded, so a recovered run replays to the same
  `correlate.jsonl`. A lookup that failed even after the retries has nothing recorded and
  replays as a permanent "replay miss"; `repo_network` describes the recording, not a replay.
- Tests: `test_network_failures_are_retried_after_the_first_pass`,
  `test_a_small_outage_costs_one_retry_pass`, `test_an_outage_skips_the_retry_passes`,
  `test_many_failures_among_more_requests_are_retried`,
  `test_a_network_failure_that_clears_is_compared`,
  `test_a_network_failure_that_persists_stays_visible`,
  `test_a_refs_failure_is_retried_not_cached`,
  `test_a_failed_repository_fails_fast_within_a_pass`,
  `test_a_repository_still_down_says_why`, `test_a_recovered_run_replays_identically`,
  `test_a_missing_commit_is_not_retried`, `test_retry_after_is_capped_by_max_delay`.

## Addendum (2026-10-29, later): failures remembered per request, not per repository

An adversarial review of the addendum above verified four defects, each with a repro test:

1. **Output depended on thread timing.** The version whose thread sent a failing request got
   the fetcher's error ("network: GET ... failed after N attempts"), its siblings "o/r: not
   requested again in this pass (...)". Which version got which depended on scheduling, so the
   same responses gave different `correlate.jsonl` files (30 identical runs: 2 outputs).
2. **Memory keyed by repository.** One commit's failing archive failed every other version of
   the repository in the pass, even at a commit that worked or whose archive the fetcher
   already held (4 versions, 1 bad commit, 1 worker: all 4 uncompared).
3. **Outage guard counted versions.** One failed refs request of a monorepo burst (20+
   versions, one repository) counted as 20+ failures, called an outage, and skipped the retry
   that would have recovered all of them.
4. **Release tarballs retried twice.** A tarball Stage 2 had failed to fetch was retried by
   Stage 4 and counted as a repository failure, though `collect`'s Stage 2 catch-up redoes the
   run on the next tick anyway.

Changes (`STAGE_VERSION` 3):

- **Per-request memory:** `RepoMemory` keys locks and failures by request: a repository's refs,
  or its archive at one commit. One thread at a time sends a request; the others wait for it.
  A request that `HttpFetcher` would not send (it is in this run's snapshot, or an archive in
  the immutable index: `HttpFetcher.needs_network`, new) bypasses the memory and is always
  served. Alternative considered: key by archive URL string; the same thing, but the
  `(repo, commit)` key also gives the explanation its label.
- **One stable explanation per request:** `RepoNetworkError` names the request, not the error
  ("network: o/r refs unavailable", "network: o/r@<commit[:12]> archive unavailable"), for the
  sender and the refused alike. The fetcher's error text goes to `correlate.json`
  (`repo_network.errors`, per request label, last pass run), which is metadata about the
  recording. Alternative considered: keep the error in the text and make every version copy
  the first error; rejected because the error text itself (connect error vs. HTTP 503, attempt
  counts) can vary between runs with no bearing on the analysis.
- **Outage guard over requests:** `failed_requests >= OUTAGE_MIN` and
  `failed_requests >= OUTAGE_SHARE * requests`, where both count distinct requests the first
  pass sent to the network (refusals and cache hits excluded). Both are recorded in
  `repo_network`. The lookup protocol gains `requests()` for this.
- **Release files left to Stage 2:** a transient `Unavailable` from `ArtifactFiles` gives
  `files_transient` (not `transient`) with the fixed reason "package files: network failure;
  Stage 2 retries next tick". Not retried, not in the guard, not in `still_failing` or
  `repo_network_failures`, so the report's "not compared (network)" still means repository
  failures; counted as `repo_network.package_files_network`.
- **Doc correction:** the stage page said a replay's `repo_network` counts are all zero. Every
  field except `lookups` resets on replay: the counts are zero (including
  `package_files_network`), `retry_skipped` is null and `errors` empty. Verified by the second
  review (`retry_skipped` "outage" → null and `package_files_network` 1 → 0 on replay).
- **Rejections are remembered for the run** (second review): a request the fetcher rejects
  without recording a response, such as an archive over `max_bytes`, was downloaded again by
  every version that needed it, one after another under the request lock (5 downloads for 5
  versions). `RepoMemory` now keeps the `FetchError` / `ValueError` and re-raises the same
  text; `test_a_rejected_archive_is_downloaded_once`.

Tests (the review's repros, adapted to the fixed behaviour):
`test_the_output_does_not_depend_on_thread_timing` (21 runs, delays, 1 or 8 workers: one
`correlate.jsonl` and one `correlate.json`), `test_one_bad_commit_does_not_fail_other_commits`,
`test_a_cached_archive_is_never_refused`,
`test_one_failed_request_in_a_monorepo_burst_is_no_outage`,
`test_release_files_on_the_network_are_not_retried`,
`test_replay_of_a_failure_records_no_requests`, `test_a_repository_still_down_says_why` (now
asserts identical texts), `test_the_outage_guard_counts_requests_not_versions`,
`test_release_files_failing_on_the_network_are_left_to_stage_2`,
`test_needs_network_says_whether_get_would_send`.

## Addendum (2026-11-08): a per-run comparison budget

**Context.** The 4-day catch-up run `20261107T163310Z-npm` wanted 80,934 repository comparisons
(an hourly run wants ~500). Its archives filled the disk to the blob store's floor after 108 GB;
Stage 4 failed, saved no snapshot, and the prune deleted the archives, so every later tick would
have repeated it until the run left the 48-hour catch-up window. Catch-ups run before the newest
run's stages, so those ticks also skipped Stage 2 (tarball capture) of the newer runs.

**Options.** (1) A cap on versions compared per run, flagged first. (2) A byte budget on
archives: closer to the real limit, but which versions fit would depend on the order threads
finish, so the output would not be deterministic. (3) Also running newer runs' Stages 1-2 before
older runs' catch-ups; the owner chose the budget alone for now.

**Decision.** (1): `MAX_REPO_COMPARISONS` = 2,000, chosen by `plan_comparisons` before any
request; versions over it carry `BUDGET_UNCOMPARED` and `correlate.json` counts them
(`repo_budget`). Stage version 11. See [the stage page](../stages/correlate.md#comparison-budget).

**Consequences.** Hourly runs are unchanged. After a long gap, routine updates of watched
packages beyond the budget are not compared with their repository, so a malicious update of a
watched package with no other finding can go unreported in that run. Flagged versions are
compared first, up to the same cap.
