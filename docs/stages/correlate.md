# Stage 4: Correlation, repository comparison and score

> **Status:** implemented 2026-10-28 (`stages/correlate.py`, `stages/repo.py`,
> `githost/github.py`; npm wiring in `stages/review.py`). It runs in `collect` after Stage 3.
> Design: [decision 0010](../decisions/0010-stage4-correlation-and-repo-comparison.md).
> Dependency reputation (`npm.dependency.fresh-foreign`, `npm.dependency.name-embeds-popular`)
> added 2026-10-29 from [the proposal](../proposals/dependency-reputation.md); `STAGE_VERSION` 4.
> After review the same day: dependency lookups are retried like repository lookups, capped per
> release as well as per run, and shown in reports; `STAGE_VERSION` 5.

## Purpose

Stages 1-3 each judge a version on their own evidence. Stage 4 puts the evidence together and
decides what a person should review:

- **Combines** weak signals that mean little alone (a dormant package revived; a dependency
  added) into named combination findings.
- **Looks up** outside knowledge: does the release depend on a package OSV calls malware, or on
  one registered days ago by accounts unrelated to it? (A dependency-chain attack leaves the
  dependent's own tarball clean, so Stages 2 and 3 see nothing.)
- **Compares** the release with its source repository at the commit it was built from. Code on
  npm that isn't in git is the mark of a publish with a stolen token, whatever the code does.
- **Scores** each version and orders the review queue by score.

## Usage

```sh
uv run kitsunox correlate <run_id>                          # after `ast`; writes correlate.jsonl
uv run kitsunox eval run <dataset> --predictor pipeline+4   # end to end: what would be reported
```

## Input and output

- **Input:** every version Stage 1 triaged (`triage.jsonl`), with Stages 2-3's findings for
  those routed to them (`ast.jsonl`). Unrouted versions carry only Stage 1 findings, but those
  can still combine.
- **Fetches:** for the versions `wants_repo` picks (any stage flagged it, or it updates a
  watched package), at most `MAX_REPO_COMPARISONS` (2,000) a run, flagged versions first
  (see [Comparison budget](#comparison-budget)): the repository's refs and one source archive
  per commit. Recorded in
  `correlate-snapshot.json` and kept by retention like Stage 2's tarballs. The release's own
  files come from the blob store (Stage 2 fetched them). For dependencies a release adds that
  aren't its own, its scope's or watched: their packument (see
  [Dependency lookups](#dependency-lookups)), recorded in the same snapshot.
- **Also reads:** the run's watchlist (the one Stage 0 recorded in `manifest.json`, checked
  against its SHA-256): watched dependencies are exempt, and its popular names are what
  `name-embeds-popular` compares with.
- **Output:** `correlate.jsonl` (one `Candidate` per line, in triage order, with Stage 4's
  findings and a `StageDecision`) and `correlate.json`: the label set, the watchlist id,
  `stage_version` (`STAGE_VERSION`: 2 since the network retries, 3 since failures are
  remembered per request, 4 since the watchlist and dependency lookups, 5 since dependency
  lookups are retried and limited per release; absent means 1), rule
  fingerprint and report score used, `repo_network` (see below) and `dependency_lookups`
  (see [Dependency lookups](#dependency-lookups)).

## Comparison budget

An hourly run wants ~500 comparisons. After a long gap one run can want far more: the 4-day
catch-up `20261107T163310Z-npm` (405,710 changes) wanted 80,934 (1,745 flagged, 79,189
watched-package updates). Its archives took 108 GB in 4.4 hours, the blob store refused writes
at its 10 GB floor, Stage 4 failed without saving its snapshot, the end-of-tick prune deleted
the archives as unreferenced, and the next tick started over.

So `plan_comparisons` decides, before any request, which versions a run compares: the flagged
ones, then watched-package updates, each in triage order, up to `MAX_REPO_COMPARISONS` (2,000,
about 4 hours of normal ticks; the first live day averaged ~14 MB an archive, so at most
~30 GB). The choice depends only on the run's input, so a replay makes the same one. Each
version over the budget gets `BUDGET_UNCOMPARED` ("not compared with its repository: over the
run's comparison budget") on its decision, `collect` logs how many, and `correlate.json`
counts them under `repo_budget` (`max_comparisons`, `wanted`, `flagged`, `over_budget`).
Stage version 11. Hourly runs never reach the cap; sliced catch-ups (`MAX_RUN_FEED_SPAN`,
~95k changes) do, and their routine watched-package updates go uncompared.

## Network failures

Repository lookups that fail on the network are retried, and so (since `STAGE_VERSION` 5) are
dependency lookups ([below](#dependency-lookups)); nothing else is (decision 0009, and
the [0010 addendum](../decisions/0010-stage4-correlation-and-repo-comparison.md#addendum-2026-10-29-network-failures-are-retried)).

- **What counts as network:** `HttpFetcher` raises `TransientFetchError` once its own attempts
  (5, with exponential back-off, a server's `Retry-After` capped at the same 60 s) run out on
  connection errors or HTTP 429/5xx. For a repository request (refs, or an archive) that marks
  the comparison `transient` (`RepoComparison.transient`). A 404 (repository gone, commit never
  pushed), an oversized archive or a malformed ref advertisement is permanent and is not
  retried.
- **Release files are Stage 2's:** when the release's own tarball fails on the network
  (`ArtifactFiles` returns a transient `Unavailable`), the comparison is marked
  `files_transient` instead, with the fixed reason "package files: network failure; Stage 2
  retries next tick". Stage 4 compares only versions Stage 2 read (decision 0008), and Stage 2's
  successful fetches are in the immutable index, so this happens only when Stage 2 failed on
  the same tarball; Stage 2 marked it, and `collect`'s catch-up redoes the run from Stage 1 on
  the next tick. Stage 4 doesn't retry these, doesn't count them in the outage guard or in
  `still_failing`, and doesn't add `NETWORK_UNCOMPARED`; `repo_network.package_files_network`
  counts them.
- **One network attempt per request per pass:** `RepoMemory` (`stages/repo.py`), shared by
  the worker threads, keys what it remembers by the request: a repository's refs, or its
  archive at one commit. Only one thread at a time sends a given request; versions that need
  it wait and use its response (refs are kept for the run, archives come from the fetcher's
  snapshot) or its failure. Once a request failed on the network, the versions that need it in
  the same pass fail at once instead of each waiting out up to ~1 minute of back-off and
  timeouts. Other commits of the same repository are unaffected, and a request the fetcher
  already holds (this run's snapshot, or the immutable index for archives;
  `HttpFetcher.needs_network`) is always served, never refused.
- **Extraction in worker processes** (2026-10-30): at most three archives are extracted at
  once (`ARCHIVES_IN_MEMORY`), and `run_correlate_stage` does it in a pool of three worker
  processes (`compare_pool`, `forkserver`; each replaced after 25 comparisons), which also
  compare the trees and return the `RepoComparison`. Extracting is pure-Python `tarfile` work,
  so threads did it one at a time under the GIL: about 85% of a replayed Stage 4. Downloads
  stay in the threads. Results are the same either way (`test_a_pool_compares_exactly_as_
  threads_do`); without a pool (tests, evaluation) it all runs in the thread. GitHub archives
  also skip the strict second tar pass that looks for hidden entries.
- **One explanation per failed request:** every version whose comparison failed on a request
  reads the same, whichever thread sent it: "No comparison: network: o/r refs unavailable." or
  "... network: o/r@<12-char commit> archive unavailable." (`RepoNetworkError`). The fetcher's
  error text goes only to `correlate.json` (`repo_network.errors`). Before `STAGE_VERSION` 3
  the thread that sent the request got the error and its siblings "not requested again in this
  pass", so `correlate.jsonl` depended on thread timing
  (`test_the_output_does_not_depend_on_thread_timing` now runs one setup 21 times, with
  delays and 1 or 8 workers, and gets one output).
- **Retry passes:** after the first pass, `correlate_run` calls the lookup's `new_pass()` (so
  the memory of failed requests is cleared and the retry really goes to the network) and runs
  the transient lookups again, at most `RETRY_PASSES` (2) times, stopping early when a pass
  recovers none. No pass sleeps beyond the fetcher's own back-off. Failed requests are never
  recorded; a success is recorded in `correlate-snapshot.json` like any other fetch.
- **Outage guard:** no retry pass runs when the first pass looks like an outage: at least
  `OUTAGE_SHARE` (half) of the distinct repository requests it sent to the network, and at
  least `OUTAGE_MIN` (20) of them, failed there. Requests served from the snapshot or the
  immutable index, and requests refused because they already failed, aren't counted. A flaky
  connection or a rate limit fails a few requests an hour; half failing means GitHub or the
  VM's link is down, and a retry pass would mostly pay the back-off again, pushing Stage 4 past
  the hourly tick. Under 20 failed requests a retry pass costs a few minutes at most, so small
  runs always retry. The guard counts requests, not versions: a 30-package monorepo burst
  whose refs failed once is one failed request, and is retried
  (`test_one_failed_request_in_a_monorepo_burst_is_no_outage`). It counts, not times, so it
  never reads the clock.
- **Still failing:** the version keeps `repo.compared` "No comparison: network: ...
  unavailable.", and its decision reason ends with `NETWORK_UNCOMPARED` (`; not compared with
  its repository: network failure`), which `repo_network_failures(candidates)` counts
  (repository failures only; the report's "not compared (network)" line reads it as
  `still_failing`).
- **`repo_network` in `correlate.json`:** `lookups` (versions `wants_repo` picked),
  `first_pass` (of those, failed on a repository request in the first pass), `requests` and
  `failed_requests` (distinct requests the first pass sent to the network, and how many failed
  there: what the outage guard compares), `retry_passes` (run), `retry_skipped` (`"outage"`
  when the guard skipped them, else null), `still_failing`, `package_files_network` (release
  files that failed on the network, left to Stage 2) and `errors` (request label to the
  fetcher's error, for the requests that failed in the last pass run, sorted).
- **Replay:** replaying `correlate-snapshot.json` gives the same `correlate.jsonl` when every
  lookup eventually succeeded (`test_a_recovered_run_replays_identically`). A lookup that
  failed even after the retries has no recorded response: on replay it is a permanent "replay
  miss" (not transient), so the replay's reason lacks `NETWORK_UNCOMPARED`; a release whose
  files failed on the network replays as a package-files replay miss, not
  `PACKAGE_FILES_NETWORK`. A replay sends no requests, so every `repo_network` field except
  `lookups` resets: `first_pass`, `requests`, `failed_requests`, `retry_passes`,
  `still_failing` and `package_files_network` are zero, `retry_skipped` is null and `errors`
  is empty (`test_replay_of_a_failure_records_no_requests`). `repo_network` describes the
  recording.
- **Rejections:** a request the fetcher rejects without recording a response (a body over its
  256 MB limit, a bad redirect), or an archive that can't be read, is permanent: it is sent
  once per run, and every version that needs it gets the same "archive: ..." text
  (`test_a_rejected_archive_is_downloaded_once`).

## Dependency lookups

`npm.dependency.fresh-foreign` needs to know when a dependency first existed and who publishes
it. `NpmDependencyLookup` (`stages/review.py`, a `DependencyLookup`) gets it from the
dependency's packument.

- **Which names:** `foreign_added_dependencies` (`ecosystems/npm/rules/correlate.py`): registry
  runtime and optional dependencies the release adds, or re-points through an `npm:` alias
  (for a new package, all of them), that are not the package itself, not in its scope, not on
  the run's watchlist, and not `workspace:` siblings. Both dependency rules and the lookup plan
  use it. The proposal measured ~640 such names a day (~27 an hourly tick).
- **One request per name per pass**, the request Stage 0 sends (`NpmEcosystem.packument`,
  `Accept: application/json`), through the run's `HttpFetcher`: recorded in
  `correlate-snapshot.json` and replayed. Not kept across runs (packuments change).
  `correlate_run` looks up every planned name before any rule runs, so the rules only read
  answers and a retry pass can still change them.
- **Plan and limits** (`plan()`, called with every version before any lookup):
  - **Updates first**, then new packages, each in run order. On an update this rule is the one
    signal Stages 2-3 can't supply; a new package's own code they read anyway.
  - **Per release:** each release may claim at most `MAX_LOOKUPS_PER_RELEASE` (40) names that
    no earlier release claimed, in the order the rule lists them (by `package.json` key). Names
    another release already claimed cost nothing. Measured on run `20261029T221803Z-npm` (24 h,
    110,084 versions): 487 versions added foreign dependencies; the most was 34
    (`@tabaxal/web@0.1.0-alpha.0`), then 22 and 16, so 40 cuts no release of that day. A
    release with 2,000 junk dependencies (names that don't exist still cost a request, since
    nothing tells them apart before asking) claims 40, and the rest of the run is checked
    (`test_one_release_cannot_use_up_the_lookup_cap`).
  - **Per run:** `MAX_DEPENDENCY_LOOKUPS` (1,000) names per started day of the run's window
    (`dependency_cap`): the same day had 628 names, and a 2-day catch-up run (~1,250) gets
    2,000. At the median 29 KB, 1,000 names is ~30 MB. Exhausting a day's cap takes 25
    releases at the per-release limit.
  - Names over either limit share **one** INFO "not evaluated" finding per release ("N added
    dependencies were not checked ... over the dependency lookup limits"), so a release with
    2,000 dependencies gets one finding, not 2,000. The plan is fixed before any request, so
    the limits pick the same names however the workers are scheduled.
- **What the record holds:** every `time[version]` entry whose key is a version (listed, or
  valid semver: a stray key such as `__proto__` is not; this includes versions npm has since
  removed: `Packument.version_times`), the maintainers and publisher of each version still
  listed, and the current top-level maintainers. Rules keep versions published by `as_of`.
- **Network failures (decision 0009):** a lookup that fails on the network after the fetcher's
  own attempts (`TransientFetchError`) answers `FAILED`, `transient`, for the rest of the pass,
  so the versions depending on it don't each wait out the back-off. After the repository
  retry passes (giving the registry those minutes too) `correlate_run` asks for the failed
  names again, up to `RETRY_PASSES` times, stopping when a pass recovers none, under the same
  outage guard as repository lookups but counted on its own (a different host): distinct
  names sent and failed in the first pass, `OUTAGE_SHARE` and `OUTAGE_MIN`. A name still
  failing gives an INFO finding, "Not evaluated: `x` was not checked for age and accounts: its
  registry record could not be fetched.", never a silent "not fresh", and is counted in
  `still_failing`, which the report index and the Discord update show
  (`Report.dependency_network_failures`). The run is not redone on a later tick.
- **Other failures** are permanent for the run and not retried: a replay miss, an oversized
  response, a 4xx other than 404, and a document that isn't this package's packument (not
  JSON, a proxy's or captive portal's HTML page, another name). They read the same as a
  network failure, so a replay of a failed run gives the same `correlate.jsonl`. Only a 404 is
  `MISSING` and gives no finding. (Before `STAGE_VERSION` 5 a malformed document was
  `MISSING`, so a captive portal page silently cleared the dependency.)
- **`dependency_lookups` in `correlate.json`:** `cap`, `per_release`, `names` (distinct names
  the rule would look up), `capped` (over either limit), `releases_limited` (releases with
  names over the per-release limit), `looked_up`, `found`, `missing` (404), `failed` (not
  fetched, for any reason, after retries), then as for `repo_network`: `first_pass` (names
  that failed on the network in the first pass), `requests` and `failed_requests` (distinct
  names the first pass sent, and failed there: what the outage guard counts), `retry_passes`,
  `retry_skipped` (`"outage"` or null), `still_failing` (names still failing on the network);
  then `versions_not_evaluated` (versions with an INFO finding starting `NOT_EVALUATED`: a
  lookup failed or was over the limits, or account information was missing) and `errors`
  (name to error, for every name still `failed`, sorted).
- **Replay:** byte-identical `correlate.jsonl` when every lookup succeeded, and the same
  `correlate.json` except `requests` (a replay sends none, as for repository lookups)
  (`test_dependency_lookup_replays_byte_identically`); the same `correlate.jsonl` for a run
  whose lookup failed (`test_dependency_network_failure_is_not_evaluated`); one distinct
  output over 20 runs with a name down, one that clears on the retry, a slow one and limits
  that bind, on 1 or 8 workers (`test_dependency_output_does_not_depend_on_thread_timing`).

## Decision and score

- **Report** a version when any finding is MEDIUM or above, or its score reaches
  `REPORT_SCORE` (6). The first keeps recall at least that of Stages 1-3 together; the second
  lets LOW findings add up. Since 2026-10-30 a MEDIUM finding from a rule in `WEAK_ALONE` only
  reports through the score or beside another MEDIUM: `npm.publish-method.downgrade` on an
  unwatched package (MEDIUM, weight 3). On `vm-day1` no malicious sample was reported by it
  alone; on the first live days it was the commonest reason for a report. Since 2026-11-01
  also `code.capability-gained` and `static.webhook-placeholder`: of the 888 live benign
  verdicts still reported, 60 and 3 were carried by one of them alone, and no malicious or
  inconclusive verdict nor any `vm-day1` malicious sample was. Simulated and not adopted the
  same day (each loses real attacks): `revived-with-new-dependency` (-83 benign, loses
  `xrpl@2.14.2`), `install-script-changed` (-105, loses `aicp-tracker`'s last reported
  release, `fooobar` and 2 inconclusive), `fresh-foreign` (-9, loses 2), and requiring two
  MEDIUM rules (-438, loses 169 `vm-day1` samples and 11 of 27 live malicious). Measured before choosing it: "HIGH or score 6" for every rule would have
  lost 202 malicious samples (`npm.install-script-code` alone catches 85, new packages'
  install hooks 29, `npm.dependency.non-registry` 12), so the other MEDIUM rules still report
  alone.
- **Established repository match** (stage version 9, 2026-11-04): clearing install-code
  MEDIUM findings for a version whose code is exactly an established repository's is built
  but off (`CLEAR_ESTABLISHED`; Repository trust, below).
- **History match** (stage version 10, 2026-11-06): clearing the same findings for a version
  whose code is exactly the repository's at a commit ahead of the previous release's is built
  but off too (`CLEAR_HISTORY`; Repository history, below).
- **Score:** the sum over the rules that fired, each counted once at its largest weight
  (Stage 2 reports a finding per matching file), INFO excluded. Rules whose findings are all
  LOW together add at most `LOW_CAP` (3; stage version 7, 2026-10-30), so LOW findings alone
  never report a version: a large release matches six generic regexes at once
  (process-exec, network, dynamic-code, env-harvest, npm-publish, sensitive-path, many in
  CHANGELOGs and tests). Such LOW-only versions were 165 of the 1,078 unreviewed live-queue
  versions still reported under the current rules; on `vm-day1` the cap costs no malicious
  sample and drops 2 of 20 benign. A `WEAK_ALONE` MEDIUM (weight 3) with three LOWs still
  reaches 6. Reports say when the cap applied. The CLI lists reported versions by score.

## Repository comparison (`stages/repo.py`)

1. **Repository and directory:** the normalised `repository` URL (GitHub only) and
   `repository.directory` for monorepos (`ecosystems/npm/repo.py`). When a release doesn't
   set `repository.directory`, the package is the repository's `package.json` with the
   release's `name`: the root's if it matches, else the shallowest (outside `node_modules/`).
   If none matches, the root manifest still counts unless it is a workspace (`workspaces`, or
   `private: true`): forks and renamed packages keep the old name. Otherwise there is no
   comparison. (Until `repo.compared` v2, such releases were
   compared with the monorepo's root manifest, which made Playwright's, `workerd`'s and taro's
   install hooks look absent from git; see the devlog, 2026-10-29.)
2. **Commit:** `gitHead` if recorded; otherwise a release tag: `v1.2.3`, `1.2.3`,
   `name@1.2.3`, `short@1.2.3`, `name@v1.2.3`, `short-v1.2.3`, `short@v1.2.3`. Tags come from the
   smart-HTTP ref advertisement (`<repo>.git/info/refs?service=git-upload-pack`), the same data
   `git ls-remote` reads, with annotated tags peeled. No GitHub API, no token.
3. **Contents:** `codeload.github.com/<repo>/tar.gz/<commit>`, through the immutable index
   (once per commit, across runs and across a monorepo's packages), extracted in memory with
   only the package's directory kept. Archives over 128 MB compressed are not compared.
4. **Manifest:** the release's `package.json` against the repository's: install hooks it has
   that the repository's doesn't (or has differently), and runtime dependencies the
   repository's manifest doesn't name in any section (names only: tools rewrite specs).
   Comparable `day1` updates: hooks 51 of 55 malicious, 0 of 116 benign; dependencies 7 of 55
   malicious, 2 of 116 benign (before `repo.compared` v2: hooks 53/57 and 0/121, dependencies
   30/57 and 14/121, inflated by root-manifest comparisons).
5. **Compare** the release's JavaScript/TypeScript files (line endings normalised):
   - *differing:* in the repository at the same path, different content;
   - *unexplained:* not in the repository, in a directory the repository has (the root
     always counts), with no file there of the same stem (`lib/x.js` next to `lib/x.ts` is
     compiled output). Build directories git ignores (`dist/`) are not in the repository, so
     their files never count.

## Repository trust (`with_trust`, `repo.established-match`; stage version 9)

A clean comparison says the release's code is the repository's. Whether that repository is
worth trusting is a separate question, answered by GitHub's REST API with `GITHUB_TOKEN` (from
the environment or `.env`; without one nothing changes):

1. **When:** a clean comparison (`RepoComparison.clean`: every code file identical, nothing in
   the manifest the repository doesn't explain) of a version an earlier stage found something
   MEDIUM or above in. Only those can be cleared, and asking for every watched update would
   spend ~10 times the quota.
2. **What:** `GET /repos/{owner}/{repo}` (fork, archived, created, stars, default branch), and
   for a repository that isn't a fork, `GET /repos/{owner}/{repo}/compare/{commit}...{head}`
   with `head` the default branch's commit from the refs already fetched: the commit is on
   the default branch when `head` is "ahead" of it or "identical". Page 2 at one commit a page
   carries the status without page 1's file list (18 KB instead of 129 KB for
   `npm/node-semver`). Each request once per run (`RepoMemory.api`), recorded in
   `correlate-snapshot.json`; the token is a header, which neither the request key nor the
   snapshot holds, and goes only to `api.github.com` (httpx drops it on a redirect elsewhere).
3. **Failures** (a rate limit, the network, a replay miss) leave the version with
   `trust.unavailable` = "GitHub API request failed" and no established match: it is reported
   as it would be without the API. Not retried: a retry would only spend quota.
4. **`repo.established-match`** (INFO, weight 0) fires when the comparison is clean and the
   repository is not a fork or archived, was created at least 30 days before the release, has
   at least 5 stars, and holds the commit on its default branch.
5. **Decision (off: `CLEAR_ESTABLISHED = False`):** a version whose MEDIUM findings are all
   install-code findings
   (`CLEARED_BY_REPO`: `npm.install-hook` at MEDIUM, i.e. a new package's hook;
   `npm.install-script-changed`; `npm.install-script-code`) is not reported when it has an
   established match, no HIGH finding, and its score without those findings stays below
   `REPORT_SCORE`. The reason says so ("... cleared by repo.established-match").

Measured 2026-11-04 (decision [0017](../decisions/0017-repository-trust.md)):
- **Live queue** (two days, 1,231 reported versions with a GitHub repository): the clearing
  would remove 33 (2.7%); all 20 reviewed are benign.
- **`vm-day1`:** it would lose one of 2,507 reported malicious samples, `gina@0.7.1`, whose
  code is in its 2013 repository (11 stars).
- **So it is off,** and the finding is reviewer evidence only. Each of the four conditions is there for a reason seen in the data: the one
malicious clean match (`@finzzcloud/baileys`) came from the attacker's own 1-star repository,
and the attacker's `tavern-labs-ai/persona-ai-sdk` had 197 stars three days after it was
created (stars can be bought; age can't).

## Repository history (`with_history`; stage version 10)

What git saw between the previous release and this one (decision
[0018](../decisions/0018-commit-history.md)). For every update compared at a commit:

1. **The previous release's commit**, found as the release's is: its `gitHead`, else a release
   tag in the refs the comparison already fetched. No request.
2. **How the two relate** (`history.status`, from GitHub's compare API: `identical`, `ahead`,
   `behind`, `diverged`, with the counts):
   - `identical` without asking when both releases name the same commit;
   - otherwise asked, with a token, only for versions an earlier stage found something
     MEDIUM or above in (the ones a match could clear): `compare/{previous}...{release}`, page
     2 at one commit a page, so the status comes without the file list.
   - A version that isn't flagged never reads an answer another version asked for, so its
     output doesn't depend on lookup order.
3. **When a tag-found commit was made** (`history.commit_date`, with a token): the committer
   date from `git/commits/{sha}`, the commit object only. A `gitHead` is written at publish
   time, so it isn't asked.
4. Each request once per run, recorded in `correlate-snapshot.json`. Failures leave
   `history.unavailable` = "GitHub API request failed" and aren't retried (as trust).

Rules over it:

- **`repo.commit-after-release`** (MEDIUM): the tag points to a commit made more than 6 hours
  after the publish, so the release wasn't built from it. Of 815 live tag-found releases, the
  latest tag commit came 1.4 hours after the publish. The malicious ones came 7 hours to 255
  days later: a stolen token published the version first, and the maintainers' own release of
  it came later. `vm-day1`: 13 malicious, 0 benign, all reported anyway. A tag of the version
  alone (`v3.2.2`) on a package in a subdirectory doesn't count: in a monorepo it may be
  another package's (`@mongodb-js/mcp-atlas-telemetry`, the one benign hit before).
- **`npm.repo.no-new-commits`** (LOW): a stable version, higher than the previous stable one,
  built from the same commit or an older one, while its code isn't a clean match there.
  Compared updates: 61 of 102 malicious, 9 of 626 benign. `vm-day1`: 60 malicious, 0 benign. It is LOW because developers
  publishing uncommitted work look the same (2.9% of all live stable updates reuse `gitHead`).
- **`repo.history-match`** (INFO): a clean comparison at a commit ahead of the previous
  release's (and no `commit-after-release`). With `CLEAR_HISTORY` on, it clears install code
  as `repo.established-match` would.
  - Live, it would clear 78 of 1,507 reported versions (5.2%): 60 reviewed benign, none
    reviewed malicious.
  - On `vm-day1` it loses `gina@0.7.1`, whose 44 commits since its previous release are its
    maintainer's. So it is off.

## Rules

| Rule | Fires when | Severity | Weight |
|---|---|---|---|
| `npm.provenance.githead-dropped` | the previous release recorded `gitHead`, this one doesn't | LOW | 2 |
| `npm.dependency.known-malware` (v3) | an added (or re-pointed) runtime dependency, or its `npm:` alias target, is malware in every version per an OSV record published by `as_of`. LOW (weight 1) when the specifier only matches npm's empty `0.0.1-security` holding package (`fs: ^0.0.1-security`, what `npm install fs` writes), or when a Unity (UPM) package (`unity` field) depends on a `com.unity.*` built-in module, which Unity resolves from its own registry while the npm names are malware squats (v3) | HIGH | 5 |
| `npm.combination.revived-with-new-dependency` | `npm.dormant-revived` and `npm.dependency.added` both fired, on a release (not a prerelease) | MEDIUM | 2 |
| `npm.dependency.fresh-foreign` | an added dependency (not the package, its scope or watched) was first published (earliest `time[v]` ≤ `as_of`) less than 7 days before this release, and none of its accounts (maintainers and `_npmUser` of its versions by `as_of`, else its top-level maintainers) is a maintainer or publisher of this release or the previous one. No account data on either side, or a failed lookup: INFO "not evaluated" instead; dependencies over the lookup limits: one INFO for all of them | MEDIUM | 3 |
| `npm.dependency.name-embeds-popular` | an added unscoped dependency (not watched) is, lowercased without `-_.`, a name with ≥ 1M downloads a month on the watchlist (≥ 5 characters) plus a prefix or suffix of 1-8 characters (`easy-day-js` / `dayjs`); not when its record (already looked up) shares an account with this release (`react-dom-utils` from React's maintainers) | LOW | 1 |
| `repo.compared` | a comparison was attempted: what it found, or why there was none | INFO | 0 |
| `repo.established-match` | a clean comparison with a repository that is not a fork or archived, ≥ 30 days old at the release, ≥ 5 stars, the commit on its default branch (Repository trust, above). Clears install-code MEDIUM findings in the decision | INFO | 0 |
| `repo.history-match` | a clean comparison at a commit ahead of the previous release's commit, no `commit-after-release` (Repository history, above). Clears install-code MEDIUM findings in the decision when `CLEAR_HISTORY` is on (off) | INFO | 0 |
| `repo.commit-after-release` | the release's tag points to a commit made more than 6 hours after the release was published | MEDIUM | 3 |
| `npm.repo.no-new-commits` | a stable version, above the previous stable one, built from the previous release's commit or an older one, its code not a clean match there | LOW | 2 |
| `repo.code-differs` | a shipped code file differs from the repository's file at the same path | LOW | 2 |
| `repo.code-not-in-repo` | shipped code files are *unexplained* (above). Since `STAGE_VERSION` 6 a file whose content is elsewhere in the repository, byte for byte, is explained (a build copied it) | LOW | 2 |
| `npm.repo.install-script-not-in-repo` (v2) | the release's install hook isn't in the repository's `package.json` (or has another command). INFO instead when the repository's build writes it (`ManifestDifference.built_by`): every package file the command names is in the repository byte for byte, and another repository file holds the command (the release's version may be a placeholder there). First VM day: `@nutui/nutui-react-taro` (`scripts/build-taro.mjs`) and `@opencode/cli` (`script/pack.ts`); `@pulumi/*` still fire, since Pulumi's code generator, not the repository, writes their hook. With `repository.directory` only that directory is searched. v3: LOW, weight 1, when the previous release shipped the same hook (its version string aside), so a generated hook that is in every release (`@pulumi/*`) stops counting; the release that adds a hook still fires HIGH | HIGH | 5 |
| `npm.repo.dependency-not-in-repo` | a runtime dependency the repository's `package.json` doesn't name in any section | LOW | 1 |

## Evaluation

`day1` (sha256 `d99626981ae6`), 2026-10-28. Updates are shape A, new packages shape B; DataDog
is the malicious set; follow-on releases in parentheses.

| Predictor | Updates | New packages | Benign (weighted) |
|---|---|---|---|
| `pipeline+3` (Stages 1-3) | 89.7% (38.7%) | 66.0% (22.8%) | 0.8% |
| **`pipeline+4`** (what is reported) | **91.1%** (38.7%) | **66.5%** (22.9%) | **0.9%** |
| `pipeline+4` + manifest-vs-repo rules | **91.2%** (39.7%) | 66.5% (22.9%) | 0.9% |

What Stage 4 added: 13 malicious updates (12 `@mastra/*` and `xrpl@2.14.2`, through
`revived-with-new-dependency`) and 5 malicious new packages plus 1 follow-on release (through
`known-malware`, e.g. `tailwindcss-setfavicon` depending on the malware package `fs`). One benign update
(`@settlemint/dalp-cli@3.1.29-main.*`, a prerelease that dropped its `gitHead`) reached the score.
It lost nothing.

**Choosing the report score.** From a dump of every stage's findings for every sample: LOW
findings of Stages 1-3 summing to 3, 4 or 5 added 0.6, 0.2 and 0 points of recall on
malicious updates for 2.0, 0.8 and 0.4 points of benign updates; at 6 they add neither. A
score bar *instead of* the per-stage MEDIUM bars ("score ≥ 6" alone) is much more precise
(0.1% / 0.6% benign) but loses 2.2 points on updates and 9.5 on new packages. Missing an
attack costs more than a false positive, so the MEDIUM bars stay and the score orders the
queue.

The manifest-vs-repo rules add 1 malicious update and 5 follow-on releases end to end: live,
the comparison runs only for flagged or watched versions, which are mostly reported already.
Their value today is evidence a reviewer can check in seconds.

**Repository comparison** (965 malicious, 300 sampled benign updates):

| | Malicious | Benign |
|---|---|---|
| no GitHub repository | 237 | 46 |
| repository gone | 114 | 22 |
| no `gitHead` and no tag for the version | 543 | 75 |
| archive unavailable (404, too large) or directory empty | 15 | 30 |
| no manifest for the package (monorepo root only, v2) | 1 | 5 |
| **compared** (by `gitHead` / by tag) | **55** (32 / 23) | **116** (59 / 57) |
| differing or unexplained code | 48 | 3 |

Table as of `repo.compared` v2 (2026-10-29). Under v1, which compared monorepo packages with
the root manifest: 57 and 121 compared, 49 and 9 hits. The text below is from v1: 43 of the 49 malicious hits were already flagged by Stages 1-3; the other 6 (`@voiceflow/*`,
Shai-Hulud 2.0's `setup_bun.js`) are neither watched nor flagged, so live Stage 4 wouldn't
compare them. Benign hits were generated files at the package root (`@girs/*` bindings,
`index.cjs` bundles). Hence LOW: 3% of benign updates at MEDIUM would triple the pipeline's
false positives for no measured recall. The comparison's value today is evidence in the report
("this code is not in git"), and its reach grows with the git path.

**Dependency reputation** (2026-10-29, `vm-day1`, sha256 `0ffe388910a3`: 1,000 benign
updates, 500 benign new packages, DataDog). `pipeline+4` before → after the two rules:

| Cell | Before | After |
|---|---|---|
| malicious A (updates) | 876 / 965 (90.8%) | **877 (90.9%)** |
| malicious A, follow-on | 142 / 481 (29.5%) | 142 (29.5%) |
| malicious B (new packages) | 571 / 905 (63.1%) | **583 (64.4%)** |
| malicious B, follow-on | 250 / 1,093 (22.9%) | 250 (22.9%) |
| benign A / B | 8 / 1,000, 13 / 500 | 8, 13 (the same samples) |
| benign weighted pass-through | 1.12% | 1.12% |

- **Gained:** `@mastra/node-audio@0.1.8` (shape A, the one dependency-chain sample missed
  before, as the proposal predicted), and 12 shape-B tea.xyz-farm packages published by
  `bipyruss` in 2024-07 (`armed-brown-loon`, `clumsy-coffee-alpaca`, `experienced_wildfowl_z3n`,
  ...) whose ~20 farm dependencies were 11-140 hours old and published by other farm accounts
  (`davidrockefeller`, `kimyuni`, ...). The proposal expected about 0 on shape B, having found
  older farm dependencies elsewhere in the farm.
- **Independence:** `fresh-foreign` fires on 119 of the 120 `easy-day-js` / `plain-crypto-js`
  samples (`easy-day-js`, 119); 118 of them were already reported, so they now have a second
  MEDIUM reason. `axios@1.14.1` is "not evaluated": `plain-crypto-js`'s record lost its
  maintainers in the takedown. The recall is still two incidents plus one farm.
- **Benign:** `fresh-foreign` fires on none of the 1,500. `name-embeds-popular` fires on 2
  new packages (`@whizard/micro-rest` → `micro-router`, `microrouter`, `micro-compose`;
  `coda-player-sdk` → `videojs-flvjs-es6`), neither reported (LOW, score below 6). On the
  malicious side it fires on 120 A, 16 B and 2 B follow-on samples.
- **Not evaluated** (INFO, no account data, mostly taken-down dependencies): 1 A, 10 B, 2 B
  follow-on. Without `REGISTRY_ACCOUNTS`, 3 of those B samples (`@universeorg/dotenv`,
  `imgbundle`, `zentra-finance`) were "foreign" only because npm's takedown lists `npm` /
  `npm-support` as maintainers; that would have been an evaluation artifact, so those
  accounts don't count.
- **Cost:** 173 distinct dependency names looked up for the 3,444 + 1,500 samples (172 found,
  1 missing), no network failures.
- **Re-run after the review fixes** (`STAGE_VERSION` 5, both rules v2, rules fingerprint
  `ec80d6148db6f04f`, watchlist and labels `20261029T221803Z`): A 877 (90.9%), B 614 (67.8%),
  benign 8 A / 14 B (1.1% weighted). The +31 B and +1 benign B (`@zerodot/discord@1.0.0`) are
  not from Stage 4: none of those 32 samples gets a dependency-rule finding (checked offline
  against the pinned packuments); they follow the Stage 2 `exfil-endpoint` v3 /
  `webhook-placeholder` change made while the previous run was in progress. No sample was
  lost. The same 173 names (172 found, 1 missing, 0 failed). The `pipeline+4` predictor now
  pins dependency packuments under `data/eval/dependencies/` (`PinnedFetcher`), and its
  `notes` record the rules fingerprint, watchlist, labels and lookup counts.

**Known-malware dependencies.** Matching by package name alone hit 11 benign new packages
(`axios`, `chalk`, `debug`: OSV has records for compromised *versions*); counting only records
that cover every version: 11 malicious new packages, 0 benign.

## Known limits

- **An established match can't see a compromised repository.** A malicious commit pushed to
  a real repository (a stolen maintainer account, a merged pull request, CI tampering) matches
  cleanly, and its install code would be cleared. That is what watching commits is for
  ([proposal](../proposals/git-path.md), Phase B); until then the clearing rests on the
  measured numbers alone. Facts are as of the fetch (stars now, not at the release), and a
  version Stage 4 clears is never exported to Stage 5.
- **History can't see a maintainer's own commits.** A history match says the change went
  through git, not who wrote it: `gina@0.7.1` is 44 commits by its maintainer. Commit dates
  are the committer's claim, so a forged early date hides `commit-after-release`. The
  previous release's commit is found by tag when it recorded no `gitHead`, and tags can move.
- **Budget.** After a long gap most watched-package updates are not compared (see
  [Comparison budget](#comparison-budget)); flagged versions are, up to 2,000 a run.
- **Volume.** The first live day (`20261027T210847Z-npm`) downloaded 2,142 archives, 31 GB,
  and Stage 4 took ~7.5 hours for 109k versions. Archives can be kept for less time than the
  run (`--keep-repo-days`, decision 0006 addendum).
- **Reach.** The comparison needs a GitHub repository and a commit. Most malicious updates
  record no `gitHead` and have no tag for the malicious version, so they get "no commit or tag
  for this version" (which `githead-dropped` already scores). It works best for the case it was
  designed for: a release whose `gitHead` or tag points at the clean commit while the tarball
  carries extra code.
- **Tags can move**, and anyone with push access can tag a malicious commit. The comparison
  records whether it used `gitHead` or a tag.
- **Monorepos over 128 MB** (compressed) and commits never pushed (HTTP 404, 15% of benign
  `gitHead`s sampled) can't be compared.
- **Non-JS payloads** (shell scripts, binaries) aren't compared; `package.json` is compared for
  install hooks and dependency names only.
- **Dependency reputation** rests on two incidents (`easy-day-js`, `plain-crypto-js`): its
  measured recall is redundancy for samples already caught, not new coverage (see
  Evaluation). A dependency npm has taken down keeps its version times but loses its
  maintainers, so in evaluation (DataDog's dependencies are all gone) a taken-down dependency
  without top-level maintainers is "not evaluated", never "foreign". The 7-day threshold is
  the proposal's; 1, 2 and 30 days have not been swept on `vm-day1` yet. Stage 0's run
  snapshot already holds the packuments of dependencies published in the window (~45% of the
  names); Stage 4 fetches them again rather than reading Stage 0's snapshot, which keeps
  `correlate-snapshot.json` self-contained.
- **Dependency reputation, evasions and timing gaps** (from the 2026-10-29 review):
  - **A shared account clears the rule.** Any account in common between the dependency and
    the dependent suppresses `fresh-foreign`. An attacker holding the victim's npm token can
    publish the payload dependency from the victim's account (or list the victim among the
    dependency's version-level `maintainers`, a field the publisher writes), and it is never
    "foreign". Narrowing the check to the dependency's publishers (`_npmUser`) would close
    the second route (npm's 2022 "package planting" fix means `npm owner add` now needs the
    added user's consent), but its benign cost is unmeasured.
  - **A dependency first published after `as_of`** (the attacker publishes the dependent
    first, then the payload) gives no finding, isn't counted, and the dependent is never
    re-evaluated on a later tick.
  - **A dependency that is 404 when Stage 4 runs** (published and taken down, or published
    later) gives no finding.
  - **A dependency published after its dependent but before `as_of`** is evaluated; the
    finding says "first published N hours after this release".
  - **Padding.** A release with more than 40 new foreign dependencies is checked on the first
    40 by `package.json` key that no earlier release claimed; the payload placed after 40 junk
    names gets "not evaluated" (one INFO), not MEDIUM. 25 such releases exhaust a day's cap.
    Both are visible in `dependency_lookups` (`releases_limited`, `capped`).
  - **Benign cost on live data is not measured by the eval.** The 1,500 benign samples can't
    show a few reports a day. On run `20261029T221803Z-npm` `name-embeds-popular` (v1) fired
    on 27 versions and pushed 1 over `REPORT_SCORE` (`@cube-dev/ui-kit@0.0.0-canary-b6b4af7`
    via `react-types`); the proposal estimated ~3 a day from `fresh-foreign`. With v2's
    account check (packuments fetched 2026-10-29, versions by the run's `as_of`) it fires on
    12 of those 27 (quiet: same-author helpers such as `hanger-editor`, `overtone-format`,
    `mutate-react`); the one tipped over `REPORT_SCORE` still is (`react-types` is not
    published by `@cube-dev/ui-kit`'s accounts).
- **Network failures** of repository and dependency requests are retried within the run only
  (see above). A version still failing after the retry passes stays uncompared (or not
  evaluated) and is counted; it is not redone on a later tick. (A release tarball that failed on the network is: Stage 2's
  catch-up redoes the whole run.)
