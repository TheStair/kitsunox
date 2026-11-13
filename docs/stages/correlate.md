# Stage 4: Correlation, repository comparison and score

> **Status:** implemented 2026-10-28 (`stages/correlate.py`, `stages/repo.py`,
> `githost/github.py`; npm wiring in `stages/review.py`). It runs in `collect` after Stage 3.
> Design: [decision 0010](../decisions/0010-stage4-correlation-and-repo-comparison.md).
> Dependency reputation (`npm.dependency.fresh-foreign`, `npm.dependency.name-embeds-popular`)
> added 2026-10-29 from [the proposal](../proposals/dependency-reputation.md); `STAGE_VERSION` 4.
> After review the same day: dependency lookups are retried like repository lookups, capped per
> release as well as per run, and shown in reports; `STAGE_VERSION` 5. A dependency the
> registry doesn't have (404) is a finding since 2026-11-08 (`npm.dependency.missing`,
> [Missing dependencies](#missing-dependencies-npmdependencymissing-stage-version-12));
> `STAGE_VERSION` 12. An earlier stage's explanation finding makes the finding it explains LOW
> since the same day (`EXPLAINED`, [Decision and score](#decision-and-score)); `STAGE_VERSION` 13.
> Stage 3's explained-install shapes (`npm.install-explained`, S1-S3) explain the three install
> rules since the same day; `STAGE_VERSION` 14. A follow-on release that keeps a reported
> release's payload unchanged is reported as such since 2026-11-11 (`correlate.follow-on`,
> [Follow-on releases](#follow-on-releases-correlatefollow-on-stage-version-18));
> `STAGE_VERSION` 18. The install code of a git dependency a version adds is read with the
> install rules since 2026-11-12 (`npm.git-dependency`,
> [Git dependencies](#git-dependencies-npmgit-dependency-stage-version-22)); `STAGE_VERSION` 22.

## Purpose

Stages 1-3 each judge a version on their own evidence. Stage 4 puts the evidence together and
decides what a person should review:

- **Combines** weak signals that mean little alone (a dormant package revived; a dependency
  added) into named combination findings.
- **Looks up** outside knowledge: does the release depend on a package OSV calls malware, or on
  one registered days ago by accounts unrelated to it, or on one that doesn't exist yet? (A
  dependency-chain attack leaves the dependent's own tarball clean, so Stages 2 and 3 see
  nothing.)
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
- **Follow-on pass:** the files of a reported release and of its follow-ons, through the
  same fetcher (see [Follow-on releases](#follow-on-releases-correlatefollow-on-stage-version-18));
  almost always already in the blob store. Also reads earlier runs' `follow-on.jsonl` and
  writes the run's own, with `follow-on-history.jsonl` (the earlier entries it used).
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
it, and `npm.dependency.missing` whether it exists at all. `NpmDependencyLookup` (`stages/review.py`, a `DependencyLookup`) gets it from the
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
  `MISSING`: `fresh-foreign` gives nothing for it, and since `STAGE_VERSION` 12
  `npm.dependency.missing` reports it (below). (Before `STAGE_VERSION` 5 a malformed document
  was `MISSING`, so a captive portal page silently cleared the dependency.) A 404 is recorded in
  `correlate-snapshot.json` like any response, so a replay answers `MISSING` again.
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
- **Prereleases (`fresh-foreign` v3, 2026-11-09, [round 3](../proposals/precision-round3.md)
  X7):** on a prerelease the finding is LOW, weight 1, with a note, as
  `npm.publish-method.downgrade` v3 decided for the same reason: npm installs a prerelease only
  when asked for it by version or tag. Live, real code on all 3,716 verdicted versions (the
  rule rerun on registry records rebuilt from each finding's evidence, which reproduces all 34
  recorded findings on the old code): 13 fewer reports, all benign (`@sparkelf/dsh-*`
  alphas on DeepSeek's new `@deepseek-ai/dsh-*` packages, `@doubao-dev/*` canaries,
  `@paean-ai/harness-profile` rc, `@hatk/hatk` alpha, ...); `tailwind-animora@2.0.1`
  (unverified) is a release and stays reported. `vm-day1`: none of the 131 malicious samples
  it fires on is a prerelease. The rule can't see dist-tags, so a dependency-chain attack
  published as a prerelease and tagged `latest` needs its other signals.
- **Established scopes (`fresh-foreign` v4, 2026-11-10, [round 4 C](../proposals/precision-round4-C.md)
  F1):** LOW, weight 1, with a note, when the fresh dependency is in an npm scope that also
  holds a package on the run's watchlist (`@earendil-works/pi-schema` beside a watched
  `@earendil-works/*`, `@deepseek-ai/dsh-fs-patch`, `@midnightntwrk/zkir-v3`). Only a scope's
  owner (the user, or the organisation's members) can publish into it, so the new package
  comes from an established, popular publisher, not from an account registered for the
  attack; taking that over takes the popular scope's own account, whose new package is in the
  feed as a new package of its own. Live, real code on all 3,716 verdicted versions: 11 fewer
  reports, all benign; `tailwind-animora@2.0.1` (unverified, `@asapsion` holds nothing
  watched) stays reported. `vm-day1`: every dependency-chain payload the rule fires on is
  unscoped (`easy-day-js`, `plain-crypto-js`, `aethlong`, `elaverse`), so none changes.

## Missing dependencies (`npm.dependency.missing`; stage version 12)

A release that adds a dependency the registry doesn't have (its lookup returned 404) can't be
installed until someone publishes that name, and whoever does decides what runs. A campaign of
Tailwind-plugin wrappers did exactly this from 2026-10-29: an Animate.css plugin ("A
configurable, namespaced Animate.css integration for Tailwind CSS") whose code requires a
scoped postcss-style package published *after* the wrapper, the payload
(`tailwindcss-animate-bridge@2.0.8` → `@utilitycraft/tailwindcss-motion-atelier`,
MAL-2026-18468; `tailwindcss-visual-kit@1.3.7` → `@nexlayerlabs/postcss-keyframe-utils`,
MAL-2026-18407). The wrapper is clean for Stages 2-3, `fresh-foreign` can't age a package that
doesn't exist yet, and until 2026-11-08 a 404 gave no finding, so every such release was missed.

- **What fires:** an added dependency (`foreign_added_dependencies`, the lookup's own
  selection) whose record is `MISSING`. `FAILED` (the network, a malformed record) is never
  missing (decision 0009) and `CAPPED` was never asked: `fresh-foreign` says both were not
  evaluated. MEDIUM, weight 3, one finding for all of a release's unrelated missing
  dependencies. Not `WEAK_ALONE`, and not tied to a second signal (an install hook, obfuscated
  code): 8 of the 16 campaign releases had no other finding and the rest only LOW ones
  (`npm.dependency.added`), so either would report none of them.
- **Siblings are INFO** (weight 0, `sibling_reason`): a dependency whose specifier is exactly
  the release's version (a release train; a *range* doesn't count: `fast-deep-thinking@1.0.1`,
  a wrapper, asked for `^1.0.1`), whose name extends the release's or the reverse (platform
  builds such as `envdoc-cli-linux-x64`), whose name starts with the same part
  (`monolith-core-*`), or whose scope is kin to a part of the release's name (`@ocean/*` from
  `@amoree-code/ocean`, `@allyhub-next/*` from `allyhub`; parts of 3+ characters, equal or one
  starting the other from 4). Parts that are watched package names never make two names kin
  (`tailwindcss`, `postcss`: the campaign borrows them), so
  `@utilitycraft/tailwindcss-motion-atelier` is not `tailwindcss-animate-bridge`'s sibling.
- **JSR packages are INFO** (v2, 2026-11-11, [round 6 S](../proposals/precision-round6-S.md)
  S6): an alias into `@jsr/` (`"@sevenc-nanashi/utaformatix-ts":
  "npm:@jsr/sevenc-nanashi__utaformatix-ts@^0.4.0"`) is JSR's npm-compatibility scope, served
  by `npm.jsr.io` to projects that map the scope there; the npm registry answers 404 for it by
  design. Live: `ichikara@0.1.0` and `@audiflo/ichikara@0.1.0` (both benign, reported only
  through this rule) are no longer reported. No `vm-day1` sample depends on a `@jsr/` name.
- **Measured** (read-only, every recorded run of 2026-10-28 22:18Z to 11-08 15:32Z, 10.7 days,
  from each run's `correlate-snapshot.json` 404s and `correlate.jsonl`): 121 releases added a
  dependency that was 404 (~11 a day; 234 distinct names were 404), 86 of them only siblings
  (INFO).
  The other **35** get the MEDIUM finding: **16 are the campaign** (all 16 recorded wrappers
  that declared their payload; 5 carry their own OSV `MAL-` record; verdicts: 1 malicious,
  3 unverified, the rest unreviewed), and 19 are not: 4 were reported already (benign
  verdicts: `@nutui/nutui-react-taro` → `@jmfe/npm-usage-stats-tool`, `gihanga`, two
  `@mchp-mcc/*` → `@microchip/*`), 15 are new reports (~1.4 a day, against ~290 reports a
  day), all unreviewed and apparently benign: private registries' packages
  (`@fortawesome/pro-*`; `@virtualkey/*`, `@skillspec/*` look private too), monorepos not
  published yet (`@capyclaw/*` → `dsh-*`), a Unity package's NuGet name, and `mm_os` →
  `mm_no_such_module_xyz` (twice). Private packages are dependency-confusion exposures: anyone
  may register the name. Of the 86 INFO releases, none is the campaign.
- **Code vs. manifest:** the wrapper's code requires the missing dependency (checked in the 38
  captured tarballs: `lib/styles/variables.js:5`, `src/motion.js:5`), but so does the code of
  almost every benign sibling and platform launcher, so "required by the code" doesn't separate
  them and isn't used.
- **Bundled dependencies are INFO** (v3, 2026-11-13, round 11 P9,
  [proposal](../proposals/gap-fixes-round11-N2.md)): a dependency the manifest also lists in
  `bundleDependencies` (or `bundledDependencies`, or `true` for all) is installed from the
  tarball, never the registry, so its 404 is expected (`faberloom@0.1.8-alpha.1` with 34
  bundled `@deepseek-ai/dsh-*` modules, `badbot@0.1.0`; both benign, the only such reports).
- **Carried to follow-ons** (`STAGE_VERSION` 26, round 11 P9): a later release that keeps the
  missing dependency isn't looked up again (it isn't "added"), so `tailwind-kinetix` 2.0.9 and
  2.0.10 (MAL-2026-19078; 2.0.8's payload `@unipswap/postcss-animate-units`, its range bumped
  from `^1.0.4` to `^1.0.5`) were missed. `npm.dependency.missing` and `npm.undeclared.missing`
  are now in `FOLLOW_ON_ALONE`; a missing dependency is carried while the follow-on still
  declares the same package, whatever range (`DECLARED_ONLY`, npm's `declared_dependency`), an
  undeclared one while the file that loads it is unchanged. The carried finding says "still
  declared": the follow-on itself was not looked up, and its payload may have been published
  since (which is what the campaign does next). Cost in the
  [Follow-on releases](#follow-on-releases-correlatefollow-on-stage-version-18) table.
- **Not caught (until stage version 15):** wrappers that require the payload without
  declaring it (`tailwind-animate-engine@1.0.6` requires `@unipswap/postcss-animate-units` in
  `src/motion.js`; 4 of the 8 adjudicated wrapper misses): no dependency, no lookup. See the
  next section.

## Undeclared and missing (`npm.undeclared.missing`; stage version 15)

Stage 3's `npm.undeclared-package` (v2, INFO) names the packages that *loading* a release
loads at module load, from its entry points and the files they load, without declaring them
([ast.md](ast.md)). Stage 4 asks the registry about those names with the same lookup as
declared dependencies (`NpmDependencyLookup`, its request, its snapshot and its 404 semantics),
and a 404 is **`npm.undeclared.missing`**, MEDIUM, weight 3, like `npm.dependency.missing`.

- **Which names** (`undeclared_lookups`): the finding's (at most 10 per release), minus names in
  the release's own scope (only its members can publish there), watched names (they exist) and
  names `sibling_reason` relates to the release (a monorepo package published on its own).
  Those are never asked.
- **Plan:** they are planned after every declared dependency of the run, in the same order
  (updates first) and under the same limits (`MAX_LOOKUPS_PER_RELEASE` per package, the run's
  cap), so they never take a declared name's place. `correlate.json`'s `dependency_lookups`
  counts them as `undeclared`.
- **Only a 404 counts** (decision 0009). A lookup that failed or was over the limits gives an
  INFO `NOT_EVALUATED` finding naming the packages. The 404 is the run's recorded answer, so a
  replay reads the same.
- **Measured** on the eight unpruned live runs (29.2 h, 29,470 versions Stage 3 read; registry
  status checked 2026-11-08): v2 names 123 distinct packages in 204 versions; 15 versions load
  a name npm lacks, 14 of them only siblings or own-scope names (`@ranujs/*` -> `@ranu/*`,
  `@gtkx/*`, `chatluna-plugin-*` -> `@chatluna/*`). One would be reported:
  `@ohos-ports/cms-components`, which loads 21 `@smallstack/*` names npm doesn't have (a
  dependency-confusion exposure). **~0.8 extra reports a day**, against the owner's ceiling of
  ~5. About 18 extra lookups in those 29 hours. Recall: `tailwind-animate-engine@1.0.6`
  (`@unipswap/postcss-animate-units` was 404 at Stage 4 on 2026-11-02 08:46Z); the other three
  wrappers of the template (`tailwind-animate-final@1.0.6`, `tailwind-animate-test` 1.0.1 and
  1.0.4) have the same manifest and their tarballs are gone. No reviewed positive loses
  anything: the rule only adds. On `vm-day1` (a per-sample dump of Stage 3's v2 names with the
registry's answer on 2026-11-08; `pipeline+4` itself doesn't fit the 4 GB cap): no benign sample
has a name npm lacks; 2 malicious ones would get the finding after the exemptions
(`react-tmedia@2.1.4` and `tailwind-state@1.0.3`, whose code loads the undeclared
`bingo-logger-abstract-transport`), both reported already: recall unchanged.

## Follow-on releases (`correlate.follow-on`; stage version 18)

Stages 1-3 judge what a release *changes*. A release that keeps a reported release's payload
byte for byte therefore shows nothing: Stage 2 reads only contents the base doesn't have
(and, in a batch, attributes a content to the first version holding it), and Stage 3 counts
only capabilities new to the install code. `pdf-html5-page-flip@2.0.2` (malicious) was
published 15 minutes after 2.0.1 with the same credential stealer in
`dist/lib/fonts/fa-solid-400.woff2`; 2.0.1 was reported at score 6, 2.0.2 scored 3. Stage 2's
`ALWAYS_NEW` (known signatures, WhatsApp channel follow and tagging) never reaches an
unchanged file either, so a Baileys fork's second release went unreported. Decision 0007 kept
such *follow-on* releases in their own `vm-day1` cells for this reason; this pass is the
pipeline's answer ([round 6 U](../proposals/precision-round6-U.md), decision 0007 addendum).
Built in four commits, A (zero-cost) and B1, B2, C (trade-offs for the owner); this section
describes all four.

**The pass.** `correlate_run(follow_on=..., history=...)` correlates every version as
before, then runs a second pass over the versions whose previous release is in the same run
or in `history` (earlier runs' reported releases, part C):

1. While correlating, it notes each version's place and previous release, and each reported
   release's **payload evidence** (`reported_release`, `payload_evidence`, below).
2. A version whose previous release is in the run waits until that release is settled (not
   itself waiting); one whose previous release is an earlier run's is ready at once. If that
   release was reported with payload evidence and the version was published at most
   `FOLLOW_ON_WINDOW` (7 days) after it, it is checked (`ReleaseFollowOn`): a file is still
   there when the version has the same bytes at the same path, a manifest field when it has
   the same value (`stages/review.manifest_field` reads npm's `package.json:scripts.<hook>`
   and `package.json:dependencies.<name>` paths).
3. A version that still holds some of it is correlated again with what it holds
   (`ctx.follow_on`). `correlate.follow-on` (MEDIUM, weight 3) names the earlier release
   (and its run, when not this one), the hours between them and that release's decision, and
   lists each file or field. Its carried evidence becomes its own payload evidence, so a
   chain of follow-ons (2.0.1 → 2.0.2 → 2.0.3) carries it on. A version already reported gets
   the finding too, as context.
4. Those lines of `correlate.jsonl` are replaced (streamed through a synced temp file);
   `correlate.json` counts the pass under `follow_on`: `in_run` and `earlier_runs` (versions
   whose previous release is in the run, or only in an earlier run's index), `checked`,
   `carried`, `reported`, `newly_reported`, `not_evaluated`, `retry_passes`, and `errors` by
   version.
5. The run writes its own reported releases with payload evidence to `follow-on.jsonl`
   (`FOLLOW_ON_INDEX`), and the earlier runs' entries its pass used to
   `follow-on-history.jsonl` (`FOLLOW_ON_HISTORY`). `review.follow_on_history` gives the next
   runs the indices of the runs of the same ecosystem whose `as_of` is within the window before
   theirs (a later run's entry for the same release wins); a seeded re-score reads the run's
   own `follow-on-history.jsonl` instead, so it doesn't depend on what earlier runs hold now
   (re-scored or pruned since).

Every pass takes the ready versions in run order and the checks are pure functions of the two
releases, so the output doesn't depend on thread scheduling (tested with 1 and 4 workers and a
chain written backwards; the run order is the change feed's, not publish order). Release
files come through the run's fetcher under Stage 2's size limits, so they are recorded in
`correlate-snapshot.json` and a re-score reads the same bytes; most are already in the blob
store (a reported release always is: Stage 2 read it, and retention holds reported tarballs
30 days). A check that fails on the network is retried like the other lookups; one whose files
still can't be read gives an INFO `Not evaluated:` finding (counted as `not_evaluated`), never
a silent skip. Nothing here reads the clock or a verdict.

**What is carried** is narrow on purpose (`payload_evidence`):

| Part | Carried (MEDIUM-or-above evidence of the reported release) | Same-run live, newly reported |
|---|---|---|
| A | `static.known-signature`, `static.channel-follow`, `static.channel-tagging` (`FOLLOW_ON_ALONE`; the owner wants them on every release, Stage 2's `ALWAYS_NEW`) | +10 unwanted, 0 benign |
| B1 | a `static.hardcoded-ip` or `static.exfil-endpoint` file (`FOLLOW_ON_DESTINATION`) that a LOW-or-above `static.sensitive-path` / `static.env-harvest` or install-code finding (`npm.install-script-code`, `-loader`, `-exfil`, `npm.install-persistence`; `FOLLOW_ON_COMPANION`) of the same release also names | +3 malicious (`pdf-html5-page-flip@2.0.2`, `template-cards@16.1.2`, `template-pictogram@9.1.3`), +2 benign (`chuxin-agentdesk@0.1.1`, `@prismatic-io/components-bigcommerce@0.1.0`) |
| B2 | `npm.install-persistence` (owner rulings, decision 0015), in `FOLLOW_ON_ALONE` | +22 unwanted, +4 benign (`agy-statusblocks@0.1.1`, `repilot@0.3.1`, `basinfy@1.3.14`, `@c0dingbear/termius-mcp@0.6.2`), +1 unverified (`wkappbot-code@0.3.8`) |
| T | `static.disguised-file` (round 6 T, MEDIUM or HIGH: a script or executable under a font, image or media name), in `FOLLOW_ON_ALONE`, `STAGE_VERSION` 19: a follow-on too small for Stage 2's routing still reports | 0 benign (its only severe findings on 230,290 tarballs are `pdf-html5-page-flip` 2.0.1/2.0.2) |
| P3 | `static.shell-startup` (round 11, `STAGE_VERSION` 25, [proposal](../proposals/gap-fixes-round11-N2.md)): its MEDIUM forms, in practice `inject` (a `hook` match is in `package.json`, which changes with every version); Stage 2 keeps `inject` on changed files too (`ALWAYS_NEW_FORMS`) | +2 positives (`@atedone/workspace-context` 0.0.22 unwanted, 0.0.23 malicious); live cost in the proposal |
| P9 | `npm.dependency.missing` (carried while the same package is still declared, `DECLARED_ONLY`) and `npm.undeclared.missing` (round 11, `STAGE_VERSION` 26, same proposal) | +2 malicious-labelled (`tailwind-kinetix` 2.0.9, 2.0.10), +1 unverified campaign wrapper (`tailwindcss-animationkit@1.0.7`); live runs on disk (11-08 to 11-13): +5 versions whose reported release was verdicted benign (`@turnit-ou/webshop-search-widget@1.1.2`, `@ilkal/sdk@0.1.2`, `@rapidoc/docusaurus@0.1.0`, `service-tunnels@0.3.78`, `create-duots-neo@1.1.0`), about 1.1 a day |
| C | the same, from earlier runs within 7 days | over A-B2: +27 unwanted, +1 benign (`memtrace@1.2.14`), +1 unverified; over A alone: +5 unwanted |

A destination alone is not carried: benign CLIs with a bundled ngrok table or a default server
IP release every few hours. Rules about a *change* (`npm.install-script-changed`,
`code.capability-gained`, a new maintainer or publisher, a revived package) are never carried:
an unchanged follow-on doesn't have their evidence. Neither are Stage 1's install hook and
non-registry dependency, nor obfuscation and other content rules. On the same follow-ons,
same run: every severe content finding would add 65 positives and 64 benign versions; with
install hooks and non-registry dependencies 80 and 171; parts A-B2 plus an added (HIGH)
install hook 45 and 65.

**Measured** (2026-11-11, real code, verdicts of that day): the 812 follow-ons of the live
runs whose previous release was reported (recorded, or by the main replay) and that the main
replay doesn't report, each pair replayed through Stages 1-4 with this code
(`~/kitsunox-scratch/r6/U/scripts/u_follow.py`). Most follow-ons were never reported, so never
reviewed: their truth is the earlier release's verdict ("inherited": the carried evidence is
identical, byte for byte), except where they have their own (`pdf-html5-page-flip@2.0.2`
malicious, `aum-framework@1.8.2` unwanted, `chuxin-agentdesk@0.1.1` benign). On the 3,716
verdicted versions of the replay set, parts A-B2 change two decisions: `aum-framework@1.8.2`
(unwanted) and `chuxin-agentdesk@0.1.1` (benign) become reported; no positive is lost (the pass
only adds findings). The real `correlate_run` over every live run's recorded Stage 1-3 output
(149 runs, older rules for older runs; part C off) changes 20 lines, 16 newly reported; on
`20261110T205323Z-npm` (5,016 versions) the pass took 0.85 s. `vm-day1` (`pipeline+4` per sample plus the pass, on the 82 malicious follow-ons
whose previous version is a sample and that round 3 didn't report): A +0, B1 +12
(`@operato/*`, `@things-factory/email-base`: the same install-time `bundle.js`, 6-27 minutes
later), B2 +0, none lost.

## Git dependencies (`npm.git-dependency`; stage version 22)

A dependency installed from a git repository runs its install code when the release is
installed, and none of it is in the release's tarball. `web3-mev-error-decoder@0.1.0`
(2026-11-09, malicious) shipped a clean tarball and depended on
`github:outgoingyang/multicall-error-decoder`, whose `install` hook decrypted its strings and
downloaded and started a payload; only `npm.dependency.non-registry` fired. Since
`STAGE_VERSION` 22 Stage 4 reads such a dependency's install code
([decision 0020](../decisions/0020-git-dependency-install-code.md); measured in
[round 10 G](../proposals/git-dependencies-round10-G.md)):

- **Which dependencies** (`stages/gitdeps.wanted`): runtime dependencies (`dependencies`,
  `optionalDependencies`) the version adds or changes, from outside the registry; not local
  paths, protocols npm can't fetch or registry tarball URLs. Of those, the ones whose spec
  names a GitHub repository are read (`ecosystems/npm/gitdep.github_spec`: `github:o/r`, `o/r`,
  `git+https://`, `git+ssh://`, `git://`, `git@github.com:o/r`, `https://github.com/o/r`, and
  archive URLs); credentials in a spec are never sent, and shown as `***@`. Since
  `STAGE_VERSION` 23 (owner, 2026-11-12) every GitHub dependency of the version is read,
  unchanged ones included: a branch or default-branch spec installs whatever the branch holds
  today, so the same spec can install new code. An unchanged spec is read as new (what the
  previous release installed is not known); other unchanged non-registry specs get no note.
- **Resolve, fetch, extract.** The reference (`#<commit>`, `#<tag or branch>`,
  `#semver:<range>`, none for the default branch; `::path:<dir>`) is looked up in the
  repository's refs (`HEAD` included), then the archive at that commit is fetched through the
  run's fetcher (recorded in `correlate-snapshot.json`, immutable index, pruned with
  `--keep-repo-days`) and extracted with `extract_archive` under `DEPENDENCY_LIMITS` (64 MB
  compressed, 512 MB, 100,000 files) in the comparison pool. Only what npm runs is kept.
- **What npm runs** (`npm_runs`): for a git dependency `preinstall`, `install`, `postinstall`
  and `prepublish`, `preprepare`, `prepare`, `postprepare` (the root lifecycle of the
  `npm install` npm runs in the clone; pacote runs only `prepare` around the pack); for a
  GitHub archive URL, a remote tarball to npm, the install hooks only. The rules read three
  install slots, so a git-only hook takes a free one (with none free, it joins the last with
  `&&`), and `npm run <script>` is expanded to the script npm runs (with its `pre`/`post`
  scripts, three levels).
- **Analysis** (`stages/gitdeps.analyse`): Stage 1's `npm.install-hook`, Stage 2's file rules
  on those files, and Stage 3's code rules, the dependency taken as a new package; for a
  commit bump in the same repository (the previous release pinned a full commit id), as an
  update of that commit, so unchanged install code is not new. The explanations (`EXPLAINED`:
  build tool, explained shapes, inert hooks, ...) are applied within the dependency.
- **The rule** `npm.git-dependency` (v1) shows those findings with their own rule ids,
  severities and weights (they score like the release's own install findings), the dependency
  named in the explanation and the evidence under `dep:<name>@<commit12>/<path>`; a hook the
  rules read in a slot is shown under its own name (`scripts.prepare`). An INFO summary gives
  the repository, commit, how the reference resolved, the scripts npm runs and what the
  install code uses (`[network]`, `[process]`, `[filesystem]`, `[decrypt]` lines). An INFO note
  lists the dependency's own non-registry dependencies (not followed).
- **Build-only dependencies** (`npm.git-dependency.build-only`, INFO; `STAGE_VERSION` 24,
  owner 2026-11-12): when every command npm runs for the dependency is a build tool
  `npm.install-build-tool` accepts (`BUILD_TOOL_HOOKS`, whole `&&` parts) or, in a slot that
  holds only git-only hooks (`prepare` and friends), `tsc`, `publint`, `rimraf` or `rm -rf`
  with plain relative arguments (`COMPILE_ONLY`), and `binding.gyp` runs nothing, the
  dependency's `npm.install-hook` is explained (LOW, weight 1), as the package's own hooks
  are by `npm.install-build-tool`. Not `webpack`, `rollup`, `vite`, `babel`: their
  configuration is JavaScript they run. Not a tool the dependency's own `bin` names, nor
  `tsc` when the dependency takes `typescript` from outside the registry.
- **Subjects.** An explanation applies only within its subject (`dependency_subject`: the
  package, or one dependency): the package's `npm.install-build-tool` doesn't explain a
  dependency's `npm.install-hook`, nor the other way round. A dependency's severe finding is
  never cleared by the package's repository match (`CLEAR_ESTABLISHED`, `CLEAR_HISTORY`), and
  `dep:` evidence is never carried by a follow-on.
- **Not read** (INFO `Not evaluated:`; `npm.dependency.non-registry` alone speaks for it, as
  before): a deleted or private repository, a reference not in its refs, an archive that is
  404 or over the limits, a dependency over the caps, another git host, a GitHub release asset
  or raw file, a tarball URL on another host. Tarballs on other hosts are not fetched: the
  host is often the attacker's, a request tells them the package is being analysed and lets
  them answer differently, and requests to arbitrary hosts are what an SSRF needs.
- **Caps** (planned in run order before any request): `MAX_GIT_DEPENDENCIES` 200 distinct
  specs a run, `MAX_PER_PACKAGE` 10 for all versions of one package. A network failure is
  retried in the same passes as the repository lookups and stays visible (`transient`).
- **`correlate.json`** `git_dependencies`: the caps, the inner rules' fingerprint (`rules`),
  `wanted`, `capped`, `read`, `unavailable`, `with_findings`, `planned`, the retry counts and
  `still_failing`, and why each unread dependency was not read (`errors`).

Measured on the live runs on disk (190 runs, 2026-10-29..11-12): 273 versions add or change a
non-registry dependency (335 dependencies). Of the 167 GitHub repository specs, 162 were read
(115 commits of 70 repositories, 191 MB of archives), 30 with findings; 1 repository was
deleted, 2 abbreviated commits were in no ref, 1 archive was 404. 110 were tarballs on other
hosts, 56 GitHub release assets or raw files, 3 other git hosts. With today's Stage 1, 4 benign
versions are newly reported (`@aimuzov/kaiten-mcp`, `@aimuzov/thinks-mcp`, `@biongff/vizarr`:
a dependency's `prepare: ... tsc ...`; `@eqtylab/vcomp-verify-js`: `prepublish: webpack`), no
positive is lost or gained, and 20 versions reported already gained a severe dependency
finding (10 positives, 10 benign). The replay set (3,716 verdicted) changes the same 4
versions and nothing else; `vm-day1` changes nothing (its waves' fork commits are gone from
GitHub).

With unchanged specs read too (`STAGE_VERSION` 23), the live runs on disk give 1,538 versions
with a GitHub or added non-registry dependency (2,001 dependencies) and 108 more versions
reported, all unverdicted (26 packages: `@filen/sdk-rs` 16, `@xrpl-utilities/mcp` 15,
`@kubohiroya/turbowarp-kamishibai-app` 15, `handoff-app-next` 11, ...: `prepare` builds of
the same dependency in every release), besides the 4 benign above; no positive lost or
gained. `vm-day1`: +2 malicious (`trex-proxy-browser-extension-sdk` 0.1.1 and 0.1.11: their
unchanged `reclaimprotocol/tls#8e0669a2…` dependency's `prepare` downloads,
`npm.install-download`), none lost. Caps: the 4-day catch-up run `20261107T163310Z-npm` wanted
160 specs (151 commits read, 442 MB of archives); no run reached either cap.
With the build-only explanation (`STAGE_VERSION` 24), the live runs on disk give 1 benign
version newly reported (`@eqtylab/vcomp-verify-js@0.0.8`: `prepublish: webpack`) and 71
unverdicted (19 packages; bundlers with JavaScript configuration, the dependency's own
scripts, unexpanded `yarn build`), instead of 4 and 108; no positive lost or gained;
`vm-day1` 116 of 143 malicious (`reclaimprotocol/tls`'s `npm exec tsc` is not explained). The
replay set (3,716 verdicted) reports 1 more benign version, the same `@eqtylab/vcomp-verify-js`,
and changes no positive.
`web3-mev-error-decoder@0.1.0` is reported by its dependency's `npm.install-hook` and
`npm.install-script-code`. Details: the proposal.

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
  MEDIUM rules (-438, loses 169 `vm-day1` samples and 11 of 27 live malicious). Instead,
  `revived-with-new-dependency` v2 (2026-11-08) is LOW when the same account comes back with no
  maintainer added: 74 of the 140 live versions it alone reported (Oct 28 - Nov 3, all benign)
  had that shape, and no `vm-day1` takeover does (`xrpl@2.14.2` was published by another
  account), so none is lost ([proposal](../proposals/stage1-precision.md)). A dormant account
  hijacked as itself now needs its other signals. v3 (2026-11-08, [round 2](../proposals/precision-round2.md),
  F7) is LOW when the release carries a provenance attestation too: a takeover that publishes
  with provenance needs the repository's CI as well as the npm account, and the rule has no
  positive live at all; the takeovers it catches on `vm-day1` (`xrpl@2.14.2`, `@mastra/*`)
  have none. Provenance explains nothing else: as an explanation for install code it would
  lose 37 `vm-day1` samples published from compromised CI. Live, with the implemented rule:
  65 fewer reports among the proposal's 3,032 reported versions (65 packages; 69 of all 3,211
  with a verdict), all benign; the rule's one `vm-day1` malicious sample at risk is still
  reported. **Rejected by the owner (2026-11-10):** a v4 that is LOW when no maintainer was
  added and every added dependency is on the run's watchlist ([round 4 C](../proposals/precision-round4-C.md)
  R1). It removed 9 benign live reports and no positive, but on `vm-day1` it lowers the rule
  on the real `vant` takeover (`vant@2.13.3`, `3.6.13`: the maintainer's own account, no
  maintainer added, only popular dependencies added; still reported through a HIGH
  `npm.install-hook`), so a takeover shipping its payload in its own code would lose the
  revived MEDIUM. The rule stayed at v3. v4 (2026-11-10, [round 6 N](../proposals/precision-round6-N.md)
  C1) is LOW for a release published through trusted publishing too, which npm can record
  without an attestation (`productenv@2.0.0`, `@musedesignsystem/tokens@2.12.2`, `GitHub
  Actions` publishing with `trusted_publisher` github): 2 benign reports fewer, no positive, no
  `vm-day1` sample touched. v5 (round 6 N C2) drops v2's "no maintainer added": the account
  that published the previous release publishing this one is LOW whatever joined the list in
  the year or more since (`@rbbn/distant-*` x3, `@coorpacademy/update-node`,
  `@terrahq/design-system`, `@iqb/eslint-config`, `@biodiv-platform/naksha-gmaps-draw`,
  `docx-populator`, `pockethost`: 9 benign reports fewer, no positive). A newly added
  maintainer who publishes (the `event-stream` handover), or a listed maintainer who did not
  publish the previous release (`xrpl@2.14.2`, `vant@2.13.3`), keeps MEDIUM. On `vm-day1`
  it lowers the rule on one sample, `@antv/data-set@0.12.8` (`atool` again, 40 maintainers
  joined), which stays reported through its install hook and five other rules; the recall
  risk is v2's (an account hijacked as itself). v6 (2026-11-11, [round 7 W](../proposals/precision-round7-W.md)
  W1, W2) is LOW in two more shapes read from the manifests. **A new major version** (the
  major grows and is at least 1: `3.6.1` -> `4.0.0`, `0.5.2` -> `1.0.0`): a takeover wants
  its payload to reach the projects that already depend on the package, and npm resolves
  their `^`/`~` ranges inside the major they name, so a new major reaches none of them. All
  36 `vm-day1` samples the rule fires on stay inside their major (`vant@2.13.3`,
  `xrpl@2.14.2`, `@mastra/*`, the `@antv/*` `1.6.13` -> `1.7.13` bumps); 0.x minor bumps are
  not counted, because `@antv/g2-extension-3d@0.3.0` (after `0.2.0`) is a takeover. **Every
  added dependency was a dev or peer dependency of the previous release**: the project
  already used those packages and now ships them (`imghash-cli@0.0.2`,
  `@saasquatch/vanilla-components@1.4.2`); `@mastra/speech-*` move `@mastra/core` from dev
  but add `easy-day-js` too, so keep MEDIUM. Live, real code: 12 benign reports fewer
  (`@capacitor/assets@4.0.0`, `@livepreso/webpack-deck@4.0.0`, `amphora-html@7.0.0`,
  `@squareboat/nest-storage@1.0.0`, ...), no positive changes; on `vm-day1` the rule's
  finding changes on none of its 36 samples, `vant` included. **Recall risk:** a takeover
  that publishes a new major reaches only new installs and projects that follow `latest`;
  it now needs its other signals. Measured before choosing it: "HIGH or score 6" for every rule would have
  lost 202 malicious samples (`npm.install-script-code` alone catches 85, new packages'
  install hooks 29, `npm.dependency.non-registry` 12), so the other MEDIUM rules still report
  alone.
- **Explanations** (stage version 13, 2026-11-08): an earlier stage's INFO finding can
  explain another rule's finding (`EXPLAINED`, applied by `explained` after the rules run and
  before the decision). The explained rule's MEDIUM and HIGH findings become LOW, weight at
  most 1, with a note, so the report still shows them and the score still counts them. The
  one explanation so far is Stage 3's `npm.install-build-tool` (every install hook only runs
  a build tool, and `binding.gyp` runs no command) for `npm.install-hook`
  ([ast.md](ast.md#rules), [round 2](../proposals/precision-round2.md) F2). The install
  code's own findings are never explained this way. Live, on the proposal's 3,032 reported
  versions: 7 fewer reports where the tarball was captured (12 if the 5 without one have no
  `binding.gyp`), all benign; `vm-day1`: nothing lost (none of the 433 samples reported only
  through install rules has build-tool-only hooks).
- **Explained install** (stage version 14, 2026-11-08): Stage 3's `npm.install-explained`
  (the install code is a platform-binary launcher, an own-release download with a checksum,
  or an agent-skill copier whose copied configuration passes the owner's three guards; S1-S3,
  [ast.md](ast.md#explained-install-s1-s3-and-agent-configuration)) explains
  `npm.install-hook`, `npm.install-script-changed` and `npm.install-script-code`. `EXPLAINED`
  maps a rule to its explanations in order (`npm.install-build-tool`'s note comes first for
  `npm.install-hook`). Never explained: the install code's obfuscation
  (`npm.install-script-obfuscated`), content findings (`static.*`, `known-signature`),
  `code.capability-gained`, and Stage 3's `agent.hostile-instructions`, which reports on its
  own. Live, on the 3,244 reported verdicts
  (2,107 reported with today's code; the signal computed on the 738 captured tarballs of the
  1,442 versions with an install finding): 2,107 → 2,022 (-85: S1 36, S2 34, S3 15; 70
  packages), all benign, 0 malicious, unwanted or unverified lost; precision 4.23% → 4.41%.
  `vm-day1`: none of the 433 malicious samples reported only through the install rules is
  explained.
- **Inert install hooks** (stage version 16, 2026-11-10): Stage 3's `npm.install-inert`
  (a new package whose install hooks only run package code Stage 3 read in full that reaches
  nothing outside the package, or only echo a message that isn't a probe's; S5's guards;
  [ast.md](ast.md#inert-install-hooks-npminstall-inert-round-4)) explains `npm.install-hook`
  only ([round 4, agent B](../proposals/precision-round4-B.md)).
- **Hooks that run a file the package doesn't ship** (stage version 17, 2026-11-11): Stage 2's
  `npm.artifact.install-target-missing` (every install hook is `node <file>` and the whole
  tarball, checked against its declared size, has no such file;
  [static.md](static.md#metadata-vs-tarball-npm-ecosystemsnpmrulesartifactpy)) explains
  `npm.install-hook` only ([round 6, agent Q](../proposals/precision-round6-Q.md), Q1).
- **Obfuscation alone in a new package** (stage version 20, 2026-11-12): Stage 4's
  `npm.obfuscation-only` (INFO, weight 0; `ecosystems/npm/rules/obfuscation_only.py`, run after
  every other correlation rule) explains `static.obfuscated` only, for a new package (no
  previous release) whose only finding above INFO is `static.obfuscated` MEDIUM (any LOW, any
  other MEDIUM keeps it as it was), when no obfuscated file is an HTML page and the manifest
  names none (`main`, `files`, `browser`, `unpkg`, `jsdelivr`, `module`, `exports`, `bin`), the
  manifest declares no script npm runs at some install (`preinstall`, `install`,
  `postinstall`, `prepare` and its pre/post, `prepublish`), and it names a `repository` or a
  `homepage`. The publisher's own javascript-obfuscator build of a library or CLI
  (`@univerjs-pro/*`, `@numbors/cli`, `@oddsockets/*`, `xgis-cog-*`) is then score 1, not
  reported. An update is never explained: an obfuscated file new in an established package is
  how `vm-day1`'s `@duckdb/node-api@1.3.3`, `web3rpcs`, `webpikes`, `akasearch`,
  `dreame-claude` and `dzcvhfruwluwe` are caught, by this finding alone. The other clauses
  keep `vm-day1`'s new ones: `mobiwaefhxc3` (an obfuscated `index.html`), `mad-1.2.6.2.2.8`
  (no repository or homepage; its `index.html` is not in the registry's manifest, which
  strips `files`), `multi-cloud-data-migrator@1.256.25` (`prepare`, no repository).
  Replay set: -15 benign, 0 positives, 0 unverified
  ([round 8 P](../proposals/precision-round8-P.md), P1, with `vm-day1` and the options that
  remove more).
- **Dependency-confusion placeholders** (stage version 21, 2026-11-12): Stage 2's
  `npm.artifact.install-stub` (every install hook is `node <file>`, each file only throws a
  constant message, and the whole package ships no other code;
  [static.md](static.md#metadata-vs-tarball-npm-ecosystemsnpmrulesartifactpy)) explains
  `npm.artifact.hidden-install-script`, `npm.install-hook` and `npm.version.suspicious`: what
  a company's placeholder under its internal name looks like, a `999.9.9` that fails
  `npm install` on purpose. Nothing else is explained. Live: the 10 JetBrains stubs of
  2026-11-12 (`kotlinconf*`, `jetbrains-*`, `ides-perf`, `jquery-astabs`; score 8 -> 2), all
  benign; replay set: fires on none of the 825 versions with one of the three findings, no
  decision changes; `vm-day1`: of the 1,382 malicious samples with one of them, 947 run
  `node <file>` hooks and none of those files only throws (even without the whole-package and
  text-only conditions), so the rule fires on none: the 131 confusion probes run code that
  reports back ([round 9 S](../proposals/precision-round9-S.md), S1).
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
| `npm.provenance.githead-dropped` (v2) | the previous release recorded `gitHead`, this one doesn't. Weight 1 when Stage 1's `npm.publish-method.downgrade` fired on the same release: both then say it left the CI path, and given a downgrade a dropped `gitHead` is no commoner among malicious samples (34 of 149 `vm-day1` downgrades, 23%) than among live benign verdicts (81 of 273, 30%) (v2, [round 5 K](../proposals/precision-round5-K.md) G1) | LOW | 2 |
| `npm.dependency.known-malware` (v3) | an added (or re-pointed) runtime dependency, or its `npm:` alias target, is malware in every version per an OSV record published by `as_of`. LOW (weight 1) when the specifier only matches npm's empty `0.0.1-security` holding package (`fs: ^0.0.1-security`, what `npm install fs` writes), or when a Unity (UPM) package (`unity` field) depends on a `com.unity.*` built-in module, which Unity resolves from its own registry while the npm names are malware squats (v3) | HIGH | 5 |
| `npm.combination.revived-with-new-dependency` (v6) | `npm.dormant-revived` and `npm.dependency.added` both fired, on a release (not a prerelease). LOW (weight 1) when the previous release's publisher publishes this one: the package's own maintainer coming back (v2; since v5 also when maintainers were added, none of whom published it); LOW (weight 1) too when the release carries a provenance attestation (v3) or was published through trusted publishing (v4), starts a new major version (v6), or adds only packages the previous release already declared as dev or peer dependencies (v6) | MEDIUM | 2 |
| `npm.dependency.fresh-foreign` (v4) | an added dependency (not the package, its scope or watched) was first published (earliest `time[v]` ≤ `as_of`) less than 7 days before this release, and none of its accounts (maintainers and `_npmUser` of its versions by `as_of`, else its top-level maintainers) is a maintainer or publisher of this release or the previous one. No account data on either side, or a failed lookup: INFO "not evaluated" instead; dependencies over the lookup limits: one INFO for all of them. LOW (weight 1) when this release is a prerelease, which npm installs only when asked for it (v3, [round 3](../proposals/precision-round3.md) X7), and when the dependency's npm scope also holds a package on the run's watchlist (v4, [round 4 C](../proposals/precision-round4-C.md) F1) | MEDIUM | 3 |
| `npm.dependency.missing` | an added dependency (as for `fresh-foreign`) was 404 when the run looked it up, and its name is unrelated to the release's (Missing dependencies, above). INFO, weight 0, when it looks like a sibling: exact specifier equal to the release's version, a name that extends the release's or starts with the same part, or a scope kin to the release's name (watched names never count), and an alias into JSR's `@jsr/` scope (v2) | MEDIUM | 3 |
| `npm.undeclared.missing` | a package Stage 3's `npm.undeclared-package` names (loaded at module load, not declared; not own scope, watched or a sibling) was 404 when the run looked it up (Undeclared and missing, above). INFO, weight 0, when the lookup failed or was over the limits | MEDIUM | 3 |
| `npm.dependency.name-embeds-popular` | an added unscoped dependency (not watched) is, lowercased without `-_.`, a name with ≥ 1M downloads a month on the watchlist (≥ 5 characters) plus a prefix or suffix of 1-8 characters (`easy-day-js` / `dayjs`); not when its record (already looked up) shares an account with this release (`react-dom-utils` from React's maintainers) | LOW | 1 |
| `npm.git-dependency` (v2) | a version adds or changes a dependency from outside the registry: the install rules' findings on a GitHub dependency's install code, each with its own rule id, severity and weight and `dep:<name>@<commit12>/` evidence; an INFO summary (commit, scripts npm runs, what the install code uses); an INFO `Not evaluated:` note when it wasn't read (Git dependencies, above) | INFO (its findings: theirs) | 0 |
| `npm.git-dependency.build-only` | inside a git dependency: every command npm runs for it is an accepted build tool or, in `prepare` and the other git-only hooks, `tsc` / `publint` / removing build output (Git dependencies, above). Explains the dependency's `npm.install-hook` (LOW, weight 1) | INFO | 0 |
| `repo.compared` | a comparison was attempted: what it found, or why there was none | INFO | 0 |
| `repo.established-match` | a clean comparison with a repository that is not a fork or archived, ≥ 30 days old at the release, ≥ 5 stars, the commit on its default branch (Repository trust, above). Clears install-code MEDIUM findings in the decision | INFO | 0 |
| `repo.history-match` | a clean comparison at a commit ahead of the previous release's commit, no `commit-after-release` (Repository history, above). Clears install-code MEDIUM findings in the decision when `CLEAR_HISTORY` is on (off) | INFO | 0 |
| `repo.commit-after-release` | the release's tag points to a commit made more than 6 hours after the release was published | MEDIUM | 3 |
| `npm.repo.no-new-commits` | a stable version, above the previous stable one, built from the previous release's commit or an older one, its code not a clean match there | LOW | 2 |
| `repo.code-differs` | a shipped code file differs from the repository's file at the same path | LOW | 2 |
| `repo.code-not-in-repo` | shipped code files are *unexplained* (above). Since `STAGE_VERSION` 6 a file whose content is elsewhere in the repository, byte for byte, is explained (a build copied it) | LOW | 2 |
| `npm.repo.install-script-not-in-repo` (v2) | the release's install hook isn't in the repository's `package.json` (or has another command). INFO instead when the repository's build writes it (`ManifestDifference.built_by`): every package file the command names is in the repository byte for byte, and another repository file holds the command (the release's version may be a placeholder there). First VM day: `@nutui/nutui-react-taro` (`scripts/build-taro.mjs`) and `@opencode/cli` (`script/pack.ts`); `@pulumi/*` still fire, since Pulumi's code generator, not the repository, writes their hook. With `repository.directory` only that directory is searched. v3: LOW, weight 1, when the previous release shipped the same hook (its version string aside), so a generated hook that is in every release (`@pulumi/*`) stops counting; the release that adds a hook still fires HIGH | HIGH | 5 |
| `npm.repo.dependency-not-in-repo` | a runtime dependency the repository's `package.json` doesn't name in any section | LOW | 1 |
| `npm.obfuscation-only` | a new package whose only finding above INFO is `static.obfuscated` MEDIUM, with no HTML page among the obfuscated files or in the manifest's entry fields, no script npm runs at some install (`prepare` included) and a declared `repository` or `homepage` (Decision and score, above). Explains `static.obfuscated` (LOW, weight 1) | INFO | 0 |
| `correlate.follow-on` | the previous release, published at most 7 days earlier, was reported by this run or (part C) an earlier one with payload evidence (`payload_evidence`) that this release still holds unchanged: the same bytes at the same path, or the same manifest value (Follow-on releases, above). INFO "not evaluated" when the files couldn't be read | MEDIUM | 3 |

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

**Missing dependencies** (2026-11-08, `npm.dependency.missing` v1). On `vm-day1` the rule can
fire only where an added dependency is 404 at evaluation time (found packuments are pinned):
1 of 3,444 DataDog samples (`@financials/using-dep-conf@1.0.0` → `@tag/test1234`, already
reported through its `preinstall`; checked with the real `pipeline+4` predictor on a
hard-linked scratch copy of `data/eval`) and 0 of 1,500 benign (`rsshub@1.0.0-master.*`'s one
unpinned dependency, `narou`, is found). Recall can't drop: the rule only adds findings, and
nothing clears them (`CLEAR_*` are off). The full `pipeline+4` run was not repeated. DataDog can't measure the pattern: of its
1,231 added-dependency edges none has a dependency first published after the dependent (6
within the hour before, which is `fresh-foreign`'s case), and its dependencies are taken down
now. The evidence is live (Missing dependencies, above): 16 of 16 campaign wrappers reported,
for ~1.4 extra benign reports a day.

## Known limits

- **Git dependencies** (decision 0020). Only GitHub repositories and archives are read; other
  git hosts, GitHub release assets (owner, 2026-11-12: not read) and tarballs on other hosts
  are noted, not read. A push to a dependency's branch is seen only when a release that
  depends on it is published. The reference is resolved when Stage 4 runs, not when the release was
  published: a branch moved since, a deleted repository or a garbage-collected fork commit
  reads differently or not at all. The dependency's own dependencies (registry ones, whose
  install hooks also run, and the devDependencies npm installs to run `prepare`) are not read,
  nor its git dependencies (listed only). `npm run` is expanded three levels; `yarn <script>`
  without `run`, `npx` of the dependency's own bins and Makefiles are not. The evaluation
  predictor reads git dependencies as of the evaluation, not as of the sample. Stage 5's
  offline sandbox can't fetch a git dependency, so a release reported only for its
  dependency's install code is not run there. Stage 4 plans the dependencies with one more
  pass over the run's versions (read from disk, like the other plans).
- **Follow-ons.** A follow-on more than 7 days after the reported release is judged on its
  changes alone, as before; so is one whose payload moved to another path or changed by a
  byte, one whose earlier release was reported for evidence the pass doesn't carry (an install
  hook, obfuscation, a non-registry dependency), and (without part C) one in a later run. With
  part C, an earlier run whose Stage 4 hadn't finished when a later run's did (a Stage 2
  retry) is missing from that run's history; the history the run used is recorded, so a
  re-score agrees with it. A release reported only after the fact (Stage 5's results) isn't
  in the index. The evaluation predictor (`pipeline+4`) scores samples one at a time and
  doesn't run the pass; the `vm-day1` figure above comes from the round-6 harness.
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
    later) is `npm.dependency.missing` since `STAGE_VERSION` 12, unless its name looks like a
    sibling's (INFO). Naming the payload after the wrapper (`@kinetics-x/units` for
    `tailwind-kinetics`) or pinning it to the wrapper's own version avoids it, and so does
    publishing a placeholder of the payload first (the campaign already does it for wrappers:
    `fast-deep-thinking@0.0.0-stage`, "Temporary package placeholder for staged publishing");
    a days-old placeholder from other accounts is `fresh-foreign`'s. The same sibling test
    exempts an undeclared name (`npm.undeclared.missing`), so a payload named after its
    wrapper and loaded without being declared is missed too; one loaded only by a `bin` or
    postinstall-only file, or inside a function (webpack's module functions included), is
    never looked up.
  - **The evaluation pins 404s as well as found packuments** (`PinnedFetcher`, since
    2026-11-09): a `vm-day1` sample whose dependency was 404 at its first evaluation stays
    missing in later ones, even once the name is published. Before that a 404 was asked again
    on every evaluation; only `@financials/using-dep-conf@1.0.0` (DataDog, → `@tag/test1234`)
    was affected. The first evaluation's answer is the one kept, so an index built after a
    payload was published sees it as found.
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
