# Proposal: new-dependency reputation (Stage 4)

> **Status:** implemented 2026-10-29 (Stage 4, `STAGE_VERSION` 4): both rules in
> `ecosystems/npm/rules/correlate.py`, the lookup in `stages/review.py` (`NpmDependencyLookup`).
> See [stages/correlate.md](../stages/correlate.md#dependency-lookups) for how it works and
> the `vm-day1` before/after numbers. Choices this proposal left open, and changes from it:
>
> - **Lookup cap:** 1,000 distinct names per run (`MAX_DEPENDENCY_LOOKUPS`), applied in run
>   order before any rule runs, so it is deterministic. A name over it is "not evaluated".
> - **Network failures:** no Stage 4 retry pass for dependency lookups (the fetcher's own
>   attempts only; the repository retry logic is untouched). A failed lookup gives an INFO
>   "Not evaluated" finding and is counted in `correlate.json` (`dependency_lookups`), never a
>   silent "not fresh". Missing account data (either side) is also "not evaluated".
> - **npm's own accounts** (`npm`, `npm-support`), which replace a taken-down package's
>   maintainers, are not counted as the dependency's accounts: 3 DataDog new packages were
>   "foreign" only through them.
> - **Stage 0's snapshot is not reused:** every name is fetched by Stage 4 (~640 a day rather
>   than ~350), which keeps `correlate-snapshot.json` self-contained.
> - **Popular-name tie-break:** the longest matching popular name, then the first by name.
>
> **Revised after review (2026-10-29, `STAGE_VERSION` 5, both rules v2).** An adversarial
> review found the first two choices above too weak; they are replaced by:
>
> - **Network failures are retried**, as section 4 proposed: planned names are looked up
>   before the rules run, and those that failed on the network are retried in Stage 4's retry
>   passes, under the repository lookups' outage guard (counted separately). Names still
>   failing are counted (`dependency_lookups.still_failing`) and shown in the report index and
>   the Discord update. A document that isn't the packument (e.g. a captive portal page) is
>   now "not evaluated" rather than silently clean.
> - **Limits per release and per day:** each release may claim at most 40 names
>   (`MAX_LOOKUPS_PER_RELEASE`; the most on the day run was 34), updates are planned before
>   new packages, and the run cap is 1,000 names per started day of the window. A release with
>   2,000 junk dependencies no longer exhausts the cap; names over a limit share one INFO
>   finding per release.
> - **`name-embeds-popular` checks accounts:** quiet when the dependency (already looked up)
>   shares an account with the dependent. On the day run it fires on 12 versions instead of 27.
> - **Evasions and timing gaps** the review listed (a shared or stolen account, a dependency
>   published after `as_of`, padding past the per-release limit) are in
>   [Known limits](../stages/correlate.md#known-limits).
>
> The text below is the proposal as written (analysis of 2026-10-29). The measurement scripts
> are outside the repository (see [Reproducing](#reproducing)).

## Summary

- **What exists today.** We already look at a dependency's *name and specifier*: Stage 1
  `npm.dependency.added` (LOW) and `npm.dependency.non-registry` (MEDIUM), and in Stage 4
  `npm.dependency.known-malware` (HIGH), `npm.combination.revived-with-new-dependency`
  (MEDIUM) and `npm.repo.dependency-not-in-repo` (LOW). We never look at the *dependency
  package itself*: how old it is, who publishes it, how popular it is, or whether its name
  copies a popular package. Typosquat-like and very new dependencies (threat model row 5) are
  not covered at all.
- **Benign baseline** (run `20261029T221803Z-npm`, 105,659 non-placeholder changes).
  2,320 of 101,232 updates (2.29%) add a runtime dependency. Most of what they add is popular,
  their own scope, or another of their own packages. Two numbers stand out. Of the 362
  brand-new packages that updates added as dependencies, every one outside the dependent's
  scope shares a maintainer with it: 0 of 101,232 updates added a brand-new dependency from
  someone else. With a packument fetch for the dependencies we didn't already have, only
  **3 updates and 0 new packages** added a dependency that is under 7 days old and shares no
  maintainer.
- **Malicious side** (DataDog, 965 first-release updates). 203 (21%) add a dependency. 120 add
  an unwatched dependency from another publisher whose name copies a popular package:
  `easy-day-js` (119 `@mastra/*` releases) and `plain-crypto-js` (`axios@1.14.1`). Both
  dependencies were about **18 hours old** when the dependent was published. **Stages 2 and 3
  can't see this attack**, because the payload is in the dependency and the dependent's tarball
  carries none (0 of the 120 were caught by `stage2-rules`). Today each of the 120 is caught
  by exactly one rule (107 by `npm.publish-method.downgrade`, 12 by
  `revived-with-new-dependency`), and one is missed.
- **Proposal.** One MEDIUM rule, `npm.dependency.fresh-foreign`, and one LOW evidence rule,
  `npm.dependency.name-embeds-popular`, both in Stage 4. Estimated effect on `vm-day1`:
  recall on updates **+1 sample (+0.1 pt)**, roughly 0 on new packages, and **about 3 benign
  reports a day**. For 119 of the 120 dependency-chain samples, the rule would be a second,
  independent reason to report. Fetch cost: about 350 packuments a day (about 15 per hourly
  tick), under 110 MB.
- **Measured and rejected:** edit-distance typosquats of dependency names, "the range admits a
  known-malicious version", "unpopular dependency" as a rule of its own, `peerDependencies`,
  and dependencies that don't exist (404). The numbers are [below](#measured-and-rejected).

## 1. What the current rules cover

| Rule | Stage | Sev. / weight | Looks at | Doesn't cover |
|---|---|---|---|---|
| `npm.dependency.added` | 1 | LOW / 1 | names of runtime + optional dependencies added to an **update** | anything about the dependency; new packages (no previous version) never fire |
| `npm.dependency.non-registry` | 1 | MEDIUM / 3 | new or changed specifier that is git, URL, GitHub shorthand or `file:` | registry dependencies |
| `npm.version.suspicious` | 1 | MEDIUM / 3 | the *package's own* version (≥ 90 major), dependency-confusion style | the dependency |
| `npm.dependency.known-malware` | 4 | HIGH / 5 | added or re-pointed dependency (and its `npm:` alias target) has an OSV `MAL-` record for **every version**, published by `as_of` | version-specific records (`easy-day-js` is listed for `1.11.22` only); anything OSV hasn't published yet |
| `npm.combination.revived-with-new-dependency` | 4 | MEDIUM / 2 | `dormant-revived` + `dependency.added`, releases only | non-dormant packages |
| `npm.repo.dependency-not-in-repo` | 4 | LOW / 1 | runtime dependency the repository's `package.json` doesn't name | only versions that get a repository comparison |

`runtime_dependencies()` means `dependencies` ∪ `optionalDependencies`.
`peerDependencies` (which npm 7 and later install by default) and `devDependencies` are left
out. Section 5 checks whether that matters.

## 2. Benign baseline: the newest live run

Run `20261029T221803Z-npm`: 110,084 changes, of which 105,659 are not registry placeholders.
101,232 are updates (shape A) and 4,427 are new packages (shape B). Watchlist
`20261029T221803Z`: 63,563 names, at least 43k downloads a month. Labels:
`20261029T221803Z`, 222,567 package names.

**Updates.** 2,320 / 101,232 (2.29%) add at least one runtime dependency, with a median of 1
added. 1,428 add exactly one. 5,625 registry dependencies were added in all.

| Added dependency is... | Updates | Occurrences | Distinct names |
|---|---|---|---|
| (a) on the watchlist | 1,457 (1.44%) | 3,761 | 1,402 |
| (b) a **brand-new package in this run** (first published in the window) | 249 (0.25%) | 530 | 362 |
|  ...outside the dependent's scope | 58 | 100 | 68 |
|  ...outside the scope **and no maintainer in common** | **0** | 0 | 0 |
| (b′) an existing package that also published in this run | 619 (0.61%) | 1,017 | 398 |
|  ...outside the scope, no maintainer in common | 8 | 8 | 6 |
| (c) **unknown** to both (needs a packument fetch) | 224 (0.22%) | 317 | 213 |
|  ...outside the scope | 136 | 196 | 116 |
| (d) at edit distance 1, or differing only in separators, from a watchlist name (and not watched itself) | 5 | 5 | 2 |
|  ...outside the scope | 4 (all `@cube-dev/ui-kit` canaries → `react-types`) | 4 | 1 |
| (d′) unwatched, and the name is a popular name (≥ 1M/month) plus a prefix or suffix of up to 8 characters | 12 | 12 | 8 |
| (e) scoped / unscoped | 1,615 / 1,035 | 3,540 / 2,085 | 1,590 / 785 |
|  same scope as the dependent | 882 | 1,779 | 810 |
| (f) known malware (all-versions OSV record by `as_of`) | 1 (`victor-nest-resource` → `fs@0.0.1-security`, which the existing rule already reports) | 1 | 1 |
|  any OSV record (compromised *versions* of real packages: `chalk`, `axios`, `debug`) | 50 | 65 | 27 |
|  the range admits a version an OSV record lists | 3 | 4 | 3 |

**New packages.** 2,162 / 4,427 (48.8%) have runtime dependencies. 1,669 use a watched one, 753
use a package that is also new in this run (65 outside their scope, all sharing a maintainer),
234 use an unknown one, 4 a near-name, and 0 known malware.

**The (c) names, fetched once** (546 distinct names across both shapes; this was a measurement
script, not the pipeline): 515 returned 200 and 31 returned 404. 107 MB in total: median
29 KB, p90 205 KB, max 10 MB. First published (earliest version time up to `as_of`): 0 under a
day old, 46 under 7 days, 104 under 30 days, 324 under a year. None was an npm security
holding package.

**Fresh and foreign together:** the dependency's first version is less than N days old, it is
outside the dependent's scope, it is unwatched, and it shares no maintainer or publisher with
the dependent. Across (b), (b′) and (c):

| Threshold | Updates (of 101,232) | New packages (of 4,427) |
|---|---|---|
| < 1 day | 0 | 0 |
| **< 7 days** | **3** (`@geonovum/standards-checker@1.5.0` → six `@openlint/*`; `@javierkaiser/opencode-indexing` → `mini-semantic-search`; `@bleedingdev/...-app-tools@3.9.3-ultramodern.14` → `rsbuild-redact-plugin`) | **0** |
| < 30 days | 9 (5 prereleases, e.g. `@opencode/ui@0.0.0-dev-*` → `@kitlangton/*`) | 2 |

## 3. Malicious side: DataDog manifests

The source is `ExternalSampleSet datadog-438afad338f8` (3,444 samples), and only the
manifests recorded in it were read. Package code was not extracted or read. "Caught today"
means a lower bound of `pipeline+4`: Stage 1 MEDIUM or above, or in the `vm-day1--stage2-rules`
forwarded list, or Stage 4's manifest rules (`githead-dropped`, `known-malware`,
`revived-with-new-dependency`) through `decide()` with `as_of` set to the sample's publish
time. Stage 3 and the repository comparison aren't included. It reproduces the published
new-package recall (66.6% vs 66.5%).

| Cell | Samples | Caught today | Add ≥ 1 dependency | Unwatched dependency outside the scope | Of which not caught |
|---|---|---|---|---|---|
| A, first release | 965 | 896 (92.9%) | 203 (21.0%) | 120 (12.4%) | 1 |
| A, follow-on | 481 | 411 | 22 (all watched) | 0 | 0 |
| B, first release | 905 | 603 (66.6%) | 356 (39.3%) | 97 (10.7%) | 69 |
| B, follow-on | 1,093 | 608 | 52 | 4 | 2 |

**Shape A in detail.** Of the 203 samples that add a dependency, 68 use non-registry
specifiers (an existing rule) and 23 add only watched packages. The 120 that add an unwatched
foreign dependency are two incidents:

| Dependency | Samples | Published by | Dependency's first version | Dependent published | Age at publish | Name |
|---|---|---|---|---|---|---|
| `easy-day-js` (`1.11.21` clean, `1.11.22` malicious; OSV `MAL-2026-5979` lists only `1.11.22`, published 2026-06-17 04:15) | 119 `@mastra/*` | `ehindero` (maintainer `sergey2016` on the dependency) | 2026-06-16 07:05 | 2026-06-17 01:17–02:02 | ~18–19 h | `dayjs` with a prefix; the spec `^1.11.21` copies dayjs's version line |
| `plain-crypto-js` (OSV `MAL-2026-2306`, published 2026-03-31 02:07) | `axios@1.14.1` | `jasonsaayman` | 2026-03-30 05:57 (`4.2.0`) | 2026-03-31 00:21 | ~18.4 h | `crypto-js` with a prefix |

The dependency dates come from fetching the two packuments on 2026-10-29. Version `time`
entries survive a takedown. `time.created` and `maintainers` don't: `plain-crypto-js` now
shows `created` 2026-03-31 04:26 and no maintainers. So who published `plain-crypto-js` at the
time cannot be recovered from the registry. For `easy-day-js` the maintainer (`sergey2016`)
is still listed.

How the 120 are caught today: **107 by `npm.publish-method.downgrade` alone, 12 by
`revived-with-new-dependency` alone, and 1 by nothing** (`@mastra/node-audio@0.1.8`, score 1).
`stage2-rules` catches **0** of them. Of the 69 shape-A samples missed today, that one is the
only one that adds a dependency. That caps the measurable recall gain on shape A at one sample.

Other shape-A measurements: OSV knew none of the added dependencies as malware at publish
time; no dependency is an edit-distance-1 typosquat; 187 of 965 add exactly one dependency;
only 5 of 171 added specifiers are exact pins (benign updates: 48%).

**Shape B in detail.** The 69 unwatched-foreign samples missed today are tea.xyz-style spam
farms (`*_z3n`, `*-tea`; publishers `voinza`, `bipyruss`, `yunina`, ...). Their dependencies
are other farm packages that were first published months earlier: `vndrabnb` 2024-03-01 and
`yninalah` 2024-03-01, against samples from 2024-07. A freshness rule wouldn't catch them.
Edit-distance-near dependencies: 3 samples, all false matches (`require`, `account`).

## 4. Proposed rules

Both live in Stage 4 (`ecosystems/npm/rules/correlate.py`), run over every triaged version,
and add their weight through the existing `score()`.

### `npm.dependency.fresh-foreign` (MEDIUM, weight 3)

**Fires when** a release adds (or re-points via an `npm:` alias) a registry runtime or
optional dependency (for a new package, any of them) that meets all of these:

1. it is not the package itself, not in the dependent's scope (a scope's packages can only be
   published by its members), and not on the run's watchlist;
2. its **earliest version time**, over `time[v]` entries no later than `as_of`, is less than
   **7 days** before the *dependent's* `published_at`. `time.created` is not used, because
   npm rewrites it on takedown;
3. none of its accounts (the `maintainers` and `_npmUser` of its versions published by
   `as_of`, falling back to the top-level `maintainers`) is among the dependent's (`new` and
   `previous` maintainers and publishers). With no account information it does not fire. That
   case is counted, not reported.

**Evidence:** the dependency name and specifier, its first version and that version's time,
age in hours, its accounts, and the dependent's accounts.

**Why MEDIUM:** it reports on its own, because dependency-chain attacks give Stages 2 and 3
nothing to see. Noise is 3 of 101,232 updates and 0 of 4,427 new packages. At a weight of 3 it
also counts toward the score with any LOW finding.

**Expected:** shape A +1 first release (`@mastra/node-audio@0.1.8`), +0.1 pt. 119 of the 120
dependency-chain samples gain a second independent reason to report. Shape B: about 0. About
3 benign reports a day; their reviewer cost is a glance at two account lists. Caveat: the
recall is **two incidents**, not 120 independent cases.

### `npm.dependency.name-embeds-popular` (LOW, weight 1)

**Fires when** an added, unscoped, unwatched dependency outside the dependent's scope has a
name that, lowercased and with `-_.` removed, is a popular unscoped name (≥ 1M downloads a
month, at least 5 characters after normalisation) plus a prefix or suffix of at most 8
characters. Examples: `easy-day-js` against `dayjs`, `plain-crypto-js` against `crypto-js`.

**Data:** the watchlist only, so no fetch. **Noise:** 12 updates (0.012%) and 15 new packages
(0.34%) a day, such as `react-types`, `mutate-react` and `micro-router`. **Malicious:** the
same 120 shape-A samples, plus 17 in B (`quasarquest`, `quarctic`). LOW: it can't report
alone. It orders the queue and gives the reviewer the pattern in one line ("name embeds
`dayjs`"). Together with `fresh-foreign` it scores 4.

### Data, cost and determinism

| | |
|---|---|
| Lookup set (per day) | Dependencies that pass condition 1 of the fresh-foreign rule: **639 distinct names** |
| Already available, at no cost | 290 of them published in the window, so Stage 0's run snapshot holds their packument (`snapshot.json` → blob store) |
| Fetched | **~349 names a day ≈ 15 per hourly tick**; measured size (all 546 unknown names) 107 MB/day, median 29 KB. For comparison: tarballs ~14 GB/day, repository archives ~30 GB/day |
| How | `HttpFetcher.get(packument_url(name))`, the same request key Stage 0 uses, recorded in `correlate-snapshot.json` and replayed offline. One request per name per run (in-memory memo, like `RepoMemory`). No cache across runs: packuments change |
| Clock | Only `time[v] ≤ as_of` and the dependent's `published_at`. The fetched document is input, as with every other snapshot |
| Network failures | `TransientFetchError` → retried in Stage 4's existing retry passes (decision 0009, 0010 addendum). If still failing, the decision reason says so, like `NETWORK_UNCOMPARED`. 404 / malformed is permanent: no finding, counted in `correlate.json` |

**Owner: Stage 4.** Stage 1 rules can't fetch (`RuleContext` carries only `as_of`), and the
in-run lookup alone would miss the (c) names. Contract change, all inside Stage 4:
`CorrelationContext` gains `dependencies: DependencyLookup | None` (a protocol like
`KnownBad`, with npm wiring in `stages/review.py`) and access to the run's watchlist. The eval
predictor (`evaluation/static_eval.py`, `pipeline+4`) passes the same lookup. Nothing changes
in Stages 0–3. Agents are editing `stages/correlate.py` and `stages/review.py` right now, so
this should start after their work is merged.

## 5. Measured and rejected

| Idea | Benign (per day) | Malicious | Why not |
|---|---|---|---|
| Dependency name at edit distance 1 (or a separator variant) of a watchlist name | 5 updates (2 names), 4 new packages | A 0, B 3, all false (`require`~`crequire`, `account`~`ccount`) | No true positive. Package-name typosquatting (shape B's own name) is a different rule, for Stage 1 |
| Specifier range admits a version an OSV record lists | 3 updates, 39 new packages (`axios ^1.x`, `chalk ^5`, `debug *`) | A 1 (`debug ^4.4.1`, coincidence), B 13/905 (1.4% vs 0.9% benign) | No lift. It flags *victims* of a compromised dependency, not attackers: a vulnerability-advisory concern |
| "Unwatched dependency outside the scope" as a rule of its own | 252 updates (0.25%); ~5% of new packages | A 120, B 97 | At LOW it pushes no missed sample over the score bar (their scores are 0–1); at MEDIUM, ~250 benign reports a day. Kept only as the lookup prefilter |
| `peerDependencies` added | 655 updates (114 with an unwatched peer) | A 3 (none unwatched) | No signal. Leave `runtime_dependencies()` as it is |
| Added dependency doesn't exist (404) | 38 updates; 31 names, 23 scoped (private, e.g. `@teambit/envs.contracts`), 8 unscoped platform binaries not yet published | not measurable | These are dependency-confusion *exposures* of benign packages, not attacks. A possible future "exposure" report. **Revisited 2026-11-08:** a campaign of Tailwind wrappers declared payloads published after them, so a 404 under an unrelated name is now `npm.dependency.missing` (MEDIUM; siblings INFO), see [stages/correlate.md](../stages/correlate.md#missing-dependencies-npmdependencymissing-stage-version-12) |
| Dependency is an npm security holding package at lookup time | 0 of 515 fetched | Live recall expected near 0: `plain-crypto-js`'s holder appeared ~3 h after `axios@1.14.1`, and `easy-day-js` never got one | Mostly overlaps `known-malware`, and it would inflate eval numbers (DataDog's dependencies are all taken down now). Deferred |
| Exact-pinned specifier | 48% of benign added specifiers | 3% of shape-A malicious | The signal runs the wrong way (attackers use `^` so the next version flows in) |

## 6. What to evaluate

1. **Eval snapshot for dependency packuments.** For every `vm-day1` sample with a dependency
   in the lookup set, fetch the dependency's packument once through `HttpFetcher` and record
   it next to the DataDog snapshot. Removed packages keep `time`, but lose `maintainers` and
   (for the security holder) `created`. So report recall twice: **age only**, and
   **age + foreign** where account data exists.
2. **`pipeline+4` before and after** on `vm-day1`, with follow-on releases separate. Expected:
   A 92.9% → 93.0% (lower-bound figures), B unchanged, benign weighted pass-through +0.003 pt
   or less.
3. **Independence.** How many malicious samples have at least two independent MEDIUM-or-above
   reasons? Expected for the dependency-chain set: 0 → 119 of 120. This metric is the main
   argument for the rule, so it should go into `docs/evaluation.md`.
4. **Threshold sweep:** 1, 2, 7 and 30 days. Benign: 0 / ? / 3 / 9 updates, and 0 / ? / 0 / 2
   new packages.
5. **Live week.** Count fires per tick over seven days of collection and hand-review every one
   (about 20 expected). Log fetch counts, bytes and network failures from `correlate.json`.
6. **Prospective.** Join the dependencies added in collected runs against later OSV records.
   This is the only way to get dependency-chain samples beyond the two incidents.

## 7. Open questions

- The measured recall is two incidents (`easy-day-js`, `plain-crypto-js`). Is that enough to
  justify a MEDIUM rule, given the precision (3 a day)? The case for it is redundancy, not
  measured recall: today, removing one rule (`publish-method.downgrade`) would lose 107 of the
  120.
- Should `fresh-foreign` also look at version-specific OSV records, flagging a dependency
  whose *newest* version an OSV record lists? For `easy-day-js`, OSV was 2–3 hours behind the
  release, so it wouldn't have helped on the first tick, but it might on a re-run.
- Should account information missing from a removed dependency count as foreign in
  evaluation only? It changes the eval numbers, not live behaviour.
- The watchlist is a monthly-downloads cutoff. Should Stage 4 treat a package added to the
  watchlist recently (new and popular) differently? Not observed in the data.

## Reproducing

Scripts live in
`/tmp/claude-1000/-home-thestair-kitsunox/b95c883b-f85a-499a-8757-d17752ec5e68/scratchpad/deps/`
and are run with `uv run --frozen python -I <script>` from the repository. They only read
`data/`. `run_deps.py` (benign baseline), `datadog_deps.py` (DataDog manifests and
"caught today"), `fetch_unknown.py` (one-off packument fetch of the (c) names, written to the
scratchpad), `unknown_stats.py` (ages and the fresh-foreign rate), `affix.py` (name-embeds-
popular), `peer.py` (`peerDependencies`). The scratchpad is temporary: if this proposal is
accepted, the measurement should become an eval predictor instead.
