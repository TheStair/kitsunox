# 0013: The git-commit path: which repositories, how to poll them, and how it joins npm

**Date:** 2026-10-29
**Status:** Proposed (design only; no code). Answers to *What you need to decide* turn it into
Accepted. No implementation starts before then.
**Builds on:** [0004](0004-git-path-parallel-to-npm.md) (the git path, parallel to npm),
[0010](0010-stage4-correlation-and-repo-comparison.md) (the tarball-vs-repo join),
[0009](0009-network-failure-handling.md) (network failures are retried, never skipped),
[0006](0006-scheduled-collection-and-retention.md) (retention), [0003](0003-popularity-watchlist.md)
(the watchlist)
**Stage design:** [stages/git.md](../stages/git.md)

## Context

Decision 0004 set up a second discovery path. It watches commits on the repositories of popular
npm packages, filters them cheaply, reads the code that changed, and joins commits to npm
releases. Its design was deferred until the npm workflow was done, and it now is (Stages 0-4
and reports run hourly). Three things make the path worth building now:

1. **Stage 4 can only compare what it can locate.** Of 965 malicious `day1` updates, 543 have
   no `gitHead` and no tag for the version, so they can't be compared with git. Only 55 can
   (correlate.md, `repo.compared` v2). A path that already knows each watched repository's
   branches and tags, and has read the commits on them, gives Stage 4 a second source.
2. **Some attacks live in git, not in the tarball.** These are malicious commits or pull
   requests that get merged, CI workflow tampering (a workflow that exfiltrates secrets, or
   publishes with them), release tags moved to another commit, and slow takeovers by a
   contributor. The npm path sees them only after a release, if at all.
3. **The two paths check each other.** A release whose commit no watched branch or tag
   contains (*release without commit*) is the registry-only publish 0004 is about. A change to
   an install hook or a workflow that is pushed but not yet released (*commit without
   release*) is early warning.

### Measured on 2026-10-29 (read-only, from `data/`)

Sources: watchlist `data/watchlists/npm/20261029T221803Z.json` and run `20261029T221803Z-npm`,
the VM's first run: a 24 h window, 110,084 versions of 50,890 packages. The scripts used the
project's models (`Change`, `Watchlist`, `GitHubRepo.from_url`) under `uv run python -I` and
wrote nothing.

| Quantity | Value |
|---|---|
| Watchlist entries (≥ 43k downloads/month) | **63,563** |
| Repository URL host, over all versions in the run | github.com 86,485 (78.6%); none 20,983 (19.1%); gitlab.com 331; bitbucket.org 290; others < 1% |
| All packages in the run: with any URL / GitHub / gitlab.com | 41,085 / 39,646 / 378 of 50,890 |
| ... distinct GitHub repositories | 15,411 |
| **Watched packages that released in the window** | **5,809**: 5,339 with a URL, **5,238 GitHub (90.2%)**, 5 gitlab.com |
| ... distinct GitHub repositories | **1,025** (heavily monorepo-weighted: `aws/aws-sdk-js-v3` 386 packages, `deepseek-ai/deepseek-harness` 283, `stacksjs/stx` 134, `backstage/backstage` 132) |
| Distinct watched GitHub repositories releasing per hour (25 hours) | min 30, **median 93**, max 157 |
| Watched updates: with `gitHead` / trusted publisher / provenance | 34.8% / 65.4% / **60.0%** (of 18,701) |
| All updates with `gitHead` | 46.5% (of 101,232) |

**The watchlist doesn't store repository URLs today.** The run gives repositories only for the
packages that released in it. The ecosyste.ms pages the weekly build already fetches do carry
`repository_url` (checked on page 1: `semver` → `https://github.com/npm/node-semver`), so a
full repository list costs **no extra requests**, only a schema change to `WatchEntry`. The
full watchlist count is therefore **not measured**. The upper bound is ~57k GitHub-hosted
packages (63,563 × 90.2%). The distinct-repository count is lower because of monorepos, by an
unknown factor (a guess of 25-40k is not a measurement). Phase G0 measures it.

**Provenance names the source commit.** 60% of watched updates carry an npm provenance
attestation. Its SLSA v1 predicate records `resolvedDependencies[0].digest.gitCommit` and the
workflow (`repository`, `ref`, `path`). Checked on `sigstore@3.0.0`: commit `3a57a741...`,
workflow `.github/workflows/release.yml` on `refs/heads/main`. That is a third commit source for
the join, next to `gitHead` and tags, and as strong as `gitHead` because it is signed. (A
hijacked workflow still produces valid provenance; see the threat model.)

### Measured: what polling costs (2026-10-29, a handful of anonymous requests from the VM)

| Request | Result |
|---|---|
| v0 ref advertisement `GET <repo>.git/info/refs` (what Stage 4 uses) | `react` 1.68 MB (24,052 `refs/pull/*`), `aws-sdk-js-v3` 3.14 MB (28,634 tags), `lodash` 203 KB, `chalk` 26 KB, `is-plain-obj` 2.1 KB. `cache-control: no-cache`, no ETag |
| Protocol v2 `ls-refs` (`POST <repo>.git/git-upload-pack`, `Git-Protocol: version=2`) with `ref-prefix refs/heads/ refs/tags/ HEAD` | `react` 96 KB, `aws-sdk-js-v3` 2.08 MB, `chalk` 5.1 KB |
| ... with `ref-prefix refs/heads/ HEAD` only | `aws-sdk-js-v3` **4.8 KB** |
| Branch Atom feed `github.com/<repo>/commits/<branch>.atom` | 40 KB, 20 entries. ETag honoured (`If-None-Match` → 304). Renames redirect (`facebook/react` → `react/react`) |
| Web compare patch `github.com/<repo>/compare/<a>...<b>.patch` | anonymous 200. `chalk` v5.3.0...v5.4.0 is 13 KB: 9 commits (author, date, subject) and 14 file diffs |
| Public events `GET api.github.com/events` | 60/h unauthenticated, `x-poll-interval: 60`. PushEvent payload is only `before, head, push_id, ref, repository_id` |
| **GH Archive** hourly files | **0 PushEvents** in both hours sampled (2026-10-27 18h: 3,213 events; 2026-10-28 12h: 3,841). File size per hour fell from ~90 MB (2025-06-02, 2025-10-01) to ~32 MB (2025-10-15), ~22 MB (2026-06-15) and **4.3 MB** (2026-10-28) |

### Published limits (checked 2026-10-29)

- **REST:** 60 requests/hour unauthenticated (per IP); 5,000/hour with a personal access
  token. Secondary limits: 100 concurrent requests, 900 points/minute for REST (GET = 1
  point), 90 s of CPU per 60 s. A conditional request answered `304` doesn't count against the
  primary limit, *if* it was authenticated. GitHub advises sending requests serially. [1][2]
- **GraphQL:** 5,000 points/hour per user (PAT). A query costs the number of connection
  requests divided by 100, minimum 1; `first`/`last` ≤ 100; ≤ 500,000 nodes per call.
  Authentication is required. [3]
- **Unauthenticated git over HTTPS, raw.githubusercontent.com and anonymous REST** got new,
  **unpublished** limits on 2025-05-08. GitHub recommends authenticating "for enhanced
  consistency and reliability". [4]
- **Events API:** up to 300 events and 30 days, "latency can be anywhere from 30s to 6h", "not
  built to serve real-time use cases". It is ETag-pollable and honours `X-Poll-Interval`. [5]
  On 2025-10-07 PushEvent lost its "commit summaries and counts". [6]
- **Fine-grained PAT:** always has read-only access to all public repositories. The default
  expiry is 30 days, set from 1 to 366 days or none. Unused tokens are removed after a year. [7]

## Options

### Where push activity comes from

| Option | Cost for N repositories, hourly | Completeness | Verdict |
|---|---|---|---|
| **A. Ref state polling.** Each tick, read every watched repository's branch and tag heads and diff them with the previous tick's | N small requests (v2 `ls-refs`, a few KB) or N/100 GraphQL queries | **Self-healing:** state, not events. A missed tick is covered by the next diff. Pushes overwritten within an hour are invisible | **Chosen** |
| B. GH Archive | 24 files a day | **No PushEvents in the current files** (above). Coverage of the rest is unknown | Rejected (0004 had suggested it for ~63k repos) |
| C. Public events firehose (`/events`) | 1 request/minute at most | A 300-event window over all of GitHub; latency up to 6 h | Rejected |
| D. Per-repository events (`/repos/{r}/events`) | N requests (free when 304 and authenticated) | Lossy (300 events), up to 6 h late; payload has no commits | Rejected: no cheaper than A and less complete |
| E. Atom feeds per branch | N × branches | 20 commits per branch; undocumented web limits | Rejected for polling. A fallback for commit metadata at most |
| F. Webhooks | free | Needs admin on every repository | Not possible |

### How to authenticate (the one choice that sets every budget)

| Option | Polling | Commit metadata and diffs | Risk |
|---|---|---|---|
| **T0. No token** (today) | v2 `ls-refs` per repository: N requests/hour against an unpublished limit | Web `compare/<a>...<b>.patch` (works anonymously, measured) | GitHub's 2025 anonymous limits are unpublished, so the safe N is unknown. Stage 4 already sends ~500 refs requests and up to ~2k archives a day without trouble, and that is the only evidence |
| **T1. Read-only fine-grained PAT** | GraphQL: 100 repositories per query, ~1-3 points by the documented formula, so ~250-1,200 points/hour for 25-40k repos (5-25% of the budget; to verify with `rateLimit { cost }`) | REST `GET /repos/{r}/compare/{a}...{b}`: commits, files, blob ids and verification, 1 request per ref change | Documented budgets. The token is a secret in `.env` |
| T2. GitHub App | Up to 12,500/hour | Same as T1 | Needs app registration and installation; more moving parts than a capstone needs |

### Which repositories

| Option | Repositories (est.) | Note |
|---|---|---|
| R1. All watchlist repositories | ≤ 57k packages; distinct repos unmeasured (guess 25-40k) | Needs the watchlist schema change; T1 only |
| **R2. Active set:** repositories of watched packages that released in the last 30 days, plus the top 5,000 packages by downloads | 1,025 in one day measured; 30-day count unmeasured | **Recommended start.** Feasible with T0 or T1 |
| R3. Only repositories Stage 4 compared recently | ~1k | Cheapest, but it watches only what npm already showed us |

## Decision (proposed)

- **Ref state polling (A)**, hourly, inside the `collect` tick, after Stages 1-3 and before
  Stage 4, so the join sees the same tick's ref state, and ingest's tarball capture is never
  delayed. Each tick
  stores every watched repository's branch and tag heads as a `RefState`. The diff with the
  previous state gives `RefChange`s: created, updated, deleted, and *tag moved*. Pull-request
  refs (`refs/pull/*`) are excluded. They are most of the v0 advertisement's size (24,052 of
  `react`'s refs), and fork PRs aren't in the repository until merged.
- **A read-only fine-grained PAT (T1) is recommended.** Without one, the path still works
  (T0) for the active set (R2) of about a thousand repositories, at an unknown risk of
  anonymous throttling. The design keeps both behind one `GitHost` interface, so the choice is
  configuration, not a redesign.
- **Repositories: R2 first.** The weekly watchlist build keeps `repository_url` (a Stage 0
  contract change, flagged), and Phase G0 measures the full and active counts before the poller
  is sized.
- **Cheap first, as in the npm path.** G1 polls refs (state, tiny). G2 triages ref changes on
  metadata: commit authors, signatures, the files touched, workflows, `package.json`, a tag that
  moved. G3 reads only the changed files' contents for the ref changes G2 forwards, and runs
  **Stage 2's `FileRule`s unchanged** and Stage 3's capability profiles on them.
- **Joins at Stage 4, keyed by `(repo, commit)`.** It has four parts:
  1. Provenance's `gitCommit` becomes a commit source, ahead of tags.
  2. Findings the git path made on a release's commit attach to the release as context.
  3. *Release without commit:* the release's commit isn't reachable from any polled branch or
     tag, or it disappeared.
  4. The `RefState` tags replace Stage 4's own v0 `info/refs` fetch when they are recent.

  Part 3 starts at INFO until it is measured on benign releases: 15% of benign `gitHead`s
  sampled were never pushed (correlate.md).
- **GitLab later**, behind the same `GitHost` interface. Only 5 watched packages released from
  gitlab.com in the measured day (0.1%).
- **Determinism:** every request goes through `HttpFetcher`, including the POST requests that
  v2 `ls-refs` and GraphQL need. That is an extension of `util/http.py` (request key = method,
  URL and body hash; the `Authorization` header never in the key, the snapshot or logs). A git
  run records the id and SHA-256 of the previous `RefState` it diffed against, so it replays to
  the same `RefChange`s. Analysis never reads the clock: "between ticks" is the two polls'
  `as_of`.

## Consequences

- **Contract changes outside the git path, each flagged for its own task and review:**
  `WatchEntry.repository_url` (Stage 0, `core/watchlist.py`); POST support in `HttpFetcher`
  (`util/http.py`); Stage 3's `CodeChange` holds an npm `VersionSnapshot`, so commit-side
  profiles need a subject that isn't a release (`stages/ast.py`); Stage 4 reads git-run outputs
  and adds a commit source (`stages/correlate.py`, `stages/repo.py`, `ecosystems/npm/repo.py`).
- **Disk:** the VM's steady state is already about 256 GB of ~393 GB: tarballs 14 GB/day × 7,
  archives 30 GB/day × 4, packuments 5.5 GB/day × 7 (a projection from the stated daily
  volumes). The git path gets a budget of **≤ 5 GB/day at 4-day retention (≤ 20 GB)**. Measured
  in G1 before G3 is turned on (stages/git.md, *Storage*).
- **Recall will be thin and mostly synthetic.** The DataDog samples are npm tarballs, and OSV
  `MAL-` records name packages, not commits. Git-side labels are a handful of public incidents
  plus injected fixtures (stages/git.md, *Evaluation*). This is said plainly in every result.
- Pushes that are overwritten within one tick are not seen, and nor is anything on
  `refs/pull/*` (fork PRs before merge, "pwn request" workflow runs). Those are known limits,
  not bugs.

## What you need to decide

| # | Decision | Options | Recommendation |
|---|---|---|---|
| **G-D1** | GitHub token | T0 none / **T1 fine-grained PAT** / T2 App | **T1.** Create a fine-grained PAT with *Resource owner*: your account, *Repository access*: **Public repositories (read-only)**, **no additional permissions**, expiry 366 days. Put it in `.env` as `KITSUNOX_GITHUB_TOKEN`. It can read only what anonymous users can, but at documented limits. If declined, the path runs on T0 with R2 only |
| **G-D2** | Which repositories | R1 all / **R2 active + top 5k** / R3 Stage-4-compared | **R2**, revisited after G0's counts |
| **G-D3** | Which refs are analysed | default branch + tags / all branches | **All branches and tags polled.** Default branch and tags are analysed fully. Other branches get workflow and `package.json` checks only (bots' update branches are numerous; workflow pushes to side branches are a real attack shape) |
| **G-D4** | Cadence | **in the hourly `collect` tick** / its own timer | **In the tick**, after Stages 1-3 and before Stage 4, under the same data-directory lock |
| **G-D5** | Storage | budget and retention for git content | **≤ 5 GB/day, `--keep-git-days` default 4** |
| **G-D6** | Git-only items in the review queue | on their own / only as context for a release | **On their own only at HIGH** (tag moved, workflow-secret exfiltration pattern, install hook added on the default branch); otherwise context for the release that ships them |
| **G-D7** | Contract changes listed above | approve each when its phase comes | Approve the watchlist field and fetcher POST now (G0-G1); the rest at their gates |

## Sources

1. GitHub Docs, "Rate limits for the REST API": https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api
2. GitHub Docs, "Best practices for using the REST API": https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api
3. GitHub Docs, "Rate limits and query limits for the GraphQL API": https://docs.github.com/en/graphql/overview/rate-limits-and-query-limits-for-the-graphql-api
4. GitHub Changelog, 2025-05-08, "Updated rate limits for unauthenticated requests": https://github.blog/changelog/2025-05-08-updated-rate-limits-for-unauthenticated-requests/
5. GitHub Docs, "REST API endpoints for events": https://docs.github.com/en/rest/activity/events
6. GitHub Changelog, 2025-08-08, "Upcoming changes to GitHub Events API payloads" (effective 2025-10-07): https://github.blog/changelog/2025-08-08-upcoming-changes-to-github-events-api-payloads/
7. GitHub Docs, "Managing your personal access tokens": https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens
8. GH Archive: https://www.gharchive.org/ (file sizes and event counts measured from `data.gharchive.org/<date>-<hour>.json.gz`, see above)
