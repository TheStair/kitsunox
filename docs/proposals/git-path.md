# Proposal: the GitHub work (git path and repository trust)

**Status:** Phase A built 2026-11-04 (A.1-A.2; A.3 built but off after the recall check; decision [0017](../decisions/0017-repository-trust.md));
A.4 measured and not built (12% reach, see 0017). Phase B: proposal, not started.
**Builds on:** [decision 0004](../decisions/0004-git-path-parallel-to-npm.md) (a git-commit path
parallel to npm), Stage 4's repository comparison ([stages/correlate.md](../stages/correlate.md)).

## What exists today

- Stage 4 compares a reported version's tarball with its GitHub repository at the version's
  `gitHead` or tag (`githost/github.py`: git smart-HTTP refs and codeload archives, no REST API,
  no token). Findings: `repo.compared`, `repo.code-differs`, `npm.repo.*`.
- No commit watching, no repository metadata (age, forks, stars), no use of the API token.

## What was measured (2026-11-04)

### Sources

- **GH Archive no longer has commits.** Hourly files from 2026-10-20 held 58k events (45k
  `PushEvent`); from 2026-10-27 on they hold 3-5k and **no `PushEvent` or `CreateEvent`** (10-24:
  31k, 23.5k pushes; 10-27, 10-29, 10-31, 11-01, 11-03: 0). Decision 0004 named it as the
  way to watch ~63k repositories without API quota; it can't be used for that now.
- **GitHub's REST API still has push events** (`/events`, `/repos/{o}/{r}/events`) and commits.
  `GITHUB_TOKEN` in `.env` works: 5,000 requests an hour.
- **Smart-HTTP refs** (what Stage 4 already uses) cost no API quota and show when a branch head
  or tag moves: a cheap poll for "something was pushed".

### Would repository data narrow the queue?

All reported versions in the last 2 days of reports with a GitHub repository field (1,231
versions, 723 repositories; repository metadata fetched once with the token):

| Repo comparison | Repository | malicious | inconclusive | benign | unreviewed |
|---|---|---|---|---|---|
| clean (every code file identical) | not a fork, ≥ 30 days old | 1 | 0 | 90 | 28 |
| clean | created < 30 days before the release | 0 | 0 | 59 | 19 |
| most files not in the repository | ≥ 30 days old | 0 | 1 | 90 | 22 |
| no commit or tag for the version | ≥ 30 days old | 0 | 0 | 181 | 84 |
| no commit or tag | < 30 days old | 3 | 0 | 34 | 6 |
| repository field names a repo that doesn't exist (404) | | 5 | 3 | 96 | 50 |

- The one malicious clean match is `@finzzcloud/baileys`: the attacker's own repository, 1 star.
  Requiring **≥ 5 stars**: 53 versions, 34 reviewed, **all benign**. That is about 3% of the
  versions reported in the window, so this lever is real but small.
- All 53 have a MEDIUM finding (usually the install hook), and Stage 4 reports any MEDIUM
  finding, so a negative weight alone would clear none of them. Clearing them means changing the
  report decision.
- **The risk of trusting a clean match:** an attacker who pushes into a real repository (a stolen
  maintainer account, a malicious PR merged, CI tampering) produces a clean match. That is
  precisely what watching commits (Phase B) is for, so the two phases cover each other.
- Malicious versions with a repository field mostly name a repo that doesn't exist, or one created
  days before the release with no stars. As a positive signal that's weak (8 non-benign of 104
  reviewed 404s).

## Proposal

### Phase A: repository trust in Stage 4 (narrowing; small, measurable)

1. **Repository metadata** for each reported version with a GitHub repository: one
   `GET /repos/{owner}/{repo}` through `HttpFetcher` (replayable; the token goes in a header and is
   never recorded: request keys hold the URL and `Accept` only). About 400 requests a day.
2. **`repo.established-match`** (INFO, recorded): clean comparison, not a fork, repository ≥ 30
   days old at the release, ≥ 5 stars, the version's commit on the default branch.
3. **Report decision:** a version whose only MEDIUM findings are install-hook findings from
   Stage 1, with no HIGH finding, no Stage 5 finding and an established match, is not reported.
   Measured before adopting on `vm-day1` and the live verdicts; expected to clear ~3% of reported
   versions. Every cleared version is still in `report.json` (not reported), as today.
4. **Commit matching for "no commit or tag"** (318 versions, the largest bucket): find the commit
   that set `package.json`'s version to the released one before the publish time (commits API,
   `path=package.json`, `until=published_at`) and compare there. Measure how many of the 318 match
   before building it.

### Phase B: watching commits on watchlist repositories (the git path proper; decision 0004)

1. **Repository list:** the watchlist's packages mapped to GitHub repositories from their packument
   `repository` field (Stage 0 already fetches packuments of packages that publish; the rest come
   from a one-off fill), the top N by downloads.
2. **Change detection:** poll smart-HTTP refs hourly (no quota), and for repositories whose default
   branch or tags moved, fetch the commits and their changed files with the API (`compare`
   between the old and new head).
3. **Rules on commits:** CI workflow changes (new secrets use, `curl | sh`, new third-party
   actions, `pull_request_target`), install-script or `package.json` script changes, obfuscated or
   minified additions to sources, a new committer pushing directly to the default branch,
   force-pushes that rewrite released history.
4. **Join with npm:** when that repository's package publishes, the commit findings travel with
   the release (and a release whose commit carries one is never cleared by Phase A).
5. **Budget:** N = 5,000 repositories, refs every hour = 5,000 unauthenticated requests an hour
   (~1.4/s); the API only for repositories that moved (typically a few hundred an hour). Disk:
   commit metadata and diffs only, kept with the runs (2 days).

## Questions for the owner

1. **Order:** Phase A first (recommended: smaller, and the measurement above says what it buys), or
   Phase B first, or both in parallel?
2. **Report-decision change in A.3:** acceptable in principle, given the measured recall check
   comes first?
3. **Using `GITHUB_TOKEN`** in Stage 4 (and Phase B) for API calls: fine? Decision 0002 kept
   GitHub to the repository comparison only.
4. **Phase B size:** the top 5,000 repositories by downloads, or another number?
