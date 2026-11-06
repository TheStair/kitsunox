# 0018: Commit history: what git saw between two releases

**Date:** 2026-11-06
**Status:** Accepted and built. The owner asked to "check the corresponding commits and repos
for the npm packages being scanned", as a source both of malicious signals and of fewer false
positives (2026-11-06), and chose to keep 0017's clearing off. The two detection rules are
on. Clearing install code with a history match is built but **off** (`CLEAR_HISTORY =
False`): like 0017's, it loses `gina@0.7.1`, so turning it on is the owner's decision.
**Builds on:** [0017](0017-repository-trust.md) (repository trust, the REST API with
`GITHUB_TOKEN`), [0010](0010-stage4-correlation-and-repo-comparison.md) (the tarball-vs-repo
comparison), [0004](0004-git-path-parallel-to-npm.md) (the git path).
**Stage:** 4 ([stages/correlate.md](../stages/correlate.md), "Repository history")

## Context

Stage 4 compares a release with its repository at one commit, the release's own. It never
looked at the commit the previous release came from, so it couldn't say whether the change
between the two releases went through git at all. Phase B of the
[proposal](../proposals/git-path.md) watched commits on 5,000 popular repositories, whatever
gets published. The owner narrowed it instead to the repositories of the packages being
scanned, and the commits behind each release.

What was measured (2026-11-06; scripts and raw answers in `~/kitsunox-scratch/commits/`):

- **Samples.**
  - Live: every Stage 4 version compared at a commit in the runs on disk (33,983). Of these,
    all 537 reported versions and 400 random unreported updates.
  - `vm-day1`: the 112 malicious updates compared at a commit.
  - For each, the GitHub compare API between the previous release's commit (`gitHead`, else
    a release tag) and the release's: 904 ranges, no errors.
- **Per range:**

  | | malicious (`vm-day1`) | reported benign | unreported live |
  |---|---|---|---|
  | no new commits (same commit, or an older one) | 61 / 102 | 2 / 261 | 7 / 365 |
  | the range has commits made after the publish | 15 / 102 | 2 / 261 | 0 / 365 |
  | a workflow file changed with a risky line (`pull_request_target`, `curl \| sh`, `toJSON(secrets)`, ...) | 1 / 102 | 21 / 261 | 13 / 365 |
  | the release commit is behind or diverged | 7 / 102 | 12 / 261 | 36 / 365 |
  | the range adds an install hook to `package.json` | 3 / 102 | 46 / 261 | 2 / 365 |
  | every commit unverified, PR-style messages, last commit > 24 h before publish | no difference | | |

- **The tag-commit date.** Over all 815 live releases whose commit a tag found, the latest
  tag commit came 1.4 hours after the publish: release tools publish, then commit and tag.
  Among the malicious updates, 14 of 15 such tag commits came 7 hours to 255 days later. A
  stolen token published the version number first, and the maintainers' own release of it
  came later (`@postman/tunnel-agent`, `zapier-platform-*`, `@asyncapi/*`).
- **Same `gitHead` without the API.** On all live updates where both releases record one:
  stable to stable 2.9% (3,969 of 137,989), every shape 4.5%. On all `vm-day1` malicious
  updates: 66% (361 of 549). Small packages often publish uncommitted work, and npm writes
  `HEAD` as `gitHead` all the same; that is the benign 2.9%.
- **gina.** `gina@0.7.1`, DataDog-malicious and reported only by `npm.install-script-changed`,
  is 44 commits ahead of its previous release (0.7.1-alpha.1). All 44 are by the maintainer
  who has run the repository since 2013, the last "Release v0.7.1" 30 minutes before the
  publish. Nothing in commit history separates it from benign releases.
- **Cost.** Distinct (previous, release) commit pairs: ~1,900 a day; tag-found release
  commits: ~500 a day. Comparing with page 2 at one commit a page, the status costs 18 KB
  instead of page 1's file list (median 212 KB, up to 2.3 MB).

## Options

1. **Commit-level rules over every range** (workflow edits, new committers, unverified
   commits): measured and not built. Workflow edits fire on more benign ranges than malicious
   ones, and the commit metadata doesn't tell them apart. The ranges themselves were legitimate
   work in nearly every malicious sample: the attack happened on the registry side.
2. **What the two releases' commits say** (chosen): whether there are new commits at all,
   whether the release's tag predates it, and, for the false positives, whether a clean match
   sits at a commit ahead of the previous release's.
3. **Phase B as proposed** (watching 5,000 repositories): not built. The owner chose the
   repositories of the packages being scanned.

## Decision

- **`RepoComparison.history`** (`with_history`, `stages/repo.py`) for every update compared at
  a commit:
  - the previous release's commit, from its `gitHead` or a release tag in the refs already
    fetched (no request);
  - `identical` without asking when both releases name the same commit;
  - with a token, how the two commits relate (`compare` page 2: status, ahead and behind
    counts), asked only for versions with a MEDIUM-or-above finding: the ones a match could
    clear;
  - with a token, the release commit's committer date when a tag found it (the git data API,
    `git/commits/{sha}`: the commit object only).
  - Each request once per run, recorded for replay. Failures (the network, a rate limit, a
    replay miss) leave `history.unavailable` = "GitHub API request failed" and are not
    retried, as 0017's.
- **`repo.commit-after-release`** (MEDIUM, weight 3): the release's tag points to a commit made
  more than 6 hours after the release was published.
- **`npm.repo.no-new-commits`** (LOW, weight 2): a stable version, higher than the previous
  stable one, built from the previous release's commit or an older one, while its code isn't a
  clean match there. A clean match there is the previous code republished, which is harmless.
  LOW because every malicious sample it fires on is reported through other rules, and the
  benign 2.9% look the same.
- **`repo.history-match`** (INFO): a clean comparison at a commit ahead of the previous
  release's, and no `commit-after-release`.
- **Clearing with it (built, off):** `decide(..., clear_history=True)` clears the same
  install-code findings, under the same conditions, as 0017's `CLEAR_ESTABLISHED`:
  - its MEDIUM findings are all in `CLEARED_BY_REPO`;
  - it has no HIGH finding;
  - its score without those findings stays below `REPORT_SCORE`.
- `STAGE_VERSION` becomes 10.

## Consequences

- **Detection.** `commit-after-release` reports a stolen-token release whose real tag came
  later, even when the comparison (against that later, clean commit) found nothing. No benign
  release in the live sample fires it.
- **If the clearing is turned on.** Live, it removes 78 of 1,507 reported versions (5.2%): 60
  reviewed benign, 18 unreviewed, none reviewed malicious. That is about twice 0017's
  established match, without stars or age. Mostly `npm.install-script-changed` alone (62).
  The cost is `gina` (see Evaluation).
- **Quota.** About 100 requests an hour next to 0017's facts, from 5,000.
- **What it can't see.** A maintainer, or someone with their git access, committing the code
  (gina). The history then looks like any release. Commit dates are the committer's claim; a
  forged date earlier than the publish hides `commit-after-release`, so the rule is evidence
  when it fires and silence proves nothing.

## Evaluation

`pipeline+4` on `vm-day1` (3,444 malicious, 1,500 benign) with a per-sample dump and the API
answers pinned under `data/eval/github-api/` (`~/kitsunox-scratch/commits/eval/`). First run
without a token (the eval reads `.env` from the working directory, so a run from elsewhere
has no API), then with one:

| | malicious reported | benign reported |
|---|---|---|
| before (no API) | 2,507 | 14 |
| with history, clearing off | 2,507 | 15, then 14 after the monorepo exception below |
| `CLEAR_HISTORY` on | 2,506 (−`gina@0.7.1`) | 14 |
| `CLEAR_ESTABLISHED` on (0017, for comparison) | 2,506 (−`gina@0.7.1`) | 14 |

- **`npm.repo.no-new-commits`:** 60 malicious, 0 benign.
- **`repo.commit-after-release`:** 15 malicious, 1 benign at first. The benign one,
  `@mongodb-js/mcp-atlas-telemetry@3.2.2`, lives in `packages/atlas-telemetry` of
  `mongodb-mcp-server`. Its tag, `v3.2.2`, is the server's own 3.2.2 release, six days later.
  A tag of the version alone doesn't identify a package in a subdirectory, so the rule
  skips that case. That also drops 2 malicious (`@posthog/rrweb-record` and
  `rrweb-player@0.0.31`, bare tags under `packages/`), both still reported through their
  install-hook findings: 13 malicious, 0 benign. These figures follow from the run's
  per-sample rows; the run itself was not repeated after the exception.
- **No new recall:** every malicious sample either rule fires on was already reported. They
  add evidence and order in the queue; on live ticks `commit-after-release` can report on its
  own.
- **Clearing:** a history match fires on 1 malicious sample, `gina`, and either clearing
  loses exactly that one.
