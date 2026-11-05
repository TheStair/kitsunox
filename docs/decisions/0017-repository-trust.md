# 0017: Repository trust: an established repository's exact code clears install-code findings

**Date:** 2026-11-04
**Status:** Facts and `repo.established-match` accepted and built (the owner asked to start
the GitHub work, Phase A of [the proposal](../proposals/git-path.md), 2026-11-04). The
clearing is built but **off** (`CLEAR_ESTABLISHED = False`): the recall check lost a malicious
sample, so turning it on is the owner's decision.
**Builds on:** [0010](0010-stage4-correlation-and-repo-comparison.md) (the tarball-vs-repo
comparison), [0002](0002-data-sources.md) (GitHub as a data source).
**Stage:** 4 ([stages/correlate.md](../stages/correlate.md), "Repository trust")

## Context

Stage 4 reports a version when any finding is MEDIUM or above. Install code is the commonest
MEDIUM: Stage 3's `npm.install-script-changed` and `npm.install-script-code`, and Stage 1's
`npm.install-hook` on a new package. For many of these releases, Stage 4's comparison already
shows that every code file is the repository's own, byte for byte, at the release's commit.
The comparison never asked whose repository that is, though. An attacker can create a
repository too.

What was measured (2026-11-04, live queue, two days of reports; scripts in
`~/kitsunox-scratch/git-path/`):

- **Repository metadata** for the 723 GitHub repositories behind 1,231 reported versions:
  - Clean matches to repositories that are not forks and are at least 30 days old: 1
    malicious, 90 benign. The malicious one, `@finzzcloud/baileys`, came from the attacker's
    own repository, which had 1 star.
  - Requiring at least 5 stars as well: 53 versions, and all 34 that were reviewed are
    benign.
- **What would be cleared.** Of those 53, 33 were reported by install-code findings alone.
  Every one of the 33 commits is on its repository's default branch (checked with the
  compare API). That is 2.7% of the 1,231, and the 20 reviewed are all benign.
- **Stars can be bought.** The attacker's repository `tavern-labs-ai/persona-ai-sdk` had 197
  stars three days after it was created. Requiring 30 days of age is what excludes it.
- **Recall on `vm-day1`** (3,444 malicious, 1,500 benign; `pipeline+4` with a per-sample
  dump, `~/kitsunox-scratch/git-path/recall/`):
  - 2,507 malicious samples are reported. Only 2 of them compare cleanly and are reported by
    install code alone.
  - `@uselagoon/ui-library@2.0.2` (repository from 2023, 0 stars) stays reported.
  - **`gina@0.7.1` would be cleared.** Its repository, `gina-io/gina`, was created in 2013
    and has 11 stars. The commit is on the default branch. DataDog labels the release
    malicious, reported only by `npm.install-script-changed`. This is the blind spot below,
    measured: the code is in the real repository.
  - On the benign side, 3 samples have the same shape. All three would stay reported:
    their repositories have 0 stars.
  - **Net: -1 malicious sample (2,507 → 2,506) for -33 live reports (-2.7%).** At 12 stars
    `gina` would stay reported and 26 live reports would be cleared. That threshold would be
    fitted to one sample, and a compromised repository can have any number of stars.

## Options

1. **A negative weight** for an established match. This clears nothing: every one of these
   versions has a MEDIUM finding, and any MEDIUM reports a version.
2. **Clear install-code findings when there is an established match** (chosen).
3. **Clear every MEDIUM when there is an established match.** This was not tried. Stage 2's
   and Stage 5's findings describe what the code does, so a match with the repository doesn't
   explain them.

## Decision

- **Facts:** with `GITHUB_TOKEN`, a clean comparison of a version that has a MEDIUM-or-above
  finding gets the repository's REST API facts, and a check that the release's commit is on
  the default branch. That is two requests per repository and commit per run. They go through
  `HttpFetcher`, are recorded for replay, and never record the token.
- **`repo.established-match`** (INFO): the comparison is clean, and the repository is not a
  fork or archived, is at least 30 days old at the release, has at least 5 stars, and has the
  commit on its default branch.
- **Decision (built, off until the owner turns it on):** a version with an established
  match is not reported if all of these hold:
  - its MEDIUM findings are all in `CLEARED_BY_REPO` (`npm.install-hook` at MEDIUM,
    `npm.install-script-changed`, `npm.install-script-code`);
  - it has no HIGH finding;
  - its score without those findings stays below `REPORT_SCORE`.
- `STAGE_VERSION` becomes 9.

## Consequences

- **Today:** the facts and the INFO finding appear in reports as reviewer evidence, and
  nothing changes in what is reported.
- **If turned on: fewer reports, but a small effect:** about 3% of reported versions on the
  live queue, for one `vm-day1` malicious sample.
  Most of the queue's noise has no clean match to clear: no repository, no commit or tag, or a
  monorepo.
- **The rule can't see a compromised repository.** A malicious commit pushed into a real
  repository matches cleanly, so its install code would be cleared. Watching commits (the
  proposal's Phase B) is meant to cover this. Until Phase B exists, the rule rests on the
  measured numbers alone.
- **Stage 5 never sees a cleared version.** It exports only reported versions.
- **Without a token, nothing changes.** If the API fails (rate limit, network), the version
  is reported, and the request is not retried.
- **The evaluation pins the API's answers** (`data/eval/github-api/`). They are as of the
  first evaluation that asked, not as of the release.

## Not adopted: commit matching for "no commit or tag" (proposal A.4)

This was measured before anything was built.
- **Scope:** 312 reported versions have a repository at least 30 days old but no `gitHead` or
  tag.
- **Method:** look for a commit before the publish time whose `package.json` (at the root,
  or in a directory named like the package) has the released version.
- **Result:** a commit was found for only 37 of them (12%), and one of those is malicious
  (`persona-ai-sdk`, from the attacker's own repository).
- **Why so few:** monorepo packages mostly never commit the released version (173 of 217):
  release tools set it at publish time.
- **Conclusion:** too little reach to build now.
