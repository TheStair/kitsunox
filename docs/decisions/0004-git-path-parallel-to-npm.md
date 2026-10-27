# 0004: A git-commit path, parallel to the npm path, after the npm workflow

**Date:** 2026-10-27
**Status:** Accepted
**Amends:** [0002](0002-data-sources.md), which set GitHub aside as a discovery source

## Context

Decision 0002 made the npm `_changes` feed the only discovery source and limited GitHub to the
Stage 4 repo comparison. The user's original intent was git-first:

1. watch recent commits on package repositories;
2. filter cheaply;
3. fetch the full repo when needed;
4. compare with what's published on npm.

That alternative was never put to them as an explicit option. They approved 0002 along with
other recommendations, and the gap only surfaced after Stage 0 was built.

## Decision

- **Two parallel discovery paths**, joined by correlation:
  - **npm path** (built): registry changes. Catches direct-to-npm publishes (account takeover,
    stolen tokens) and brand-new malicious packages with no repo.
  - **Git path** (to build): commits on the GitHub/GitLab repositories of popular npm packages,
    using the popularity watchlist as the repo list. Catches malicious commits/PRs, CI workflow
    tampering, and long-con contributor attacks, including before or without a release.
  - **Join:** when an npm release arrives for a watched repo, compare the tarball with the repo
    at the matching commit (the tarball-vs-repo signal).
- **Order (user's choice):** finish the npm workflow first, then add the git path.

## Consequences

- The `Ecosystem` contract stays. The git path needs a separate source contract
  (`GitHost`: GitHub, GitLab) that produces commit-level changes. Its design is deferred until
  that phase.
- Open questions for the git phase: polling budget (GitHub's API allows 5,000 requests/hour with
  a token, so ~63k repos need GH Archive or a smaller set), a read-only GitHub token, and
  GitLab coverage.
