# 0002: Data sources for "recent npm changes"

**Date:** 2026-10-27
**Status:** Accepted (2026-10-27)

## Context

Stage 0 has to discover what changed on npm recently, then gather enough metadata and content to
analyze each change. The sources must be free, scriptable, rate-limit friendly, and cacheable for
deterministic replay.

## What was checked (2026-10-27)

- **npm replication `_changes` feed:** `GET https://replicate.npmjs.com/registry/_changes`. The
  old CouchDB endpoints (`replicate.npmjs.com/_changes`, `skimdb`) were retired on 2025-05-29.
  Supported params: `since`, `limit` (default 1000, max 10000), `descending`, `doc_ids`.
  `include_docs`, `feed=continuous/longpoll` and `filter` are **gone**, so each result is only
  `{seq, id, rev}`. You paginate by passing the last `seq` as `since`. The root
  (`/registry/`) returns `update_seq` for bootstrapping. Verified live: `update_seq` ≈
  140.1M, `doc_count` ≈ 4.54M. A 20k-sequence window held ~6,000 packages, covering ≈80
  minutes.
- **Packuments:** `GET https://registry.npmjs.org/<name>` gives full metadata. Per version it
  includes `_npmUser` (with `trustedPublisher` and `approver` when applicable), `gitHead`,
  `scripts`, `dependencies`, `maintainers`, `dist.integrity`, `dist.attestations` and
  `dist.signatures`. The package-level `time` map holds publish times for every version. The
  abbreviated form (`Accept: application/vnd.npm.install-v1+json`) is smaller but lacks most of
  this, so it's only useful for a cheap pre-check.
- **Tarballs:** the `dist.tarball` URL, verified against `dist.integrity` (SHA-512).
- **Popularity:** `api.npmjs.org/downloads/point/last-week/<a>,<b>,...` (bulk works for unscoped
  names). `api.deps.dev/v3/systems/npm/packages/<name>` (versions, publish times, dependents,
  OpenSSF Scorecard via the project endpoint). Both are keyless.
- **Labels / known-bad:** OSV bulk export `osv-vulnerabilities.storage.googleapis.com/npm/all.zip`
  (includes `MAL-` records from `ossf/malicious-packages`); GitHub Advisory Database with
  `type=malware`.
- **GitHub:** REST/GraphQL with a read-only PAT (5,000 req/h). Used to fetch repo contents at a
  commit, not for discovery.

## Options for discovery

| Option | Pros | Cons |
|---|---|---|
| **A. npm `_changes` feed + packuments** | Authoritative, complete (every publish, including registry-only ones that never touch git), free, keyless, sequence numbers give exact resumable checkpoints | Only names in the feed, so it needs one packument fetch per changed package (~100k/day, some packuments are MBs). No timestamps in the feed itself. A package can appear once for several publishes (rev updates coalesce), so versions must be derived from `time` in the packument |
| B. GitHub API (events, releases, commits) | Sees code before it ships; rich author data | Misses the main attack path: malicious versions are typically published straight to the registry and never appear in git. Not a list of npm releases. Rate-limited |
| C. deps.dev / ecosyste.ms / libraries.io | Pre-joined metadata, dependents counts | Third-party lag (hours to days) works against "find new attacks". Coverage and freshness aren't under our control. Adds a dependency for discovery |
| D. Commercial feeds (Socket, Phylum, etc.) | Already curated | Not independent (it would be grading someone else's detector), license/cost issues, not reproducible |

## Decision

**Use A for discovery and metadata.** Use the other sources in supporting roles:

- **Discovery:** `_changes` feed, checkpointed by `seq`. A run's window is either a `seq` range
  or "versions whose `time[version]` falls in `[as_of − window, as_of]`".
- **Metadata:** full packuments, cached per run. The abbreviated packument can serve as a cheap
  first look if full-packument volume becomes a problem.
- **Content:** registry tarballs (Stage 2+), integrity-checked.
- **Popularity:** npm downloads API, with deps.dev for dependents count. Used for weighting and
  any popularity cutoff. *Superseded by [0003](0003-popularity-watchlist.md): a weekly watchlist
  from packages.ecosyste.ms; per-change downloads-API lookups are an optional fallback.*
- **Repo comparison (Stage 4):** GitHub archive at `gitHead`, or at the tag matching the
  version, via authenticated API with a cache. Requires a read-only PAT in `.env`.
- **Labels / known-bad:** OSV `MAL-` bulk export plus GHSA malware advisories.

## Consequences

- Stage 0 needs polite concurrency against `registry.npmjs.org` for ~100k packuments/day. npm
  documents no hard rate limit for reads, so we'll use bounded concurrency, backoff on
  429/5xx, and conditional requests (`ETag`/`If-None-Match`) where supported. The real limit is
  to be measured in Phase 2.
- Unpublished/removed versions disappear from packuments. Malicious versions are often taken down
  within hours, so **the cache is the only copy we'll have**. Caching tarballs of anything
  forwarded past Stage 1 is therefore also how we collect future evaluation data (see
  [evaluation.md](../evaluation.md)).
- GitHub is optional at runtime. Without a token, Stage 4 skips the repo diff and records that it
  did.
