# 0003: Popularity from a weekly watchlist, not per-change lookups

**Date:** 2026-10-27
**Status:** Accepted
**Revises:** roadmap decision 3 (popularity cutoff) and the popularity source in
[0002](0002-data-sources.md)

## Context

Roadmap decision 3 sends a change to the tarball stages if Stage 1 flags it **or** the package is
popular. "Popular" was defined as ≥1,000 weekly downloads or ≥10 dependents, looked up per change
from the npm downloads API (and deps.dev for dependents).

Measured on 2026-10-27 while implementing it:

- **Rate limit:** the npm downloads API throttles bursts with `HTTP 429` and `retry-after: 0`.
  Sequential requests (~2.4/s) never got a 429; two in parallel did almost immediately. Without
  pacing, a run of ~1,150 packages had 64 failed lookups (after 5 retries each).
- **Scoped names:** bulk lookups (128 names) reject scoped names, and **88% of changed existing
  packages were scoped** (946 of 1,075). With pacing a run had 0 failures but took 8.5 minutes
  for ~1,100 packages. A full day (~100k packages) would need about **12 hours** of lookups.
- **Dependents:** deps.dev only exposes dependent counts per version through a `v3alpha`
  endpoint, which would add another ~100k calls a day to an unstable API.
- **Cutoff:** of changed existing packages, ≥1k weekly = **57%**, ≥10k = **20%**, ≥100k = **8%**.
  A 1k cutoff would send most changes to the expensive stages without any signal.

## Options

1. **Per-change lookups, paced and cached** (built first). Correct, but ~12h/day cold, and
   bound to one API's limits.
2. **Look up only changes Stage 1 didn't flag.** Most changes aren't flagged, so it barely helps.
3. **Weekly watchlist** of packages above the cutoff, from a ranked third-party listing.
   Per-change popularity becomes a set lookup.

## Decision

- **Option 3.** `kitsunox watchlist build` pages through
  `packages.ecosyste.ms/api/v1/registries/npmjs.org/packages?sort=downloads&order=desc` (500 per
  page) until last-month downloads fall below the cutoff. It saves `{name → monthly downloads,
  dependents}` to `data/watchlists/npm/<id>.json`.
- **Cutoff: 10k weekly**, expressed as ≥43,000 last-month downloads (10k × 30/7), because
  ecosyste.ms reports monthly counts.
- **Provenance:** each run records the watchlist id and SHA-256. A run uses the newest list built
  no later than its `as_of`. Replay reloads that exact file and fails if it changed.
- **Per-change API lookups stay available** with `--popularity api` (paced at 0.5 s/request, with
  successful responses cached across runs because counts for a closed period are final).
  `--popularity none` disables popularity.
- **Dependents aren't used as a criterion for now.** The list is ranked by downloads only, so a
  package with many dependents but few downloads is not watched. The dependents count is stored
  for each watched package, for later use.

## Measured after implementing (2026-10-27)

- First build: **63,174 npm packages** at ≥43k monthly downloads, 12.4 minutes, 4.2 MB saved.
- Same-sized live ingest: **38 s** in watchlist mode vs **8.5 min** in API mode, with 0 failed
  lookups and an identical replay. 11% of changes to existing packages were from watched
  packages.
- **Agreement with the API's weekly counts** on 1,638 packages from earlier runs: 92.2%.
  - **Missed by the watchlist:** 75 packages at ≥10k weekly that aren't on the list (recall 75%:
    221 of 296). These are mostly fast risers or download spikes, e.g. platform-binary packages
    jumping to ~500k/week. The watchlist lags because it is built from last month's counts.
  - **Watched but now below the cutoff:** 53 packages.
  - **Why the gap is tolerable for now:** a miss only matters when Stage 1 also finds nothing,
    because flagged changes are forwarded regardless.
  - **Possible top-up, not built:** a bulk downloads-API check for *unscoped* names only
    (128 per request).

## Consequences

- Stage 0 makes no per-change popularity requests. A watchlist build transfers roughly 1 GB
  (gzip-compressed; ~125 pages of ~100 MB uncompressed each, since the API has no field
  selection) and takes on the order of 10 minutes. The raw pages are discarded.
- Popularity is up to a week stale, and ecosyste.ms's own sync adds more lag. Acceptable: the
  question is "is this a widely used package?", which changes slowly.
- New third-party dependency: ecosyste.ms data is CC BY-SA 4.0. It is only used as an internal
  filter and is credited here and in the stage docs.
- If ecosyste.ms is unavailable, the previous watchlist keeps working. `--popularity api` is the
  fallback.
