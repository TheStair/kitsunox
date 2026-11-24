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

## Addendum (2026-11-24): 1,000-item pages after the API capped pagination at page 100

On 2026-11-19 packages.ecosyste.ms began answering HTTP 400 past page 100 (upstream
ecosyste-ms/packages commit d91434e, PR #1972; the error points bulk users to its open-data
exports). A build needed ~132 pages of 500, so every rebuild since the VM restart on 11-23
failed at page 101: 9 failures with HTTP 400 by 16:23Z on 11-24, plus one HTTP 500 (five
attempts at page 99). Each one cost
a tick ~13 minutes and ~0.8 GB of downloads. Collection kept using the 2026-11-15 list
(65,855 packages), as designed.

- **Decision:** `PAGE_SIZE` = 1,000 (the API's maximum, pagy `limit_max`) and `MAX_PAGES` =
  100 (its cap). A build is now ~66 requests, with 50% headroom before the cap. Past it, the
  build fails with "did not reach the cutoff within 100 pages" instead of an HTTP 400.
  - A 1,000-item page is ~200 MB decoded (more near the top of the ranking), over the
    fetcher's default 256 MiB response cap, which fails without a retry. The watchlist fetch
    now allows 1 GiB (`WATCHLIST_MAX_BYTES`, next to `WATCHLIST_TIMEOUT`).
  - pagy silently clamps `per_page` to `limit_max`, and our page size now equals it. A short
    page before the cutoff therefore fails the build: a cut to `limit_max` would otherwise
    end it after one page and save a tiny list that looks valid, used for a week.
- **Alternatives:**
  - The open-data export: the supported bulk path, but a new format and parser, too large a
    change during the freeze.
  - Accepting a list cut off at 50,000 packages: this silently raises the cutoff and drops
    ~16k watched packages.
  - Keeping the 11-15 list through window B: popularity would be 17 days stale by 12-02, and
    the hourly failures would continue unless rebuilds were also held.
- **Not a rule change:** the watchlist is weekly input data, and each run's ledger records
  which list it used. The rebuild lands before window B starts (2026-11-25 00:00Z). The next
  weekly rebuild falls inside window B, as the design always had it.
- **Unproven:** whether 1,000-item pages stall more often than 500-item ones. Each request
  is twice the server work, and upstream runs rack-timeout. The 11-14/15 build already took 10
  failed attempts (7 read timeouts, 3 HTTP 500s) before one succeeded. The 120 s read timeout
  and the fetcher's retries still apply. If a build fails, the previous list keeps working.
