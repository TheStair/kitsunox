# Kitsunox dev log

Reverse-chronological. Newest entry first.

## 2026-10-27: Popularity: per-change lookups abandoned for a weekly watchlist

**Stage(s):** Stage 0 ingest (popularity enrichment). Closes Phase 2.
**Context:** Stage 1's forward policy needs "is this package popular?" for every change to an
existing package. The plan (roadmap decision 3) was per-change lookups against the npm downloads
API, with a ≥1k weekly or ≥10 dependents cutoff. Full write-up:
[decision 0003](decisions/0003-popularity-watchlist.md).

### Decisions
- **Weekly watchlist from packages.ecosyste.ms** (user-approved): packages ranked by last-month
  downloads, paged until below the cutoff, saved as a small JSON list. Runs record the list's
  id and SHA-256, and replay verifies it. Per-change API lookups are kept as `--popularity api`.
- **Cutoff raised to 10k weekly** (user-approved): ≥43k monthly on the watchlist.
- **Dependents dropped as a criterion for now**: deps.dev only has them via a per-version
  `v3alpha` endpoint. Counts are stored in the watchlist for later.
- **Per-host request pacing in `HttpFetcher`** (`set_min_interval`): generic, so any throttled
  API can use it. Replays and cache hits are never paced.
- **Download counts for a closed period are cached across runs** (immutable), since they're
  final.

### Challenges
- **The npm downloads API throttles hard**: `429` with `retry-after: 0`. The first live run with
  8 threads had 64 of ~1,100 lookups fail after retries, and took 3m22s vs 34s without
  popularity.
  - **Resolution:** a burst test showed sequential requests (~2.4/s) never got a 429 while two
    parallel ones did almost at once, so requests are paced at 0.5 s. The next run had 0
    failures.
  - **Why it wasn't enough:** 88% of changed existing packages were scoped (946 of 1,075), and
    scoped names can't use bulk lookups. That run took 8.5 minutes, which is ~12h for a full day.
- **The planned 1k cutoff was far too low**: 57% of changed existing packages clear it (20% at
  10k, 8% at 100k).
- **ecosyste.ms pages are huge**: ~100–200 MB per 1,000 packages, with no field selection.
  gzip transfer is ~8× smaller. Raw pages go to a temporary blob store and are discarded.
- **Old run files no longer load** after the `Popularity` model changed: models forbid unknown
  fields, so scratch runs recorded earlier fail validation. No real data was affected, but
  records have **no schema version**. This needs fixing before data accumulates.

### Evaluation snapshot
- Watchlist vs API weekly counts on 1,638 packages: 92.2% agreement. The watchlist caught 221 of
  296 packages that the API showed at ≥10k/week (75%). Its misses are mostly fast risers or
  spikes. Mitigated by Stage 1 forwarding anything flagged; not yet measured against attacks.
- Ingest with watchlist: 38 s per ~1,250 packages (vs 8.5 min API mode), replay identical.

### Removed / abandoned
- **Per-change downloads-API popularity as the default**: ~12h/day of paced requests for a full
  day of npm. Kept as an opt-in mode.

### Open questions / next steps
- Add a schema version to persisted records (`Change`, `RunManifest`, `Watchlist`).
- Consider a bulk downloads-API top-up for unscoped packages to catch fast risers.
- Phase 3: evaluation harness.

## 2026-10-27: Phase 2, Stage 0 ingest with record/replay

**Stage(s):** Stage 0 ingest, plus core and util foundations
**Context:** Build the foundation every later stage depends on: data models, a fetch layer that
makes runs reproducible, a safe way to open untrusted tarballs, and the npm adapter. See
[stages/ingest.md](stages/ingest.md).

### Decisions
- **Snapshot fetcher instead of a plain HTTP cache** (`util/http.py`): each run records request
  key → content hash in `snapshot.json`; replay mode answers only from it and fails on a miss.
  A TTL cache was rejected because it gives "probably the same" inputs, not provably the same.
  Integrity-pinned responses (tarballs) are also indexed across runs, so they're downloaded once.
- **In-memory tarball extraction** (`util/archive.py`): no files written means no path-traversal
  or symlink attack surface on the host. Links, devices, FIFOs and unsafe paths are *reported*,
  not silently dropped, because a symlink to `~/.npmrc` inside a tarball is itself a signal.
  Trailing gzip data is rejected, since tools disagree on how to read it.
- **Previous version = highest lower semver published earlier**, falling back to publish order.
  This diffs backports against their own release line (tested: `1.1.1` after `2.0.0` → `1.1.0`).
- **Ecosystem contract uses feed positions, not time**: the npm feed has no timestamps, so
  `list_changes(since, until)` works in sequence numbers and the publish-time window is applied
  to packument `time` entries. This differs from the Phase 1 sketch; architecture.md is updated.
- **Rule/Stage contracts deferred to Stage 1**: there's no consumer yet, and guessing them now
  would mean revising them later.
- **No popularity yet**: deferred within Phase 2, because it isn't needed until the Stage 1
  forward policy.

### Challenges
- **Packument storage blew up**: the first live run stored **1.4 GB for 1,208 packages**, because
  packages with long version histories have multi-MB packuments. At ~100k packages a day that
  would be ~140 GB/day.
  - **Resolution:** zstd-compress blobs (stdlib `compression.zstd`, Python 3.14), still keyed by
    the hash of the uncompressed bytes.
  - **Why it worked:** the second live run stored **119 MB for 1,068 packages** (≈10× smaller),
    and the replay was still byte-identical. The abbreviated packument was considered and
    rejected: it lacks the per-version `time` map and `_npmUser`.
- **Extractor false positive on real tarballs**: a real package's tarball had a bare `package`
  directory entry, which was reported as an "unsafe path".
  - **Resolution:** skip directory entries before path validation. Directories are implied by
    file paths anyway.
- **Monorepo repository URLs** (`github.com/o/repo/sub/pkg.git`) weren't normalized.
  - **Resolution:** drop the sub-path. Covered by a parametrized test.
- **FIFO reported as "device"**: Python's `tarfile.isdev()` is also true for FIFOs. Caught by
  `test_unsafe_and_special_entries_are_reported_not_extracted`; fixed by checking FIFO first.

### Evaluation snapshot
- No detection yet, so no recall/FP numbers. Ingest health on two live runs: 0 skipped packages,
  59 of 60 random tarballs extracted cleanly (1 was a 404, removed after publish), replay
  identical both times.
- Live observations (one 2h sample of 1,821 changes, worth re-measuring):
  - 40% of new versions use trusted publishing and 34% carry provenance.
  - 2.5% are brand-new packages.
  - 1.6% have install scripts.
  - No trusted → manual publish downgrades were seen.

### Open questions / next steps
- Popularity enrichment (downloads API bulk for unscoped names; deps.dev for dependents).
- Blob retention policy (roadmap decision 5).
- Cross-run dedupe of changes re-emitted when a package is touched again.
- Measure npm read rate limits at full-day volume (only ~35 packages/s tried so far, with no 429s).
- Then Phase 3: the evaluation harness.

## 2026-10-27: Planning: threat model, architecture, data sources, evaluation

**Stage(s):** all (design only, no pipeline code)
**Context:** With the scaffold in place, we drafted the Phase 1 planning docs and settled the
four decisions that block Phase 2: [threat-model.md](threat-model.md),
[architecture.md](architecture.md), [evaluation.md](evaluation.md), [roadmap.md](roadmap.md),
and [decisions/0002-data-sources.md](decisions/0002-data-sources.md).

### Decisions
- **Discovery via the npm replication `_changes` feed + full packuments**: GitHub-based discovery
  was rejected because the main attack path (publishing straight to the registry) never touches
  git. Third-party aggregators (deps.dev, ecosyste.ms) were rejected for discovery because of
  lag; commercial feeds because they aren't independent or reproducible. GitHub, deps.dev and
  OSV stay in supporting roles. See [0002](decisions/0002-data-sources.md).
- **Split attacks into shape A (compromised existing package) and shape B (new malicious
  package)**: they need different signals (delta vs. absolute + name similarity). Recall is
  reported per shape so typosquat-heavy public datasets can't hide weak shape-A recall.
- **Publish-method change as a planned Stage 1 signal**: packuments now expose
  `_npmUser.trustedPublisher`, `approver`, and `dist.attestations`. A version published
  manually where earlier ones came through OIDC trusted publishing is cheap to detect. Expected
  to be high-precision, but **unproven until measured**. Provenance alone is not treated as an
  all-clear, since a hijacked CI workflow produces valid attestations.
- **Determinism by snapshot + pure analysis**: all fetches go through a caching client into a
  content-addressed snapshot; stages 1–4 never read the clock and use an explicit `as_of`.
- **Run ledger**: stages record cleared items instead of dropping them, so per-stage recall and
  pass-through can be computed.
- **Eval harness before any detection stage** (roadmap Phase 3), so every rule lands with numbers.
- **User decisions (all accepted as recommended):**
  1. Tarball-vs-repo: three checks (manifest, tarball-only JS, changed shared files) against the
     GitHub repo at `gitHead`/tag, with a build-output allow-list. Rebuilding packages is out of
     scope.
  2. "Recent" = versions published in `[as_of − 24h, as_of]`, with `as_of` explicit.
  3. Coverage: all changes through Stage 1. Tarball stages get packages above a popularity
     cutoff (start ≥1k weekly downloads or ≥10 dependents) **or** anything Stage 1 flagged.
  4. Reports: `report.json` canonical, Markdown per candidate + `index.md` rendered from it.

### Challenges
- **The npm replication API changed in 2025**: the old CouchDB `_changes` endpoint was retired
  on 2025-05-29. The new `replicate.npmjs.com/registry/_changes` has no `include_docs` and no
  streaming. Older tooling and many blog posts still describe the old API.
  - **Resolution:** probed the new endpoint live. Root `update_seq` ≈ 140.1M; a 20k-seq page
    held ~6,000 packages, covering ≈80 minutes. Designed Stage 0 around name-only changes plus a
    packument fetch per package (~100k/day).
  - **Why it worked:** verified directly against the live API, not just docs. The volume figure
    is a single sample and needs re-measuring in Phase 2.
- **Shape-A evaluation samples are scarce**: public datasets are mostly new malicious packages,
  and registries remove malicious versions fast, so the "previous benign + malicious" pair is
  rarely available.
  - **Resolution (planned):** a small curated incident set; **prospective labeling** (cache what
    we ingest, then join later against new `MAL-` records); synthetic injected cases reported
    separately. Unproven until Phase 3/9.

### Open questions / next steps
- Benign-label delay (proposed: 30 days) is still open.
- Which historical compromise samples are actually obtainable has not been checked.
- DataDog dataset license and current npm sample count need confirming before use.
- Real read rate limits for `registry.npmjs.org` at ~100k packuments/day: measure in Phase 2.
- Next: Phase 2, which covers `core/` models and interfaces, the caching HTTP client, the safe
  extractor, and the npm adapter for Stage 0. Ask before starting.

## 2026-10-27: Fresh start and project scaffold

**Stage(s):** none yet (project setup)
**Context:** Kitsunox is being rewritten from scratch as a master's capstone in Cybersecurity
Engineering. The goal is a deterministic, explainable pipeline that flags likely supply chain
attacks in recent npm releases. This session set up the repo and toolchain so later stages have a
working base with lint, type-check and test gates from day one.

### Decisions
- **Fresh rewrite, no code reuse from earlier attempts**: the project needs to be explainable and
  reproducible end to end for the capstone defense. Starting clean means every design choice is
  deliberate and documented here, instead of inherited. The README dropped the earlier "AI
  powered" framing: the pipeline is deterministic, and an LLM stage is an optional future
  extension.
- **Tooling stack**: Python 3.14 via uv, pydantic v2 for inter-stage records, mypy `--strict`
  added to the done gate, ruff including bandit (`S`) rules, network tests opt-in. Full rationale
  is in [decisions/0001-tooling-stack.md](decisions/0001-tooling-stack.md).
  - 3.15 was considered and declined for now: it's a few weeks old, and native wheels
    (pydantic-core, tree-sitter) tend to lag.
- **Scaffold before the planning docs**: CLAUDE.md lists scaffolding last, after the threat
  model, architecture and roadmap. We reordered so the "done" gate (ruff, mypy, pytest) exists
  before any real code is written. The planning docs are the next deliverable. No pipeline code
  was written.
- **Repo hygiene**: `data/` is gitignored before any downloads exist, so malicious samples can't
  be committed by accident. `CLAUDE.md` moved from `.claude/` (gitignored) to the repo root so
  the project instructions are version-controlled.

### Challenges
- **uv wasn't installed**: installed with Homebrew (uv 0.13.6). uv fetched CPython 3.14.10.

### Open questions / next steps
- Draft `docs/threat-model.md`, `docs/architecture.md` (Mermaid pipeline diagram) and
  `docs/roadmap.md`.
- Compare data sources for "recent npm changes" (registry changes feed, GitHub API, others) and
  recommend one.
- Propose the labeled evaluation set (OSV `MAL-` advisories, public malicious-package datasets,
  benign recent changes) and how to store it inertly.
- Decisions for the user:
  - Scope of tarball-vs-repo diffing.
  - How "recent" is defined.
  - All of npm vs. a popularity cutoff.
  - Report format.
