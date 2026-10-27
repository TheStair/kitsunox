# Kitsunox dev log

Reverse-chronological. Newest entry first.

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
