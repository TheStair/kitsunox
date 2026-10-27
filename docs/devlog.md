# Kitsunox dev log

Reverse-chronological. Newest entry first.

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
