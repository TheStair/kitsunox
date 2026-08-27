# kitsunox

AI-assisted workflow to detect software supply chain attacks in open source package
registries — starting with npm.

Kitsunox continuously monitors registry publishes through a **tiered filtering funnel** so
that expensive LLM reasoning is reserved for genuinely ambiguous cases:

| Tier | What | LLM? | Runs on |
|---|---|---|---|
| pre-score | metadata-only routing (maintainer change, dormancy, version jump, popularity) | no | 100% of events |
| **Tier 0** | known-bad code constructs, IOC lookups, structural heuristics | no | routed events |
| Tier 1 | structural / metadata risk *scoring* | no | *(stub)* |
| Tier 2 | gated LLM triage → escalation, structured verdict + rationale | yes | *(stub)* |

## Status

Implementation pass 1 — ingestion + Tier 0 foundation. Docs (Obsidian vault in `docs/`):

- `docs/Architecture.md` — the funnel, data flow, schema, external APIs (with diagrams)
- `docs/Build Status.md` — what's implemented, test status, what's verified
- `docs/TODO.md` — the author-owned work, ordered, with contracts and acceptance criteria

`prescore`, Tier 0 `patterns`/`heuristics`, `scanner` policy, and `eval/*` are
author-owned stubs with `xfail(strict)` tests; everything else is scaffolded and passing.

## Quick start

```bash
uv sync --extra dev
uv run kitsunox db-init            # create the SQLite schema
uv run kitsunox intel-sync         # mirror OSV + OpenSSF malicious-packages
uv run kitsunox listen --once      # drain the current _changes backlog and exit
uv run kitsunox scan event-stream@3.3.6
uv run kitsunox backfill --incident event-stream
```

Config is via env vars (`KITSUNOX_*`) or a local `.env` — see `.env.example`.

## Layout

```
kitsunox/
  config.py          settings
  ir.py              ecosystem-neutral intermediate representation
  db/                SQLAlchemy models + Repository (the only persistence seam) + alembic
  ingest/            _changes poll loop, registry client, pre-score router
  analysis/          tarball diffing, Tier 0 (iocs/patterns/heuristics), scanner
  threatintel/       OSV + OpenSSF mirror sync and lookup
  eval/              historical incident backfill + scoring
  pipeline.py        one change row -> pre-score -> Tier 0 -> persist
```

## Tests

```bash
uv run pytest                 # unit tests (no network)
uv run pytest -m network      # integration tests against the live npm registry + OSV
```

Author-owned modules ship with `xfail(strict=True)` tests that pin the expected
behaviour; implementing them correctly turns the xfail into a hard failure — delete the
marker at that point.
