# Kitsunox overview

Kitsunox is a deterministic, multi-stage pipeline that analyzes recent changes to open source
packages and flags likely **software supply chain attacks** for human review. The first target is
the npm ecosystem.

Each stage is cheaper and more over-inclusive than the one after it: metadata triage, static diff
heuristics, AST capability analysis, correlation (including published-tarball vs. git-repo
diffing), and later an optional Docker sandbox. Every flagged change gets a report showing which
named, weighted rules fired and the evidence behind them.

> **Status:** Stage 0 (ingest) works for npm. No detection stages yet. See
> [`devlog.md`](devlog.md) for current progress.

## Requirements

- [uv](https://docs.astral.sh/uv/) (it installs the pinned Python 3.14 automatically)

## Install and run

```sh
uv sync                              # create .venv and install locked dependencies
uv run kitsunox --help
uv run kitsunox ingest record        # Stage 0: collect the last 24h of npm releases
uv run kitsunox ingest replay <run>  # re-run a recorded run offline, check output is identical
```

Runs are written to `data/runs/<run_id>/`. See [stages/ingest.md](stages/ingest.md).

Secrets (e.g. a read-only GitHub token) go in `.env` in the project root. Copy
[`.env.example`](../.env.example) to start. `.env` is gitignored.

## Development checks

```sh
uv run ruff check
uv run ruff format --check
uv run mypy
uv run pytest             # tests marked `network` are skipped; run them with -m network
```

## Safety

Kitsunox never executes fetched package code on the host. Tarballs and source are downloaded and
extracted as data only. Raw downloads, caches and any known-malicious samples live under `data/`,
which is gitignored.

## Further reading

- [`architecture.md`](architecture.md): pipeline, data models, stage contracts
- [`threat-model.md`](threat-model.md): attack patterns and planned coverage
- [`evaluation.md`](evaluation.md): datasets, metrics, results log
- [`roadmap.md`](roadmap.md): phases and decisions
- [`stages/`](stages/): one page per pipeline stage
- [`decisions/`](decisions/): records of significant design choices
- [`devlog.md`](devlog.md): project journal
