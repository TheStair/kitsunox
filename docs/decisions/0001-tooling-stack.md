# 0001: Tooling stack and package layout

**Date:** 2026-10-27
**Status:** Accepted

## Context

Kitsunox is a from-scratch rewrite. Before writing any pipeline code we need a toolchain that
makes the project reproducible (same input + same rule versions → same output) and keeps the
records passed between stages well defined. CLAUDE.md already fixed uv, ruff, pytest, type hints
and a typer CLI; this note covers the choices it left open.

## Decisions

### Python 3.14 (not 3.15)

- **Options:** 3.13, 3.14, 3.15.
- **Chosen:** 3.14, managed by uv (`.python-version`, `requires-python = ">=3.14"`).
- **Why:** 3.15 was released in October 2026. Native-extension wheels the pipeline will soon
  depend on (pydantic-core, tree-sitter and its grammars) often trail a new CPython release by
  weeks or months. 3.14 has had a year for the ecosystem to catch up. 3.13 would be safer still
  but gives up nothing we need from 3.14.
- **Revisit:** when tree-sitter is added (Stage 3), or once 3.15 wheels are routine. It's a
  one-line change plus `uv lock`.

### pydantic v2 for inter-stage records

- **Options:** stdlib `dataclasses`, pydantic v2.
- **Chosen:** pydantic v2.
- **Why:** stages consume untrusted JSON from the npm registry and GitHub, so validating at the
  boundary catches malformed or hostile data early. pydantic also gives JSON round-tripping for
  free, which we need to cache stage outputs and store evaluation fixtures. Dataclasses would
  mean hand-written (and hand-tested) serialization and validation.

### mypy `--strict` in the "done" gate

- **Options:** no type checker (ruff only), pyright, mypy.
- **Chosen:** mypy strict, with the `pydantic.mypy` plugin, over `src/` and `tests/`.
- **Why:** CLAUDE.md requires type hints everywhere; without a checker that requirement isn't
  enforced. mypy is mature and has first-class pydantic support.

### uv_build backend, src layout

`uv init --package --build-backend uv` gives a `src/kitsunox/` layout. The src layout stops tests
from accidentally importing the working tree instead of the installed package. `uv_build` avoids
a separate build tool.

### Lint rules

ruff with `E, W, F, I, B, UP, SIM, RUF, S`, line length 100. `S` (flake8-bandit) is on
deliberately: a security tool should hold its own code to that standard. `S101` (`assert`) is
allowed in tests.

### Network tests are opt-in

pytest registers a `network` marker and deselects it by default (`-m 'not network'`), so the
default test run is offline and deterministic.

### Where rules live

- `kitsunox/rules/`: ecosystem-agnostic rules (entropy, hardcoded URLs/IPs, `eval` and dynamic
  code).
- `kitsunox/ecosystems/<eco>/rules/`: rules that read ecosystem concepts (npm `package.json`
  scripts, npm maintainers).

Both implement the same rule interface from `kitsunox/core/` (not yet written).

### Directories deferred

`modules/` (optional add-ons such as a future LLM stage) and `sandbox/` (Stage 5 Docker runner)
from CLAUDE.md's suggested layout aren't created until they have content. The sandbox needs a
design review before any code exists. (2026-10-30: Stage 5 uses OpenSSF package-analysis instead
of a runner of our own, so `sandbox/` is not created; see 0014.)

## Consequences

- Contributors need only uv. It fetches the pinned Python and locked dependencies.
- Every change must pass `ruff check`, `ruff format --check`, `mypy` and `pytest`.
- Moving to Python 3.15 later requires checking that the native wheels exist first.
