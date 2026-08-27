# Kitsunox — Build Status

Snapshot: **2026-08-27**, branch `scaffold/ingestion-tier0` (uncommitted).

Related: [[Architecture]] · [[TODO]]

---

## Implementation pass 1 scope

From the project handoff's "immediate next steps": repo structure + stack, `_changes`
consumer + storage schema, historical-backfill scaffolding, and Tier 0 validated to fire
on a known incident. Tier 1 and Tier 2 are deliberately stubs.

Division of labour: **Claude scaffolds, the author builds the parts that carry real
engineering judgement** (routing logic, detection rules, evaluation).

---

## Status by module

| Module | Owner | Status | Notes |
|---|---|---|---|
| `config.py` | Claude | ✅ done | pydantic-settings, `.env` |
| `ir.py` | Claude | ✅ done | ecosystem-neutral IR (PackageRef, VersionMeta, FileDiff, PublishEvent, Finding, …) |
| `db/models.py` | Claude | ✅ done | 5 tables |
| `db/engine.py` | Claude | ✅ done | SQLite WAL + FK pragmas |
| `db/repo.py` | Claude | ✅ done | `Repository`, returns dataclasses only |
| `db/migrations/` | Claude | ✅ done | alembic, one revision `04f0133b1564` |
| `ingest/changes_feed.py` | Claude | ✅ done | poll loop, cursor resume, `resolve_start_seq` |
| `ingest/registry_client.py` | Claude | ✅ done | packument (full/abbrev), tarball (+`TarballUnavailable`), downloads, deps.dev |
| `analysis/tarball.py` | Claude | ✅ done | unpack + `diff_versions` + test helpers |
| `analysis/tier0/iocs.py` | Claude | ✅ done | version-aware; mirror-first, live-OSV fallback for direct pkg |
| `threatintel/sync.py` | Claude | ✅ done | streams OSV + OpenSSF into one `index.json` |
| `pipeline.py` | Claude | ✅ done | feed row → route → Tier 0 → persist; `_fallback_route` until prescore exists |
| `cli.py` | Claude | ✅ done | `db-init`, `intel-sync`, `listen`, `scan`, `backfill` |
| `analysis/tier1/` | — | 🔴 stub | docstring only |
| `analysis/tier2/` | — | 🔴 stub | docstring only |
| **`ingest/prescore.py`** | **author** | 🟡 stub | `route()` raises `NotImplementedError` → [[TODO#1. prescore.route\|TODO #1]] |
| **`analysis/tier0/patterns.py`** | **author** | 🟡 stub | `scan()` → [[TODO#2. tier0/patterns.scan\|TODO #2]] |
| **`analysis/tier0/heuristics.py`** | **author** | 🟡 stub | `check()` → [[TODO#3. tier0/heuristics.check\|TODO #3]] (`shannon_entropy` helper provided) |
| **`analysis/scanner.py`** | **author** | 🟡 wired, policy TODO | happy path done; `_decide_status` policy → [[TODO#4. scanner policy\|TODO #4]] |
| **`eval/incidents.py`** | **author** | 🟡 stub | `INCIDENTS` list seeded; `load_incident_labels_into_db()` → [[TODO#5. incident labels\|TODO #5]] |
| **`eval/backfill.py`** | **author** | 🟡 stub | report dataclasses done; `run_backfill()` → [[TODO#6. eval/backfill — THE GRADE GATE\|TODO #6]] |

---

## Tests

```
uv run pytest              # 19 passed, 12 xfailed, 3 deselected (network)
uv run pytest -m network   # 2 passed, 1 xfailed
```

| Test file | Purpose | State |
|---|---|---|
| `test_repo.py` | Repository round-trips, baseline accretion, label lookup | ✅ pass |
| `test_registry_client.py` | packument → `VersionMeta` parsing (respx-mocked) | ✅ pass |
| `test_changes_feed.py` | poll loop, cursor advance, `resolve_start_seq` | ✅ pass |
| `test_tarball_diff.py` | unpack + add/modify/remove diff | ✅ pass |
| `test_iocs.py` | IOC checker vs fake index (version-aware) | ✅ pass |
| `test_scanner_eventstream.py` | **`network`** — Tier 0 flags `event-stream@3.3.6` via IOC path; `3.3.4` clean | ✅ pass |
| `test_prescore.py` | bucket decisions | ⏳ `xfail(strict)` → [[TODO#1. prescore.route\|#1]] |
| `test_tier0_patterns.py` | rule_id / file / line for crafted inputs | ⏳ `xfail(strict)` → [[TODO#2. tier0/patterns.scan\|#2]] |
| `test_tier0_heuristics.py` | new-install-script, new-binary, non-registry dep | ⏳ `xfail(strict)` → [[TODO#3. tier0/heuristics.check\|#3]] |
| `test_backfill_eventstream.py` | **THE GATE** — `backfill --incident event-stream` detects it | ⏳ `xfail(strict)`, `network` → [[TODO#6. eval/backfill — THE GRADE GATE\|#6]] |

`xfail(strict=True)` means: **when you implement it correctly the test flips to a hard
failure** — that's your signal to delete the marker.

---

## Manually verified

```
$ kitsunox db-init            → schema up to date, 5 tables
$ kitsunox intel-sync         → index rebuilt, 440534 hits / 220249 packages
$ kitsunox listen --once --max-events 8   (KITSUNOX_FEED_START=now-3000)
                             → cursor advances, publish_event rows recorded, resumes on restart
$ kitsunox scan event-stream@3.3.6
                             → flagged / critical  tier0.ioc.known_malicious_package  (offline, from mirror)
                             → correctly notes "tarball unavailable" (version was unpublished)
$ kitsunox scan lodash@4.17.21
                             → clean  (tarball downloaded + diffed; patterns/heuristics noted as not implemented)
```

---

## Known rough edges (fine for a capstone, note them)

- `index.json` is ~58 MB and loaded whole into memory (~440k `LabelHit`s). Fine for one
  process; if it hurts, shard by package-name prefix or move to a SQLite table.
- `IOCChecker` dependency checks are **mirror-only by default** (`allow_live_deps=False`)
  — a live OSV query per dependency would be dozens of HTTP calls per event.
- `package_baseline.publish_cadence_days_median` is a cheap running estimate (mean of
  last two gaps), not a true median over full history.
- No real work queue — `pipeline.handle_change` calls `scanner.run_tier0` synchronously.
  Adequate at current volume.
- `git clone` of the OpenSSF repo fails on Windows (invalid paths); `intel-sync` uses the
  GitHub tarball instead.
