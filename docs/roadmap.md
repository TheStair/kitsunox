# Roadmap

> **Status as of 2026-10-27:** Phases 0–2 done. Stage 0 records and replays npm runs, with
> popularity from a weekly watchlist. Next: Phase 3, the evaluation harness.

## Phases

| Phase | Goal | Done when | Status |
|---|---|---|---|
| 0 | Scaffold | `ruff`, `mypy`, `pytest` gates pass; CLI entry point runs | ✅ done |
| 1 | Plan | Threat model, architecture, data sources, eval plan reviewed; open decisions below answered | ✅ done |
| 2 | Core + ingest | `core/` models and interfaces; caching HTTP client in `util/`; safe tarball extractor; npm `Ecosystem` adapter; Stage 0 produces `Change` records for a window and replays offline from the snapshot; popularity watchlist | ✅ done |
| 3 | Evaluation harness | Eval manifest format; loader for OSV labels and DataDog samples; benign sampler; `kitsunox eval` reports per-stage recall / pass-through into `evaluation.md` | ⬜ |
| 4 | Stage 1 metadata triage | Manifest-diff, install-hook, dependency, maintainer, publish-method and version-anomaly rules, each with tests and eval numbers | ⬜ |
| 5 | Stage 2 static heuristics | Changed-file diff; entropy, blob, URL/IP/webhook, dynamic-code keyword rules | ⬜ |
| 6 | Stage 3 AST capabilities | tree-sitter JS/TS parsing; per-file capability sets; capability-delta rules | ⬜ |
| 7 | Stage 4 correlation | Tarball-vs-repo diff; OSV/GHSA lookups; new-dependency reputation; combination rules and final score | ⬜ |
| 8 | Reporting | `report.json` → Markdown per candidate + `index.md`; `kitsunox run` end to end | ⬜ |
| 8b | Git path (parallel source) | Commits on GitHub/GitLab repos of watchlist packages → filter → full repo fetch when needed → join with npm releases. See [decision 0004](decisions/0004-git-path-parallel-to-npm.md) | ⬜ after the npm workflow |
| 9 | Prospective labeling | Scheduled ingest + cache retention; nightly join against new `MAL-` records to grow the eval set | ⬜ |
| 10 | Sandbox (optional) | Design doc and review **first**; then Docker runner for install hooks, no network or capture proxy | ⬜ |
| 11 | Extras (optional) | Local web viewer for reports; Claude-based analysis stage in `modules/`; second ecosystem (PyPI) | ⬜ |

The eval harness (Phase 3) deliberately comes before any detection stage, so every rule lands
with numbers attached.

## Open decisions

These shape Phase 2 onward. Decisions 1–4 were **accepted as recommended on 2026-10-27** (see the
devlog). Decision 5 is still open.

1. **Tarball-vs-repo scope.** ✅ *Accepted:* in scope from the first Stage 4 iteration, for
   changes that pass Stage 1 *and* have a GitHub repository URL. Compare the tarball against the
   repo at `gitHead` (fallback: the tag matching the version). Start with three checks:
   - `package.json` scripts and dependencies differ from the repo's
   - JS files in the tarball that don't exist in the repo, outside an allow-list of build-output
     paths
   - files present in both but with different content, outside the same allow-list

   Not attempted: rebuilding the package to compare build output.
2. **Definition of "recent".** ✅ *Accepted:* a run covers versions whose publish time
   (`time[version]`) is in `[as_of − 24h, as_of]`, with `as_of` an explicit run parameter
   (default: the `_changes` checkpoint time). Continuous mode = consecutive non-overlapping
   windows from the last `seq` checkpoint. Eval runs use fixed historical windows.
3. **How many packages to watch.** ✅ *Accepted, revised 2026-10-27:* all of npm through Stage 1
   (metadata is cheap), then forward to tarball-based stages if **either** the package is on the
   popularity **watchlist** (≥10k weekly downloads, built weekly from ecosyste.ms) **or** Stage 1
   fired any rule. This keeps shape B (new, unpopular, malicious) in view without downloading
   100k tarballs a day. The original "≥1k weekly or ≥10 dependents, looked up per change" was
   replaced after measurement: a 1k cutoff covered 57% of changes, and per-change lookups would
   take ~12h/day. See [decision 0003](decisions/0003-popularity-watchlist.md).
4. **Report format.** ✅ *Accepted:* `report.json` is the canonical, deterministic output. Markdown
   per candidate plus a summary `index.md` is rendered from it. HTML and the web viewer come
   later, from the same JSON.
5. **Blob retention.** *Open:* a full day of ingest is ~10 GB of compressed blobs. Proposed:
   keep packuments for 30 days (matches the benign-label delay); keep tarballs for anything
   forwarded past Stage 1 indefinitely (they become evaluation data).
6. **Benign-label delay.** *Open, proposed:* 30 days without a `MAL-`/GHSA record (see evaluation.md). Shorter
   means faster iteration, but the labels are noisier.
