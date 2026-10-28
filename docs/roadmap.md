# Roadmap

> **Status as of 2026-10-27:** Phases 0–3 done (Phase 3 in its light form). Stage 0 records and
> replays npm runs, with popularity from a weekly watchlist. The first full 24h run gave 109,497
> changes and 0 malicious samples after label hygiene: everything malicious was taken down
> before the run fetched it. Hourly chained collection (Phase 9) has been running since then, so the malicious set can now
> grow. Stage 1 is done and was evaluated on DataDog samples (0007). Stage 2 runs hourly in
> `collect` with hybrid routing (0008) and captures tarballs. Next: Stage 3 AST capabilities.

## Phases

| Phase | Goal | Done when | Status |
|---|---|---|---|
| 0 | Scaffold | `ruff`, `mypy`, `pytest` gates pass; CLI entry point runs | ✅ done |
| 1 | Plan | Threat model, architecture, data sources, eval plan reviewed; open decisions below answered | ✅ done |
| 2 | Core + ingest | `core/` models and interfaces; caching HTTP client in `util/`; safe tarball extractor; npm `Ecosystem` adapter; Stage 0 produces `Change` records for a window and replays offline from the snapshot; popularity watchlist | ✅ done |
| 3 | Evaluation harness | Eval manifest format; loader for OSV labels and DataDog samples; benign sampler; `kitsunox eval` reports per-stage recall / pass-through into `evaluation.md` | ✅ light version (OSV labels, datasets from our runs, baselines). DataDog samples deferred |
| 4 | Stage 1 metadata triage | Manifest-diff, install-hook, dependency, maintainer, publish-method and version-anomaly rules, each with tests and eval numbers | ✅ 8 rules; 80% / 58% first-release recall (A / B, DataDog) at 0.6% benign pass-through. See [stages/triage.md](stages/triage.md) |
| 5 | Stage 2 static heuristics | Changed-file diff; entropy, blob, URL/IP/webhook, dynamic-code keyword rules | ✅ 10 rules; runs hourly in `collect`. End to end (`pipeline`): 86.0% / 66.0% (A / B) at 0.7% benign. Routing: [0008](decisions/0008-stage2-routing-and-tarball-capture.md). See [stages/static.md](stages/static.md) |
| 6 | Stage 3 AST capabilities | tree-sitter JS/TS parsing; per-file capability sets; capability-delta rules | ✅ parser, profiles, deltas, 2 rules; runs in `collect`. Alone 80.6% A at 0.2% benign; end to end (`pipeline+3`) 89.7% / 66.0% at 0.8%. See [stages/ast.md](stages/ast.md) |
| 7 | Stage 4 correlation | Tarball-vs-repo diff; OSV/GHSA lookups; new-dependency reputation; combination rules and final score | ⬜ |
| 8 | Reporting | `report.json` → Markdown per candidate + `index.md`; `kitsunox run` end to end | ⬜ |
| 8b | Git path (parallel source) | Commits on GitHub/GitLab repos of watchlist packages → filter → full repo fetch when needed → join with npm releases. See [decision 0004](decisions/0004-git-path-parallel-to-npm.md) | ⬜ after the npm workflow |
| 9 | Prospective labeling | Scheduled ingest + cache retention; nightly join against new `MAL-` records to grow the eval set | 🟡 hourly `kitsunox collect` (launchd) + retention running since 2026-10-27, with Stages 1–2 and tarball capture since the evening of 2026-10-27; datasets are rebuilt by hand with `eval build` |
| 10 | Sandbox (optional) | Design doc and review **first**; then Docker runner for install hooks, no network or capture proxy | ⬜ Planned host (2026-10-28): the whole pipeline moves to a VM on the user's desktop, with the sandbox (Docker) inside it; not cloud (provider terms on malware, cost). The VM holds `data/` and `.env`, so: no network or capture proxy only for detonation containers, read-only input / write-only output mounts, hardened runtime (rootless Docker or gVisor), minimal read-only secrets, VM snapshots for rollback |
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
5. **Blob retention.** ✅ *Accepted 2026-10-27:* full replayability for 7 days. After that, keep
   `changes.jsonl` (compressed) and the packuments of packages named in OSV records, and delete
   the other blobs. See [0006](decisions/0006-scheduled-collection-and-retention.md). Tarball
   retention is still open: tarballs aren't captured yet.
6. **Benign-label delay.** *Open, proposed:* 30 days without a `MAL-`/GHSA record (see evaluation.md). Shorter
   means faster iteration, but the labels are noisier.
