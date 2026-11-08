# Proposal: stream Stages 0-3 from disk (bounded memory)

> **Status:** proposed 2026-11-08. **Steps 1-2 implemented 2026-11-08**: step 1 (`collect` +
> retention) in `cd7c7b1`, step 2 (Stage 0's streaming digest) in the commit after it. Steps
> 3-7 are not implemented (see section 7 and the devlog). The measurements below were taken
> read-only on `20261107T163310Z-npm` (405,710 changes, the 4-day catch-up) before any code
> changed. Each step is a separate task (one stage per task), and each needs the owner's
> go-ahead.

## Summary

- **Why.** On the 4-day run, Stage 0 peaked at 27.6 GB RSS, triage at 17 GB, Stage 2 at
  21-23 GB, and Stage 3 at 25.3 GB, all on a 30 GB VM. Slicing catch-ups to ~95k changes
  (`MAX_RUN_FEED_SPAN`) makes a run smaller. It does not make any of these stages bounded.
- **What holds the memory (measured).** Four things:
  1. A `Change` takes **31.8 KB as objects**, 4.5 times its 7.0 KB JSON line.
  2. Stage 0's **`changes_digest`** builds the whole run as one string. That string is
     UCS-4 as soon as any line holds an emoji (737 lines in this run do), so it takes 4 bytes a
     character. The digest step alone peaks at **6.2× the file size in touched memory**,
     ~18 GB for this run. Stage 0's objects add 12.9 GB more.
  3. **Every `*_run` returns its whole output** (`triage_run`: all candidates; `static_run`
     and `ast_run`: all batches).
  4. **`collect.run_stages` keeps each return value alive while the next stage runs.** Stage 3
     on this run therefore started with triage's 13.4 GB and Stage 2's 7.8 GB still held. That is
     consistent with its 25.3 GB. By the same model, Stage 4 would start with ~29 GB held when
     Stages 1-3 ran in the same tick.
- **What doesn't.** The snapshot `entries` dict is 1.55 KB an entry: 185 MB for Stage 0's
  119k packuments and 294 MB for Stage 2's 185k tarballs. That is not worth splitting.
- **Proposal.** Write each stage's output as it goes, in the order it is written today, so
  every output file stays **byte-identical**:
  - Stage 0 hashes line by line. A streamed digest over the recorded run gives the
    manifest's `changes_sha256`, at 30 MB RSS in 11 s.
  - Triage groups consecutive lines. `changes.jsonl` is sorted and every package's lines are
    contiguous: checked over all 405,710 lines.
  - Stages 2 and 3 read their input through `LineFile` and write through a bounded, ordered
    worker map.
  - Expected peaks after the change: about 1 GB a stage, typically, for both 100k and 400k
    changes. The worst case is set by per-worker packuments and file trees, not by run size.
- **Do first** (not stages, small): drop stage results in `collect.run_stages` after counting,
  and stream `retention._prune_run`. Pruning the 4-day run is due after 2026-11-09 16:33Z.
  Today that prune would load all 405,710 changes (~13 GB) plus the 2.9 GB file.

## 1. Measurements

Every number is from `20261107T163310Z-npm`, read-only, under
`systemd-run -p MemoryMax=3G`. Object sizes come from `tracemalloc` on a strided sample: every
100th change (4,058 changes) and every 10th batch (4,272 batches, 19,651 versions).

| What | Measured |
|---|---|
| `changes.jsonl` | 2.94 GB, 405,710 lines, mean 7,249 B, max 4.7 MB; 114,661 packages |
| `Change` as objects | 31.8 KB each (4.51× the line); parse 0.50 ms |
| `Candidate` over the same `Change` | +1.2 KB (findings, decision); triage 0.08 ms |
| `batches.jsonl` / `static.jsonl` / `ast.jsonl` | 1.59 / 1.67 / 1.68 GB, 42,719 batches each; objects 4.55× / 4.65× / 4.68× the bytes (35-39 KB a version) |
| `changes_digest` on 8,116 changes (one UCS-4 line included) | line strings 1.17×, joined string 4.00×, encoded 1.00× the file bytes; `tracemalloc` peak 9.16× (the UTF-8 encoder's over-allocation, mostly never touched) |
| Lines with non-ASCII / UCS-2 / UCS-4 characters | 62,019 / 56,444 / 737 (first UCS-4 line: no. 2,680) |
| Streamed digest from the files | equals the manifest's `00652635...`; 30 MB RSS, 11 s |
| `snapshot.json` (Stage 0) | 48.8 MB, 119,389 entries, 185 MB as objects (234 MB peak to load) |
| `static-snapshot.json` | 83.7 MB, 184,617 entries, 294 MB as objects (378 MB peak) |
| Packuments in the run | p50 64 KB, p99 8.6 MB, max 78.5 MB (`weboptimizer`); parsing that one: 266 MB, peak 423 MB |
| Tarballs in the run | p50 104 KB, p99 5.8 MB, max 15.9 MB |
| Largest package group | `litmus-cli` 1,148 versions (7.4 MB of lines); `@astryxdesign/core` 18.5 MB of lines (~85 MB as objects) |
| Order | `changes.jsonl`: 0 lines out of (ecosystem, name, version) order, 0 packages non-contiguous; `batches.jsonl`: by (ecosystem, name) |

Packages per change: 3.5 on this run, 1.7 on an hourly run (`20261107T222723Z-npm`: 16,589
changes, 9,937 packages).

## 2. What each stage holds today, and why

The model below uses the measured per-record sizes. The "measured" column is RSS, which was
lower than the model because the VM swapped (7 GB of swap; `VmHWM` counts only resident pages).

| Stage | Held for the whole run | 100k changes | 400k changes | Measured (405k) |
|---|---|---|---|---|
| 0 ingest | every `Change` (31.8 KB) + digest strings (~45 KB a change) | ~7.7 GB | ~31 GB | 27.6 GB |
| 1 triage | every `Change` + `Candidate` (33 KB) | ~3.3 GB | ~13.4 GB | 17 GB |
| 2 static, alone | input lines (1×) + all output batches (4.65×) + snapshot | ~2.4 GB | ~9.7 GB | |
| 2 static, in `collect` | + triage's candidates still held | ~5.8 GB | ~23 GB | 21-23 GB |
| 3 ast, alone | input lines + all output batches + a throwaway snapshot | ~2.5 GB | ~9.9 GB | finished when resumed alone |
| 3 ast, in `collect` | + candidates + Stage 2's batches | ~7.8 GB | ~31 GB | 25.3 GB, then failed (bad blob) |
| 4, in `collect` | starts with Stages 1-3's results held | +~7.3 GB | +~29 GB | |

### Stage 0 (`stages/ingest.py: run_ingest`, `core/run.py: record_ingest`)

- `outcomes = list(pool.map(build, stubs))` keeps every package's `PackageChanges`. Then
  `changes` (all of them), `_with_popularity` (one `model_copy` each, which is shallow), and a
  sorted tuple. **Why:** the output is sorted by `Change.sort_key`. Popularity is one
  `lookup` over every non-new package name; for the downloads-API source that call sets
  how the requests are grouped. `feed_start_estimate` needs every package's `modified_at`. The
  degraded check must pass before anything is written.
- `changes_digest(result)` builds `[c.model_dump_json() for c in changes]`, joins it, and encodes
  it: 1.17× + 4× + 1× the file size. **Why:** `changes_sha256` is `sha256("\n".join(lines))`
  over changes, then skipped. `kitsunox ingest replay` recomputes it the same way, so
  **replaying the 4-day run today needs ~31 GB and cannot finish on the VM**.
- **Not a big holder:**
  - the `Snapshot` (1.55 KB a fetched URL);
  - the stubs (one per package, sorted by name by `list_changes`; retry items are appended
    unsorted);
  - per worker, one packument being parsed (≤ ~0.5 GB for the largest). This one is
    transient, but 8 workers can coincide.

### Stage 1 (`stages/triage.py: triage_run`)

- `read_changes` builds the full list, then `candidates` (a tuple), then `batch_forwarded`
  groups them in a dict by package. **Why:** grouping. The rules themselves need nothing beyond
  one change and `ctx.as_of` (`RuleContext` has only `as_of`).
- Determinism: `triage.jsonl` keeps the change order. `batches.jsonl` is sorted by
  (ecosystem, name), and each batch is sorted by `_publish_order`.

### Stage 2 (`stages/static.py: static_run`, `record_static`)

- `lines = batches.jsonl.read_bytes().splitlines()` (the whole file, briefly twice).
  `tuple(pool.map(...))` submits all 42,719 tasks and keeps every output batch until
  `write_jsonl`, and `record_static` returns them. **Why:** the output is in input order, and
  `collect` counts decisions and calls `needs_retry` on the result.
- Per worker (not run-sized): the base tree, one version tree, `BaseFiles`, the `seen` set.
  A tree is bounded by `ExtractLimits` (512 MB extracted) and not by the declared size, so a
  lying manifest can make one worker hold ~1 GB.
- `static-snapshot.json`: 294 MB at 185k tarballs. It must stay complete, because retention
  keeps the blobs it lists.

### Stage 3 (`stages/ast.py: ast_run`, `record_ast`)

- It holds the same way Stage 2 does: all of `static.jsonl` as lines, plus every output batch.
  Within a batch, `profiles` keeps each version's `Profile` and install files, because a later
  version's `previous` may be any earlier one.
- `record_ast` passes a fresh `Snapshot()` that nobody saves. Every tarball found through the
  immutable index is still added to it (`HttpFetcher.get`), so it grows to the size of Stage 2's
  snapshot (~0.3 GB) for nothing.

### Outside the stages

- `collect.run_stages` keeps `candidates`, `batches` and `coded` alive until it returns (see
  the table).
- `collect._resume_from` runs `static.read_bytes().splitlines()` and parses every batch
  (3.3 GB of bytes at 405k), for every pending run, every tick.
- `retention._prune_run` calls `read_changes` (every `Change`) and
  `zstd.compress(plain.read_bytes())`: ~16 GB for the 4-day run. That run is due for pruning
  after 2026-11-09 16:33Z.
- `evaluation/dataset.py: iter_run_changes` uses `read_changes`, so one whole run per run
  (eval only; `iter_changes` exists).

## 3. Design

### Shared helpers

- **`ordered_map(pool, fn, items, *, max_pending, cost=None, max_cost=None)`** (new, in
  `util/`). It submits ahead while fewer than `max_pending` results are outstanding and their
  summed `cost` (e.g. the input line's length) is under `max_cost`, and it yields results in
  input order. One item always runs, even when it alone is over `max_cost`.
  - The window slides, unlike `correlate._in_order`'s barrier windows, so one slow batch
    doesn't idle the other workers.
  - Output order never depends on completion order.
  - Stage 4 can switch to it later (see contract changes).
- **`JsonlWriter`** (new, in `util/files.py`). It writes `.<name>.tmp`, fsyncs and renames on
  success, so a killed stage never leaves a short or empty output. `20261103T160330Z-npm`
  still has the empty `triage.jsonl` the 2026-11-03 crash left. It can feed an optional
  running digest (below).
- **`LineFile`** (exists): input by offset, 16 B a line.

### Stage 0

1. **Streaming digest** (the minimal change). `changes_digest` hashes each
   `model_dump_json().encode()` and puts `b"\n"` between lines: the same bytes as the join.
   This removes ~45 KB a change (~18 GB at 405k) and keeps `replay` byte-identical.
2. **Write in final order while fetching.**
   - Sort the stubs (feed plus retry) by name before mapping. The output is unchanged: the
     feed stubs are already sorted, the output was re-sorted anyway, `skipped` and `modified`
     are sorted, and `packages_seen` is a count.
   - Run `build` through `ordered_map` (e.g. `max_pending` = 4 × workers). For each outcome
     in order, sort its changes by version and write them. `Packument` already checks
     `name == expected_name`, so every change of an outcome sorts under its stub's name, and
     concatenating the groups equals the global `sort_key` order. Assert that names are unique
     and non-decreasing, and raise on a violation: it would be a bug, not hostile data.
   - Write to `runs/.<run_id>.partial/` and rename it to `runs/<run_id>/` only after the
     degraded check and the manifest. "Nothing written on `IngestDegradedError`" stays true
     for the run directory. Prune deletes stale `.partial` directories (it holds the lock).
   - **Popularity.**
     - Watchlist source (what `collect` uses): pure. Look up each window's names as they are
       written; same values.
     - Downloads-API source: its requests are grouped over the whole sorted name list
       (`DOWNLOADS_BULK_LIMIT`). Keep exact request keys by writing a spool without
       popularity, doing the one lookup, then rewriting the spool. That is one more parse and
       dump of every change (~0.7 ms each), for API mode only.
     - The `PopularitySource` protocol gains a flag saying which kind it is.
   - Keep in memory only: `modified` (one datetime per package), `skipped`, the names seen,
     the snapshot.
   - **`IngestResult` changes**: instead of `changes: tuple[Change, ...]` it carries
     `change_count`, `changes_sha256` and the written path. Replay writes to a temporary file,
     or only hashes, and compares the digest. A small `ChangeFile` (a `LineFile` of `Change`,
     like `CandidateFile`) keeps tests and callers that iterate changes working.
3. **Expected peak:**
   - snapshot ~0.05 GB (100k changes, ~30k packages) or ~0.19 GB (400k);
   - window and popularity under 0.2 GB;
   - packument parsing per worker: typically a few MB, ≤ 0.42 GB each.
   - Overall: **~0.5 GB typical at both sizes, ≤ ~4 GB worst case** (8 huge packuments at once).
     A `PACKUMENTS_IN_MEMORY`-style slot, as Stage 4 has, would cap that if wanted.

### Stage 1

- Read `iter_changes` and group consecutive changes by (ecosystem, name). For each change:
  `triage`, then write its `triage.jsonl` line. At the end of each group: `_publish_order`
  sort, `PackageBatch`, then a `batches.jsonl` line if it is forwarded. Both files keep
  today's bytes, because the groups come in (ecosystem, name) order, which is the order
  `sorted(by_package.items())` gives.
- Guard the input contract: keep the set of finished packages (115k names, ~10 MB). If a
  package reappears, or a key goes backwards, raise rather than silently write different
  batches. All runs since Stage 0's first commit (21d2850, 2026-10-27) are sorted that way.
- **Return** a `TriageSummary` (changes, flagged, forwarded, batches) instead of the tuples.
- **Expected peak: ≤ 0.3 GB at both sizes** (the largest group, ~85 MB as objects). It
  stays single-threaded, like today: about 4 minutes of parsing at 405k.

### Stage 2

- `LineFile(batches.jsonl)` → `ordered_map(analyse_batch, max_pending=4×workers,
  cost=line length, max_cost≈64 MB)` → `JsonlWriter(static.jsonl)`.
- While writing, count the decisions, flags, versions without files and the `WILL_RETRY`
  reasons. **Return** a `StaticSummary` that includes `needs_retry`.
- The snapshot stays as it is (it must be complete for retention).
- **Expected peak:**
  - snapshot 0.07 GB (100k) or 0.3 GB (400k);
  - window ≤ ~0.3 GB of output objects, plus one oversized batch;
  - worker trees: typically tens of MB.
  - Overall: **~1 GB typical**. The adversarial bound is 8 workers × 2 trees × 512 MB. A tree
    semaphore (like Stage 4's `ARCHIVES_IN_MEMORY`) would close it; it is optional and
    separate.

### Stage 3

- Like Stage 2: `LineFile(static.jsonl)` → `ordered_map` → `JsonlWriter(ast.jsonl)`. **Return**
  an `AstSummary`.
- Give `record_ast` a fetcher that doesn't record: either a flag, or dropping entries after
  each read. That saves ~0.3 GB at 405k.
- Optional, within a batch: drop a version's `profiles` entry after the last version whose
  `previous` names it. That only matters for bursty packages; measure before doing it.
- **Expected peak: ~1 GB typical at both sizes**, the same per-worker caveat as Stage 2.

### `collect` and retention (not stages; do first)

- `run_stages`: reduce each stage's result to counts at once and `del` it. Once Stages 1-3
  return summaries, this becomes the natural shape.
- `_resume_from`: iterate `static.jsonl` line by line. Parse only lines that contain the
  `WILL_RETRY` text, then confirm on the parsed decision, because an evidence snippet could
  contain the same text.
- `_prune_run`: `iter_changes` (two passes or one combined pass), and streaming zstd
  compression (`zstd.open(..., "wb")`). The `.zst` bytes may differ from a one-shot
  `compress`. Nothing hashes them (only the content digest matters); a test checks that the
  round trip is identical.

### Expected peaks after all steps

| Stage | 100k changes | 400k changes | Bound set by |
|---|---|---|---|
| 0 | ~0.5 GB | ~0.6 GB | packuments in flight (≤ 0.42 GB each) |
| 1 | ≤ 0.3 GB | ≤ 0.3 GB | largest package group |
| 2 | ~1 GB | ~1.2 GB | worker trees, snapshot (1.6 KB/tarball) |
| 3 | ~1 GB | ~1 GB | worker trees, per-batch profiles |

These are estimates from the measured unit sizes. Each implementation task must measure the
real peak (systemd `MemoryPeak` of a `systemd-run` scope) on a recorded run and add it to
`docs/validation.md`.

## 4. Contract changes (flagged)

1. `IngestResult.changes` is replaced by a count, a digest and a path. `run_ingest` gains an
   output sink, and `replay_ingest` / `changes_digest` change with it. Callers: `core/run.py`,
   `cli.py ingest replay`, `tests/core/test_run*.py`, `tests/stages/test_ingest.py`. The files
   and the manifest don't change.
2. `triage_run`, `static_run` / `record_static`, `ast_run` / `record_ast` / `run_code_stage`
   return summaries, not records. Callers: `collect.run_stages`, `cli.py` (counts only),
   tests. The JSONL handoff files don't change.
3. Stage 1 now **requires** `changes.jsonl` grouped by package, which is already documented
   ("sorted by (ecosystem, name, version)", `docs/stages/ingest.md`). It is now enforced.
4. New shared helpers in `util/`. Moving `CandidateFile` and `_in_order` out of
   `stages/correlate.py` touches Stage 4. That is a separate, behaviour-free cleanup task after
   the others.
5. `PopularitySource` gains a flag for whether lookups are per-name pure (watchlist) or
   batched (API).

No schema or `STAGE_VERSION` bump: every output is byte-identical.

## 5. Risks

- **Byte identity.** Every ordering argument above rests on two facts: Stage 0's sort key
  is (ecosystem, name, version), and every change of one feed entry has that entry's name.
  Tests compare against the current implementation (below). On the VM, the new Stages 1-3 are
  run on a copied recorded run and their outputs compared with `cmp`.
- **Partial files.** Writing as you go makes partial output possible. `JsonlWriter`'s
  temp-and-rename and Stage 0's `.partial` directory keep partial files invisible. The resume
  logic keeps checking for missing outputs, as today.
- **Throughput.** `ordered_map` holds finished results behind a slow head. With
  `max_pending` = 4 × workers, one tarball-heavy batch can stall the pool at most until the
  window fills. If Stage 2's wall time grows by more than ~10% on a recorded run, raise
  `max_pending`.
- **Disk.** Stage 0 writes ~3 GB (at 405k) before the degraded check. The `collect` disk
  guard still runs between steps, and `DiskSpaceError` still propagates.
- **Replay of old runs.** Unchanged: the digest formula is the same. Replays of runs
  recorded in API popularity mode keep their request keys because of the two-pass path.

## 6. Test plan

- **Equivalence (per stage).** Keep the current function as `_reference_*` in the test module,
  and compare output bytes on synthetic runs that include:
  - several packages, one with many versions;
  - retry items that are unsorted and that duplicate feed names;
  - skipped packages and an empty run;
  - non-ASCII and astral characters (for the digest);
  - window sizes 1 and 2, so windows have boundaries;
  - workers forced to finish out of order (events or sleeps in `fn`).
- **Digest.** The streamed digest equals `sha256("\n".join(...))`: changes only, skipped only,
  both, empty.
- **Bounds.** An instrumented `ordered_map` never has more than `max_pending` results (or
  `max_cost`) outstanding, and an over-cost item still runs alone. These counts are
  deterministic; no tests measure RSS.
- **Failures.**
  - `IngestDegradedError` leaves no run directory, and a stale `.partial` is removed by prune.
  - `DiskSpaceError` propagates.
  - A killed writer leaves no visible output.
  - Triage on non-grouped input raises.
- **Existing tests** keep their expectations: replay identical, `test_collect`, the
  `test_run_streams_in_order_across_write_windows` pattern.
- **Live validation** (records the peak and the bytes in `docs/validation.md`):
  - `kitsunox ingest replay` on an hourly run, and on the 4-day run while its blobs still
    exist (pruned after ~2026-11-09 16:33Z). It must print "identical".
  - New Stages 1-3 on a hard-linked copy of a recorded hourly run in a scratch `--data-dir`,
    with `cmp` against the recorded `triage.jsonl`, `batches.jsonl`, `static.jsonl` and
    `ast.jsonl`. Use the same tool version, so the rules match.

## 7. Order of work

1. **`collect` + retention** (no stage contract change): drop results after counting, stream
   `_resume_from`, stream `_prune_run`. Removes the cumulative 13-29 GB and the prune spike.
   Do it before the 4-day run's prune.
2. **Stage 0, streaming digest only.** Tiny; removes ~18 GB at 405k and makes the 4-day
   replay possible.
3. **Stage 1** streaming plus `TriageSummary` (+ `JsonlWriter`).
4. **Stage 0** ordered writer, `.partial` run directory, `IngestResult` change (+
   `ordered_map`).
5. **Stage 2** (`ordered_map`, `StaticSummary`).
6. **Stage 3** (same; non-recording fetcher).
7. **Cleanup:** Stage 4 uses the shared `ordered_map` and `CandidateFile` from `util/`
   (behaviour-free).

After steps 1-2, even a 405k run fits: Stage 0 ~13 GB, Stage 1 ~13 GB, Stages 2 and 3 ~10 GB
each, one at a time. Steps 3-6 make the stages bounded by package and worker sizes instead of
run size.

## 8. Open questions for the owner

1. **Slicing.** Keep `MAX_RUN_FEED_SPAN` as it is after streaming? It still bounds a tick's
   duration (Stage 2 took ~8 hours on the 4-day run) and its disk use (tarballs, Stage 4
   archives). The proposal keeps it.
2. **Stage 0 staging directory.** Accept `runs/.<run_id>.partial/`, with prune removing stale
   ones?
3. **Atomic stage outputs** (`JsonlWriter`) for all stage JSONL files? This is recommended;
   it changes nothing on success.
4. **Popularity API mode.** The two-pass path costs one extra parse and dump of every change.
   The alternative is per-window lookups, which change the request grouping, so old API-mode
   runs could no longer be replayed. The proposal keeps the two-pass path.
5. **Hard limits.** Add semaphores for packuments (Stage 0) and file trees (Stages 2-3) now,
   or after measuring? A `MemoryMax=` on the `kitsunox-collect` service would also make an
   OOM kill the tick rather than starve the VM. That changes `kitsunox schedule systemd`'s
   unit file.

## Reproducing

The scripts are in `~/kitsunox-scratch/agent-streaming/scripts/`, outside the repository. They
only read `data/` and are run under `systemd-run --user --scope -p MemoryMax=3G nice -n 19`:

- `groups.py`: line sizes, package grouping, order.
- `width.py`: character widths.
- `objmem.py`: object sizes and snapshot sizes; run with `PYTHONPATH=src`, the project venv,
  and `-P -s`.
- `digest.py` and `digest2.py`: digest memory.
- `streamdigest.py`: the streamed digest equals the manifest.
- `snapsizes.py`: response sizes.
- `packparse.py`: packument parse memory.
