# Proposal: round 11 gap fixes, agent N2 (P3, P7, P9)

> **Status:** built 2026-11-13, before the rule freeze (2026-11-16 00:00Z), for the owner's
> review. One commit per target, each with its tests and docs. Not merged.
> **Builds on:** agent M's gap analysis of what npm and OSV caught and Kitsunox missed (round
> 11, `~/kitsunox-scratch/r11/GAP-ANALYSIS.md`: proposals P3, P7, P9 there), decision
> [0015](../decisions/0015-reviewer-verdicts.md) (what counts as a positive, the `probe`
> tag), [round 6 U](precision-round6-U.md) (`correlate.follow-on`),
> [round 9 Q](precision-round9-Q.md) (`npm.install-persistence` v7).

## Summary

| # | Commit (stage) | What | Recovered (verdict) | Benign added, live | Positives lost |
|---|---|---|---|---|---|
| P3 | `static.shell-startup` v2 (2) + `FOLLOW_ON_ALONE` (4, `STAGE_VERSION` 25) | the `inject` form is never "not new", and is carried to unchanged follow-ons | `@atedone/workspace-context` 0.0.19-0.0.25: 4 unwanted, 3 malicious | see P3 | 0 |

## 1. Data and method

- **Targets.** M's residual misses (`clusters.json`, `cands.jsonl.zst`, the previous
  versions in `cands_prev.jsonl.zst`) and M's recovered tarballs (`M/recovered/`). Replayed
  with M's harness (`replay_m.py`: `r5/K/replay.py` reading the recovered tarballs first) on
  this branch's `src/`, plus a model of Stage 4's follow-on pass that uses the branch's own
  `reported_release`, `ReleaseFollowOn` and `correlate.follow-on` in publish order
  (`~/kitsunox-scratch/r11/N/N2/scripts/followon_n2.py`).
- **Live benign cost.** Every distinct tarball in the live ledgers that is still held
  (`scan_n2.py`): P3 runs Stage 2's own `content_matches` (the version's new contents against
  its base tarball, `LoadedFiles`) twice, with `ALWAYS_NEW_FORMS` and with it emptied (main);
  P7 runs the rule on the tree. Held tarballs are roughly what Stage 2 reads.
- **Replay set and `vm-day1`.** See section 5.

Package text was read as data; nothing was executed and no host was contacted.

## 2. P3: shell start-up injection on every release

**Shape.** `static.shell-startup`'s `inject` form (code that writes files, refers to the home
directory, and holds a `source` line for a file under `$HOME` next to a start-up file's name,
or a command prompt under `setopt prompt_subst`) was demoted to LOW as "also in the previous
version's file" whenever the base had the same match. `@atedone/workspace-context` changed
`lib/sync.js` in most releases but kept the injected block, so only 0.0.12 and 0.0.18 were
reported.

**Change.**
- Stage 2: `ALWAYS_NEW_FORMS = {("static.shell-startup", "inject")}`; documentation and test
  paths are still LOW. Rule version 2 (the matching is unchanged).
- Stage 4: `static.shell-startup` joins `FOLLOW_ON_ALONE`, so a reported release's MEDIUM match
  is carried to a release that keeps the file byte for byte (0.0.22 and 0.0.23 kept 0.0.21's
  `sync.js`). Only MEDIUM findings are carried; a `hook` match is in `package.json`, which
  changes with every version, so in practice this carries `inject`.
- The `hook` form is left "not new" on purpose: `npm.install-persistence` v7 (Stage 3) reads
  the hook command lines on every version.

**How it differs from `npm.install-persistence` v7.** The Stage 3 rule reads only install code
(the files the install hooks run, and the hook command lines), on every version, changed or
not. `static.shell-startup` reads every file Stage 2 reads (runtime code such as
`@atedone`'s `lib/sync.js`, which no hook runs), but only the contents an update adds; v2 stops
it from calling an injection that is still there "old". Install code that injects a `source`
line is seen by both rules: one report with two findings on the same lines, never a second
report. Restricting v2 to files that loading the package runs was tried and dropped:
`load_sources` reaches `index.js` and `lib/state.js` of `@atedone`, not `lib/sync.js`, which
`state.js` reaches through split strings.

**Recovered** (replay + follow-on model, branch code):

| Version | Verdict | Main | Branch |
|---|---|---|---|
| `@atedone/workspace-context@0.0.19` | unwanted | score 1 | MEDIUM `static.shell-startup` |
| 0.0.20 | unwanted | score 1 | MEDIUM `static.shell-startup` |
| 0.0.21 | unwanted | score 1 | MEDIUM `static.shell-startup` |
| 0.0.22 | unwanted | score 0 | `correlate.follow-on` (`lib/sync.js` from 0.0.21) |
| 0.0.23 | malicious | score 0 | `correlate.follow-on` (`lib/sync.js` from 0.0.22) |
| 0.0.24 | malicious | score 1 | MEDIUM `static.shell-startup` |
| 0.0.25 | malicious | score 1 | MEDIUM `static.shell-startup` |

Not recovered: 0.0.13-0.0.17, where the start-up file's name (`state.js`) and the `source`
line (`sync.js`) are in different files (a cross-file form is post-freeze).
