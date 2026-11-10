# Proposal: precision round 5, agent M (install hooks that change the global git configuration)

> **Status:** built 2026-11-10, before the rule freeze (2026-11-12 00:00Z), for the owner's
> review, on `main` `a1ec826`. One zero-loss change: `npm.install-persistence` v3 (Stage 3),
> a rescue signal. **Live, real code against `main` (K's corrected harness, verdicts of
> 2026-11-10): 1,348 → 1,349 reported, precision 22.84% → 22.90%; the form fires on exactly
> the 6 re-labelled unwanted `signoff-cli`/`dsh-signoff` versions and nothing else; it brings
> back `signoff-cli@4.1.9`; 0 benign added, 0 positives or unverified lost. `vm-day1`:
> the form fires on none of the 2,319 hooked malicious samples, 0 gained, 0 lost.**
> **Builds on:** [round 4 A](precision-round4-A.md) (the persistence rule), [round 5 J](precision-round5-J.md)
> (`shown_not_run`, v2), [round 3](precision-round3.md) (method), decision
> [0015](../decisions/0015-reviewer-verdicts.md) and the owner's 2026-11-10 ruling (a silent
> system or user setting change at install is unwanted).
> **Scope:** agent M owns `npm.install-persistence` for this task.

## Summary

The owner ruled on 2026-11-10 that an install hook silently changing a system or user setting
is unwanted. Reviewers re-labelled seven versions unwanted: `signoff-cli` 4.0.0, 4.1.2, 4.1.9,
4.2.0 and `dsh-signoff` 3.10.0, 3.12.0, 3.13.0. Their postinstall runs `node bin/signoff.js
ensure --from-install --quiet`; `lib/bootstrap.js`'s `run()` calls `ensureGlobal()` whenever
`--from-install` is given, which writes dispatcher hooks to `~/.signoff/hooks` and runs
`spawnSync("git", ["config", "--global", "core.hooksPath", value])`: from then on every
repository on the machine runs the package's hooks. `main` reported them only through the
noisy install rules (`install-hook`, `install-script-changed`, `install-script-code`), and
`signoff-cli@4.1.9` not at all (score 3 since round 4's `install-script-changed` v5). No rule
named the behaviour.

| # | Commit (stage) | What | Benign reports added (live) | Positives gained | Positives lost | `vm-day1` lost | Kind |
|---|---|---|---|---|---|---|---|
| M1 | `4ce29e1` + `e302003` `npm.install-persistence` v3 (3) | a `git-config` form: install code that changes the global or system git configuration for a key that runs code or redirects data in every repository, or writes `~/.gitconfig` | 0 | `signoff-cli@4.1.9` (+ the finding on the 5 others, and on `signoff-cli@4.2.0`) | 0 | 0 | **zero-loss** |

## 1. Data and method

- **Versions and truth:** the 3,716 verdicted live versions (`~/kitsunox-scratch/r5/shared/
  cands.jsonl.zst`), verdicts re-joined from `data/verdicts/npm.jsonl` (last record per
  version) by `~/kitsunox-scratch/r5/final/relabel.py`. Baseline = the full replay of `main`
  `7af2e32` (rules identical to `a1ec826`): `~/kitsunox-scratch/r5/final/main-7af2e32.jsonl`.
- **Harness:** agent K's corrected `replay.py` (Stages 1-4 with the real code; the run's
  watchlist in Stage 4), 2 workers under the heavy lock, on snapshots of the worktree's
  `src/`: `src-v3` (`4ce29e1`, `out/v3.jsonl`) and `src-final` (`e302003`, `out/final.jsonl`).
  The two replays have identical findings on all 3,716 versions.
- `signoff-cli@4.2.0` was verdicted after the shared candidates were extracted; its candidate
  was copied from its run (`20261110T124923Z-npm`, `m_cands.py`) and replayed with both codes.
- **Controls named by the reviewers (must stay unflagged):** `@acertijosapps/android-viewer@1.0.0`
  (`postinstall: git config core.hooksPath .githooks || exit 0`), `@brighterly/lib-assessment@1.0.0`
  (`git config core.hooksPath _tools/git || true`), `@xingwangzhe/stalux@1.54.0` and 40
  `clavarium` versions (`prepare` sets a project `core.hooksPath`; `prepare` is not an install
  hook), `@arifbiswas/git-pre-push@1.0.0` (global only through a CLI flag, below).

## 2. The change (M1)

`npm.install-persistence` v3 adds the form `git-config` (`_git_config`), on the same install
code as the other four forms (the files the hooks run and those they load, the scripts they
start and what those start, plus the hook command lines; comments and messages masked):

- **Scope:** `--global`, `--system`, or `--file`/`-f` `~/.gitconfig`; also the new
  `git config set` syntax. Local settings (no scope flag) and `git -c k=v` overrides never
  match. Options that only read or remove (`--get*`, `--list`/`-l`, `--unset*`,
  `--remove-section`, `--rename-section`, `--show-*`, ...) end the match.
- **Keys** (`GIT_KEYS`, case-insensitive): what git runs in every repository
  (`core.hooksPath`, `init.templateDir`, `core.sshCommand`, `core.pager`, `core.editor`,
  `core.fsmonitor`, `core.askPass`, `core.gitProxy`, `sequence.editor`, `diff.external`,
  `filter.*.clean/smudge/process`, `diff.*.textconv`, `merge.*.driver`, `gpg[.*].program`),
  where it sends data or credentials (`credential[.*].helper`, `url.*.insteadOf` /
  `pushInsteadOf`, `http[.*].proxy`, `https.proxy`), another config file it loads
  (`include.path`, `includeIf.*.path`), `alias.*` only with a `!` shell command, and
  `safe.directory` only with `*`. `user.*`, plain aliases and the like don't count.
- **Shapes:** a command string (`execSync("git config --global core.hooksPath ~/.x")`, a
  shell line, a string starting at `config` handed to a helper such as
  `runGit("config --global ...")`); an argument list (`spawnSync("git", ["config",
  "--global", "core.hooksPath", dir])`, `git(["config", "set", "--global", ...])`); a write of
  `~/.gitconfig` or `~/.config/git/config` (a file-writing call naming the path or a variable
  given it, a `>>`/`>` redirection, `tee`). Reading `~/.gitconfig` doesn't count.
- **Shown, not run:** a JavaScript command string that `lang.javascript.shown_not_run` says
  is only printed, returned or kept in a table doesn't count (as for `system-package` in v2);
  printed messages and `echo` lines are masked before matching.
- **Off by default:** a change made only inside `if (p) { ... }` (`p` alone or an `&&` term),
  where `p` is a parameter of the enclosing named function with an off default (`p = false`,
  `undefined`, `null`, `0`), doesn't count unless some install file calls that function with an
  argument at that position that may be on, spreads arguments into it, or hands the function to
  another call (`lang.javascript.opt_in_parameter`, `passes_argument`; new functions, no
  existing helper edited). `@arifbiswas/git-pre-push@1.0.0`'s `src/installer.js` has
  `installHook(cwd = process.cwd(), isGlobal = false)` with `runGit(\`config --global
  core.hooksPath "${hooksDir}"\`)` inside `if (isGlobal)`; its postinstall calls
  `installHook(targetDir)` and only `bin/cli.js` (not install code) passes `true`. Without this
  test the form fires on it (the string and the file reach are the same as `signoff`'s).
  `signoff`'s guard is `if (global || fromInstall)`, local variables computed from the
  hook's own arguments, so it still fires.

Evidence on `signoff-cli@4.1.9`: `lib/bootstrap.js:236`, `spawnSync("git", ["config",
"--global", "core.hooksPath", value], { encoding: "utf8" })`; the `--get` call in
`globalHooksPathSetting` and the `--unset` in `uninstallGlobal` don't match.

## 3. Live result (real code)

| Live (K's harness, real code; verdicts of 2026-11-10) | Reported | Benign | Unwanted | Malicious | Unverified | Precision |
|---|---|---|---|---|---|---|
| `main` `a1ec826` (`main-7af2e32.jsonl`) | 1,348 | 1,017 | 254 | 47 | 30 | 22.84% |
| M1 (`npm.install-persistence` v3) | **1,349** | 1,017 | **255** | 47 | 30 | **22.90%** |

- **Findings that changed (all 3,716 versions, `m_diff.py`):** exactly 6 versions gain the
  `git-config` finding, all unwanted: `dsh-signoff` 3.10.0, 3.12.0, 3.13.0, `signoff-cli`
  4.0.0, 4.1.2 (already reported, now for the right reason), and `signoff-cli@4.1.9` (score 3
  → 6, **newly reported**). No other finding of any rule differs; no replay errors.
- **Benign newly reported: none.** The five controls stay unflagged by the form (checked
  with `m_fire.py` on their install code: `@arifbiswas/git-pre-push@1.0.0` through the
  off-by-default test, the others because they set no global key or their hook is `prepare`).
- **Positives and unverified lost: none.**
- **`signoff-cli@4.2.0`** (outside the shared set): reported by `main` (score 5,
  `install-script-changed`) and by M1 (score 8, `install-persistence` + `install-script-changed`).

## 4. DataDog check (`vm-day1`)

`m_ddfire.py` runs `persistence()` (the final code) on the install code of every `vm-day1`
malicious sample with an install hook (3,444 malicious, 2,319 hooked, all 2,319 read; files
decrypted in memory by the predictor, nothing written or run), with no base version, so it
over-counts (`ONLY_WHEN_CHANGED` is not applied). The `git-config` form fires on **none** of
them. v3 only adds this form, so no `vm-day1` sample's findings or decision can change:
**0 gained, 0 lost**, and there is nothing for `pipeline+4` to re-decide. The malicious corpus
has no install-time global git change; the form is a rescue signal for the owner's
unwanted ruling, not a recall gain on DataDog samples.

The first scan (with the commit before `e302003`) stalled: an option pattern `--?[\w-]+`
matched `--a` two ways, so a long run of options backtracked exponentially (a synthetic
`"config " + "--a " * 5000` never returned). `e302003` makes each option match one way and
keeps options before the scope from being the scope (a line of 3,000 `--global` took 1.3 s,
now 2 ms); regression tests in `test_long_option_runs_match_in_linear_time`. The live
numbers above are re-measured on the final code (section 3).

## 5. Rejected or not built

- **Any `git config --global`** (every key): `user.name`/`user.email`, `alias.st status`,
  `pull.rebase` change nothing git runs or sends; the ruling is about settings that change the
  machine's behaviour, and these would add noise for no attack shape. Not built.
- **Every `core.hooksPath` (local too):** would fire on the five benign controls the
  reviewers named (`@acertijosapps/android-viewer`, `@brighterly/lib-assessment`, `clavarium`,
  `@xingwangzhe/stalux`; husky-style setup), which change only the project's repository.
- **No off-by-default test:** fires on `@arifbiswas/git-pre-push@1.0.0` (benign; already
  reported by `install-hook` and `install-script-code`, but the finding would be false). A
  full call-graph reachability test was not attempted before the freeze; the parameter test is
  narrow (nearest named function, `if` on a parameter with an off default, callers in install
  files only).
- **`pager.<command>`:** `git config --global pager.branch false` turns paging off; dropped
  from the keys (only `core.pager` counts).

## 6. Owner questions

1. The keys go beyond the task's list by a few that also run a program (`core.askPass`,
   `core.gitProxy`, `sequence.editor`, `diff.external`, `merge.*.driver`, `gpg.program`). None
   fires live; drop any you consider out of the ruling.
2. `safe.directory=*` is counted (it disables git's ownership check for every repository).
   Common in Docker CI scripts, never seen in a live install hook so far.

## 7. How to reproduce

Scripts in `~/kitsunox-scratch/r5/M/scripts/` (read-only on `data/`; Python with `-I`, nice
19, `MemoryMax` 4G, or 8G under the heavy lock): `k_replay.sh SRC OUT full` (K's `replay.py`,
2 workers), `relabel.py` (in `r5/final/`), `m_diff.py` (findings that differ), `m_install.py`
and `m_fire.py` (install files and the form on chosen versions), `m_cands.py` (candidates of
versions verdicted later), `m_ddfire.py` (vm-day1 samples the form fires on), K's `dd.py`
(`pipeline+4` per sample). Outputs in `~/kitsunox-scratch/r5/M/out/` (`v3.jsonl`,
`late-*.jsonl`, `ddfire.jsonl`, `dd-*.jsonl`).
