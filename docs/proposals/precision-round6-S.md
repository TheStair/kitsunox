# Proposal: precision round 6, agent S (`npm.install-persistence`, `npm.dependency.non-registry`, `npm.dependency.missing`)

> **Status:** built 2026-11-10/11, before the rule freeze (2026-11-12 00:00Z), for the owner's
> review, on `main` `79958e6`. Four commits, all zero-loss on the live replay and on
> `vm-day1`; S5 carries a documented recall risk (section 3).
> **Builds on:** [round 5 J](precision-round5-J.md) and [M](precision-round5-M.md)
> (`install-persistence` v2-v4), [round 5 K](precision-round5-K.md) (`non-registry` v6, the
> corrected harness), [round 4 A](precision-round4-A.md), decision
> [0015](../decisions/0015-reviewer-verdicts.md) with its addenda.

## Summary

| # | Commit (stage) | What | Benign removed (live) | Positives lost | `vm-day1` lost | Kind |
|---|---|---|---|---|---|---|
| S4 | `0620066` `npm.dependency.non-registry` v7 (1) | a spec npm reads as a local path is LOW | 1 report | 0 | 0 of 87 | zero-loss |
| S5 | `16b0fa3` `npm.dependency.non-registry` v8 (1) | a commit bump in the package's own repository (named by the previous release) is LOW | 28 reports | 0 | 0 of 87 | zero-loss, recall risk (section 3) |
| S6 | `5679845` `npm.dependency.missing` v2 (4) | an alias into JSR's `@jsr/` scope is INFO | 2 reports (`ichikara`, `@audiflo/ichikara`, outside the replay set) | 0 | 0 (no sample) | zero-loss |
| S1-S3 | `8bd67df` `npm.install-persistence` v5 (3) | agent paths and shell start-up files in JavaScript count only when their value reaches a write; installers the analysis can't read still count; an agent CLI command kept as data doesn't | the rule leaves 8 of the 32 benign versions it fires on, gains 1 (no report changes alone) | 0 reports; the finding leaves `great-cto@3.75.6` and is gained on `rl-workspaces@0.7.0` (sections 2, 5b) | 0 reports; the finding leaves `aicp-tracker@1.0.7` (section 5) | zero-loss on reports |

**Live, real code, verdicts of 2026-11-10 ~21:00Z:** 1,349 → 1,320 reported, 851 → 822 benign,
precision 35.48% → 36.28%; no malicious, unwanted or unverified version changes decision.

## 1. Data and method

- **Versions and truth:** the 3,716 verdicted live versions
  (`~/kitsunox-scratch/r5/shared/cands.jsonl.zst`); verdicts re-joined from
  `data/verdicts/npm.jsonl` (last record per version) by `~/kitsunox-scratch/r5/final/relabel.py`.
  Reviewers re-labelled many versions while this round ran (the 2026-11-10 rulings: install-time
  downloads from a non-own host, patching another program, a background server that outlives
  the install), so every count below uses the verdicts of the moment it was taken; section 4
  gives the final ones.
- **Baseline:** `~/kitsunox-scratch/r6/shared/base.jsonl` (rules identical to `79958e6`).
- **Harness:** agent K's corrected `replay.py` (Stages 1-4 with the real code); subsets of the
  versions a fix can touch, patched over the baseline (no full replay: section 5b).
- **`vm-day1`:** `pipeline+4` per sample (`dd.py`) on every malicious sample the
  `non-registry` change can touch (the 87 on which the rule fires); for `install-persistence`,
  the rule itself on the install files of all 2,207 malicious samples with an install hook
  (`s_ddip.py`: the same `persistence()` the rule calls, on `install_files(...)`, in memory),
  base and fix, then `pipeline+4` on any sample whose finding changes.

## 2. `npm.install-persistence` v5 (Stage 3)

### What the benign hits were

On the baseline the rule fires on 52 reported benign versions (verdicts at the start of the
round; 32 with the final verdicts, after reviewers re-labelled `@mearl/native-host` ×8,
`universal-plugin-hub` ×4, `great-cto` and others unwanted). Grouped by why reviewers called
them benign:

| Group | Versions (final benign verdicts) | What the install code does with the path |
|---|---|---|
| reads a user-wide location at run time | `aiimpactmeter` 0.1.5/0.1.6, `nansen-cli@2.4.0`, `dsh-undo-savepoint@0.5.1`, `@agentonweb/terminal-host@0.4.4`, `@gleapai/kai-bridge` 0.16.0/0.16.1, `opencode-blocker-diverter@0.3.1` | reads, `existsSync`, reports; the path sits in a CLI bundle the hook loads |
| a setup the user agreed to earlier, refreshed | `memtrace@1.2.13`, `gkg-cli@1.0.1`, `0xray` 4.1.5/4.2.0, `zn-gate@1.15.0-rc.1`, `agy-statusblocks@0.1.0` | writes, but only into its own earlier setup |
| writes only behind an interactive prompt, an opt-in, or a user-run command | `common-context-mcp` ×5, `@c0dingbear/termius-mcp@0.6.1`, `vana-cli@0.48.0`, `polydev-ai` 1.11.0/1.12.0, `basinfy@1.3.13`, `@usebitl/cli` 0.1.32/0.1.33, `@finebi/finebi-cli@2.0.9`, `symbiot` 0.94.6/0.94.7 | real writes, reached only when a person says yes or runs a command |
| other forms | `@mavenagi/apps@1.3.0` (a `>> ~/.zshrc` line in a help template), `@hsusulist/luc@0.3.0` (Windows `install.ps1` PATH), `@flover124/hanx@2.13.5` (a `brew install` hint in a ternary) | text, or the user's own installer |

### The fix

**S1, a value analysis (`lang/flow.py`, new).** v4 matched an agent path wherever install
code named it; the install files are the hook's script and everything it loads, often a whole
CLI. In JavaScript, v5 follows the value of each expression the `agent` patterns match
(variables, properties, returns, parameters, `for ... of`, containers) and counts it only if
it reaches a write: a Node file write at its destination argument, a writing shell command, or
a library function named for writing. Reads, conditions, printing and content arguments end
it; a write only inside `if (process.env.X === "1")` is the user's switch. It gives up
towards "write" (4,000 steps, 1,000 uses of a name). **Rescue (same commit):** when the
install files never write the path but run a program with an installer subcommand the
analysis can't read (`unfollowed_installer`), it still counts: `wkappbot-code` 0.3.11/0.3.12
(unwanted) and 0.3.7/0.3.19 (unverified) spawn their own CLI's `install`, which is not an
install file; `local-mcp@3.0.430` (unwanted) runs a downloaded binary with
`--configure-clients`.

**S3, shell start-up files the same way (rescue, same commit).** In JavaScript, `ShellStartup`'s
`code` form (a start-up file's name within 1,000 characters of any write) is replaced by the
value analysis from the name. Without it S1 loses `coding-friend-cli` 1.43.0/1.43.1
(unwanted): `getRcPath()` returns `join(home, ".zshrc")` and `ensureShellCompletion()` writes
it far away; v4 caught them only through an agent path they read.

**S2, an agent CLI command kept as data.** `claude mcp add --scope user` and the like in a
JavaScript string that is only shown or kept as data (`shown_not_run`) no longer count
(`memtrace@1.2.13` describes what an earlier setup may have written). `memtrace` is still
caught by S1: its `uninstall.js` writes `~/.claude/CLAUDE.md`.

### Development measurements (subset: the 176 versions the rule fires on)

| Step | Benign it fires on | Positives it fires on | Notes |
|---|---|---|---|
| baseline (final verdicts) | 32 | 142 unwanted, 2 unverified | |
| first prototype (every call that isn't a read counts as a write) | -6 | -8 unwanted, -2 unverified | over-tainted through generic property names and `options` objects; lost `blue-crab`, `coding-friend-cli`, `wkappbot-code`, `local-mcp`, `basinfy` 1.3.8/1.3.12 |
| + containers (`list.push`), options objects handed to a library, function values (`(opts.dirs ?? defaultDirs)()`), the unfollowed-installer rescue, S3 | -8 | -1 (`great-cto@3.75.6`, below) | `blue-crab`, `basinfy`, `wkappbot`, `local-mcp`, `coding-friend-cli` kept |
| v5 (S1+S2+S3), these 176 versions | **24** | **141 unwanted, 2 unverified** | plus `repilot@0.3.0` (benign) and `rl-workspaces@0.7.0` (unwanted) gained elsewhere (section 5b) |

**The one positive that loses the finding: `great-cto@3.75.6`.** Re-labelled unwanted on
2026-11-10 for a reason this rule never described (a detached `great-cto board` server that
outlives the install, "pending owner"); v4 fired only because `postinstall.mjs` reads
`~/.claude/plugins/cache` to print a notice, which the reviewer notes is a read. It stays
reported (`npm.install-script-changed`). A rule for "install code starts a detached process
that outlives npm" would name it; that ruling is still pending, so it is not built.

**No report changes:** each of the 8 benign versions the rule no longer fires on is still
reported by `npm.install-script-changed` (or `install-hook`), so v5 alone moves no live
report; it removes 8 of the 32 benign versions from the
`install-persistence + install-script-changed` cluster, for whoever narrows the other rule.

## 3. `npm.dependency.non-registry` v7 and v8 (Stage 1)

What is left of the rule's benign reports (89 where it is the only MEDIUM, at the start of the
round), by shape (first non-registry finding per version): an update's commit pin in the
account of the package's own repository (34; 28 of them were already pinned to the same
repository in the previous release), other updates (13: another account such as
`drewstone/cli-bridge` for `@tangle-network/sandbox-cli`, forks such as `PenguinMod/*`), a new
package from its own scope or repository account (12), `pkg.pr.new` previews (10),
well-known vendors at a tag or branch (`uNetworking/uWebSockets.js`, `TurboWarp/*`,
`tangrams/*`: 6), updates whose dependency came from the registry before (6, among them
`web-audit-module-*`), other new packages (5), Baileys forks' `libsignal` (2), one
OpenHarmony alias.

- **S4 (v7), a spec npm reads as a local path is LOW** (`npm_local_path`): npm-package-arg
  sends a spec with a `/` that is not a URL or GitHub shorthand to the file system
  (`"esbuild": "@ohos-ports/esbuild@0.25.5-beta.1"`). Nothing is downloaded. 1 benign
  (`@ohos-ports/modern-js-node-bundle-require@2.32.1`), 0 positives, 0 `vm-day1` changes.
- **S5 (v8), a commit bump in the package's own repository is LOW** (`trusted_commit_bump`):
  on an update, the previous release took the dependency from the same repository (host,
  account and name, any reference), and the previous release's `repository` names that
  account. 28 benign (`@diffci.com/diffci` ×17, `package-registry-manager` ×3,
  `@blockrun/*` ×3, `trac-peer` ×2, `@coda-console/plugin-check@0.8.3`, `slack-axi@1.3.1`,
  `@miragari/dsh-client-canvas@0.1.5`), 0 positives.
  **Recall risk, measured:** a first version that compared only the account lost
  `vm-day1`'s `@opensearch-project/opensearch@3.8.0` (malicious): its previous release 3.7.0
  (also malicious) already took `@opensearch/setup` from
  `github:opensearch-project/openearch#d446803f`; 3.8.0 moved it to `opensearch-js#d446803f`.
  The repository name keeps it MEDIUM now (87/87 at-risk samples reported), but a follow-on
  release of an attack that keeps its own malicious pin in the same repository would get
  LOW. K's lane-m objection (round 5) is met (`lane-m-snackager-probe@1.0.1`'s previous
  release names no repository). A default-branch check of the pinned commit (round 5 K,
  section 7) would close the gap after the freeze. **The owner may prefer to drop S5**: it
  is its own commit.

## 4. `npm.dependency.missing` v2 (Stage 4)

**S6:** an alias into JSR's `@jsr/` scope (`npm:@jsr/sevenc-nanashi__utaformatix-ts@^0.4`) is
INFO with the reason: JSR serves `@jsr/*` from `npm.jsr.io`, and the npm registry answers 404
by design. Live: `ichikara@0.1.0` and `@audiflo/ichikara@0.1.0` (benign, reported only through
this rule; verdicted after the shared candidates were made, so not in the replay set). No
`vm-day1` sample depends on a `@jsr/` name (the rule fires on one sample there, not a JSR one).

## 5. `vm-day1`

- **`non-registry`:** `pipeline+4` on all 87 malicious samples the rule fires on, `main`'s code
  and the final code: 87 reported before and after, 0 errors, no finding of the rule changes.
  (The account-only first version of S5 lost `@opensearch-project/opensearch@3.8.0`; section 3.)
- **`install-persistence`:** the rule's `persistence()` on the install files of all 2,207
  malicious samples with an install hook: it fires on 27 with `main`'s code (19 `shell-rc`,
  all JavaScript: `@nx/*` ×7 `telemetry.js`, the `lib/worker.js` / `trap-core.js` family ×12;
  3 `system-package`; 1 `agent`). With v5: 26 unchanged; **`aicp-tracker@1.0.7`** loses its
  `agent` finding. Its `src/log-scanner.js` *reads* `~/.claude/projects` transcripts, which
  v4 matched as a write, the same shape as the benign `aiimpactmeter`. `pipeline+4` on it:
  reported before (score 7) and after (score 4, `npm.install-script-changed`). Not lost, but it
  now rests on that one MEDIUM; a rule for install code that reads agent transcripts and sends
  them out would name it (Stage 2's exfiltration rules don't fire on it).
  The final code on all 2,207: no sample gains or loses a form besides `aicp-tracker` (two
  samples timed out at 120 s under the machine's load in the fix run; re-run alone they take 4
  s each and give the same empty result as `main`).
- **`missing`:** the rule fires on one sample, not a `@jsr/` one.
- **Cost:** `persistence()` on the 176 live versions the rule fires on: median 0.04 s (v4
  0.02 s), slowest 1.24 s (`@mearl/native-host@3.0.0-beta.9`, 306 KB of install files; v4's
  slowest 0.46 s).

## 5b. Live result (full replay)

No full replay was run (the shared lock had four jobs queued); every version the changes can
touch was replayed or scanned instead:

- the 234 versions on which `non-registry` fires at all (S4 and S5 only lower its findings)
  and the 176 on which `install-persistence` fires (S1-S3 can only change those, except for
  new `shell-rc` findings), with the final code through K's harness, patched over the
  baseline;
- the other 1,567 versions with an install hook, the rule's `persistence()` on their install
  files (`s_liveip.py`) with the final code and, where it fires on a changed installer, with
  `main`'s: two new findings, both on versions reported already, so no report changes:
  `rl-workspaces@0.7.0` (**unwanted**, gained: its `dist/common.js` writes the marked block to
  `~/.bashrc`/`~/.zshrc` the value analysis follows from the name) and `repilot@0.3.0`
  (benign: completion written to `~/.zshrc` only when `REPOPILOT_ACCEPT_EULA=1`, an opt-in the
  analysis doesn't see because it is an early return, not an `if` around the write).

| | Reported | Benign | Unwanted | Malicious | Unverified | Precision |
|---|---|---|---|---|---|---|
| `main` (`base.jsonl`), verdicts of 2026-11-10 ~22:00Z | 1,349 | 851 | 421 | 47 | 30 | 35.48% |
| **S1-S6** | **1,320** | **822** | 421 | 47 | 30 | **36.28%** |

29 versions change decision, all benign (S4 1, S5 28). No malicious, unwanted or unverified
version changes decision. `install-persistence` itself: benign versions it fires on 32 → 25
(-8: `@agentonweb/terminal-host@0.4.4`, `@gleapai/kai-bridge` 0.16.0/0.16.1, `aiimpactmeter`
0.1.5/0.1.6, `dsh-undo-savepoint@0.5.1`, `nansen-cli@2.4.0`,
`opencode-blocker-diverter@0.3.1`; +1 `repilot@0.3.0`); positives 144 → 144
(-`great-cto@3.75.6`, +`rl-workspaces@0.7.0`).

## 6. Rejected or not built (with the sample that rules each out)

- **Fire only on agent-path matches that are new since the previous release** (a delta of the
  matches): 75 of the 122 positives are re-releases whose install code did the same before
  (`aptly` ×7, `openyida` ×8, `@ciandt-flow/flow-ai-obs` ×7, ...). Not built.
- **"The match is in the hook's entry file"**: 34 of 40 benign matches are in loaded files,
  but so are 36 of 100 positive ones (`aptly`'s `dist/src/setup.js`, `triflux`'s
  `hud/*.mjs`). Not built.
- **Writes behind a TTY check** (`common-context-mcp` ×5: on `npm -g` it writes only after
  the user picks tools at a prompt): the gate is an early `return` in the caller, three calls
  away from the write; no structural test found in time, and the rule's v1 owner note counts a
  write behind a prompt. Owner question 2.
- **Non-registry, a new package's own scope or repository account** (`@aimuzov/*`,
  `@bitfinex/*`): K's counter-example stands (`avantas@2.0.4`, malicious, names its own
  account's repository).
- **Non-registry, `pkg.pr.new` previews and well-known vendors' tags** (`uWebSockets.js`,
  `TurboWarp`): per-vendor origins are the owner's call (round 4 C, question 3).
- **Non-registry, the source changed from the registry to the author's GitHub**
  (`web-audit-module-*` ×7): a registry spec swapped for a GitHub one is the hijack shape.

## 7. Owner questions

1. S5 (commit bumps in the package's own repository): keep, with the recall risk of
   section 3, or drop until the default-branch check exists?
2. Writes that only an interactive prompt (`common-context-mcp`, `polydev-ai`, `vana-cli`) or
   a user command (`@usebitl/cli`) reaches: the reviewers call them benign; v1's note counts
   them. Which holds? (They are 13 of the 24 benign versions the rule still fires on.)
3. A detached process that outlives the install (`great-cto@3.75.6`): if unwanted, it
   deserves its own form; v4 caught it by accident.
4. JSR: is the `@jsr` scope reserved on npmjs.org (so a 404 there can't become a dependency
   confusion)? S6 assumes it.

## 8. How to reproduce

Scripts in `~/kitsunox-scratch/r6/S/scripts/` (Python with `-I`, under `systemd-run --user
--scope`): `k_replay.sh SRC OUT KEYS|full` (K's harness), `s_patch.py` (a subset replay over
the baseline), `relabel.py` (counts), `s_rulediff.py BASE FIX RULE` (where a rule's finding
appears or disappears), `s_changed.py` (decisions that changed), `s_ddip.py SRC KEYS OUT`
(`install-persistence` on `vm-day1` install files), `s_dd2.sh` / `dd.py` (`pipeline+4`),
`s_ddcmp.py`. Prototype and traces: `s_agentflow.py`, `s_proto.py`, `s_trace.py`.
