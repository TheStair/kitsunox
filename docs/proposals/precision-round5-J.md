# Proposal: precision round 5, agent J (install-script-changed, install-script-code, install-persistence)

> **Status:** built 2026-11-10, before the rule freeze (2026-11-12 00:00Z), for the owner's
> review, rebased on `main` (measured against `cde7f12`; later `main` commits are other
> agents' Stage 2 rules). Three zero-loss changes: J1 and J3 (`4896b41`), J4 (`44f2a5d` + `bdf62f5`),
> and `e0728ce` removing the switch of J2. **J2 (a trade-off) was rejected by the owner on
> 2026-11-10** (`gina@0.7.1` must stay reported) and is not built. **Live, real code against
> the corrected `main` (K's harness): 1,402 → 1,388 reported (14 benign, 14 packages),
> precision 21.57% → 21.80%. No malicious, unwanted or unverified version stops being
> reported. `vm-day1`: 0 lost.**
> **Builds on:** [round 4 A](precision-round4-A.md) (`npm.install-script-changed` v5, the
> persistence rule), [round 3](precision-round3.md) (method, harness), decision
> [0015](../decisions/0015-reviewer-verdicts.md) and its addenda.
> **Scope:** agent J owns `npm.install-script-changed` and `npm.install-script-code`, and
> (integrator, 2026-11-10) `npm.install-persistence`.

## Summary

v5 keeps `npm.install-script-changed` MEDIUM when a changed line touches what an attack needs.
On the 102 benign versions it still reported alone, most of those "touches" were things the
previous install code already ran: the same `spawnSync(` on a re-indented or guarded line, the
same `process.env` on an edited option line, the package's own release URL with a new path, a
bundle chunk renamed between releases. J1 stops counting what was demonstrably there before.
J2 went further (a trade-off, rejected by the owner). J3 and J4 remove two shapes from the other
two rules that are not what they look for.

| # | Commit (stage) | What | Benign reports removed (live) | Positives lost (live) | `vm-day1` lost | Kind |
|---|---|---|---|---|---|---|
| J1 | `4896b41` `npm.install-script-changed` v6 (3) | a changed or newly run line that is a line of the previous install code (any file; whitespace, comments, messages and volatile strings aside) is not touched; a URL counts only when its host (and on a code host, the repository owner) is new | 12 (`@einsia/agent-git`, `@heyinkeji/cli`, `@qwen-code/cua-sdk@0.28.0`, `@squareboat/nest-console`, `@tetsuo-ai/agenc`, `@whiter001/autobrowser@0.1.5`, `@zhizai/cli`, `brewtui-bar`, `engramgraph`, `locus-cli`, `node-sword-interface`, `stacklit`) | 0 | 0 | **zero-loss** |
| J3 | `4896b41` `npm.install-script-code` v4 (3) | `env-all` doesn't count when every whole-`process.env` reference is a parameter's default (`function f(env = process.env)`) | 0 alone (14 benign findings removed; 5 of those versions keep only `npm.install-hook`) | 0 | 0 | **zero-loss** |
| J4 | `44f2a5d`, `bdf62f5` `npm.install-persistence` v2 (3) | a system-package command string JavaScript only prints, returns or keeps in a table doesn't count; the same command as an argument list (or a string in an argument list) does | 2 (`argonauts-code@0.2.0`, `uniwind-pro@1.9.2`; `wyrm-mcp@9.4.2` stops firing, stays reported) | 0 | 0 | **zero-loss** |
| J2 | not built (was v7) | on a changed line, a match the previous install code had anywhere doesn't count either, unless the line holds a string literal that is new | 21 more (section 4) | 0 | **2** (`esoftplay@0.0.196`, `gina@0.7.1`) | **rejected by the owner, 2026-11-10** |

## 1. Data and method

- **Versions and truth:** the 3,716 verdicted live versions (`~/kitsunox-scratch/r4/shared/
  cands.jsonl.zst`), verdicts re-joined from `data/verdicts/npm.jsonl` (last record per
  version) on 2026-11-10: 15 versions were relabelled since the shared baseline was made (14
  benign to unwanted, `esoftplay@0.0.269-beta96052d3` benign to malicious). Baseline = `main`
  `cde7f12` as agent K replayed it with the corrected harness (the run's watchlist in Stage 4,
  known-malware findings regenerated; `~/kitsunox-scratch/r5/K/out/fix.jsonl`, whose source
  tree is `cde7f12`'s): 1,402 reported, 1,076 benign, 249 unwanted, 47 malicious, 30
  unverified, precision 21.57%. The shape analysis and offline estimates were done on the
  shared baseline (`31e96fa`); K's changes don't touch Stage 3.
- **Shape analysis:** every version where one of the three rules is MEDIUM (638) had its Stage 3
  `CodeChange` rebuilt with `main` exactly as the replay builds it (`cc.py`) and pickled. Re-running
  `main`'s Stage 3 rules on those dumps and Stage 4's real `explained` and `decide`
  (`evalJ.py`) reproduces every baseline decision (412 benign, 186 unwanted, 14 malicious, 8
  unverified, all reported; 0 differences), so the offline estimates below use the real rule
  code. `tdetail.py` records, for every `TOUCHED` match on a changed line, where the previous
  install code had it; `pmatches.py`/`pro.py` list every persistence match and test the
  narrowings.
- **Real replay:** K's `replay.py` (round 4 C's plus regenerated known-malware findings,
  resumable; 2 workers) on the 1,781
  versions with an install hook or install finding (round 4 A's subset; the other 1,935 rows are
  the baseline's), with the J1+J3+J4 code; and, for the record, with the J2 code on the 426
  versions where `npm.install-script-changed` is MEDIUM in the baseline (J2 can only lower that
  rule). Merged over the baseline by `table.py`, which also checks that no other rule's finding
  differs. Removing J2's switch (`e0728ce`) leaves v6's behaviour: re-running the final code
  offline on all dumped live and `vm-day1` changes gives the same decisions and severities.
- **`vm-day1`:** the samples a change could unreport are those whose only severe rules (MEDIUM
  outside `WEAK_ALONE`, or HIGH) are install rules: 271 of the reported malicious samples
  (from round 4's full dump). Their `pipeline+4` rows were produced with `main` (`dd.py`, my
  own data directory with a fresh cache: 265 reported, the 6 accepted `esoftplay` losses not),
  their `CodeChange`s dumped (`ddcc.py`), and re-decided with each fix's Stage 3 rules
  (`evalDD.py`; `main` reproduces all 271 decisions); then `dd.py` with the J2 code (section 5).

## 2. What keeps v5's MEDIUM on the 102 benign it reports alone

Kinds touched (a version can have several): processes 50, URLs or hosts 36, the whole
environment 32, the home directory 24, the network 22, shell commands 20, credentials 17,
package-manager commands 12, dynamic code 10, a 4 KB literal 9, encoded data 7, binary 1.
Where the previous install code had each matched token (decisive rows, benign / positive):

| Origin of the touched tokens | Benign | Positive (of 8) |
|---|---|---|
| some token new to the install code | 61 | 8 (5 through the agent guard, 2 `scarwise` through the 4 KB literal, `@su-record/vibe@4.2.50` the home directory) |
| all tokens in the same file before | 30 | 0 |
| all tokens in another install file before | 11 | 0 |

The questions of the brief, answered:

- **A process call that was already there and only moved?** Yes, the largest group: 30
  processes, 24 whole-environment, 11 home-directory touches are tokens the same file already
  had. When the whole line was already there (moved, re-indented, a renamed chunk), J1 drops
  it; when the line changed around the token (a new guard, an extra argument), only J2 would
  have, and J2 is rejected.
- **A URL that is the package's own?** 27 benign are kept by a URL token that is new, but in
  most the host was not: `@hanzo/cli`'s `github.com/hanzoai/...` releases, `registry.npmjs.org`,
  `@ohos-ports/esbuild`'s registry, `fluxware`'s `github.com/${REPO}`. J1 compares who serves the
  URL (host, plus the owner on a code host). A templated host or owner still counts.
- **The home directory read for a cache dir?** 6 benign have a new home token
  (`@heyvamz/carry`, `@upskillsafrica/gihanga`, `evolcore`, ...). Not narrowed: `gina@0.7.1`
  (`vm-day1`) is kept by the home directory alone, as round 4 found.
- **A rebuilt bundle where every risky token existed before?** `scarwise` 0.1.4-0.1.6 (benign)
  and 0.1.7/0.1.8 (unwanted) are the same rebuilt minified CLI; the positives are kept only by a
  new 4 KB literal, so the literal kind stays. J2 covered rebuilds whose literals are not new.

## 3. The changes

See [ast.md, round 5](../stages/ast.md#round-5-what-the-previous-install-code-already-ran-and-what-is-only-shown-2026-11-10)
for each rule's exact definition.

- **J1** `touched` compares with `_Before` (the previous install code's masked lines and URL
  identities).
- **J2** (rejected, not built) set a switch, `OLD_TOKENS_COUNT = "never"`, that ignored tokens the
  previous install code had on changed lines unless the line had a new string literal. Its
  first version (no string exception) removed 13 benign reports more, but `exec("a")` →
  `exec("b")` became LOW. `e0728ce` removes the switch.
- **J3** `environment_injected`: every install file Stage 3 saw take `env-all` must have
  whole-`process.env` references, all parameter defaults.
- **J4** `lang.javascript.shown_not_run` (a new function in a shared module, no existing one
  changed) and `SYSTEM_PACKAGE_ARGV`.

## 4. Live result (real code)

| Live (K's harness, real code; verdicts of 2026-11-10) | Reported | Benign | Unwanted | Malicious | Unverified | Precision |
|---|---|---|---|---|---|---|
| `main` `cde7f12` | 1,402 | 1,076 | 249 | 47 | 30 | 21.57% |
| J1 + J3 + J4 (zero-loss) | **1,388** | **1,062** | 249 | 47 | 30 | **21.80%** |
| + J2 (rejected by the owner, not built) | 1,367 | 1,041 | 249 | 47 | 30 | 22.14% |

- **No longer reported, zero-loss (14 benign, 14 packages):** J1's 12 (table above) and J4's
  `argonauts-code@0.2.0` and `uniwind-pro@1.9.2`. J2 (rejected) would have added 21 (17
  packages): `@aziron/atlas`
  0.1.55 and 0.1.55-readme.0, `@blakeley-place/medley@0.11.1`, `@vibead/cli@0.1.0-beta.36`,
  `@whobot/cli@2.0.3`, `@whobot/cli-test@0.1.3`, `@zero-x.live/neuron@7.0.0-alpha.5`,
  `@znmin/claude-remote-cli` 0.2.0 and 0.3.0, `bend-lint@0.3.0`, `codeoutline` 0.3.1 and 0.3.3,
  `dokky@0.1.7`, `eiows@11.2.0`, `fairlead@0.18.0`, `git-history-ui@5.5.1`, `jsql-neo@6.5.22`,
  `lingua-rs@0.2.4`, `qdd-framework` 2.9.9 and 2.10.0-rc.5, `riciplay@1.9.3`.
- **Positives and unverified:** none stops being reported, none is newly reported. Three
  unwanted lose J3's `install-script-code` finding and stay reported through
  `npm.install-persistence` (`@civitas-cerebrum/achilles@0.1.8`,
  `@polymorphism-tech/morph-spec@10.5.3`, `aptly@0.1.0`); no other positive's finding of these
  three rules changes.
- **Replay fidelity:** on the 1,781 replayed versions no finding of any other rule differs from
  `main`'s. The offline estimates (section 1) predicted the same 14 and 35.
- **`hauntview@0.2.9`** (must-keep), replayed from its run's candidate with the J2 code (which
  only lowers `npm.install-script-changed` further than the final code): reported, score 12,
  `npm.install-script-changed`, `npm.install-script-code` and `static.padded-code` MEDIUM.

## 5. DataDog check (`vm-day1`)

The real `pipeline+4` (`dd.py`) on the 271 at-risk samples with the J2 code (`31e96fa` + J1-J4
before the rebase, which adds only K's Stage 1/4 rules) reports 263, against 265 for `main`: it
loses exactly `esoftplay@0.0.196` and `gina@0.7.1`. J2 only lowers `npm.install-script-changed`
further than v6, so the final code (J1 + J3 + J4) loses nothing: the offline re-decision of
the final code (`evalDD.py`; `main` reproduces all 271) reports all 265.

| Code | Reported of 271 | Lost |
|---|---|---|
| `main` | 265 | (6 `esoftplay` follow-ons, accepted in round 4) |
| J1 + J3 + J4 | 265 | 0 |
| + J2 (rejected) | 263 | `esoftplay@0.0.196` (score 4 → 2), `gina@0.7.1` (score 6 → 3) |

The two samples J2 lost are follow-ons (a later version of a family with a malicious release).
`esoftplay@0.0.196`'s only install change wraps `execSync("mkdir -p ./raw && cp -r ...")` in
an `existsSync` guard (same string); `gina@0.7.1` adds an `escapeRegex` helper and wraps
`getUserHome()` in it. No rescue signal names what either does: the family's malicious code is
not in what changed. J4 on `vm-day1`: `persistence()` on the install files of every malicious
sample with an install hook (`ddpers.py`, `main`) fires on 35, 4 of them `system-package`:
`free-anthropic-claude` 5.0.3 and 5.1.1 (`execFileSync("/bin/bash", ["-c", "... brew install
python3"])`: kept since `bdf62f5`, which reads a string in an argument list as run),
`free-claude@1.0.1` (`execSync("brew install node")`, kept), and `uipathisfun@1.0.14` (a table
of package managers: dropped; reported through `install-script-code`, `load-fingerprint` and
`static.exfil-endpoint`).

## 6. Rejected or not built

- **J2, rejected by the owner on 2026-11-10** (`gina@0.7.1` must stay reported): ignoring tokens
  the previous install code had on a changed line unless the line has a new string literal.
  21 benign reports for 2 `vm-day1` follow-ons (`esoftplay@0.0.196`, `gina@0.7.1`).
- **Ignore every token the previous install code had, on every changed line** (J2 without the
  string exception): 13 benign more than J2, same 2 `vm-day1` losses, but an edited command in
  an existing call (`exec("a")` → `exec("b")`) becomes LOW. Rejected for that blind spot.
- **Same-file tokens only** (the brief's example) loses the same 2 `vm-day1` samples and
  removes fewer (30 vs 41 decisive benign) than "any install file".
- **Old tokens only on minified lines (500+ characters):** removed no report beyond J1.
- **Narrowing the home-directory or 4 KB literal kinds:** `gina@0.7.1` (home only) and
  `scarwise` 0.1.7/0.1.8 (unwanted, 4 KB literal only).
- **Persistence: a path only read or existence-tested** (`existsSync(join(home, ".claude"))`,
  a variable used only in read calls): loses 4 unwanted (`wkappbot-code` 0.3.11/0.3.12,
  `local-mcp@3.0.430`, `@follenfang/fupload@1.1.0`) and 2 unverified (`wkappbot-code`
  0.3.7/0.3.19) and frees none of the reviewer's 47 benign: each of them also names an agent
  path it writes or passes on.
- **Persistence: code after an early `process.exit`** (`@usebitl/cli` x2): the exit depends on
  the hook's argument (`if (syncOnly) process.exit(0)` after `process.argv[2] === '__sync'`); not
  a static shape. `@hsusulist/lcode` (`-NoPath -NoEnvironmentChanges`) and `@mavenagi/apps`
  (a completion template in a string) are single versions.
- **Persistence: installers that prompt first:** rejected in round 4 (loses 20 unwanted).
  `@juyoungsuh/hanx` really runs `spawn('brew', ['install', ...])` behind its prompt.
- **`install-script-code`: any capability alone.** Every one has positives on live or
  `vm-day1`: `dynamic-require` alone (11 benign) carries the malicious `*-bg@9.9.x` beacons;
  `process` alone has 86 `vm-day1` samples where install rules are the only severe ones;
  `network` alone 24. `env-all` alone has 10 positives, but all are caught by
  `npm.install-persistence` too except `@visual-z/xeno@0.13.2`, whose `{ ...process.env }` child
  environment J3 still counts.
- **J3 extended to an environment handed to a child** (`env: process.env`, `env: {
  ...process.env, X }`, `env: Object.assign({}, process.env, ...)`): no report changes, and it
  removes the finding from 5 unwanted (`@muggleai/works`, `@ziniao-open/cli` x2,
  `ai-usage-meter@0.1.7`, `claude-gemini-architect@0.1.1`, whose `env: process.env` is not a
  child's) and 1 unverified (`@swirls/cli@0.1.143`) for 3 benign. Not built.

## 7. Owner questions

1. (Answered 2026-11-10: J2 rejected, v6 kept.)
2. **For the hook owners (H/I):** J3 leaves `npm.install-hook` as the only severe rule on 5
   benign versions (`@danielmeneses/harness2@0.1.0`, `@humwick/server@0.130.0`,
   `chuskybrowser@1.18.1`, ...); an explanation of their hook would free them.
3. The reviewer's other persistence shapes (opt-in prompts, readers) need a data-flow test (does
   the path reach a write at install?), not a pattern: not before the freeze.

## 8. How to reproduce

Scripts in `~/kitsunox-scratch/r5/J/scripts/` (read-only on `data/`; Python with `-I`, nice 19,
`MemoryMax` 4G, or 8G under the heavy lock): `j_sets.py` (keys, verdicts), `cc.py` and
`ddcc.py` (CodeChange dumps), `tdetail.py`/`tvar.py` (token origins and variants),
`codekinds.py`/`codeuses.py` (install-script-code kinds), `pmatches.py`/`pro.py`
(persistence), `evalJ.py`/`evcmp.py` and `evalDD.py` (offline estimates), K's `replay.py`
(`replayK.py`, run by `runK.sh`) + `table.py` (live: `out/zlK.jsonl`, J2's `out/j2K.jsonl`),
`dd.py` (vm-day1), `ddpers.py`, `evfinal.sh` (the final code against the measured one).
Outputs in `out/`.
