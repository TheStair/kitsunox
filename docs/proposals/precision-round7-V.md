# Proposal: precision round 7, agent V: install hooks no shape explains

> **Status:** built 2026-11-11, before the rule freeze (2026-11-16 00:00Z), for the owner's
> review. Cluster: reported benign versions whose only MEDIUM-or-higher findings are the
> install rules (`npm.install-hook`, `npm.install-script-changed`, `npm.install-script-code`).
> Stage 3 only: `npm.install-explained` v7 (`ecosystems/npm/rules/install_shapes.py`) and a
> new parse-tree helper module, `lang/effects.py`. Nothing in `lang/javascript.py`,
> `ecosystems/npm/install.py` or `stages/correlate.py` changes.
> **Result (full live replay, real code, today's verdicts):** 1,469 → 1,448 reported, **all 21 benign**; no malicious, unwanted or unverified version changes; precision 46.42% → 47.11%.
> `vm-day1`: the new code changes the explanation of none of the 2,319 malicious samples with
> an install hook; `pipeline+4` on the 205 samples whose install code reaches the new code
> paths (a `chmod`, only inline hooks, or an `env-all` file read by name): 201 reported with `main` and 201 with the fix (the same samples), 0 lost; no S7 or S8 explanation on any of them.
> **Builds on:** [round 4 E](precision-round4-E.md) (S5 and its guards, and E3, the dropped
> inline S5), [round 4 B](precision-round4-B.md) (B1 and what it refused),
> [round 6 Q](precision-round6-Q.md) (v5 and the added-hook rule),
> [round 6 R](precision-round6-R.md) (v6, no download shape), decision
> [0015](../decisions/0015-reviewer-verdicts.md) with all addenda.

## Summary

| # | Commit (Stage 3) | What | Benign removed | Positives lost | Unverified lost | `vm-day1` lost |
|---|---|---|---|---|---|---|
| V1 | `d52ed82`, `d16914b` S8 | inline `node -e` install guards: a Node-version, platform or global-install check that is silent unless it fails the install, or code that does nothing | 7 | 0 | 0 | 0 |
| V2 | `d52ed82` refinements | `env-all` that only reads named variables, and a computed `require` of a `.json` file, no longer refuse a shape | 5 | 0 | 0 | 0 |
| V3 | `2f58977` S7 (**separable**) | permission fixes: install code whose only change to the machine is making files executable (node-pty's `spawn-helper`) | 9 | 0 | 0 | 0 |

All three are zero-loss. V3 is its own commit because round 4 kept `spawn-helper` `chmod`s
reported as "patchers" (B1's refusal, E's `OTHER_PACKAGE` guard): revert `2f58977` and V1/V2
stand alone (owner question 1).

## 1. Data and method

- **Truth:** today's verdicts (last record per version), counted with
  `~/kitsunox-scratch/r5/final/relabel.py` against the shared baseline
  (`~/kitsunox-scratch/r7/shared/base.jsonl`, rules identical to `main` `8ee117c`).
- **Diagnosis:** the 465 versions of the four install-only clusters (387 benign, 70 positive,
  8 unverified on the baseline) were dumped as Stage 3 `CodeChange`s with `main`'s code
  (tarballs read in memory with `extract_tar_gz`, nothing run; `dump.py`), and for each the
  first S1/S3/S5 guard that refuses it was recorded (`v_diag.py`), next to the reviewer's note.
- **Development:** `explain()` with `main` and with the fix on all 1,620 dumped live versions
  with an install hook (`v_explain.py`, `v_diffx.py`) and on R's dump of the 2,319 `vm-day1`
  malicious samples with an install hook (no base, a superset of live behaviour); then a subset
  replay (244 versions: every version whose explanation changed, every positive and unverified
  version in the clusters, 150 random) with the real harness, `main` vs fix; then one full
  replay.
- **`vm-day1`:** `pipeline+4` per sample (`dd.py`, repository comparison off as in rounds 3-6),
  `main` and fix, on the 205 samples whose install code exercises the new paths.

## 2. Why each cluster is not explained today

Benign versions of the four clusters on the baseline (387), by the first reason no shape
explains them, after v7:

| Reason | Benign | What it is, with examples | Safe to explain? |
|---|---|---|---|
| never routed to Stage 3 | 64 | tarball over the fetch limit (`@bitfun-test/bitfun` ×14, `tree-sitter-mssql`, `@okayok/embed`, `@tianshu-ai/tianshu` ×3, `@zpi-dev/desktop`) | out of Stage 3's reach: no code was read |
| tarball not captured | 18 | stored findings kept by the replay (`@teamcoderio/gui`, `basinfy`) | out of reach |
| `env-all`, `dynamic-code` or `dynamic-require` | 71 | the environment handed whole to a child (`dfcode`, `@almadar/orb`, `@ohos-ports/esbuild`), CLIs whose whole bundle is install code (`scarwise`, `totemlayer`, `@tailor-platform/sdk`), dependency patches (`@tianshu-ai/tianshu`, `@oiioii/cli`), telemetry (`trail-*`, `@iamem/amem`) | no: see 6.2 (`@visual-z/xeno@0.13.2`, unwanted) |
| a process | 59 | own CLIs run at install (skill installers, setup wizards), `npm`/`pip`/`python` runs, launchers that run a bundled binary with `--version`, version probes (`@genduo/desk`, `@orvyen/agentic`) | no shape: a bundled binary run at install can do anything Stage 3 can't see |
| no install code Stage 3 reads | 36 | `npm run x` (`dns-worker` ×8), tools (`nuxt prepare`, `cmake-js`, `patch-package`, `biome`), `git config core.hooksPath`, `find ... ln -sf` of a shipped `.so`, extensionless `node ./scripts/postinstall` | no: Stage 3 has nothing to judge (6.3) |
| a `binding.gyp` command | 20 | gyp actions and expansions beyond header lookups (`pkg-config`, `sh build_deps.sh`, `cp`) | `npm.install-build-tool`'s domain |
| another installed package | 18 | dependency patches (`@lobehub/editor`, `@spacecorexdev/core`, `opencode-ollama-ps` ×2), the `@ohos-ports/dsh-subprocess-local` helper restore | no (decision 0015: patching another program is unwanted) |
| new capability in an update | 11 | `@adrianmg/noted` (own binary run with `--version`), `@codeyam/codeyam-cli@0.1.0-staging.74e2564` (S7 shape, but its base had no `chmod`) | kept: the update rule |
| Baileys's `engine-requirements.js` | 11 | forks keeping upstream's Node check | owner rejected (round 4 B 7.2) |
| home directory | 10 | own config dirs under `~` (`@upskillsafrica/gihanga`, `pluton-cli`, `prxagent`) | no: S3/S5's user-wide rule |
| package loaded by name | 8 | `@anshul37_/twig` ×3 (`env-paths`), `@siteglide/siteglide-cli` (`chalk`) | no: what that package does isn't read |
| placeholder | 7 | packages that are only their install code (`mussazeb1`, `@enjoy-gaming/rng`) | no: the `vm-day1` placeholders |
| other text guards | 17 | `module` without `chmod` (`@uremysunshine/dsh-next-sentence`, which patches DSH's TUI), shell hooks, unreadable or UTF-16 code | no |
| inline banners | 3 | `@signalridge/pi-files-widget`, `@webship.co/workspace`, `dsh-tiered-compaction` | no: `shoal-cli@0.4.5` |
| agent directory, deletes, empty hooks, other | 13 | `next-security-dashboard` (scaffolds into the app), empty hook strings (round 4 B2) | no |
| **explained by v7** | **21** | sections 3-5 | |

Prompt-named shapes that stay reported, and why:

- **`@bitfun-test/bitfun` (14 versions):** never routed (tarballs of 70-87 MB), so Stage 3
  never reads them; and the shape (spawning its own vendored binaries with `--version`) runs a
  binary at install, which no shape explains.
- **Plain `node-gyp-build` / `node-gyp rebuild`:** when the gyp file runs only header lookups,
  `npm.install-build-tool` already explains the hook. Those left run gyp actions (`sh
  build_deps.sh`, `python <@(_inputs)`, `cp`), `pkg-config` lookups, or are never routed.
- **Symlinking its own `.so`:** `@amazon-devices/react-native-fast-image` does it with `find
  ... -exec sh -c 'ln -sf ...'` in the hook line: shell, which no shape reads.
- **Copying its own platform binary into `bin/`:** `@bluink/cli`, `@dalyem/hopkey`,
  `@rolandpeelen/reclap` each also delete or rename (the file they replace), and S5 refuses
  deletes (`@uselagoon/ui-library@2.0.2`, `vm-day1` malicious, empties its directory). A shape
  for "every write's destination is inside the package" needs a destination flow analysis
  (`lang.flow` follows values to writes, not writes back to their roots); not built for three
  versions.
- **Monorepo preinstall pointing at a file not shipped:** `@evercam/api` ×2 run `node
  ../shared/ci-scripts/check-bootstrap.js`. Installed, `..` is the scope directory: the path
  is `node_modules/@evercam/shared/ci-scripts/check-bootstrap.js`, another package's file if
  `@evercam/shared` is installed. Not explainable as "missing".
- **`npm run x`:** `dns-worker` ×8 run `npm run db:generate-migrations` (`tsx` of a file not
  shipped). Following `npm run` (round 4 B's rejection: `eslint-config-sdk@99.0.0` runs
  `npm run payload`) and proving the target missing needs the tarball's file list, which
  Stage 3's `CodeChange` doesn't carry; it is Stage 2's `npm.artifact.install-target-missing`
  territory (owner question 3).

## 3. V3: S7 permission fix (`2f58977`)

Twelve reviewed benign versions run install code that only restores node-pty's prebuilt
`spawn-helper` execute bit (it ships as `0644`; node-pty#850). S5 refuses them all: they name
another package (`require.resolve("node-pty/package.json")`, `node_modules/node-pty`) and
most use `createRequire`, so the text names `node:module`.

S7 holds when the install code's **only change to the machine is file modes**:

- at least one `chmod` (`chmodSync`, `fs.promises.chmod`, `lchmod`), every one with a constant
  mode that has the owner's execute bit and nothing beyond `0o777` (`0o755`, `info.mode |
  0o111`; no setuid, setgid or sticky bit), read from the parse tree (`chmod_modes`);
- no other write or delete (`install_code.WRITES` with the `chmod` names removed, `DELETES`);
- capabilities `filesystem` and `os-info` only, every hook `node <file>` or `node -e`, every
  install file JavaScript, no package loaded by name;
- `createRequire` only to locate files: every result is used as `.resolve(...)` or given to
  another `createRequire` (`requires_only_resolve`; `createRequire(...)("x")` loads a package
  the profile's package list does not see);
- S5's text guards (`RISKY_TEXT`, `SYSTEM_PATH`, home and agent directories) except that
  `module` may be named; not a placeholder.

Making a file executable runs nothing; running it needs a process, which S7 refuses. It may
name another installed package, which is the point: the files it touches are node-pty's.

Live: 9 benign unreported (`@anisirji/pocket-dev@1.1.0`, `coban@0.2.1`,
`@codeyam/codeyam-cli@0.1.0-staging.67f40c5` and `905dc39`, `@easyx/ucode@0.5.0`,
`@k-electron/k-bench@0.1.0`, `@ryamgoh/terminal-mcp@0.1.0`, `@setupsworks/office@0.7.4`,
`unfold-deploy@0.1.0`). It also holds for `pull-pal@0.2.0` and `@val.io/valio@0.1.0`, already
explained by S1. Not explained: `@zpi-dev/desktop` and `@yalehwang/cloudpit@2.0.0`
(unverified) are never routed; `usage-report@0.2.2` is an update whose hook is new and its
install code names a GitHub release URL (v5's added-hook guard); `@codeyam/...74e2564` is an
update whose base had no `chmod`. Fires on no positive, live or `vm-day1`.

## 4. V1: S8 inline install guard (`d52ed82`)

Round 4's E3 (S5 for inline `node -e` code) was dropped because `shoal-cli@0.4.5` (`vm-day1`
malicious, a follow-on) is reported only through its inline banner. S8 is narrower: every hook
is `node -e <code>`, no other install file, and the code is a **guard** (`guard_only`): its
statements are declarations of values computed from `process.version(s)`, `process.platform`,
`process.arch` and named environment variables (`process.env.X`, `process.env["X"]`) with a
short list of string/array/number helpers (`split`, `map`, `trim`, `includes`, `Number`,
`parseInt`, ...), `if` tests on them, and `process.exit(<number>)`; it prints only in a branch
that then ends in `process.exit(<non-zero>)`. Empty code (`node -e ""`) and `process.exit(0)`
are guards too. Every other call, assignment, loop or function refuses it. A banner that
prints on every install is not a guard, so `shoal-cli` stays reported. Inline only: the same
check in a file is S5's to judge, and upstream Baileys's `engine-requirements.js` stays
reported (round 4 B, owner question 7.2 of that round).

Live: 7 benign unreported (`@muhgholy/next-drive` 9.0.0 and 9.1.0, Node-version checks;
`puppet-mcp@6.1.2`, refuses a global install; `@zintrust/core@3.5.1` and
`@h1stealthy/gh046-npm-transfer-9421a2@0.0.8`, `process.exit(0)`; `ezsnmp-data-logger`
2026.11.6 and 2026.11.6-1, `node -e ""`). `vm-day1`: the five malicious samples with only
inline install code and no capability (`shoal-cli` 0.4.3 and 0.4.5, `base_parts_ai@1.0.37`:
banners; `sysverify@2.0.10`: loads `electron`; `maybe-i-would-like-a-banana@1.0.2`) are not
guards.

## 5. V2: `env-all` read by name, `require` of JSON (`d52ed82`)

Every shape refuses `env-all`, `dynamic-code` and `dynamic-require`. Two of those are counted
coarsely by the capability profile, and v7 reads them precisely, for the shapes only
(`install_shapes.capabilities`; the profile and every other rule are unchanged):

- **`env-all`** is any value-use of `process.env` (`const env = process.env`,
  `isCI(process.env)`). It is dropped when every install file with it only accesses named
  variables (`env_read_by_name`): `process.env.X`, an alias (also through `||`, `??`, a
  ternary) whose every use is `name.X` or `name["X"]`, or an argument to a function the same
  file declares whose parameter is used only so (and that doesn't read `arguments`).
  Spreads, `Object.keys`, `JSON.stringify`, `{ env: process.env }`, calls of functions the
  file doesn't declare, `Reflect.get`, `process["env"]` and `getBuiltinModule` keep it.
  Live: `erin-report@0.1.0`, `erinyu-slides@0.1.1` (S5: an install guide unless `env.CI`),
  `nestjs-boost@1.2.0` (S3).
- **`dynamic-require`** is any `require` of a computed path. It is dropped when every one
  loads a `.json` file (`requires_only_json`): a path expression ending in a constant `.json`
  (`path.join(here, "package.json")`, `require.resolve(`${pkg}/package.json`, {paths})`),
  directly or through a name given exactly one such value; never `import(...)`, never in a
  file that names `extensions` (`require.extensions[".json"] = ...` would make JSON run as
  code). Live: `tttt-ts@3.0.0`, `lockpicks@0.8.0-go.11` (S1, esbuild-style launchers reading
  their platform package's version), and `@corepassinc/remy@0.1.0-rc.27` (already
  unreported).

## 6. Rejected or measured and not built

1. **Restricting the install code to the files that can run** (a file only named as a
   `chmod` target is followed as install code, e.g. `@promethea-research/sundial@0.2.4`'s
   `dist/sundial.js`): measured, 1 benign version. Not built.
2. **Dropping `env-all` whenever the environment only goes to a child process's `env`
   option** (`{ ...process.env, X: y }`, no more than the child inherits anyway): would add
   `dfcode` ×3 and `@almadar/orb` to S1, but upper-bound measurement (no `env-all` at all)
   also explains `@visual-z/xeno@0.13.2` (unwanted: a persistent PATH change through
   PowerShell) as S1, which allows a process. Not built; S1's process allowance is the wider
   question (owner question 2).
3. **Dropping `dynamic-require` entirely:** upper bound +4 benign, and explains `doukui@0.3.0`
   (unwanted, user-wide agent writes) as S3. Built only for `.json` (V2).
4. **A runtime-version-probe shape** (`spawnSync("python3", ["--version"])`: `@genduo/desk`,
   `@orvyen/agentic`, `worktree-for-agents`): 3-4 benign, but the program is often an
   environment override (`ORVYEN_PYTHON`) or a parameter; a process shape needs a dataflow
   this round didn't build.
5. **Extensionless hook targets** (`node ./scripts/postinstall` is `scripts/postinstall.js`,
   which `install_sources` doesn't find): a reach gap, so Stage 3 reads no install code for
   them (`@ohos-ports/foundation-cli`, `@ohos-ports/onnxruntime-node`). Fixing it is a change to
   `ecosystems/npm/install.py` (shared) that adds install code everywhere; worth doing for
   recall, not for this cluster (2 live versions). Reported, not built.

## 7. Live result

| | Reported | Benign | Unwanted | Malicious | Unverified | Precision |
|---|---|---|---|---|---|---|
| `main` `8ee117c` (shared baseline, `base.jsonl`) | 1,469 | 771 | 620 | 48 | 30 | 46.42% |
| **`main` + V1 + V2 + V3** (`d16914b`, `full-final.jsonl`) | **1,448** | **750** | 620 | 48 | 30 | **47.11%** |

The 21 benign versions unreported: S7 `@anisirji/pocket-dev@1.1.0`, `coban@0.2.1`,
`@codeyam/codeyam-cli@0.1.0-staging.67f40c5`, `...905dc39`, `@easyx/ucode@0.5.0`,
`@k-electron/k-bench@0.1.0`, `@ryamgoh/terminal-mcp@0.1.0`, `@setupsworks/office@0.7.4`,
`unfold-deploy@0.1.0`; S8 `@muhgholy/next-drive` 9.0.0 and 9.1.0, `puppet-mcp@6.1.2`,
`@zintrust/core@3.5.1`, `@h1stealthy/gh046-npm-transfer-9421a2@0.0.8`,
`ezsnmp-data-logger` 2026.11.6 and 2026.11.6-1; V2 `erin-report@0.1.0`,
`erinyu-slides@0.1.1`, `nestjs-boost@1.2.0`, `tttt-ts@3.0.0`, `lockpicks@0.8.0-go.11`. No
version became newly reported, and no non-benign decision changed (`relabel.py` lists none).
Without V3 (revert `2f58977`): 12 benign removed, the same zero loss (V3's nine are exactly
the S7 rows; `explain()` per version, section 1).

Of the brief's clusters: `install-hook` alone 199 → 182 benign (its 24 unwanted and 4
unverified unchanged); `install-hook` + `install-script-code` 63 → 61;
`install-script-changed` alone 49 → 49 (14 unwanted unchanged); `install-hook` +
`install-script-changed` (+ code) 58 → 55. `teleton@0.11.8` also leaves the `install-hook`
alone set without changing its decision: the shared baseline carries
`npm.dependency.non-registry` v8 (LOW) for it, `main`'s v9 makes it MEDIUM (a commit pin in
another repository); not this change.

## 8. `vm-day1`

- `explain()` with `main` and with the fix on all 2,319 `vm-day1` malicious samples with an
  install hook (dumped with `main`'s code, no base): **no sample's explanation changes**. R's
  round-6 dump gives the same.
- `pipeline+4` per sample, `main` and fix, on the 205 samples whose install code reaches the
  new code paths (142 with a `chmod`, 62 with only inline hooks, 1 whose `env-all` is read by
  name): 201 reported with both, the same 201; **0 lost**. The four not reported are not
  reported by `main` either.
- Kept reported on purpose: `shoal-cli` 0.4.3 and 0.4.5 and `base_parts_ai@1.0.37` (inline
  banners, not guards), `sysverify@2.0.10` (inline code loading `electron`).

## 9. Owner questions

1. **S7 (`2f58977`):** take it? Round 4 kept `spawn-helper` `chmod`s reported with the other
   patchers. S7 explains only install code whose sole effect is making files executable (no
   content written, no process); 9 benign versions, no positive. Reverting the commit leaves
   S8 and the refinements.
2. **S1 allows a process** (to run the platform binary with `--version`); with `env-all`
   gone it would also explain a PowerShell PATH change (`@visual-z/xeno`, unwanted). Should S1
   require that every process it runs is the platform package's binary? That would make the
   `env`-option refinement (6.2) safe.
3. **`npm run x` to a file the tarball doesn't ship** (`dns-worker` ×8): a Stage 2 extension
   of `npm.artifact.install-target-missing` (follow `npm run` one level, then the same
   missing-file test) would explain them; outside this agent's stage.

## 10. How to reproduce

Scripts in `~/kitsunox-scratch/r7/V/scripts/` (data only; tarballs read in memory, nothing
run): `v_clusters.py` (clusters from the baseline), `dump.py` and `dd_dump.py` (Stage 3
`CodeChange` dumps), `v_diag.py` (first refusing guard), `v_explain.py` + `v_diffx.py`
(`explain()` with two code trees), `v_ddnear.py` (`vm-day1` samples on the new paths),
`replay.py` (agent K's harness), `dd.py` (`pipeline+4` per sample).

```sh
python -I replay.py final/src ~/kitsunox-scratch/r5/shared/cands.jsonl.zst out/full-final.jsonl 2
python -I ~/kitsunox-scratch/r5/final/relabel.py ~/kitsunox-scratch/r7/shared/base.jsonl out/full-final.jsonl
python -I dd.py base/src out/dd-near-base.jsonl 2 work/ddnear.keys
python -I dd.py fix/src out/dd-near-fix.jsonl 2 work/ddnear.keys
```
