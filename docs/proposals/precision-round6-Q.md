# Proposal: precision round 6, agent Q: versions reported only because they have an install hook

> **Status:** built 2026-11-10, before the rule freeze (2026-11-12 00:00Z), for the owner's
> review. Cluster: versions whose only MEDIUM-or-higher findings are the install rules
> (`npm.install-hook`, `npm.install-script-code`, `npm.install-script-changed`).
> **Result on `main` `79958e6`/`b767898`, real code, 3,716 verdicted live versions, today's
> verdicts: 1,349 → 1,328 reported, all 21 benign; no malicious, unwanted or unverified version
> changes.** Precision 34.80% → 35.36% (the verdicts re-labelled under the strict download
> ruling already moved the baseline from 22.90%). `vm-day1`: DD_RESULT. Zero-loss.
> **Builds on:** [round 3](precision-round3.md) (method), rounds 4 and 5 (agents B, E, H, I, J),
> decision [0015](../decisions/0015-reviewer-verdicts.md) with all addenda, including the
> owner's strict ruling of 2026-11-10 (install-time downloads of code are unwanted, own
> binaries included; a hook that runs a Windows executable is unwanted at best).

## Summary

| # | Change | Benign removed | Positives at risk → lost | Unverified lost | `vm-day1` fired → lost |
|---|---|---|---|---|---|
| Q1 | Stage 2 `npm.artifact.install-target-missing` (INFO), explaining `npm.install-hook` in Stage 4 (`EXPLAINED`, `STAGE_VERSION` 17): every hook is `node <file>` and the whole tarball has no such file | **8** (fires on 9; `agent-god-view@0.1.0` stays reported by `npm.repo.install-script-not-in-repo`) | 0 → 0 (fires on no positive) | 0 | DD_Q1 |
| Q2 | Stage 3 `npm.install-explained` v5: an update whose hook is new is judged like a new package, S1/S3/S5 only, no home directory, no URL but the registry | **13** (fires on 14; `@octane-xplat/cli@0.20.0` stays reported by `npm.repo.install-script-not-in-repo`) | 0 → 0 (fires on no positive) | 0 | DD_Q2 |

**Commits** (on `worktree-agent-a2badfee15539caac`, on `b767898`): `ac9812f` (Stage 2: Q1 rule
and tests), `70d3ec7` (Stage 4: `EXPLAINED` entry, `STAGE_VERSION` 17, test), `1ff56b9`
(Stage 3: Q2, `npm.install-explained` v5, tests); docs in a separate commit. Both zero-loss; no
trade-off commit. `correlate.decide`, `WEAK_ALONE` and `REPORT_SCORE` are unchanged (section 5).

## 1. Method

Agent K's corrected harness (`replay.py`, real code, Stage 4 with the run's watchlist), today's
verdicts (`relabel.py`: last record per version). Baseline: `main` `79958e6`, replayed by the
integrator (`~/kitsunox-scratch/r6/shared/base.jsonl`; rules identical to `b767898`, which
only adds decision 0015's text). Both changes only *lower* the three install rules (they add an
explanation), so they can only unreport a version that carries one of them at MEDIUM or above:
779 reported versions whose Stage 2/3 were recomputed. On those, the new code was run on the
tarballs read in memory (`qfire.py`: Stage 2's artifact rule and Stage 3's `code_change`, as the
replay does) to find every version either change fires on; those were replayed end to end with
the new code and compared with the baseline row by row. Every other version carries neither
new finding, so its findings and decision are the baseline's.

Diagnostics (`qdiag.py`, `qvar.py`): for each of the 591 versions in the five clusters below,
every guard of S5 / `npm.install-inert` / S6 that refuses it, and which shape it would get with
one guard relaxed.

## 2. What is left: the clusters, by what the hook does

The five med+ rule sets the brief names (current `main`, today's verdicts):

| Set | Benign | Positives | Unverified |
|---|---|---|---|
| `npm.install-hook` alone | 243 | 7 | 4 |
| `install-hook` + `install-script-code` | 111 | 30 | 0 |
| `install-script-changed` alone | 90 | 8 | 0 |
| all three | 59 | 6 | 0 |
| `install-hook` + `install-script-changed` | 32 | 1 | 0 |

### 2.1 `npm.install-hook` alone (243 benign)

**76 benign are never read** (`unrouted`: declared size over Stage 2's 32 MB cap for hooked
versions): `@bitfun-test/bitfun` ×13 (daily platform packages), `@testmuai/kane-cli-node-*` ×4,
`@tianshu-ai/tianshu` ×5, `@mmmbuto/codex-vl` ×2, `tree-sitter-mssql`, `tree-sitter-razor-modern`,
`clap-cpp`, `@okayok/embed`, `keyrouter`, `@karartech/9router`, `98router`, `vibelet` and
`@vibelet/cli`, ... With them sit 4 positives/unverified (`@ywabgl/musepool-html-mcp@0.2.0`,
`charape@1.0.20`, `@algorithco/algocli@0.1.6`, `@yalehwang/cloudpit@2.0.0`). Nothing can be
explained without reading the files, and clearing unread hooks would lose the two unwanted
versions: left alone (routing is Stage 2's, not this cluster's).

**7 benign + 3 positives have no tarball left** (`stored`: the replay keeps their recorded
findings): unmeasurable, left alone.

**The 160 benign read by Stage 3**, by what blocks every explanation:

| Group | Benign | Examples | Why it stays reported |
|---|---|---|---|
| Hook is not `node <file>` (shell, a tool, `npm run`) | 42 | `npm run install:prebuilt` (`@agoric/xsnap` ×4), `npm run db:generate-migrations` (`dns-worker` ×8), `nuxt prepare` ×4, `git config core.hooksPath` ×2, `npm install` (`gihanga-*` ×3), `bunx bun-git-hooks` ×2, `camoufox fetch`, `npx playwright install`, `curl` (`@groupdocs/*`) | `npm run` is how `vm-day1` payloads hide (`eslint-config-sdk@99.0.0`); dev tools run the project's config (B's rejections); Playwright/Camoufox/`curl` are downloads (owner, strict) |
| Hook runs a file the package doesn't ship | 12 | `@copio/sdk@0.1.0`, `@statusline/claude-plugin@1.1.3`, `@igorjpimenta/doppler-harness`, `cdeops@13.5.32`, `site2paper@0.1.0`, `@evercam/api` ×2 (`../shared/...`) | **Q1** (below) for those whose whole tarball is known |
| Baileys fork, upstream `engine-requirements.js` | 13 | `@barzenv404/baileys`, `@yui-bails/*`, `mfsavana-baileys`, `supernova-baileys` | owner question 7.2 of round 4 B; `luna-baileys@1.0.0` (unwanted, tarball gone) has the same shape |
| Inline `node -e` | 15 | `@muhgholy/next-drive` ×2, `ezsnmp-data-logger` ×2 (`node -e ""`), `@zintrust/core`, `puppet-mcp`, `@webship.co/workspace` | owner rejected E3 (`shoal-cli@0.4.5`) |
| Touches another package (`require.resolve`, `node_modules/...`) | ~25 | node-pty `spawn-helper` `chmod` (`@easyx/ucode`, `teamfactory`, `unfold-deploy`, `@setupsworks/office`, `@codeyam/*` ×3), dependency patches (`@lobehub/editor`, `parquet-tool`, `opencode-ollama-ps` ×2) | owner keeps patchers reported (round 4 B, E) |
| Placeholder (no code but the install code) | 6 | `mussazeb1`, `mussazeb2`, `mcp-turbo-setup`, `@enjoy-gaming/rng`, `zero-day-v1` ×2 | the `vm-day1` dependency-confusion PoCs have this shape |
| Home directory | ~12 | `gihanga@2.0.0`, `@kernaut/*`, `prxagent`, `@code2knowledge/skill`, `@anshul37_/twig` | user-wide writes; the owner's rulings make several of them unwanted |
| Native build (`node-gyp`, `cmake-js`, shell build scripts) | ~15 | `@ohos-ports/*` ports, `neuropile`, `node-gd`, `electron-storekit` | a `binding.gyp` command, `cmake-js` or a shell script runs the package's build; the scripts must be analysed, not explained by name (owner) |
| **Update whose hook is new** | 9 | `@cheezmil/aek-websearch@1.1.11`, `@nathanzhou/meridian@0.1.1`, `@contentsquare/react-native-bridge@6.6.0`, `@anyglade/kit@0.3.0`, `@arbol-ai/ui@0.2.0`, `tm-playwright-framework@2.3.1`, `@nlayer/cli@0.2.0`, `@octane-xplat/cli` | **Q2** (below): the new-capability test refuses any new hook, whatever its code does |
| Deletes, writes the project, runs a process | the rest | `focus-guard`, `@bluink/cli`, `@dalyem/hopkey` (copy/delete own files), `@ohos-ports/pre-push` (git hook into the project) | `DELETES` (`@uselagoon/ui-library@2.0.2`), project writes (round 4 B) |

### 2.2 `install-hook` + `install-script-code` (111 benign, 30 positives)

The install code uses the network or runs processes. 102 benign are new packages: downloaders
(`@mateuszwrobel/*` ×6, `kenvoy`, `kondor`, `simflux-cli`, `codegraph-mcp-server`,
`ihsg-cli`, ...), which the owner's strict ruling of 2026-11-10 makes positives (they are being
re-labelled now), third-party browser and tool installers (Playwright, Mutagen, V, Caddy,
ffmpeg, pip), version probes (`python3 --version`: `@genduo/desk`, `worktree-for-agents`),
builds (`cargo`, `node-gyp`), and project/agent setup. The 30 positives are the 24
`@byteplus/` and `@volcengine/arkcli-probe-*` downloaders, `@jarvis_1234/env-preloader@1.0.6`,
`@rgctl/migiq@0.4.23`, `claudecode-ms-teams@0.1.0`, `doukui@0.3.0` (unwanted) and
`dependencykfeg@1.5.6` (malicious). No shape here is safe to add under the strict ruling: left
alone (agent R owns downloads).

### 2.3 `install-script-changed` alone (90 benign, 8 positives) and the two mixed sets

Updates whose install code changed with a risky token on a changed line (agent J's v6). The
benign ones are rebuilt installers (`@progress/kendo-licensing` ×3, `qdd-framework` ×4,
`sigmob-monetization-cli` ×3, `scarwise` ×3) and downloaders. `scarwise@0.1.4`-`0.1.6` are
benign and `0.1.7`/`0.1.8` unwanted with the same installer, so no install-code shape can
separate them. J2 (ignore tokens the previous code had) is rejected. Left alone, except the
added-hook updates Q2 takes (`all three` and `hook + changed` sets).

## 3. The fixes

### Q1. Hooks that run a file the package doesn't ship (`npm.artifact.install-target-missing`)

A hook `node scripts/x.mjs` whose file the tarball doesn't have runs nothing: Node fails to
find it and npm reports a failed script. Reviewers cleared every one (a `files` list that
leaves `scripts/` out, a monorepo hook published as is). Stage 3 can't tell "missing" from "not
read" (it keeps only the files it reads), so the rule is a Stage 2 artifact rule, which sees the
whole tree. It holds only when:

- every install hook is exactly `node <path>` (optionally `|| true` / `|| exit 0`): no other
  program, `node` option, inline code, chain, redirect, variable, absolute path, `..` (from
  `node_modules/<pkg>`, `../shared/x.js` is another package's file: `@evercam/api` ×2 stay
  reported) or `node_modules/` path;
- no file is the path, the path plus any suffix (Node resolves `x` as `x.js`, `.json`, `.node`,
  ...), or a directory of that name (`index.js`, `main`), compared without case (macOS and
  Windows);
- the tree is the whole package: the tarball's hooks equal the registry's (else
  `hidden-install-script` is the finding), no `binding.gyp` (npm then adds `node-gyp rebuild`),
  nothing skipped (links, unsafe paths, unreadable entries), no tar anomaly or duplicate, and the
  files add up to the declared `unpackedSize` within `size-mismatch`'s tolerance. The last guard
  is for sample sets: DataDog's zips miss files (`@tushar-br/desktop`: 47 MB declared, 13 KB
  present), and a missing hook file there is the dataset's gap, not the package's;
- the line has no backslash (Windows runs `node lib\\index.js` as `lib/index.js` while a
  POSIX shell reads `libindex.js`: `company-ts@1.0.3`, `vm-day1` malicious) and the "path" is
  not a `node` option (`node --version`);
- the package doesn't look like a broken attack (`broken_attack`), which the next release
  fixes: it ships some JavaScript (not a probe placeholder: `@testcarrot/supply9@1.0.2`), its
  declared `main` is shipped (not an emptied package: `modern-react@17.2.6`), and no JavaScript
  file named like an install script (`instal` in the name) sits at its root or beside the
  missing target (the script the hook misnames: `instal.js` beside `node install.js` in
  `parashaxmgflhg@0.33.4`, `postinstall.js` beside `node install.js` in
  `@vampirchik147/libxmljs2@0.19.7`). These four `vm-day1` malicious samples are reported only
  by their hook; the first version of Q1 lost them (section 5), this guard keeps them.

Benign unreported (8): `@copio/sdk@0.1.0`, `@igorjpimenta/doppler-harness@2026.11.4-beta.1`,
`@statusline/claude-plugin@1.1.3`, `@toothfairyai/tfcode@3.0.4`, `@upskillsafrica/gihanga@1.0.1`,
`@whcecw/maotu@0.0.29`, `cdeops@13.5.32`, `site2paper@0.1.0`. `agent-god-view@0.1.0` also gets the
finding and stays reported (`npm.repo.install-script-not-in-repo`, MEDIUM). Not reached:
`@tianshu-ai/tianshu` ×3 and `@jzwvip/chengyu` (never read live: over Stage 2's cap),
`dns-worker` ×8 (`npm run`, then `tsx` on a missing file).

### Q2. An update whose install hook is new (`npm.install-explained` v5)

Every explained shape refuses an update whose install code has a capability the previous
version's install code lacked. When the previous version ran no install code (`hook_added`: no
hook, or a hook that named no file of the package), *every* capability is new, so any added
hook was refused, whatever its code, while the same code in a new package is S1, S3 or S5. Most
are the first real release after a `0.0.0` name-holding placeholder (`@square/cli@0.3.0`,
`@nlayer/cli@0.2.0`, `@deadbolt/cli`, `braintentacle_cli@2.2.0`) or a CLI that moved to
per-platform npm packages (`@octane-xplat/cli`, `@litol-ai/cli`, `@anysola/code`). v5 judges such
an update like a new package, with three extra limits:

- only S1 (platform builds from the npm registry), S3 (agent copies into the project) and S5
  (inert code): never S2 or S6, which explain downloads (decision 0015, strict, 2026-11-10);
- not when the install code (or hook line) names the home directory;
- not when the install code names any URL other than the npm registry or a page link. This is
  what keeps `qpq@0.3.0` and `usage-report@0.2.2` (S1 in `qvar.py`, but naming GitHub release
  URLs: candidates for the strict download ruling) and `@toothfairyai/tfcode@3.0.5` reported.

Benign unreported (13): S1 `@anysola/code@0.2.0`, `@deadbolt/cli@0.0.0-dev-134`,
`@litol-ai/cli@0.0.0-dev-202611041116`, `@nlayer/cli@0.2.0`,
`@octane-xplat/cli@0.0.0-nightly.gf55b7b9`, `@square/cli@0.3.0`, `braintentacle_cli@2.2.0`; S3
`@anyglade/kit@0.3.0`, `@apthubies/dfix@0.1.1`, `@arbol-ai/ui@0.2.0`, `tm-playwright-framework@2.3.1`;
S5 `@cheezmil/aek-websearch@1.1.11`, `@contentsquare/react-native-bridge@6.6.0`.
`@octane-xplat/cli@0.20.0` gets S1 and stays reported (`npm.repo.install-script-not-in-repo`).

Why it is safe to judge a new hook as a new package's: the guards of each shape are the ones
the owner accepted for new packages; an update is not more dangerous for having a hook it
didn't have, *given* the code is S1/S3/S5 (registry-only launchers, project-only agent copies,
inert code). A takeover that adds a hook with any other capability, a download, the home
directory or a foreign URL keeps the HIGH "script added" finding. The positives the brief
names with an added hook all keep it: `@minonl/dia@0.0.19` (process), `@patchgg/cli@0.4.0`
(inline), `@benwallacestock/lantern@0.4.0`, `rl-workspaces@0.7.0`, `@olierjs/fugue-cli@0.1.6`
(process, environment), `@safetech/inheriti-cli@0.0.21-dev.0`, `@nareshramesh/code-walkthrough@1.0.2`
(home, agent directory), `kevinx-baileys@1.2.2` (Baileys guard; its hook was not added).

## 4. Live table (today's verdicts, `relabel.py`, re-run before hand-back)

| replay | reported | benign | unwanted | malicious | unverified | precision |
|---|---|---|---|---|---|---|
| `main` `79958e6` (`base.jsonl`) | 1,349 | 860 | 412 | 47 | 30 | 34.80% |
| + Q1 + Q2 (`final.jsonl`) | 1,328 | 839 | 412 | 47 | 30 | 35.36% |

`relabel.py` lists no changed non-benign version. Of the brief's positives in the five sets
(7 + 30 + 8 + 6 + 1, plus 4 unverified) none gets a new explanation; every one is reported as
before. Named: `@nuri.yavuz.tr.2/my-unique-pinger@1.0.0` (unwanted) and `@1.0.2` (malicious),
`@atedone/workspace-bootstrap@0.0.1`, `@ywabgl/musepool-html-mcp@0.2.0`, `charape@1.0.20`,
`kevinx-baileys@1.2.2`, `luna-baileys@1.0.0` (unwanted), `@algorithco/algocli@0.1.6`,
`@yalehwang/cloudpit@2.0.0`, `prctls@1.0.0`, `testbail@1.0.0` (unverified); the 24
`@byteplus/`/`@volcengine/arkcli-probe-*`, `@jarvis_1234/env-preloader@1.0.6`,
`@rgctl/migiq@0.4.23`, `claudecode-ms-teams@0.1.0`, `doukui@0.3.0` (unwanted),
`dependencykfeg@1.5.6` (malicious); `@aweray/aweshell-cli@0.4.25`, `@datarails-ai/dr-cli@1.6.200`,
`@mobileaidev/ai-app-bridge@0.4.20-distribution.1`, `@su-record/vibe` ×3, `scarwise@0.1.7`,
`@0.1.8`; `@benwallacestock/lantern@0.4.0`, `@minonl/dia@0.0.19`, `@olierjs/fugue-cli@0.1.6`,
`@patchgg/cli@0.4.0`, `@safetech/inheriti-cli@0.0.21-dev.0`, `rl-workspaces@0.7.0`;
`@nareshramesh/code-walkthrough@1.0.2`. No rescue rule was needed.

DD_SECTION


## 5. Rejected or not built

- **A lone install hook on a new package as `WEAK_ALONE`** (or reported only with a second
  signal), the `correlate.decide` question of the brief: of the 243 benign versions carried by
  `npm.install-hook` alone, 76 were never read, and the 160 read by Stage 3 are exactly what
  S5 / `npm.install-inert` refuse on purpose. Weakening the hook in `decide` would drop those
  guards: on the live set it loses `@nuri.yavuz.tr.2/my-unique-pinger@1.0.0` (unwanted: a
  `curl` beacon, no install file), `@atedone/workspace-bootstrap@0.0.1` (unwanted: the payload
  is a `binding.gyp` action), `kevinx-baileys@1.2.2` (unwanted: the follow code is in an
  unchanged file), the unread `charape@1.0.20` and `@ywabgl/musepool-html-mcp@0.2.0`, and on
  `vm-day1` the dependency-confusion placeholders S5 guards against (`wc@1.5.0`,
  `coldbox@6.7.71`, `pmcrypto@0.1.0`, `grab-service-worker@1.0.1`) and the `/tmp` proofs
  (`cesium-native@0.56.0`, `dep-graph-gen@1.0.0`). Even "Stage 3 read it and
  `install-script-code` is silent" keeps all of those but the beacon in play. Not built;
  `decide`, `WEAK_ALONE` and `REPORT_SCORE` are unchanged.
- **Downloaders of the package's own binary** (S2/S6 relaxations: `env-all` from passing
  `process.env` to `tar`, the home cache directory, `process` for `--version`): ~40 benign in
  2.2/2.3, now positives under the owner's strict ruling of 2026-11-10. Not touched (agent R).
- **S1 with a whole-environment read** (`qvar.py`: `@g1728578755/atb` ×2, `@almadar/orb`,
  `dfcode`, `codeoutline`, `agent-browser-cli2`, `@silkcipher/link`, `@ohos-ports/esbuild`: 9
  benign): `env-all` is excluded from every shape because install code that reads the whole
  environment can carry tokens away; telling a harmless `{...process.env}` passed to a child from
  a harvest needs data flow the extractor doesn't have. Not built.
- **`npm run <script>` hooks** (`@agoric/xsnap` ×4, `dns-worker` ×8, `paseo-jira-sprint-workspace`):
  following the script needs `install_sources` (a shared helper) to read what `npm run` runs;
  `vm-day1` payloads use exactly this. An owner question (below), not built.
- **Inline `node -e ""` / `process.exit(0)`** (`ezsnmp-data-logger` ×2, `@zintrust/core`,
  `@h1stealthy/gh046-npm-transfer-9421a2`: 4 benign): inline code is E3, which the owner
  rejected; four versions don't justify a carve-out.
- **Missing-target hooks whose path climbs out** (`@evercam/api` ×2: `node ../shared/...`): from
  `node_modules/@evercam/api` that path is another package's file (`@evercam/shared`), which can
  exist. Refused (`hook_target` takes no `..`).
- **Version probes** (`python3 --version`: `@genduo/desk`, `worktree-for-agents`): 2-3 benign; a
  probe-only process shape needs its own command parser next to S6's, which agent R is changing.
  Not built.

## 6. Owner questions

1. Keep Q1 and Q2 for the freeze? Both zero-loss live and on `vm-day1`; 21 benign together.
2. **A Stage 3 recall gap found on the way (not changed):** `install.files_named` takes a hook's
   path only as written, so `node ./scripts/postinstall` (Node runs `scripts/postinstall.js`) or
   `node index` is never read as install code; only `npm.install-hook` sees such a hook, and no
   install-code rule (`install-script-code`, `-obfuscated`, `-persistence`) reads it. Live:
   `@ohos-ports/foundation-cli@15.92.0-beta.0`, `@ohos-ports/onnxruntime-node@1.21.0-beta.0`,
   `@pkmn/engine@0.1.0-dev.1986dd93`. Resolving the path as Node does (`x`, `x.js`, `x.json`,
   `x.node`, `x/index.js`) is a shared-helper change (`ecosystems/npm/install.py`) for after the
   freeze; Q1 already treats such a path as present.
3. S1 does not check the home directory or a process that downloads (`curl` through
   `child_process`); for new packages that is round 2's shape, unchanged here. Under the strict
   download ruling, should S1 refuse install code whose process calls are not the platform
   binary's `--version` (agent R's area)? Q2 refuses home and foreign URLs for added hooks.
4. After the freeze: let `install_sources` follow `npm run <script>` (round 4 B's question 5);
   12 benign live versions here (`@agoric/xsnap` ×4, `dns-worker` ×8) would then be read.

## 7. How to reproduce

Scratch: `~/kitsunox-scratch/r6/Q/`. `clus.py base.jsonl clus.json` (the five sets),
`scripts/qdiag.py SRC CANDS KEYS OUT` (every refusing guard), `scripts/qvar.py` (one guard
relaxed), `scripts/qfire.py SRC CANDS instkeys.txt fire.jsonl` (the 779 reported versions with
an install rule at MEDIUM+; fires on 23), `scripts/replay.py srcq2/src CANDS q2-fire.jsonl 2
@firekeys.txt` (end to end on those 23), `final.jsonl` (= `base.jsonl` with those rows), then
`~/kitsunox-scratch/r5/final/relabel.py base.jsonl final.jsonl`. `vm-day1`: `scripts/ddq.py
SRC BASE ddq.jsonl` (samples Q1/Q2 fire on), then `dd.py` with `main` and the fix on those keys.
