# Stage 3: Capability analysis (AST)

> **Status:** implemented 2026-10-28 (`lang/javascript.py`, `stages/ast.py`, rules in
> `rules/capabilities.py` and `ecosystems/npm/rules/install_code.py`). It runs in `collect`
> after Stage 2. Evaluation numbers are below. Since 2026-11-08 it also recognises "explained
> install" shapes (`ecosystems/npm/rules/install_shapes.py`) and reads the AI-agent
> configuration a package's install code may copy (`lang/agent_config.py`,
> `rules/agents.py`): [Explained install](#explained-install-s1-s3-and-agent-configuration).

## Purpose

Stage 2 reads code with regular expressions, so a URL in a comment and a `require("https")` look
the same. Stage 3 parses every JavaScript/TypeScript file with tree-sitter and asks what the
code **can do**. It then compares that with the previous version: a package whose code
suddenly gains network access, or starts taking the whole environment, has changed in the way
supply-chain payloads change packages.

## Usage

```sh
uv run kitsunox ast <run_id>                                  # after `triage` and `static`; writes ast.jsonl
uv run kitsunox eval run <dataset> --predictor stage3-rules   # Stage 3 alone, every release
uv run kitsunox eval run <dataset> --predictor pipeline+3     # end to end with Stage 3
```

## Capabilities (`lang/javascript.py`)

| Capability | Found from |
|---|---|
| `network` | `http`, `https`, `http2`, `net`, `tls`, `dns`, `dgram`, `undici`, `axios`, `node-fetch`, `got`, `request`, `ws`; `fetch()`, `new WebSocket`, `new XMLHttpRequest` |
| `process` | `child_process` |
| `filesystem` | `fs` (and `fs/promises`), `fs-extra`, `graceful-fs` |
| `os-info` | `os` |
| `env-all` | `process.env` used as a value (passed, serialised, spread, `{...rest}`), not one variable read |
| `dynamic-code` | `eval()`, `Function()`, `new Function`, `vm`, `global["eval"]`; the Function constructor reached through `constructor` (`x.constructor.constructor`, `(async () => {}).constructor`; extractor v5) |
| `dynamic-require` | `require(x)` / `import(x)` with a non-constant argument |
| `native` | `require("*.node")`, `process.binding`, `process.dlopen` |

What the parse adds over Stage 2's regular expressions:

- Comments and plain strings are ignored.
- Constant string concatenation is folded (`require("child_" + "process")`).
- Bracket access with literal keys is resolved (`global["ev" + "al"]`, `process["env"]`).
- Reading `process.env.HOME`, or destructuring `{HOME}`, is not environment harvesting.

Modules are matched by `require`, `import`, `export ... from` and dynamic `import()`, with or
without the `node:` prefix. `.d.ts` files are skipped, since no code runs.

**Performance.** Name filters run inside the tree-sitter query, in C. One hourly run (about
760 MB of distinct JS/TS, base versions included) parses in 81 s on 8 threads. Per-file
results are cached by (content hash, language, `EXTRACTOR_VERSION`) under `data/cache/ast/`.

## Contract

- **Input:** the batches Stage 2 wrote (`static.jsonl`). Stage 3 reads the same versions;
  narrowing to Stage 2's flags would repeat the recall loss measured in
  [0008](../decisions/0008-stage2-routing-and-tarball-capture.md).
- **Profile:** a version's capabilities, the union over its files, with where each is used.
  Since extractor v8 (2026-11-09) also `Profile.identity`: the calls reading the machine's
  identity (`os.hostname()`, `userInfo()`, `networkInterfaces()`, `homedir()`) that run when
  their file is loaded ([load-time payloads](#load-time-payloads-npmload-fingerprint-extractor-v8)),
  and since v9 (2026-11-09) `Profile.commands`: the commands that run then
  ([self-publishing](#self-publishing-at-load-or-install-npmpublish-at-load-extractor-v9)).
  The **install profile** covers only the files its install hooks run (`node setup.js` →
  `setup.js`; `ecosystems/npm/install.py`), and since 2026-10-30 the package files those
  load or run by a constant path (`require("./lib/x")`, `import`, `export ... from`,
  `path.join(__dirname, "lib", "x.js")`, `new URL("./x", import.meta.url)`; `local_paths`
  in `lang/javascript.py`): two levels deep, at most 20 files of at most 256 KiB, so a hook
  that loads the whole library doesn't make it all install code. `@next2012/aistudio-runtime`'s
  hook only imported `lib/postinstall.js`. On `vm-day1`: +12 malicious samples (the
  `@emilgroup/*` SDK series, `free-anthropic-claude`, `github-badge-bot`, `aicp-tracker`),
  none lost, +1 benign (`domain-driver@0.8.2`).
- **Delta:** each version is compared with its `change.previous` (the base, an earlier
  version in the batch, or, since 2026-10-30, fetched on its own: `@bike4mind/cli` publishes
  snapshots of many branches at once, each following its own branch's last snapshot, and
  without that previous every capability of their install code counted as new: 47 queued
  updates, 40 reported for that alone). A capability is attributed to the version that gained it, even if a
  later version in the burst drops it. A version with no previous is a new package, even when
  the batch holds a staged-publishing placeholder before it (`0.0.0-stage`, then `1.4.0`).
  Comparing with the placeholder made every capability "gained": 37 of the 44 versions Stage 3
  flagged in the first live hour were such packages (fixed 2026-10-28).
- **Build commands** (2026-11-08): `CodeChange.build_commands` holds the commands the
  version's own build files run at install besides its hooks, as the ecosystem finds them
  (`build_commands=`, npm: `install.gyp_commands`, `binding.gyp`'s actions and command
  expansions). Empty when the ecosystem passes none.
- **Agent files** (2026-11-08): `CodeChange.agent_files` holds the AI-agent configuration
  the install code may copy, when that code names an agent directory
  (`agent_config.agent_files`): skills, instruction files, agent settings, plugin manifests
  and the package scripts their hook commands name, each cut at 256 KiB, at most 301 (more
  is "too many to check"). Empty otherwise. Ecosystem-agnostic: computed from the tree and
  the install files.
- **Rules** implement `CodeRule.evaluate_code(CodeChange)`. A version is flagged at MEDIUM
  or above.
- **Output:** `ast.jsonl`, with the same batches in the same order, plus Stage 3 findings and a
  `StageDecision`.

## Rules

Rates are from `day1`. Updates are shape-A first releases; new packages are shape B; DataDog
is the malicious set.

| Rule | Fires when | Severity | Benign (updates / new) | Malicious (updates / new) |
|---|---|---|---|---|
| `code.capability-gained` (v4) | an update's code gains capabilities. MEDIUM if it gains `dynamic-code` through `eval`, or `network` together with `process`, `env-all` or `dynamic-code` (not after a base with no capabilities at all) | LOW / MEDIUM | per capability ≤ 0.5% / n/a | env-all 70.9%, dynamic-code 57.3%, network 57.6% / n/a |
| `npm.install-script-code` (v3) | a file an install hook runs uses `network`, `process`, `env-all`, `dynamic-code` or `dynamic-require`. On updates, only capabilities new to the install code count. v3 (2026-11-10): also code hidden past the edge of the screen (100+ spaces or tabs, then code that is no comment, message or string) in a new install file or one whose previous version had none: `hauntview@0.2.9`, malicious, the only one of 1,710 verdicted versions with install code and 18 `vm-day1` samples | MEDIUM | ≤ 0.9% / 0.2% | 70.2% / 33.7% |
| `npm.install-build-tool` (v3) | every install hook (`preinstall`, `install`, `postinstall`, from the registry manifest) is one of a fixed list of build-tool command lines (`BUILD_TOOL_HOOKS`: `node-gyp-build`, `node-gyp rebuild`, `prebuild-install`, `node-pre-gyp install --fallback-to-build`, `husky`, `npx only-allow pnpm`, `patch-package`, ...; v3 adds `only-allow npm`, `opencollective-postinstall`, `node-gyp-build \|\| node-gyp rebuild`, `npx @mapbox/node-pre-gyp ...`, and Playwright's browser download when the package depends on Playwright), no tool it runs is one of the package's own `bin` names (v3), and `binding.gyp` runs no command but `node-addon-api`/`nan` header lookups (v2) or tree-sitter's `src/scanner.c` test (v3). An explanation for Stage 4, which then makes `npm.install-hook` LOW (`correlate.EXPLAINED`) | INFO | live (with Stage 4): 7 of the 2,208 reports go where the tarball was captured, 12 if the 5 without one (`husky`, `only-allow`, `patch-package` hooks) have no `binding.gyp`; all benign | `vm-day1`: 0 of the 433 reported only through install rules has such hooks; 4 other malicious samples do, decided as before |
| `npm.install-explained` (v2) | the install code is a platform-binary launcher (S1), an own-release download with a checksum (S2), or an agent-skill copier whose copied configuration passes the three guards (S3); since v2 (2026-11-09) S3 only for copies into the project: no home-directory reference in the install code or hook line, no package loaded by name; [below](#explained-install-s1-s3-and-agent-configuration). An explanation for Stage 4, which makes the three install rules LOW | INFO | live (with Stage 4, 3,244 reported verdicts): 85 fewer reports (S1 36, S2 34, S3 15; 70 packages), all benign, 0 positives; v2: S3 keeps 23 of the 69 live versions it explained (5.6 days), +7 reports, 16 reviewed benign (14 user-wide copiers) reported again | `vm-day1`: 0 of the 433 malicious samples reported only through install rules |
| `npm.install-inert` (v1) | a new package whose every install hook only runs package code (`node <file>`, `node -e`, chained with `&&`/`\|\|`/`;`) or a constant `echo`, that Stage 3 read in full and that reaches nothing outside the package; carries agent E's S5 guards (no Baileys `engine-requirements.js`, no `require.resolve`, no placeholder, no risky text, no deleting, readable UTF-8) and refuses probes (`PROBE_TEXT`). An explanation for Stage 4, which makes `npm.install-hook` LOW; [below](#inert-install-hooks-npminstall-inert-round-4) | INFO (weight 0) | live: see below | `vm-day1`: fires on none |
| `npm.install-agent-user-wide` (v1) | install code that names an agent directory refers to the user's home directory (`os.homedir()`, `process.env.HOME`, `~/`, `$HOME` in the hook line, ...): it may write skills or agent settings user-wide, which the owner rules unwanted (decision 0015, addendum 2026-11-09). A reviewer's note: such code is never S3; [below](#s3-v2-copies-into-the-project-only-2026-11-09) | INFO (weight 0) | live: 311 of 479 versions whose install code names an agent directory (5.6 days), most unreported; reviewed: 148 of 202 | `vm-day1`: 1 of the 433 reported only through install rules (`aicp-tracker@1.0.7`, reported as before) |
| `npm.install-persistence` (v1) | new or changed install code (or a hook command line), comments and messages aside, writes an AI agent's configuration user-wide, a shell start-up file or the persistent PATH, or installs system packages; [below](#install-code-that-changes-the-machine-beyond-the-project-npminstall-persistence-2026-11-09) | MEDIUM (weight 3) | live (reviewed versions with install code): see the round-4 proposal | `vm-day1`: adds findings only |
| `npm.install-script-loader` (v1) | a shell, PowerShell or batch install script (run by a hook or started by install code) or a hook command line, comments and messages aside, fetches or decodes code and runs it, or hides it: `curl ... \| sh`, `bash -c "$(curl ...)"`, `base64 -d \| sh`, `/dev/tcp/`, `-EncodedCommand`, `irm ... \| iex`, `iex` of decoded text, `[char]` chains, `-join` reversals, `certutil -urlcache`/`-decode`, `bitsadmin /transfer`, `mshta`, `regsvr32 /i:http`, batch substring chains, code behind 100+ spaces that the hidden-code check skips; only shapes new to the install code; [below](#shell-powershell-and-batch-loaders-in-install-code-npminstall-script-loader-npminstall-script-exfil-2026-11-10) | MEDIUM (weight 3); LOW (weight 1) for a download piped into a shell from the package's own site | live: 0 of the 3,716 verdicted versions change (64 have install scripts); 0 fires in a day of 2,044 hooked versions | `vm-day1`: fires on 8 malicious samples, all reported already (one, `@optimystic99/dev-utils@1.0.17`, otherwise only by `npm.install-hook`); 0 of 1,452 benign |
| `npm.install-script-exfil` (v1) | the same scripts and hook lines pipe command output into an upload, upload a file, read the cloud metadata service, or name a credential file (SSH private key, `~/.npmrc`, `.aws/credentials`, ...); only shapes new to the install code; [below](#shell-powershell-and-batch-loaders-in-install-code-npminstall-script-loader-npminstall-script-exfil-2026-11-10) | MEDIUM (weight 3) | live: as above, 0 | `vm-day1`: fires on 81; **3 newly reported** (`justgetit@1.2.4`, `ts-form-helpers` 1.0.3 and 1.0.12), 0 lost; 0 of 1,452 benign |
| `agent.hostile-instructions` | agent text the install code may copy (`CodeChange.agent_files`) tells the agent to hide its activity from the user, ignore its earlier instructions, switch off its safeguards, or send credential files away | MEDIUM | live: 0 of the 3,244 reported verdicts, 0 of 3,552 hooked versions in the retained runs (narrowed after 2 benign live and 2 benign unreviewed packages) | `vm-day1`: 0 of 433 (one names an agent directory) |
| `npm.install-script-obfuscated` (v2) | a file an install hook runs (as `install-script-code` reads them, first 256 KiB each) has 20+ javascript-obfuscator `_0x` identifiers (`static.obfuscated`'s test) or, with identifiers renamed, the tool's string-array rotation prologue (`while(!![]){try{const x=parseInt(`). On updates, only an obfuscated file that is new to the install code or changed | HIGH | `vm-day1`: 0 of 1,500 | `vm-day1`: 100 of 3,444 |
| `code.function-constructor` (v1) | a version's code reaches the Function constructor through `constructor` (extractor v5). New packages count; on an update, only a form the previous version's code didn't use | MEDIUM (a constructor's constructor, or Node's loader handed over) / LOW (a function literal's otherwise) | `vm-day1`: 2 of 1,500 (both LOW); live: ~3 reports a day | `vm-day1`: 4 of 3,443, all LOW (recall unchanged); live: `txnforge`, `mock-datas-lib` and 3 unreviewed |
| `npm.undeclared-package` (v2) | loading the version (its `exports`/`main`/`module`/`browser` entry, `index.js` by default, and the package files those load by a constant relative path, `ecosystems/npm/entry.py`) loads a package at module load (not in a `try`, not inside a function that isn't called in place; extractor v7) that `dependencies`, `peerDependencies`, `optionalDependencies` and `bundleDependencies` don't list and the tarball doesn't ship (Node's modules, paths and the package's own name don't count; on an update, only names the previous version's code didn't load). One evidence item per package (at most 10), which Stage 4's `npm.undeclared.missing` looks up | INFO (weight 0) | `vm-day1`: 3 of 1,500 (v1: 61), none for a name npm lacks; live: 204 of 29,470 versions in 29.2 h (v1: 993) | `vm-day1`: 131 of 3,443 (v1: 669); live: `tailwind-animate-engine@1.0.6` (with Stage 4's lookup: reported) |
| `npm.load-fingerprint` (v1) | one file that loading the version runs (`CodeChange.load`) reads two or more of `os.hostname()`, `os.userInfo()`, `os.networkInterfaces()`, `os.homedir()` in code that runs at load (extractor v8, `lang/at_load.py`), and the loaded files use the network; not a `bin` target's file; on an update, only if the previous version's code didn't; [below](#load-time-payloads-npmload-fingerprint-extractor-v8) | MEDIUM | `vm-day1`: 0 of 1,500; live: 4 newly reported in 33.2 h (~3 a day) | `vm-day1`: 310 of 3,444, 42 newly reported (2 new packages, 40 follow-ons); live: `archetype-index-sdk` and 2 others, reported already |
| `npm.publish-at-load` (v1) | a command that runs at load (extractor v9, `lang.at_load.commands`: an `exec`/`spawn`/`execa` call, or a same-file wrapper of one, reached at load) in a file loading the version runs (not a `bin` target) or a file its install hooks run publishes to npm (`npm`/`pnpm`/`bun publish`, `yarn [npm] publish`); on an update, only if the previous version's code didn't; [below](#self-publishing-at-load-or-install-npmpublish-at-load-extractor-v9) | MEDIUM | `vm-day1`: 0 of 1,452; live: 0 of 37,154 versions in 33.7 h; reviewed: 0 of 1,434 | `vm-day1`: 105 of 3,444, **46 newly reported** (the `*_z3n` spam); live positives: none publishes |

New packages get no `capability-gained` finding: with no previous version everything is
"gained", and 34% of benign new packages would fire. They are covered by what their install
scripts run.

`npm.install-script-code` also covers a case Stage 1 cannot see: the command stays
`node setup.js` and only `setup.js` changes.

`code.capability-gained` v2 (2026-10-30): gaining `env-all` alone is LOW (it was MEDIUM).
Apps that start reading `process.env` were the commonest MEDIUM-only report on the first live
days (about 170 of 396), and on `vm-day1` all 35 malicious samples reported through this rule
alone had gained `dynamic-code`. `env-all` with `network` is still MEDIUM.

`code.capability-gained` v3 (2026-10-30): gaining `dynamic-code` alone is MEDIUM only through
`eval` (`eval(x)`, `globalThis["eval"](x)`); `Function`, `new Function` and `vm` alone are LOW.
Of the 90 live-queue reports this rule made alone through `dynamic-code`, 85 were `Function`
or `vm` (`new Function(body)` in template and test helpers, `import vm` for expression
sandboxes). All 35 `vm-day1` malicious samples reported through it alone were injected `eval(`
payloads (`autotel-*`, `awaitly-*`), so none is lost. `Function` or `vm` together with
`network` stays MEDIUM. Extractor v3 keeps up to three uses per capability *and detail* in a
file, so a file's first three `new Function(x)` calls no longer crowd out a later `eval(x)`,
and the evidence shows `eval` first.

`code.capability-gained` v4 (2026-10-31): after a base whose code used no capability at all
(a placeholder release such as `0.0.0-placeholder` or `1.0.0-reservation.0`), gaining
`network` with another capability is LOW, as it would be for a new package; gaining `eval` is
still MEDIUM. 11 unreviewed live reports were first real releases after a placeholder
(`inki-cli`, `kurage`, `vexla`, `@yozz.app/cli`, ...). The first version made `eval` LOW too
and cost 18 `vm-day1` malicious samples, every one an `eval(` payload published after an empty
first version (`autotel-*`, `awaitly-*`); the narrowed rule loses none.

**Inline install code** (2026-10-30): the code a hook passes to `node -e`, `--eval`, `-p` or
`--print` is profiled as `package.json#scripts.<hook>.js`
(`ecosystems.npm.install.install_sources`), so the install-code rules read it. Before, an
inline hook named no file and its code went unread (`dependencykfeg`: a one-line DNS
exfiltration of the working directory).

**`binding.gyp` commands** (2026-10-31): a package with a `binding.gyp` is built with
`node-gyp rebuild` when it is installed, a hook npm adds itself, and gyp runs commands while it
builds: each `action`'s command, and each command expansion `<!(...)` / `<!@(...)`
(`install.gyp_commands`). The files those commands name are install entries like a hook's, and
code they pass to `node -e` / `-p` is profiled as `binding.gyp#commands.js`.
`@atedone/workspace-bootstrap@0.0.1` had no install script; a gyp action ran
`node scripts/write-state.js --install`, which went unread.

**Extractor v4** (2026-10-31): `process.getBuiltinModule("fs")` loads a module as `require` does
(a computed name is `dynamic-require`), and `Reflect.get(process, "env")` is `process.env`
(the whole environment unless only one variable is read from it). The same package used both,
so that its install code carried none of the usual tells.

**`npm.install-build-tool`** (INFO, weight 0; 2026-11-08,
[proposal round 2](../proposals/precision-round2.md), F2): a hook that only runs a build tool
says nothing about what the package does at install; what a native build runs is in
`binding.gyp`. npm itself adds `install: node-gyp rebuild` to any package with a
`binding.gyp`, so a hook that writes it out adds nothing. The rule needs both the hooks
(whole command lines, compared exactly: `node-gyp rebuild && node x.js` is not one) and the
gyp file, which is why it is a Stage 3 rule and not a Stage 1 condition: a gyp action or a
`<!(...)` expansion keeps the hook's own severity (`@atedone/workspace-bootstrap@0.0.1`,
inconclusive, ran its payload from a gyp action). Most `tree-sitter-*` grammars keep MEDIUM:
their `binding.gyp` expands `<!(node -p "require('node-addon-api').include")`. Stage 4 makes
`npm.install-hook` LOW, weight 1, with a note, when this finding is present; the install code's
own findings (`install-script-code`, `-changed`, `-obfuscated`) are untouched. Measured with
the real code on the proposal's 3,032 reported live versions: 7 fewer reports where the
tarball was captured (`tree-sitter-angular-html`, `tree-sitter-aspx`,
`@inkdropapp/electron-vibrancy-gpu-fix`, `ezsnmp-data-logger`, `@prettier/cli`,
`vscode-colaview`, `@globalpayments-private/gpds-pattern-web`), 12 counting the 5
`husky`/`only-allow`/`patch-package` versions without a tarball as having no `binding.gyp`;
all benign. On `vm-day1` none of the 433 malicious samples reported only through the install
rules has build-tool-only hooks; 4 other malicious samples do (`duckdb@1.3.3`,
`@mastra/node-speaker@0.1.1`, ...), and `pipeline+4` decides each as before (1 reported, 3
not reported either way).
**v2** (2026-11-09, [round 3](../proposals/precision-round3.md), X6): a `binding.gyp` command
that only asks `node` where `node-addon-api`'s or `nan`'s headers are
(`<!(node -p "require('node-addon-api').include")`, `.include_dir`, `<!@(... .gyp)`,
`<!(node -e "require('nan')")`; `install_code.HEADER_LOOKUP`, a full match of the command as
`gyp_commands` extracts it) is not counted as a command: it prints a directory of an installed
package. Any other expansion or gyp action keeps the hook's severity, as before
(`@lakutata/barcode`'s `node scripts/sources.mjs`, `@atedone/workspace-bootstrap`'s action); `tree-sitter-*` grammars whose only command is the header lookup are explained now (when Stage 3 reads them).
The hook list is unchanged. Live, real code on all 3,716 verdicted versions: 9 fewer reports
(`@lakutata/netif`, `/serial`, `/mongo-embedded`, `@ohos-ports/gc-stats`, `gcstats.js`,
`v8-profiler-next`, `contrast-code-events`, `@memoryprocess/bindings`,
`@mongodb-js/macos-export-certificate-and-key`), all benign; no positive's install finding
changes. `vm-day1`: of the 4 malicious samples with build-tool-only hooks, `duckdb@1.3.3`
has a header-lookup-only `binding.gyp`, but its hook is unchanged from 1.3.2, so
`npm.install-hook` doesn't fire on it; nothing changes (proposal, section 5).
**v3** (2026-11-10, [round 4, agent B](../proposals/precision-round4-B.md), B3): more hook
lines (`npx only-allow npm`, `npx -y only-allow npm|pnpm`, `bunx only-allow bun`,
`opencollective-postinstall`, `node-gyp-build || node-gyp rebuild`,
`npx @mapbox/node-pre-gyp install --fallback-to-build`); Playwright's browser download
(`playwright install [chromium]`, with or without `npx`) when the manifest depends on
`playwright`, `playwright-core` or `@playwright/test` (`--with-deps` installs system packages
through `apt-get`, decision 0015, and is not on the list); a tool the package's own `bin`
names is the package's code, not the tool (`tool_shadowed`: npm links a package's bins before
its hooks run); and in `binding.gyp`, tree-sitter's `fs.existsSync('src/scanner.c')` test
(the ternary form and the newer `has_scanner` form, which `gyp_commands` receives cut at its
first `)` before a quote) and `require('node-addon-api').targets` count as lookups
(`SCANNER_LOOKUP`, `HEADER_LOOKUP`). Live: 12 fewer reports (`docsify@5.1.0`,
`autorunqa-runner`, `phloem-ai`, `tree-sitter-swi-prolog`, ...), all benign; no positive
changes.
**Known gap (not this rule's):** `gyp_commands` only finds an expansion whose `)` is followed
by a quote on the same line, so `"<!(node payload.js):target"` is not extracted at all, and
neither this rule nor `npm.install-script-code` would see that command (proposal, owner
question 4).
**Extractor v5 and `code.function-constructor`** (2026-11-08). `txnforge@1.0.4` and
`mock-datas-lib@1.0.1` (2026-11-02, same author, adjudicated malicious: a Python dropper
fetched from a hard-coded host) decoded their payload and ran it with the Function
constructor taken from `globalThis.constructor.constructor`, split over two variables
(`const c = g.constructor; const F = c.constructor; return F`). Nothing in Stages 2-3 fired
(score 0): neither `eval` nor `Function` appears. The extractor now counts as `dynamic-code`:

- the constructor of a constructor: `x.constructor.constructor`, `x["constructor"]["constructor"]`
  (keys folded), and `c.constructor` where `c` is declared as `x.constructor` in the same
  function (detail `constructor.constructor`);
- the constructor of a function literal: `(async () => {}).constructor`,
  `Object.getPrototypeOf(async function () {}).constructor`, generators and classes too
  (detail `function.constructor`).

Only where the result is used as a function: called, `new`ed, stored, passed or returned. A
read (`.name`, `.prototype`), a comparison or `instanceof`, a test (`if`, `?:`, `typeof`) or
a bare statement is not, and a variable holding it counts only if one of its references in
that function is such a use (echarts keeps `function () {}.constructor` only for its
`.prototype`). Called directly with short constant code it is exempt, as `Function` is
(`[].constructor.constructor("return this")()`). The first version followed any variable of
the same name anywhere in the file: in minified bundles one-letter names are reused for
everything, and on the 6-hour run of 2026-11-07 22:27Z it found uses in 135 of 5,850 versions
read and fired on 15 (`t.constructor.name` in zod, React's `publicInstance.constructor`).
Scoping the variable to its function, and requiring a use as a function, left uses in 15 and
firings on 2 (both function literals). Cost: the
same as before within measurement noise on 3-12 MB bundles (references are found by searching
the scope's text for the name; a query over every identifier took 0.4 s on a 7 MB bundle).

The rule is MEDIUM (weight 3) for the constructor of a constructor, which is plain `Function`,
a name code that isn't hiding writes directly, and for either form in a file that hands Node's
loader to code: a call passing `require`, `process` or `module` (`txnforge`:
`f(Buffer, require, process)`), or the built function given one as a parameter name
(detail suffix `(require)`). Otherwise a function literal's constructor is LOW (weight 1): it
is the only way to build an *async* function from text, which code-mode executors and
expression compilers use (`@opencode/codemode`, `@uipath/maestro-builder-sdk`, echarts).
`code.capability-gained` sees the new uses as `dynamic-code` that is not `eval` (LOW alone),
and `npm.install-script-code` as dynamic code in install code.

Measured on the unpruned live runs (Stage 3's versions with captured tarballs: 2026-11-07
22:27Z, 6.2 h, 5,850 versions; 2026-11-08 07:31Z, 9.3 h, 9,783; the 4-day catch-up run of
2026-11-07 16:33Z, 1 in 10 by tarball digest, 16,639):

- **The constructor of a constructor fired on no benign version.**
- A function literal's fired on 15 versions; 7 with the loader handed over. Of those, 3 are
  `jmrwd-gjdob-util`, `smfos-bskdz-util` and `tsbwt-hawsi-util` `@1.0.1` (07:31Z run, not
  reported, unreviewed): each XOR-decodes a field of its own `package.json` and runs it with
  `(function(){}).constructor("require", "__dirname", code)(require, __dirname)`. The other 4
  look benign: `@nodegx/backend@0.1.0` (compiles user code to check its syntax),
  `@muqian/xiangsu-mcp-plus@0.6.0` (an editor plugin's dev `eval`), and two
  `@tailwindcss/oxide-wasm32-wasi` insiders builds (`@napi-rs/wasm-runtime` bundled under
  `node_modules/`; their base was not in the capture, so live they may not fire at all).
- **Extra benign reports: about 3 a day** (2 in the 15.5 hours of full runs), at most about 8 if
  the sampled `oxide` builds fire live. The 8 LOW firings report nothing on their own (3 were
  reported already for other reasons).
- `vm-day1`: 2 of 1,500 benign samples fire, both LOW (`@maofuxing/mfx-ds-bot`,
  `@oxidevm/sdk`); 4 of 3,443 malicious samples fire, all LOW (javascript-obfuscator's
  `function(){return!![];}['constructor']` in three, `zapier-platform-core@18.0.3`'s
  `AsyncFunction`), each already reported or not routed to Stage 3: no sample gains or loses
  a report.
- Reviewed live malicious versions with captured tarballs (42 of 90, plus 8 OSV-labelled misses):
  `txnforge@1.0.4` and `mock-datas-lib@1.0.1` gain the MEDIUM finding (both were score 0); no
  other Stage 3 finding changes on any of them.

**Extractor v6 and `npm.undeclared-package`** (2026-11-08, INFO). Four Tailwind-wrapper
campaign misses (`tailwind-animate-engine@1.0.6`, `tailwind-animate-final@1.0.6`,
`tailwind-animate-test` 1.0.1 and 1.0.4) required their payload, `@unipswap/postcss-animate-units`,
without declaring it, so `npm.dependency.missing` (Stage 4, declared names) could not see it.
The extractor now records the packages a file loads by a constant name (`require`, `import`,
`export ... from`, `import()`; not `import type`), whether the load is inside a `try`, and
the profile records which packages the tarball ships under `node_modules/` (files there are
not the package's own code). The rule compares them with `dependencies`, `peerDependencies`,
`optionalDependencies` and `bundleDependencies`. Node's modules (with or without `node:`),
paths, `#imports`, URL-like and capitalised specifiers (bundler externals and AMD globals such
as `React`) and the package's own name are not packages to declare. `.d.cts` and `.d.mts` are
now skipped as declarations, like `.d.ts`.

The rule is **INFO** (scores nothing): as MEDIUM it would have reported 700-1,150 benign
versions a day that nothing else reports, measured on the same live versions as
`code.function-constructor` above. The names were overwhelmingly real packages provided by a
host or used only at build time: `react` (217 versions), `zod` (71), `vscode` (38),
`better-sqlite3` (23), `@deepseek-ai/dsh-client-ui-primitives` (19, a host's plugin API).

| Variant (live, versions not reported otherwise) | 6.2 h run | 9.3 h run | 4-day run, 1 in 10 | per day |
|---|---|---|---|---|
| As built | 179 | 337 | 467 | 700-1,150 |
| devDependencies count as declared | 122 | 239 | 281 | 480-700 |
| also no test, example, template or declaration files | 113 | 177 | 225 | 440-560 |
| also only a scoped name of another scope | 24 | 24 | 53 | 60-130 |
| devDependencies and paths as above, and the name was not on npm (2026-11-08) | 1 | 4 | 19 | 8-47 |

Only the last is near a reportable rate, and it needs to know whether the name existed when
the release was published: a registry lookup, which Stage 4 makes for declared dependencies
(`npm.dependency.missing`) and could make for these names (an owner decision; it changes
Stage 4's input). Even then, path aliases (`@shared/x`, `@generated/gql`) and AMD module
names remain. In `vm-day1` the rule fires on 64 of 1,500 benign samples and on 758 of 3,443 malicious ones, mostly the Shai-Hulud `bun_environment.js` importing `undici`
(which Bun provides), already reported through other rules.
**Extractor v7 and `npm.undeclared-package` v2** (2026-11-08, still INFO). The owner asked for a
narrower version that a registry lookup could make reportable ("measure a narrower version";
build only if benign stays under ~5 reports a day). Version 2 counts only what *loading the
package* runs:

- **at module load**: the extractor records whether a load is *deferred*, inside a function
  that isn't called where it is defined (`PackageLoad.deferred`; `(function () {...})()`,
  `!function () {...}()` and `(() => {...}).call(this)` defer nothing, static `import` never
  is). A `try` still excludes it, as in v1;
- **from the entry points**: `ecosystems/npm/entry.py` takes the files `exports` (every
  condition but `types`, no `*` patterns), `main`, `module` and a string `browser` name
  (`index.js` when there is neither `main` nor `exports`), and follows the package files they
  load by a constant relative path (`followed_files`, 8 levels, at most 300 files of at most
  4 MiB). Stage 3 profiles those files as `CodeChange.load`. `bin` scripts are not entries:
  they run when typed, and adding them changed 3 versions, none with a missing name. This is
  what drops shipped TypeScript sources, templates, tests and examples (a path filter on top
  removed nothing more).

devDependencies are *not* treated as declared: npm doesn't install them for users either, and
leaving them out removed no name the registry lacked. Measured on every version Stage 3 read
in the eight unpruned live runs (2026-11-07 16:18Z to 11-08 21:30Z, 29.2 h, 29,470 versions;
registry status checked on 2026-11-08 for every name involved; of the 18 v2 names that exist
and need a lookup, none was created after the release that loaded it, so "missing now" stands
for "missing when Stage 4 would have asked"):

| Variant | Versions | Distinct names | Versions with a name npm lacks | ... after Stage 4's exemptions |
|---|---|---|---|---|
| v1 (every own file, outside `try`) | 993 | 655 | 59 | |
| devDependencies as declared | 709 | 497 | 42 | |
| also at module load | 504 | 447 | 40 | |
| **v2: also only what the entry points load** | **204** | 123 | 15 | **1** |
| v2 with devDependencies as declared | 165 | 102 | 13 | 1 |

Stage 4's exemptions are `npm.dependency.missing`'s (the release's own scope, watched names,
siblings by `sibling_reason`); they cleared the `@ranu/*` monorepo of `@ranujs/*` (9 releases),
`@gtkx/*` (own scope, 3) and `@chatluna/*` (2). The one left, `@ohos-ports/cms-components`,
re-publishes `@smallstack/*` code that loads 21 `@smallstack/*` packages that don't exist on
npm: a dependency-confusion exposure, like the private names `npm.dependency.missing` reports.
That is ~0.8 extra benign reports a day. The wrapper `tailwind-animate-engine@1.0.6` gets the
finding (`plugin.js` -> `src/styles.js` -> `src/motion.js:5`), and the 404 for
`@unipswap/postcss-animate-units` is in run `20261102T083824Z`'s Stage 4 snapshot. Of the 56
reviewed positives (malicious, unwanted) with a captured tarball, 7 Baileys forks and
`cantarel` get the finding, all for names npm has (`long`, `fflate`, `form-data`): none
changes. On `vm-day1` (every sample, Stage 1 routing as the pipeline does it, a per-sample
dump because `pipeline+4` doesn't fit the 4 GB cap; `llm-oracle@1.0.2` alone exceeded it and
is not counted) v2 fires on 3 of the 1,046 routed benign samples (`react`, `expo-font`,
`@angular/forms`, `rxjs`: all on npm) and on 131 of the 3,117 routed malicious ones (v1: 61 and
669); 7 malicious samples load a name npm lacks now, 5 of them only siblings (`@ember/*` from
`ember-*`, `rc-logger-abstract-transport` from `rc-logger`), and the other 2
(`react-tmedia@2.1.4`, `tailwind-state@1.0.3` -> `bingo-logger-abstract-transport`, the
wrapper-and-payload shape again) are reported already.

### Load-time payloads: `npm.load-fingerprint` (extractor v8)

`archetype-index-sdk@1.0.0` (2026-11-08, malicious) has no install hook: `dist/index.js`
imports `telemetry-info.mjs`, which collects the host name, user name, home directory, MAC
address and the names of set environment variables, sends them to an outside host, writes a
helper under `~/.cache` and spawns it detached. It was reported at score 5 on two
`static.obfuscated` findings alone; Stage 3 said nothing (a new package has no capability
delta, and no install code). Measured before building (task: find the load-time population,
build only what passes the owner's bar for a MEDIUM, under ~5 benign reports a day with a
measurable recall gain):

**The population.** Malicious versions with no `preinstall`/`install`/`postinstall`, whose
harm must run when the package (or a command it ships) is used:

| Set | No install hook | Reported | Missed |
|---|---|---|---|
| `vm-day1` malicious, routed to Stages 2-3 | 880 of 3,117 | 420 with today's code (358 on the 2026-10-31 dump; today's routing and Stage 2 rules add 62 follow-ons) | 460 (279 new packages, 14 updates, 167 follow-ons) |
| `vm-day1` malicious, not routed | (not read) | 27 of 327 | 300: no Stage 3 rule sees them |
| live reviewed positives (malicious, unwanted) with a tarball, captured or downloaded again as data | 53 of 108 | 26 (when reviewed) | 27: 14 `@atedone/workspace-context` releases (process and file names built from split strings), 7 Baileys forks, 3 loader tests, `txnforge`, `mock-datas-lib`, a payload in a dependency |
| live OSV misses with a tarball | 8 of 8 | 0 | 8: payload in a dependency, or exported functions only |

What the missed `vm-day1` ones load (the entry points and the files they load):
no JavaScript at all 195 (HTML, binaries, a `bin`-only payload), code with no capability 94,
process execution only 67, **two or more host-identity reads with network 63** (32
`blocks-nextjs` follow-ons), dynamic code 35, network with process or the whole environment
24, network only 23. The reported ones carry the same shapes, mostly through
`static.exfil-endpoint`, `static.encoded-url`, `static.obfuscated` and
`static.hardcoded-ip`. The identity-and-network shape is the dependency-confusion probe moved
from `preinstall` into `index.js` (`seznam-diskuze`: `os.homedir()`, `os.hostname()`,
`os.userInfo().username` in a JSON body POSTed to an `oastify.com` host at module load).

**At load, not merely in a loaded file.** The text form ("a loaded file calls two of
`hostname(`, `userInfo(`, `networkInterfaces(`, `homedir(` and the load profile uses the
network") fires on 1 of 1,500 benign `vm-day1` samples but on 46-101 unreported live
versions in 33.2 h (33-73 a day; the range is updates whose base wasn't captured): CLIs
(`litmus-cli`'s `connect` command, `create-mastra`), playwright's bundled `utilsBundle.js`,
agent plugins. Their reads sit in functions that run when called.
Extractor v8 (`lang/at_load.py`) records only the reads that run when the file is loaded
(`FileCapabilities.identity_at_load`, carried as `Profile.identity`): top-level code,
functions called in place, functions passed to a call that runs or a `new Promise` executor,
and functions the running code calls by name. Class and object methods never count, nor
names reached across files or through an alias. Built, it keeps 310 of the 335 `vm-day1`
malicious samples the text form fires on, and of the 46-101 live versions it leaves 4.

**Rule.** `npm.load-fingerprint` (MEDIUM, weight 3): one loaded file reads at least two of the
four facts at load, and the loaded files use the network. Not counted: a file that is one of
the package's `bin` targets (a CLI that `main` points at: `codeam-cli`, `@mearl/native-host`,
6 of the 7 reviewed benign versions it fired on, all reported already), and on an update
anything the previous version's code already did. Measured with the built code:

| | Fires | Newly reported |
|---|---|---|
| `vm-day1` benign (1,500) | 0 | 0 |
| `vm-day1` malicious | 310 (149 new packages, 161 follow-ons; 0 shape-A updates) | **42**: 2 new packages (`@twilio-client/twilio-client@0.0.1`, `safe-chain-test@1.0.0`), 40 follow-ons (32 `blocks-nextjs`, `overstock-*`, `seznam-diskuze` x2, `@zentrafinance/*`, ...) |
| live reviewed positives with a tarball | 3 (`archetype-index-sdk`, `@pcb-dp/qa-commons`, `service-roles-registry`), all reported already: score +3 | 0 |
| live reviewed benign with a tarball (1,428 of 3,218) | 1 (`filedrawer@0.2.0`, an Electron app's main), reported already | 0 |
| live, every version Stage 3 read in the 12 runs whose tarballs are all captured (2026-11-07 16:18Z to 11-09 01:31Z, 33.2 h, 35,734 versions) | 5: `archetype-index-sdk` (reported already) and 4 others | **4** (~2.9 a day): `dsh-session-gallery@0.1.0` (a plugin registering its host), `@saccolabs/questrade-mcp@2.0.1` and `@saccolabs/wave-mcp@1.0.1` (MCP servers whose `main` loads their CLI), `chatbotx-mcp@1.20.0` (an update; the CommonJS twin of its `bin`); unreviewed, they look benign |

The bin guard costs one follow-on (`@sentry-browser-sdk/profiling-node@1.0.4`, whose
`cli.js` is both `main` and `bin`). Vendor telemetry (benign by the owner's ruling) did not
appear among the live hits; an SDK that reads two identity facts at import and phones its
vendor would be reported.

Not built, with numbers (`vm-day1` new packages newly reported / `vm-day1` benign that fire /
unreported live versions in the same 33.2 h): a command run at load (`exec`/`spawn`
reached at load) 50 / 3 / 100; with a network call at load 1 / 1 / 11; with a file write (the
46 `*_z3n` self-publishing spam packages) 46 / 1 / 76; a detached spawn 1 / 0 / 58. None
is under the bar with a gain, and an "obfuscated loaded file in a new package" rule adds
nothing: `static.obfuscated` already reports such a file.

### Self-publishing at load or install: `npm.publish-at-load` (extractor v9)

The 46 `*_z3n` samples above (DataDog, `vm-day1`, shape B) are self-publishing spam: `main`
is `publishScript.js`, which at load starts a loop of timers that rewrites the *current
directory's* `package.json` (drops `private`, a random version and `<adjective>_<animal>_z3n`
name) and runs `exec("npm publish --access public")`, with whatever npm credentials the user
has. Nothing reported 46 of the 47 (one through `npm.dependency.fresh-foreign`).
Self-propagation is threat #9, and `static.npm-publish` (Stage 2, LOW) only matches the text:
350 reviewed benign versions, 0 positives (release tooling that mentions `npm publish` in
scripts, docs and CLIs). Task (2026-11-09): find the malicious code that publishes, where
that publish runs, and build a narrow rule only if it passes the owner's bar for a MEDIUM
(under ~5 benign reports a day, a measurable recall gain).

**The population.** Every `vm-day1` sample (4,944; 48 benign have no files), every version
Stage 3 read in the 13 live runs whose tarballs are captured (feed 2026-11-07 16:49Z to
11-09 02:31Z, 33.7 h, 37,154 versions), every reviewed version with a tarball (latest
verdict: 108 positives, 1,434 benign, 16 unverified) and the 35 live misses (`kitsunox live
misses`, 94) with one, all read in memory. Publish or npm-token text (`npm`/`pnpm`/`yarn`/
`bun publish`, `libnpmpublish`, `.npmrc`, `NPM_TOKEN`, `_authToken`, the registry with `PUT`)
is in the loaded or install files of 574 `vm-day1` malicious samples (mostly Shai-Hulud's
`bundle.js`), of one live positive (`charape@1.0.20`, unwanted, whose postinstall reads
`.npmrc` and publishes nothing), of no live miss, and of 8 benign `vm-day1` samples, 185 live
versions and 52 reviewed benign ones (changelogs, help text, release helpers in the library).
No live positive or miss publishes.

**Where it runs.** With `lang/at_load.py`'s reach (top level, in-place calls, callbacks of
running calls, functions called by name from running code):

| Shape | `vm-day1` malicious | `vm-day1` benign | live (33.7 h) | reviewed benign |
|---|---|---|---|---|
| that text in a loaded or install file | 574 | 8 | 185 (181 unreported) | 52 |
| a publish string that runs at load or install, any use | 106 | 0 | 2 (help text, a data table) | 5 (a changelog string, CLI help) |
| **a command runner called at load or install with a publish command** | **105** | **0** | **0** | **0** |
| an npm token, the registry URL and `PUT`, all at load or install | 0 | 0 | 0 | 0 |

The 105: the 47 `*_z3n` (`main`, `exec` in a timer loop), 28 `@emilgroup/*` releases
(CanisterWorm: `postinstall: node index.js` finds tokens in `.npmrc` files and runs
`scripts/deploy.js`, whose `run(cmd)` wraps `execSync`), `@opengov/*`, `@teale.io/eslint-config`,
`@automagik/genie`, `pgserve`, `@fairwords/*` and 11 others (`execSync` of
`` `npm publish --userconfig="${rc}"` `` from an install file). The 58 that aren't `*_z3n`
are reported already through `npm.install-hook` or `npm.install-script-code`. Shai-Hulud's
`bundle.js` publishes from functions of a minified bundle the parse doesn't see run; its
install rules report it. Release tooling never matched: its publish runs in a function its
user calls (an exported `release()`, a CLI command handler), from a `bin` script, or from a
`scripts` entry that isn't an install hook, none of which is load or install code.

**Extractor v9** records the commands that run when a file is loaded
(`FileCapabilities.commands_at_load`, carried as `Profile.commands`; `lang.at_load.commands`):
a call to `exec`, `execSync`, `execFile(Sync)`, `spawn(Sync)` or `execa` (any receiver), or
to a function of the same file whose first parameter is passed to one (`run(cmd)`), that
runs at load, with the command as written: a string, a template (`${...}` kept), a `+` of
those (other operands as `…`), a name the file binds to one, plus a following list of
strings (`spawn("npm", ["publish"])`). Each distinct text once, at most 50 a file, 200
characters each.

**Rule.** `npm.publish-at-load` (MEDIUM, weight 3; npm because of `npm publish` and the `bin`
guard): a command that runs at load in a file loading runs (`CodeChange.load`, without the
`bin` targets) or in a file the install hooks run (`CodeChange.install`) publishes to npm
(`npm|pnpm|bun [flags] publish`, `yarn [npm] publish`; not `npm run publish`). On an update,
only if no file of the previous version did. Measured with the built code:

| | Fires | Newly reported |
|---|---|---|
| `vm-day1` malicious | 105 (47 new packages, 28 shape-A updates, 30 follow-ons) | **46**, every one a `*_z3n` new package |
| `vm-day1` benign (1,452 with files) | 0 | 0 |
| live, 37,154 versions in 33.7 h | 0 | **0** |
| live reviewed positives (108 with a tarball), live misses (35 with a tarball) | 0 | 0 |
| live reviewed benign (1,434 with a tarball) | 0 | 0 |

The `bin` guard removed nothing in any set; it is kept for the shape it guards (a CLI whose
`main` is its `bin`, as for `npm.load-fingerprint`). Not built: the token-and-PUT form
(fires on nothing), any publish string at load (help text), and the hook command line itself
(`"postinstall": "npm publish"`: none in any set).

### Explained install (S1-S3) and agent configuration

`npm.install-explained` (INFO, weight 0; 2026-11-08,
[proposal round 2](../proposals/precision-round2.md), S1-S3, approved by the owner before the
rule freeze) recognises install code of a shape reviewers clear at a glance. Like
`npm.install-build-tool` (S4) it is an explanation for Stage 4, which makes the three install
rules (`npm.install-hook`, `npm.install-script-changed`, `npm.install-script-code`) LOW,
weight 1, with a note ([correlate.md](correlate.md#decision-and-score)); content findings
(`npm.install-script-obfuscated`, `static.*`, `known-signature`) and `code.capability-gained`
are never explained. The shapes, all strict (a miss only keeps a version reported), and never
by a package's name, description or keywords:

| Shape | Condition, on the install files `install_sources` finds |
|---|---|
| S1 platform-binary launcher | 2 or more `optionalDependencies` that are the package's own platform builds (same scope, or containing its name, plus an OS or CPU token: `@kx/tool-linux-x64`); no network, or network with every URL literal on `registry.npmjs.org` (GitHub issue/file pages and `example.com` in messages allowed) |
| S2 own-release download | network; the `repository` is on GitHub; every URL literal (after substituting `const` strings) is that repository's releases (`github.com/<o>/<r>/releases`, `api.github.com/repos/<o>/<r>/releases`), GitHub's release asset hosts, the npm registry or a page link, and one is its own (or cargo-dist's `artifactDownloadUrls` all are); a checksum check (`createHash("sha256"`, `SHA256SUMS`, `checksums.txt`, `.sha256`, `verifyChecksum`), or since v3 cargo-dist's `artifactDownloadUrls` all being its own releases; no URL whose host or owner is a variable |
| S3 agent-skill copier | no network, no process; the code names an agent directory (`.claude`, `.agents`, `.cursor`, `.codex`, `.gemini`, `.windsurf`, `.opencode`, `SKILL.md`, `AGENTS.md`, `.mcp.json`), and the agent files it may copy pass the three guards below |
| S5 inert install code (v3) | hooks are plain `node`, install files JavaScript; capabilities only `filesystem` and `os-info`; no package loaded by name; no home, agent, system (`/etc/`, `C:\`, ...) or other-package path (`node_modules`, `require.resolve`); no network- or exec-naming text (`fetch`, `import(`, `"node:https"`, `spawn(`); not upstream Baileys's `engine-requirements.js` |
| every shape | an install hook that is not shell (`curl`, `wget`, `sh`, `bash`, `python`, `./x`, `\| sh`, `$(...)`, backticks); no `binding.gyp` command; no `env-all`, `dynamic-code` or `dynamic-require` in the install code; for an update, no capability the install code didn't have before; plain UTF-8, no line over 1,000 characters, no whitespace-padded code (v3) |

The **three guards** on S3 (the owner, 2026-11-08: an agent-skill copier is benign as a
verdict, decision 0015, but the rule may stay quiet only when the code proves the plain shape),
in `lang/agent_config.py`:

1. **What gets installed is scanned.** Every `command` in the agent configuration (JSON parsed,
   TOML and code by pattern; an MCP server's `command` with its `args`) and every `command`
   value in install code that writes hooks or MCP servers must be a constant `echo`, or a
   script shipped in the package (matched by file name, under `${CLAUDE_PLUGIN_ROOT}`,
   `$CLAUDE_PROJECT_DIR`, `$HOME` or `~`) run by a plain interpreter with constant arguments
   (`plain_command`; `command -v`, `|| true`, `/dev/null` redirections allowed). `npx -y x`,
   `curl ... | sh`, `node ${dir}/x.js`, `echo $TOKEN` are not. A shipped JavaScript hook
   script must have no `network`, `process`, `env-all`, `dynamic-code` or `dynamic-require`
   (its parsed capabilities); a shell or Python one no network tool, URL, download-and-run,
   environment dump, `eval`/`exec` or `subprocess` (`script_concerns`).
2. **Permission widening is never explained** (`widening`): a tool allow-list naming anything
   beyond the read-only tools (`Read`, `Grep`, `Glob`, `LS`, ...): settings' `permissions.allow`,
   `allowedTools`, a skill's or command's `allowed-tools`; bypass modes and flags
   (`bypassPermissions`, `--dangerously-skip-permissions`, `--yolo`, Codex's
   `approval_policy = "never"`/`danger-full-access`, `autoApprove`, `alwaysAllow`,
   `"trust": true`, `defaultMode` `acceptEdits`/`dontAsk`); a remote MCP server (`url`,
   `serverUrl`, `httpUrl`, an `http`/`sse` transport, `mcp-remote`). The 2025 nx compromise ran
   its users' AI CLIs with permission-bypass flags to search for secrets.
3. **Instructions aimed at the agent are flagged** (`hostile_instructions`, and the MEDIUM rule
   `agent.hostile-instructions`, weight 3, which reports the version): text in the agent
   files (and strings in the install code) telling the agent to hide what it does from the
   user, to ignore its earlier instructions, to switch off its safeguards, or, in one
   sentence, to send a credential file (`~/.ssh`, `id_rsa`, `.npmrc`, `.env`, a wallet or
   private key) away, the credential within 80 characters of the sending verb. A phrase in
   quotes, a sentence that discusses attacks (`injection`, `example`, `detect`, `refuse`,
   `report`, ...), a negated "ignore"/"disable" ("never ignore earlier instructions") and
   "do not tell the user *to* ..." are not instructions: security-review agents quote the
   attack they look for (`great-cto@3.75.6`, `tesseract-agent@0.12.2-beta.2`, both benign).
   Sentences end at CJK full stops too.

More than 300 agent files is "too many to check" and not explained.

**Measured** (2026-11-08) with the real code, before building Stage 4 on it:

- **`vm-day1`, all 433 malicious samples reported only through the install rules** (they
  would go if the three were LOW; the proposal had checked 149). Each encrypted DataDog zip is
  read in memory: the ZipCrypto members a rule reads are decrypted by `unzip -p` into the
  process (the still-encrypted zip on `/dev/shm`), never extracted to disk, and the shape and
  agent rules run on the result with no base (the most permissive case: no "gained" check).
  **None is explained, none has hostile instructions.** Only `@nx/key@3.2.0` (the 2025 nx
  compromise's `telemetry.js`) has 2+ platform builds; S1 refuses it for `env-all` and for
  network to a host other than the registry. Only `aicp-tracker@1.0.7` names an agent
  directory, and it reaches the network and runs processes. None names its own repository's
  releases. 185 have `env-all`, `dynamic-code` or `dynamic-require` in their install code, 22
  a shell hook, 38 a `binding.gyp` command, 49 no install code. The proposal's own (broader)
  definitions, strict or loose, match none of the 333 they were computed for.
- **Live**, the 3,244 latest verdicts with rank > 0 (`data/verdicts/npm.jsonl`; 2,107
  reported with today's code: 1,970 benign, 41 malicious, 46 unwanted, 50 unverified), the
  signal computed on the captured tarballs (738 of the 1,442 versions with an install
  finding) and Stage 4's real `explained` and `decide`: **85 fewer reports, all benign**
  (S1 36, S2 34, S3 15; 70 packages: `@opencode/cli`, `banyancode`, `react-native-executorch`
  nightlies, `@onreza/nrz`, `@bullpenfi/cli`, `@anyglade/kit`, `@ku-utils/*`, ...); 0
  malicious, unwanted or unverified lost. Precision (malicious + unwanted) 4.23% → 4.41%.
  19 of the 85 are updates whose previous tarball is no longer held, so the "gained" check
  could not run; the rest are new packages or passed it.
- **What the guards cost:** 5 live S3 candidates stay reported, all benign: `ai-aleks-tool`
  2.4.0 and 2.5.1 (commands with `allowed-tools: Edit, Write, Bash(node:*)`), `catalyst-os`
  (`Bash(cat:*)` in `settings.local.json`), `@karajan-family/code` (hook commands built in
  code), `@mobileaidev/ai-app-bridge` (an `npx` hook). The owner's guards are strict on
  purpose.
- **Narrowed from the proposal**, each a condition the proposal's numbers didn't have: S1's
  network only to `registry.npmjs.org` (the script also allowed GitHub's asset hosts); no
  `dynamic-require` in any shape; for an update, nothing new in the install code (the owner:
  "updates keep the normal diff rules"); S3's agent directories without a bare `skills/`.
  Nothing dropped: no shape explained a malicious sample.
- **Guard 3 narrowed twice:** the first version flagged two benign packages live, both quoting
  the attack (`great-cto@3.75.6`'s security-review agents, `tesseract-agent@0.12.2-beta.2`'s
  "...ignore earlier instructions, is something to report..., never something to do"), and,
  on every hooked version of the retained runs, `@acedatacloud/skills` ×6 ("do not tell the
  user to reconnect") and `@finebi/finebi-cli` ×4 (Chinese notes naming `.env.local` and a
  `POST` endpoint 200 characters apart). The other hits of that first pass (`@wowok/skills@3.4.0`,
  `nameslink` 1.0.5 and 1.0.6, not reported otherwise) were pruned before they could be read;
  whether the narrowed rule still fires on them is unknown. As built, on the 3,552 hooked
  versions with a tarball in the 8 retained runs of Nov 7-8 (397 with install code naming an
  agent directory) it fires on none. The shapes fire on 845 of them (S1 599, S2 176, S3 70),
  68 of which Stage 4 reported.

#### S3 v2: copies into the project only (2026-11-09)

The owner ruled (decision 0015, addendum 2026-11-09) that install code silently writing a
package's skills, hooks, agent settings or MCP registrations into **user-wide** agent locations
(`~/.claude/`, `~/.agents/`, `~/.codex/`, `~/.cursor/`, `~/.gemini/`) is **unwanted**, a
positive; writes into the project (`INIT_CWD`, `process.cwd()`, the project's `.claude/`,
`AGENTS.md`) stay benign. S3 explained both, so it now costs recall. `npm.install-explained`
v2 keeps S3 only for install code that:

- refers nowhere to the user's home directory (`agent_config.home_references`, over the install
  code and the install hooks' command lines): `os.homedir()`, a `homedir` import,
  `userInfo().homedir`, `process.env.HOME`/`USERPROFILE`/`HOMEPATH`/`APPDATA`/`LOCALAPPDATA`/
  `XDG_CONFIG_HOME`/`XDG_DATA_HOME`, an agent's own `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, ...,
  `const { HOME } = process.env`, `$HOME`/`${HOME}`/`%USERPROFILE%` in shell, `"~/..."` and
  `path.join("~", ...)` paths, the `os-homedir`/`user-home`/`xdg-basedir`/`env-paths` packages;
- loads no package by name (`Profile.packages`): where a dependency writes can't be seen
  (`@doist/todoist-cli` refreshes installed skills through `@doist/cli-core`), so the target
  is undetermined.

Everything else about S3 (no network, no process, the three guards) is unchanged; S1 and S2
are untouched, and nothing new is explained. A version refused for its home reference gets
**`npm.install-agent-user-wide`** (INFO, weight 0; Stage 3), a note for the reviewer that names
where the install code refers to the home directory (up to three file:line spans), so a
reported user-wide copier says why it is not an explained install. It fires whenever install
code names an agent directory and refers to the home directory, whatever else the code does.
No STAGE_VERSION or extractor change: Stage 4 reads the shape finding as before, and the rule
set id changes with the new rule and version.

**Measured** with the real code (`~/kitsunox-scratch/wt-s3/tools/measure.py`: tarballs in
memory, today's S3 vs v2, Stage 4's real `explained` + `decide` on each version's stored
findings with the explanation undone from `ast.jsonl`):

| Set | Today's S3 | User-wide | Undetermined | Kept (project) | Reports added back |
|---|---|---|---|---|---|
| Live, 17 fully captured runs (2026-11-07 16:33Z to 11-09 06:33Z, 38 h; 2,368 hooked versions, 1,699 with a tarball) | 30 (14 packages) | 17 | 2 (`@doist/todoist-cli`) | 11 | **0** |
| Live, the 4-day catch-up run before them (11-03 15:48Z to 11-07 16:33Z; 2,868 of 9,574 hooked tarballs still held) | 39 (22) | 26 | 1 | 12 | 7, all reviewed benign |
| Reviewed, latest verdicts (912 hooked versions with a tarball) | 25 (22 packages, all benign) | 16 | 0 | 9 | 16 benign |
| `vm-day1`, the 433 malicious samples reported only through the install rules (each read in memory from the encrypted zip) | 0 | - | - | - | 0 (the note fires on `aicp-tracker@1.0.7` only) |

- **Live: about 0 to 2 reports a day added back.** S3 only lowers install findings, and most
  versions it explains have none to lower: with no network and no process there is no
  `install-script-code` finding, and an update whose hook and install code didn't change has
  no `install-hook` or `install-script-changed` either (`@lingjingai/scriptctl@0.79.8`: only
  LOW Stage 2 findings, score 3). In the 38 fully captured hours none of the 19 versions that
  lose S3 changes its decision (`@lingjingai/scriptctl` x7, `pi-gauntlet` x4, `vit`,
  `codebaseiq`, `claude-spotter`, `@aweray/hsk-cli`, `skill-port-cli`,
  `@herjarsa/omo-meta-governor`, `@doist/todoist-cli` x2). The 7 added back are all in the catch-up run (4 days, ~1.7 a day there)
  and all reviewed benign: `@easyhaloo/afk-opencode` 1.2.0 and 1.2.1, `@gabrielahn/gtfs-tools`,
  `enlighten-agent-tool@1.0.9`, `install-anything-skill`, `mxcad-skill`, `@draig/lexis-two`.
  Nothing is removed. Today's computed S3 agrees with the stored `npm.install-explained` on
  every version of the S3-era runs, and the recomputed decisions match the stored ones.
- **Reviewed: 16 benign versions S3 explains today are user-wide by this test**, and are
  reported again: `@aweray/aweshell-cli@0.4.25`, `@easyhaloo/afk-opencode` 1.2.0 and 1.2.1,
  `@gabrielahn/gtfs-tools@1.5.4`, `@josetra/wacon@0.4.0`, `@linkquejs/card-craft@0.1.7`*,
  `enlighten-agent-tool@1.0.9`, `ha-integration-skill@0.1.0`, `install-anything-skill@1.0.0`,
  `join-com-cli@0.0.0`*, `mxcad-skill@1.0.0`, `novita-sandbox-cli@2.1.2`*, `omnishpilot@0.0.6`,
  `weaver-e9-builder-cli@1.5.13` (14, read by hand: their install code writes skills under the
  home directory; * only on a global install, `npm_config_global`), and two whose install code
  writes into the project and only *mentions* home: `@draig/lexis-two@1.5.0` (a comment on
  OpenCode's plugin cache) and `opencode-blocker-diverter@0.3.1` (compares `INIT_CWD` with
  OpenCode's global directory). The 14 are the `sino-bc-cli` shape the addendum re-labels
  unwanted: once relabelled they are true positives S3 would have hidden. No reviewed positive
  changes: the 22 unwanted and 1 unverified versions whose install code names an agent
  directory all refer to the home directory and none was S3 (network, process or
  obfuscation), so recall under today's labels is unchanged.
- **The note** fires on 311 of the 479 live versions whose install code names an agent
  directory (65%; most are not reported) and on 148 of the 202 reviewed ones. INFO, weight 0:
  it changes no score and no decision.

#### Install code that changes the machine beyond the project (`npm.install-persistence`, 2026-11-09)

The owner's rulings of 2026-11-09 (decision 0015 addenda) make four install-time behaviours
**unwanted**, harmless as what they install may be: writing an AI agent's configuration
**user-wide** (skills, hooks, settings, MCP servers under `~/.claude`, `~/.codex`, `~/.cursor`,
`~/.agents`, `~/.config/opencode`, Claude Desktop's config, ...), editing the user's **shell
start-up files**, changing **PATH persistently**, and installing **system packages**. Until
round 4 the pipeline caught most of them only because their install files had changed
(`npm.install-script-changed`); `npm.install-agent-user-wide` (INFO) says only that the install
code names an agent directory and the home directory somewhere, which is true of 55% positives
and 45% benign versions. `npm.install-persistence` (MEDIUM, weight 3; `ecosystems/npm/rules/
install_persistence.py`) names the behaviour itself, in four forms, on the install code (the
files the hooks run and those they load, plus the hook command lines) with comments and
messages masked (`lang.javascript.mask_comments_and_messages`: comments, and strings only
printed, logged or put in an error; for shell, PowerShell and batch files, comment and `echo`
lines; other files the hooks name, such as a README, are data):

- **`agent`**: a path under the home directory to an agent's configuration, written out
  (`"~/.claude/skills"`, `$HOME/.codex`, `%USERPROFILE%\.cursor`, `` `${os.homedir()}/.agents` ``)
  or joined to a home expression (`join(os.homedir(), ".claude", ...)`, also minified
  `l.join(e, ".claude", "settings.json")` after `let e = l.homedir()`, a variable or function
  result named for home, a choice `join(homedir(), t ? ".codex" : ".agents")`, a caller's
  override `join(options.home ?? homedir(), ".workbuddy")`), the XDG config home joined to
  `opencode`/`crush`/`goose`, `~/.claude.json`, Claude Desktop's `claude_desktop_config.json`,
  or an agent's own config-dir variable read in code (`env.CLAUDE_CONFIG_DIR`, `CODEX_HOME`; not
  the name in a help text). Agent homes include DSH's `~/.dsh` (the owner's 2026-11-09 ruling),
  `~/.hermes`, `~/.workbuddy`, `~/.zcode`. A path is matched, not the write itself, so code that
  only reads an agent's files there fires too (`aicp-tracker`'s session-log reader);
- **`shell-rc`**: `static.shell-startup`'s four forms on the install code;
- **`path`**: `SetEnvironmentVariable("Path", ..., "User"|"Machine")`, `setx PATH`,
  `reg add HKCU\Environment`, `/etc/paths.d/`, `/etc/profile.d/`, `launchctl setenv PATH`;
- **`system-package`**: a package manager's install command where a command starts (the start
  of a string or shell line, after `&&`, `||`, `;`, `|`, `$(`), with or without `sudo`: `apt-get`,
  `apt`, `dnf`, `yum`, `zypper`, `apk`, `pacman -S`, `brew`, `port`, `winget`, `choco`, `scoop`,
  `snap`. "Install it with: brew install x" doesn't start a command.

Since 2026-11-10 the install code includes the shell, PowerShell and batch scripts it starts
(`install.spawned_scripts`: a constant relative path such as `path.join(__dirname,
"install.sh")`, the constant tail of a `join` naming a script, `join(dir, "claude-code",
"scripts", "install.sh")`, or a script's bare name used in the code when at most three package
files have it), read as data; and the `agent` form includes an agent's own CLI installing into
its user configuration (`claude plugin install`, `claude plugin marketplace add`, `claude mcp
add --scope user`, `codex mcp add`, also as `"$CLAUDE_BIN" plugin install`). That is how
`@ornexus/neocortex@4.60.77` (`install.sh`: `${HOME}/.claude/agents`), `@ziniao-open/cli@0.1.0-beta.175`
(`setup-ziniao-cli.ps1`: the user PATH) and `anolisa-tokenless@0.9.3` (`claude plugin
install` in `install.sh`) are seen; every install rule reads these scripts too. A binary the
install code runs (`tmailcli`'s `install-skill`) stays unread.

Since 2026-11-10 (round 4 G) the install code also includes what such a script starts
(`install.script_started`): another package script (`sh ./stage2.sh`, `. "$(dirname
"$0")/lib.sh"`, `bash "${SCRIPT_DIR}/x.sh"`, `& "$PSScriptRoot\helper.ps1"`, `call
%~dp0setup.bat`, `powershell -File %~dp0tools\x.ps1`), up to `SCRIPT_DEPTH` (2) levels past
the first script, and a package JavaScript file a script runs (`node ./lib/run.js`), which
`followed_files` then follows. A path is resolved from the script's directory, then the package
root, with leading variable segments dropped; a bare name is the script's own directory's file
or one of at most three; comments, printed messages and URLs (`curl https://x/install.sh`) are
not read; at most `MAX_SPAWNED` (10) files. And a hook path written Windows-style names the
package file (`files_named`: `powershell -File .\scripts\x.ps1`, `node lib\index.js`).
Measured ([precision-round4-G](../proposals/precision-round4-G.md), update): of the 1,743
verdicted hooked live versions, 18 get a different install code set and all 18 decide as
before; in a day of live hooked versions (2,112 read) 10 change and one gains MEDIUM
findings, `@raditia/craftkit@1.63.0` (unreviewed: `scripts/postinstall.sh` runs `sync.sh`,
whose adapters write `~/.claude/commands`, `~/.claude/agents` and `~/.cursor/rules`, the
ruled-unwanted shape); `vm-day1`: +1 malicious reported, `company-ts@1.0.3`
(`preinstall: node lib\index.js`).

Script masking (2026-11-10, round 4 G, [precision-round4-G](../proposals/precision-round4-G.md)):
`code_text` reads a shell, PowerShell or batch file with `lang.shell.mask_script_messages`,
which `npm.install-script-loader` uses too. Two things changed for every install rule that
reads script text (this one, `install-script-code`'s hidden-code check, `install-script-changed`'s
`TOUCHED`): a message printed through the script's own print-only function is blanked
(`@ornexus/neocortex@4.61.5`'s `info "Para persistir: echo 'export ...' >> ~/.bashrc"` was a
`shell-rc` write), and an `echo` that pipes, writes a file or chains a command is kept
(`echo 'export PATH=...' >> ~/.zshrc` is the usual rc write; before, every `echo` line was
blanked). It also fixes a line-number bug: the old pattern's `^\s*` ran from a blank line into
the comment after it and blanked the newline, so every later line of the script read one off
(`node-sword-interface@1.0.127`'s changed `git clone` line was compared as the line after it).
Measured with the real code on the 64 verdicted live versions with install scripts (the only
ones it can change): **1 benign newly reported**, `node-sword-interface@1.0.127` (that
`git clone` URL line, now seen by `install-script-changed` v5), no positive changed;
`vm-day1`: the 4 samples with install scripts decide as before.

It fires only when the install code is new or changed since the previous version
(`ONLY_WHEN_CHANGED`), where the install rules already look: it names what that code does and
adds no report for an installer that is the same as in the version before. Two variants were
measured and not built: a write call within a few lines of the path (loses 35-53 of 87
unwanted user-wide writers: the path is computed in one helper and written in another), and
skipping install code that asks the user (`readline`, `prompts`, `inquirer`): it loses 20 of 80
unwanted, whose installers ask something else and write anyway. Measured in
[precision-round4-A](../proposals/precision-round4-A.md).

**`npm.install-script-obfuscated`** (HIGH, weight 4; 2026-10-31, at the owner's request) flags
install code nobody can review by reading it: what it does at install is a question only Stage 5
can answer, and HIGH puts it in front of Stage 5's per-run cap of 30 and of the queue. Five
packages reviewed inconclusive for this reason (`sppurt`, `motionchart-cli`, `sino-bc-cli`,
`whybug`, `calculatorscool346`) scored 3-11 without it. On `vm-day1` it changes no reporting
decision (every malicious sample it fires on was reported) and fires on no benign sample.
v2 (2026-11-01) adds the rotation prologue, which only javascript-obfuscator writes, for output
whose identifiers were renamed: `sino-bc-cli`'s `dist/index.js` has no `_0x` at all. `vm-day1`:
+4 malicious samples (`analytics-browser`, `qdrant-js`, `react-native-country-select`,
`tailwin`), still no benign. Known limit: install code that starts a script through
`execFileSync(process.execPath, ['dist/cli.js'])` isn't followed (only `require`/`import` and
the command line are), and a followed file over 256 KiB is skipped, so `sppurt`'s 3 MB obfuscated
CLI, run from an inline `node -e` hook, is not seen.

**`npm.install-script-changed`** (MEDIUM, weight 3; 2026-10-30) compares the files the install
hooks name with the previous version's, byte for byte, and puts the changed lines in the
evidence as a unified diff (one line of context, 40 lines and 200 characters a line at most;
reports render it as a `diff` block). It fires when such a file changed or is newly run. A file
whose only change is its own version string (`workerd`'s `install.js` downloads
`${pkg}@<version>`), or its line endings (v2: `@tera-system/pro` 0.2.33 converted CRLF to LF
and was reported "+0 -0 lines"), is unchanged. A file over 2,000 lines is reported changed without a diff:
`difflib` is quadratic on lines that repeat without being junked (20,000 lines cycling 150
values took 45 s). Each file is kept up to 256 KiB for the comparison. Stage 1 forwards every
update with an install hook so this rule sees them. On the first VM day it fired on 47 of the
601 hook updates whose two tarballs were captured (7.8%), and not on `@pulumi/*`, whose
`install-pulumi-plugin.js` didn't change.

Hidden code in the diff (2026-11-10, report text only, round 4 F): runs of 40 or more spaces or
tabs in a diff line are shown as a counted marker (`⟨266 tabs⟩`, `util.text.collapse_runs`)
before the 200-character cut, and the summary names the longest added line when it is longer
than the cut (`scripts/postinstall.mjs (+3 -1 lines, longest added line 12,699 characters)`).
`hauntview@0.2.9`'s added line was 266 tabs and then a loader: cut at 200 it showed as a blank
added line. No severity, weight or decision changes, so the rule keeps its version.

`npm.install-script-changed` v3 (2026-10-31): since install code follows what a hook loads,
the rule also saw ordinary library changes two files down. A file another install file loads
(`install.loaded_files`) now counts only when its change adds a line with a risky use
(network, process, the whole environment or dynamic code). The files the hooks name, and
inline code, count on any change as before. On the first 120 re-scored live reports, 7 were
reported through a loaded file alone, all benign (`openyida`'s auth library, `warp-agent-mcp`'s
tool descriptions); 6 of them add no risky line. `vm-day1`: 3 malicious lost, all
`aicp-tracker` (the family is still reported through 1.0.7, which adds one), 1 benign.

`npm.install-script-changed` v4 (2026-11-09) is LOW, weight 1, when every changed file is the
same code but for **volatile strings** or for **printed text**; the diff stays in the evidence,
with a note. Volatile strings (`VOLATILE`) are versions in any form (`v2.3.38`,
`1.4.4-canary.20261030.1+f7607a3`, never part of a dotted quad, so an IP address is not one),
dates and build stamps, digests and commit hashes (7-12, 32, 40, 64, 96 or 128 hex digits with a
letter and a digit) and integrity values; the URL hosts must stay the same. Printed text is a
string that is an argument of `console.*` or `process.std{out,err}.write` (directly, or through
`+` and parentheses: not through a function call, a ternary or a template's `${...}`), masked by
`lang.javascript.mask_printed_text` on a clean parse. A newly run, binary or too-long file, or
any other change in any file, keeps the MEDIUM: a new host or repository owner, a changed IP
address, a changed command string, added code beside a message, formatting.

Measured before building, on the latest verdict of the 750 reviewed versions the rule fired on
(benign 714, unverified 27, malicious 6, unwanted 3; both tarballs for 742, 371 of them
downloaded again from npm as data) with today's other findings (round 2's groups, the
explained-install shapes recomputed on the tarballs) and Stage 4's real `explained` and
`decide`. 422 benign versions are reported only through this rule. Their changed install
files, by tree-sitter tokens (comments aside):

| Shape of the change | Reported benign |
|---|---|
| ordinary code changes (refactors, new options, error handling) | 283 |
| only versions, digests, dates (generated installers: `workerd`, `bun` canaries, `@depot/cli`, `@ejfkdev/*`, `onpod`, `statuz-cli`) | 52 |
| only string literals: printed messages (14), but also download URLs, shell lines, file names | 27 |
| shell, Python or PowerShell install files | 21 |
| a file newly run (with or without other changes) | 30 |
| only comments or formatting | 8 (and `hyrox@0.1.6`, unverified) |
| a binary | 1 |

Of the 422, 113 download with a checksum but are not S2 (another host, a templated URL, a
whole-environment read); 90 download without one; 219 use no network at all. The proposals,
each as LOW (none touches a malicious, unwanted or unverified version unless said):

| Proposal | Benign reports removed | Positives / unverified lost | `vm-day1` malicious touched / lost |
|---|---|---|---|
| **volatile strings only** (built) | 50 | 0 / 0 | 0 / 0 |
| **printed text only** (built) | 14 | 0 / 0 | 0 / 0 (a line-based estimate matched `shoal-cli@0.4.5`, reported by `npm.install-hook` HIGH anyway; the built masking doesn't) |
| comments or formatting only | 8 | 0 / 1 (`hyrox@0.1.6`) | 0 / 0 |
| install code with no capability at all | 7 | 0 / 1 (`hyrox@0.1.6`) | 1 / 0 |
| any string-literal-only change | 27 | 0 / 0 | 8 / **8** (`esoftplay` ×4, `@emilgroup/*` ×3, `fooobar@1.0.14`) |
| S2 for a checksum-verified download from the `homepage`'s domain | 17 (5 packages; 2 beyond the built shapes) | 0 / 0 | not measured |

As built (v4 on the same versions): **64 fewer reports (27 packages), all benign; 0 malicious,
unwanted or unverified lost**; 74 benign findings LOW. On `vm-day1`, v4 was run on every
malicious update whose manifest has an install hook (the encrypted zips read in memory, the base
from a copy of the evaluation's tarball cache; 1,203 have no base npm still serves, so the rule
can't fire on them): v3 fires on 629, and **all 629 stay MEDIUM**, so no sample's report
changes. Not built: string-literal-only
(strings carry behaviour: the 8 malicious samples change template code or commands in strings),
comments-only and no-capability code (both lose `hyrox@0.1.6`, unverified, whose only install
change is reformatting: an owner decision), and the vendor-host download (the `homepage` is the
publisher's own claim). Known limit: a version pinned by a string that something other than a
download uses (`npx tool@1.2.3`) is volatile too, so moving a pinned tool's version is LOW.

`npm.install-script-changed` v5 (2026-11-09, round 4; [precision-round4-A](../proposals/precision-round4-A.md))
is **content-aware**: the finding stays MEDIUM only when the change touches what an attack
needs, and says what (`TOUCHED`, on the code with comments and messages masked, plus Stage 3's
risky uses on those lines): processes (`exec`, `spawn`, `child_process`, ...), the network
(`https.get`, `fetch`, `net`, `dns`, ...), URLs, IP addresses or host names, encoded data or
decoding (100+ base64 or hex characters, `atob`, `Buffer.from(.., "base64")`, `\x` runs),
credentials and tokens (`.npmrc`, `.ssh`, `.aws`, `npm publish`, `_authToken`, `*_TOKEN`), the
home directory, shell commands (`curl`, `wget`, `sudo`, `powershell`, `| sh`, `chmod +x`, ...),
package-manager commands (`npx`, `npm install`, `pip install`, ...), the whole environment, or
dynamic code. For a diffable file that is the changed and added lines; a newly run file counts
as a whole; for a file too long to diff, the matches it has that its previous version didn't; a
binary always counts, and so do code hidden past the edge of the screen (`hidden_code`, as
`npm.install-script-code` v3) and a string literal of 4 KB or more (`LONG_LITERAL`): both
also make a loaded file's change count (`_adds_risky`), since neither shows its uses to Stage 3
(`hauntview@0.2.9`: 266 tabs, then a loader that builds `Function` from a computed key; on the
live versions the two additions change no finding). Install code that names an agent directory and the home directory
(`npm.install-agent-user-wide`'s test) keeps the MEDIUM on any change: it may write
user-wide through code the diff doesn't show (`@aweray/aweshell-cli@0.4.25`,
`@easyhaloo/afk-opencode@1.2.1`, `@mobileaidev/ai-app-bridge`, unwanted, whose diffs are
inert). Anything else, a refactor, an option, error handling, a template's text, is LOW,
weight 1, with the note "nothing an attack needs"; the diff stays in the evidence. With
`npm.install-persistence` and `static.channel-tagging` naming the behaviour of the positives that
relied on this rule (of its 65 unwanted live reports, 51 are now caught by the persistence rule,
2 by channel tagging, 8 keep v5's MEDIUM), v5 removes **188 benign reports** (153 packages) of
the 3,716 verdicted live versions and loses **1 unwanted** (`tmailcli@0.1.5`, whose user-wide
skill install is done by its Go binary; the other three it lost at first, `@ornexus/neocortex`,
`@ziniao-open/cli@0.1.0-beta.175` and `anolisa-tokenless`, are caught since the install code
includes the scripts it starts, 2026-11-10), **1
unverified** (`hyrox@0.1.6`, a reformatted Node-version check) and **6 `esoftplay`
follow-ons on `vm-day1`** (0.0.142-m, 0.0.143-w, 0.0.183, 0.0.185, 0.0.256, 0.0.262: build
configuration edits in `bin/build.js`; the Telegram code that makes the family malicious is in
`bin/cli.js`, unchanged, a CLI command). A trade-off, the owner's call
([precision-round4-A](../proposals/precision-round4-A.md)). Known
limits: a change that only edits a value another line runs (a bare command name, a path
without a lexicon word) or that removes a guard is LOW; install code a hook starts through a
spawned shell script or a binary is not read at all.
#### Shell, PowerShell and batch loaders in install code (`npm.install-script-loader`, `npm.install-script-exfil`, 2026-11-10)
#### Shell, PowerShell and batch loaders in install code (`npm.install-script-loader`, 2026-11-10)

The owner, 2026-11-10: "the scripts triggered by the package should be analyzed. For example
if that .ps1 file had obfuscation it should be flagged." A shell, PowerShell or batch script
is install code when a hook names it (`"postinstall": "sh setup.sh"`, `powershell -File
x.ps1`: `install.files_named`) or install code starts it by a constant name
(`install.spawned_scripts`, round 4 A). Before this rule and the script masking above, what read such a script:

| Rule | Reads a `.sh`/`.ps1`/`.bat`/`.cmd` install script? |
|---|---|
| Stage 2 file rules (`exfil-endpoint`, `hardcoded-ip`, `encoded-url`, `sensitive-path`, `env-harvest`, `shell-startup`, `encoded-blob` LOW, `padded-code`) | yes: every new text file, whatever its suffix. `static.obfuscated` (`_0x` names), `dynamic-code` (`eval(`), `process-exec` and `network` (`require(...)`) are JavaScript forms and never match a script; `padded-code` needs `(` or `=` in the hidden tail, so `curl ... \| sh` behind spaces is not code to it |
| `npm.install-script-code` capabilities | no: tree-sitter profiles JavaScript only, so a script has no capability |
| `npm.install-script-code` v3 hidden code | yes, on `code_text`, which blanked every `echo` line whole: code pushed off screen after an `echo` on the same line was missed (fixed by the script masking above, 2026-11-10) |
| `npm.install-script-changed` v5 | updates only: its `TOUCHED` lexicon (`curl`, `iex`, `powershell`, `certutil`, `\| sh`, base64 runs) keeps the MEDIUM when a script's changed lines have them; a new package has no base, so nothing |
| `npm.install-script-obfuscated` | runs on scripts, but its tests (`_0x`, javascript-obfuscator's rotation prologue) never match one |
| `npm.install-persistence` | yes: agent paths, shell rc, persistent PATH, system packages |

So a new package whose hook runs `install.ps1` with `-EncodedCommand`, `[char]` codes or
`irm ... | iex` was reported only by `npm.install-hook` (MEDIUM for a new package), and an
update whose script gained one only by `install-script-changed`. A script run by the hook and
one spawned from JavaScript get the same reading (both are in `install_sources`); a script that
another script starts was not followed, and a hook path written Windows-style
(`.\scripts\x.ps1`) was not resolved; both are read now (`install.script_started`, `files_named`; above).

`npm.install-script-loader` (MEDIUM, weight 3; `ecosystems/npm/rules/install_loader.py`) reads
the shell, PowerShell and batch install scripts (and a suffix-less file starting `#!`) and the
hook command lines, with comment lines and message lines blanked (`lang.shell.
mask_script_messages`: a line starting with `echo`, `printf`, `Write-Host`, or a function the
script defines that only prints, such as `info() { echo -e "  $1"; }`, when nothing outside its
quotes pipes, redirects to a file, chains another command or substitutes one; unlike
`code_text`, `echo <base64> | base64 -d | sh` stays code), for the precise shapes of a loader
(`SHAPES`):

- shell: a download piped into a shell (`curl ... | sh`, `wget -qO- ... | sudo bash`; not into
  `jq` or `python -c`), a shell or `eval` running a download (`bash -c "$(curl ...)"`,
  `sh <(curl ...)`), decoded data run (`... | base64 -d | sh`, `eval "$(... base64 -d)"`,
  `xxd -r`, `printf '\x..' | sh`), a reverse shell (`/dev/tcp/host/port`, `nc -e /bin/sh`);
- PowerShell: `-EncodedCommand`/`-enc` with base64, `iex`/`Invoke-Expression` of a download
  (`irm ... | iex`, `iex (New-Object Net.WebClient).DownloadString(...)`) or of decoded text
  (`FromBase64String`, `GetString`, `-join`, `[char]`), `[char]` code chains (8+), a string
  reversed with `-join ... [-1..`, `[Reflection.Assembly]::Load(`;
- Windows tools: `certutil -urlcache`/`-decode`, `bitsadmin /transfer`, `mshta http:`/
  `vbscript:`, `rundll32 javascript:`, `regsvr32 /i:http`, batch substring chains
  (`%v:~3,1%` x8);
- code after 100+ spaces or tabs on a script line (outside quotes, not a comment) that
  `npm.install-script-code`'s hidden-code check doesn't report (one whose tail starts with a quote, which that check takes for a string's own padding).

A download piped into a shell from the package's own site (its `homepage`, `repository` or
`bugs` host, or GitHub under the repository's owner) is LOW, weight 1; one from a raw IP, a
paste site, a tunnel, a shortener or a file drop says so. On an update only a (shape, host) the
previous version's install code didn't have counts.

`npm.install-script-exfil` (MEDIUM, weight 3, same module and reading) names what such a script
sends away (`EXFIL_SHAPES`): command output piped into an upload (`env | curl --data-binary @-`,
`-d @-`, `-T -`), a file uploaded (`curl -F file=@/etc/passwd`, `--data-binary @file`, `-T file`,
`wget --post-file`), the cloud metadata service (`169.254.169.254`, `metadata.google.internal`,
`100.100.100.200`: instance credentials), and credential files (`.ssh/id_rsa`/`id_ed25519`/...,
`~/.npmrc` under the home directory, `.aws/credentials`, `.git-credentials`,
`.docker/config.json`, `.kube/config`, `/etc/shadow`). It was added for three `vm-day1`
malicious samples whose hook runs such a script and that nothing reported: `justgetit@1.2.4`
(links `~/.ssh/id_ed25519` into the package, then prints instructions addressed to an AI
agent), `ts-form-helpers` 1.0.3 (`{ env; git config --global --list; } | curl --data-binary @-`)
and 1.0.12 (a GCP token from `metadata.google.internal`). A bare `env` (reading it in a loop,
`@codyswann/lisa`) is not a shape.

JavaScript install files are not read:
there the same text is mostly help messages that `mask_comments_and_messages` keeps (strings
returned or put in arrays: `bun`'s `install.js`, `agentiqa`, `symbiot`, `gloomberb`), and a
JavaScript installer that runs `curl | sh` has `process` for `npm.install-script-code`.
Measured in [precision-round4-G](../proposals/precision-round4-G.md): on the 3,716 verdicted
live versions neither rule changes a decision (64 have install scripts; only
`@geekbeer/minion@5.28.0` has a shape, `curl -fsSL https://claude.ai/install.sh | bash`, in
its base too); a day of live hooked versions (23 runs, 2,044 read): 0 fires; `vm-day1`
(`pipeline+4` on the 103 malicious samples either rule fires on): 100 → 103 reported, 0 lost.
Only 4 of the 3,444 `vm-day1` malicious samples run an install script at all; the loader
shapes there are on hook command lines (`curl ... | node`, `bash -i >& /dev/tcp/...`).

#### v3: S5 inert install code, and cargo-dist downloads (2026-11-10, round 4)

Of the benign reports carried only by the install rules, 388 have two or three of them severe at
once (`install-hook` + `install-script-code`, `install-hook` + `install-script-changed`, ...),
so no single install rule's demotion can unreport them; an explanation lowers all three
([proposal](../proposals/precision-round4-E.md)). v3 adds:

- **S5 inert install code.** Every hook is `node` running a shipped file (`|| true` and
  `|| exit 0` allowed, nothing else chained; no inline `node -e` code), every install file is
  JavaScript or TypeScript and plain UTF-8, the package has code besides its install code, and
  the install code:
  - has only `filesystem` and `os-info` capabilities (`INERT`) and loads no package by name;
  - names neither the home directory (S3 v2's test), an agent directory, a system path
    (`SYSTEM_PATH`: `/etc/`, `/usr/`, `/tmp`, `tmpdir`, `/Library/`, `C:\`, ...) nor another
    installed package
    (`OTHER_PACKAGE`: `require.resolve(`, a path into `node_modules`): a hook that rewrites a
    dependency is tampering, which decides a verdict (decision 0015);
  - has no text that reaches the network or runs code, whatever the analysis saw
    (`RISKY_TEXT`: `fetch`, `import(`, `"node:https"`, `child_process`, `eval`, `spawn(`, ...):
    `@openrouter/sdk@1.5.59` passes the global `fetch` as a default parameter, and
    `@onescience/onecode`'s postinstall is UTF-16, which the parser reads as nothing;
  - deletes no file (`DELETES`: `unlink`, `rmdir`, `rm`, `rmSync`);
  - is readable (a guard every shape now has, below);
  - is not upstream Baileys's `engine-requirements.js` (`BAILEYS_ENGINE_CHECK`): the
    auto-following fork `kevinx-baileys@1.2.2` (unwanted) is reported only by that hook,
    because its follow code is in an unchanged file Stage 2 doesn't read again.

  Four guards come from `vm-day1`: the first S5 explained 8 DataDog malicious samples, all
  reported only by their install hook. A package that is nothing but its install code
  (`placeholder`) is a dependency-confusion placeholder or proof of concept (`wc@1.5.0`,
  `coldbox@6.7.71`, `pmcrypto@0.1.0`, `grab-service-worker@1.0.1` print a line;
  `cesium-native@0.56.0` and `dep-graph-gen@1.0.0` write an "RCE proof" to `/tmp`);
  `@uselagoon/ui-library@2.0.2` deletes the files of the directory it runs in under yarn; and
  `shoal-cli@0.4.5`, a follow-on, is reported only through its changed inline `node -e`
  banner.
- **S2 without a checksum for cargo-dist.** When every `artifactDownloadUrls` entry is the
  package's own GitHub releases (and the code is readable), S2 no longer needs a checksum
  check: cargo-dist's npm installer has none, and a checksum in the same release says nothing
  about its author.
- **Every shape: code a reader and the parser can see.** Install files must be plain UTF-8
  (`plain_text`), with no line over 1,000 characters and no code after 64+ spaces or tabs
  (`unreadable`). `hauntview@0.2.9` (malicious, 2026-11-09) hides an obfuscated C2 loader
  after 266 tabs on one 12,699-character line of its postinstall; the analysis sees only the
  legitimate `child_process` beside it. None of the 140 live versions S1-S3 explained before
  v3 is refused by this guard.

**Measured** with the real code (round 3's replay of the 3,716 verdicted live versions, against
round4-base): **68 fewer reports, all benign** (S5 51, S2 17); on `main` after agents A, C and
D (`829dd41`, whose `install-script-changed` v5 already lowers 16 of them) **52** (S5 36, S2
16); no malicious, unwanted or unverified version loses a report or even a finding; `hauntview@0.2.9` stays reported. `vm-day1`: all 344 malicious samples that
demoting the three install rules would unreport were re-run with `pipeline+4`: 0 lost. What
the guards cost, in benign reports kept: the Baileys exclusion 15 (without it S5 loses
`kevinx-baileys@1.2.2`, unwanted, and the unverified `hyrox@0.1.6` and
`@lunabotv6/luna-baileys@8.1.0`), `OTHER_PACKAGE` 34 (`node-pty` spawn-helper `chmod`,
`fastmcp` fixes), the text and hook guards 16 (`dotnet build`, `prisma generate`, shell
scripts, the two above), the `vm-day1` guards 8 and inline code 12.

### Inert install hooks: `npm.install-inert` (round 4)

`npm.install-inert` (INFO, weight 0; 2026-11-10,
[precision round 4, agent B](../proposals/precision-round4-B.md), B1) is an explanation for
Stage 4 that makes `npm.install-hook` LOW, weight 1, on a **new package** whose hooks provably
do nothing (`correlate.EXPLAINED`, stage version 16). It explains no other rule. It covers the
same population as agent E's S5 ("inert install code", `npm.install-explained` v3), carries all
of S5's guards, and adds what S5 doesn't take: inline `node -e` code, several `node` files
chained with `&&`/`||`/`;`, and echo-only hooks. All of these must hold:

- **New package.** Stage 2 reads every file of a new package but only the changed files of an
  update, so on an update the hook may be what still points at a payload in an unchanged file
  (`kevinx-baileys@1.2.2`, unwanted, follows channels from an unchanged
  `lib/Socket/newsletter.js`).
- **Hook lines that only run package code** (`hook_runs`, split with `shlex`): each segment is
  `node [harmless option] <file> [args]`, `node -e|-p <code>`, a constant `echo`, `true`, `:`
  or `exit N`. Not another program, a pipe or redirect, `$(` or a backtick anywhere, an
  environment assignment, `node -r`/`--import`. Every file is among what Stage 3 read.
- **Read in full and readable**: parsed without errors, nothing cut at 256 KiB, every relative
  path the code loads or names as a script read too (`_complete`), plain UTF-8 (UTF-16 parses
  as nothing), no line over 1,000 characters and no code padded off-screen (S5).
- **Reaches nothing**: no `network`, `process`, `env-all`, `dynamic-code`, `dynamic-require` or
  `native` use, no package loaded by name, and no text naming them either (`RISKY_TEXT`, S5's:
  `fetchImpl = fetch` is a use the analysis misses).
- **Touches nothing outside the package** (`outside`): no home-directory reference, agent
  directory, `node_modules`, `INIT_CWD`, `process.cwd()`, system path, `/tmp`/`tmpdir`,
  `%VAR%`, credential or shell file (`.npmrc`, `.ssh`, `.bashrc`, `.profile`, ...), no more `..`
  than the file is deep, no other package resolved by name (`require.resolve`, even for a
  `node-pty` chmod: the owner keeps patchers reported), no deleting.
- **Not upstream Baileys's `engine-requirements.js`** and not a **placeholder** (a package with
  no code but its install code), both S5's; no `binding.gyp` command.
- **Not a probe** (`PROBE_TEXT`: `poc`, `takeover`, `inject`, `confusion`, `red team`,
  `install works/fired`, ...), in an echo, in the install code or in its file name. Echo-only
  hooks are otherwise inert. Eight `vm-day1` malicious samples needed this:
  `echo "code injection possible by golu"` (`node-pdfmake@7.7.7`, `surpaonchainagent@7.7.7`,
  `contentful-app-entry-localization-matrix@7.7.7`), `echo "takeover poc"`
  (`openwhisk-probot-builder@1.0.0`), and inert PoC code (`wc@1.5.0`, `grab-service-worker@1.0.1`,
  `coldbox@6.7.71`, `pmcrypto@0.1.0`'s `poc.js`).

Measured on `main` `bd222bd` (S5 merged), all 3,716 verdicted live versions: 4 fewer reports,
all benign new packages (`@8-interactive/parse-server`, `@focus-at/zs3`: inline `node -e`/`-p`;
`@buoy-gg/bug-links`, `lilia-mcp`: echo-only), and it fires on no positive. On `vm-day1` it
fires on no malicious sample
(the pre-filter `ddfire.py` over all 2,319 malicious samples with an install hook: it fires on
2 Baileys forks before the engine guard, 0 after).

## Evaluation

`day1` (sha256 `d99626981ae6`), 2026-10-28:

| Predictor | A | A follow-on | B | B follow-on | Benign (weighted) |
|---|---|---|---|---|---|
| `stage3-rules` (Stage 3 alone, every release) | **80.6%** | 90.4% | 33.7% | 34.4% | **0.2%** |
| `pipeline` (Stages 1–2) | 86.0% | 38.0% | 66.0% | 22.5% | 0.7% |
| **`pipeline+3`** (Stages 1–3) | **89.7%** | 38.7% | 66.0% | 22.8% | **0.8%** |

- **Stage 3 is the most precise stage so far.** On its own it catches four in five malicious
  updates while flagging 0.2% of benign releases. Stage 1 rules alone: 80.1% at 0.6%.
- **End to end it adds 3.7 points on updates for 0.1 points of pass-through.** On new packages
  it adds nothing yet: what `install-script-code` catches there, Stage 1's `install-hook`
  (MEDIUM for new packages) already flags.
- **The follow-on figure for Stage 3 alone (90.4%) is optimistic**, for the same reason as
  Stage 2's: the malicious base is often gone, so the version is compared with nothing.

## Known limits

- `npm.install-script-loader` and `npm.install-script-exfil` are line patterns on script text,
  not a shell parser: a command split over variables (`c=curl; $c ... | sh`), built from a
  `case` table, or started more than `SCRIPT_DEPTH` scripts deep is missed, and a
  message printed by a function that does more than print is read as code. A download's host
  is the first URL on the line; one held in a variable is "no host" (MEDIUM). JavaScript
  install files are not read by either (see their section).
- The agent-configuration checks are text matching (`lang/agent_config.py`): what a copier
  actually copies is not followed, so every agent file in the package counts, and a hook
  script is matched by file name. A templated hook command (`node ${hookPath}`) is not
  plain even when the template is a shipped path. Instructions can be phrased in ways the
  patterns don't know; guard 3 catches the plain forms only.
- S3's scope test (v2, `agent_config.home_references`) is text matching over the whole
  install code, not data flow to the write: a `~/` in a comment or a message, or
  `os.homedir()` used for something else, keeps a project-scoped copier from S3
  (`@draig/lexis-two@1.5.0`: a comment; `opencode-blocker-diverter@0.3.1`: compares
  `INIT_CWD` with OpenCode's global directory). The reverse miss needs code we can't read:
  a home path built from a string table, a computed `process.env[name]`, or a copy done by a
  package loaded by name, which is why such install code is not S3 either. A copier that
  writes into the project on a local install and into the home directory on a global one
  (`npm_config_global`) counts as user-wide.
- Tree-sitter gives syntax, not data flow. `const m = "child_process"; require(m)` is a
  `dynamic-require`, not `process`, and a capability reached through a dependency is invisible.
- The Function constructor through `constructor` (extractor v5) follows one variable only when
  it is declared (`const`, `let`, `var`) in the same function as its use: a `c` declared in an
  outer function, or assigned (`c = x.constructor`), or passed through a parameter, is not
  followed. Minified code reuses short names in every scope, so the wider rule fired on
  unrelated reads. `Function.prototype.constructor` and `Reflect.construct(Function, ...)` are
  not recognised.
- `npm.undeclared-package` reads constant specifiers only: `require(name)` is
  `dynamic-require`, and a package loaded through `createRequire`, `module.require` or a
  bundler's runtime is not seen. It does not know whether a name exists on npm (Stage 4's
  `npm.undeclared.missing` asks). Since v2 it reads only what the entry points load: a
  payload required from a `bin` script, a postinstall-only file or a file reached through a
  computed path is missed, and a load inside a bundler's module function (webpack's
  `__webpack_modules__`) counts as deferred.
- "Runs at load" (extractor v8, `npm.load-fingerprint`) is decided within one file and by
  name: a function called from another file (`index.js` calling `state.initialize()`, as
  `@atedone/workspace-context` does), through an alias (`const run = main`), as a method, or
  an identity read through a computed name (`os["host" + "name"]()`) is not seen as running,
  and a function handed to any call counts as run even when it is only an event handler.
  Obfuscated payloads that build `hostname` from a string table (the Tavern stealer family)
  are not seen either; `static.obfuscated` covers those. Only identity reads and (since v9)
  commands are followed; file writes at load were measured and not built.
- Commands at load (extractor v9, `npm.publish-at-load`) are the first argument of a known
  runner (`exec`, `execSync`, `execFile`, `spawn`, `execa`, ... by name, whatever the
  receiver) or of a same-file function that passes its first parameter to one, one level
  deep. A runner reached through an alias (`const run = cp.execSync; run(x)`), a minified
  bundle's renamed helper (Shai-Hulud's `bundle.js`), a command built at run time from
  values the parse can't read, `libnpmpublish` or a registry `PUT` are not seen (Shai-Hulud
  is reported by the install rules today). A name bound twice in a file reads the first
  binding.
- Install-entry detection reads command lines. `node -e "<code>"` and shell scripts are not
  parsed.
- **tree-sitter 0.26.0 is excluded** (`pyproject.toml`). Using nodes from query matches
  corrupted the heap and crashed the process (segfault in GC) on a real TypeScript file;
  0.25.2 is fine. Found while measuring cost on a live run, and reproduced with a minimal
  script on one 14 KB file.
- Parsers are per thread: a shared tree-sitter `Parser` crashed with a bus error under
  threads.
