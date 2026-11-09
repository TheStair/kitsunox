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
| `npm.install-script-code` | a file an install hook runs uses `network`, `process`, `env-all`, `dynamic-code` or `dynamic-require`. On updates, only capabilities new to the install code count | MEDIUM | ≤ 0.9% / 0.2% | 70.2% / 33.7% |
| `npm.install-build-tool` | every install hook (`preinstall`, `install`, `postinstall`, from the registry manifest) is one of a fixed list of build-tool command lines (`BUILD_TOOL_HOOKS`: `node-gyp-build`, `node-gyp rebuild`, `prebuild-install`, `node-pre-gyp install --fallback-to-build`, `husky`, `npx only-allow pnpm`, `patch-package`, ...), and `binding.gyp` runs no command. An explanation for Stage 4, which then makes `npm.install-hook` LOW (`correlate.EXPLAINED`) | INFO | live (with Stage 4): 7 of the 2,208 reports go where the tarball was captured, 12 if the 5 without one (`husky`, `only-allow`, `patch-package` hooks) have no `binding.gyp`; all benign | `vm-day1`: 0 of the 433 reported only through install rules has such hooks; 4 other malicious samples do, decided as before |
| `npm.install-explained` | the install code is a platform-binary launcher (S1), an own-release download with a checksum (S2), or an agent-skill copier whose copied configuration passes the three guards (S3); [below](#explained-install-s1-s3-and-agent-configuration). An explanation for Stage 4, which makes the three install rules LOW | INFO | live (with Stage 4, 3,244 reported verdicts): 85 fewer reports (S1 36, S2 34, S3 15; 70 packages), all benign, 0 positives | `vm-day1`: 0 of the 433 malicious samples reported only through install rules |
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
| S2 own-release download | network; the `repository` is on GitHub; every URL literal (after substituting `const` strings) is that repository's releases (`github.com/<o>/<r>/releases`, `api.github.com/repos/<o>/<r>/releases`), GitHub's release asset hosts, the npm registry or a page link, and one is its own (or cargo-dist's `artifactDownloadUrls` all are); a checksum check (`createHash("sha256"`, `SHA256SUMS`, `checksums.txt`, `.sha256`, `verifyChecksum`); no URL whose host or owner is a variable |
| S3 agent-skill copier | no network, no process; the code names an agent directory (`.claude`, `.agents`, `.cursor`, `.codex`, `.gemini`, `.windsurf`, `.opencode`, `SKILL.md`, `AGENTS.md`, `.mcp.json`), and the agent files it may copy pass the three guards below |
| every shape | an install hook that is not shell (`curl`, `wget`, `sh`, `bash`, `python`, `./x`, `\| sh`, `$(...)`, backticks); no `binding.gyp` command; no `env-all`, `dynamic-code` or `dynamic-require` in the install code; for an update, no capability the install code didn't have before |

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

- The agent-configuration checks are text matching (`lang/agent_config.py`): what a copier
  actually copies is not followed, so every agent file in the package counts, and a hook
  script is matched by file name. A templated hook command (`node ${hookPath}`) is not
  plain even when the template is a shipped path. Instructions can be phrased in ways the
  patterns don't know; guard 3 catches the plain forms only.
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
