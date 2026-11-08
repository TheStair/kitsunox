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
| `dynamic-code` | `eval()`, `Function()`, `new Function`, `vm`, `global["eval"]` |
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
- Install-entry detection reads command lines. `node -e "<code>"` and shell scripts are not
  parsed.
- **tree-sitter 0.26.0 is excluded** (`pyproject.toml`). Using nodes from query matches
  corrupted the heap and crashed the process (segfault in GC) on a real TypeScript file;
  0.25.2 is fine. Found while measuring cost on a live run, and reproduced with a minimal
  script on one 14 KB file.
- Parsers are per thread: a shared tree-sitter `Parser` crashed with a bus error under
  threads.
