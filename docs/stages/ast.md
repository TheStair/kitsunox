# Stage 3: Capability analysis (AST)

> **Status:** implemented 2026-10-28 (`lang/javascript.py`, `stages/ast.py`, rules in
> `rules/capabilities.py` and `ecosystems/npm/rules/install_code.py`). It runs in `collect`
> after Stage 2. Evaluation numbers are below.

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
| `npm.install-script-obfuscated` (2026-10-31) | a file an install hook runs (as `install-script-code` reads them, first 256 KiB each) has 20+ javascript-obfuscator `_0x` identifiers (`static.obfuscated`'s test). On updates, only an obfuscated file that is new to the install code or changed | HIGH | `vm-day1`: 0 of 1,500 | `vm-day1`: 72 of 2,539 / 24 of 905 |

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

**`npm.install-script-obfuscated`** (HIGH, weight 4; 2026-10-31, at the owner's request) flags
install code nobody can review by reading it: what it does at install is a question only Stage 5
can answer, and HIGH puts it in front of Stage 5's per-run cap of 30 and of the queue. Five
packages reviewed inconclusive for this reason (`sppurt`, `motionchart-cli`, `sino-bc-cli`,
`whybug`, `calculatorscool346`) scored 3-11 without it. On `vm-day1` it changes no reporting
decision (every malicious sample it fires on was reported) and fires on no benign sample.

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
