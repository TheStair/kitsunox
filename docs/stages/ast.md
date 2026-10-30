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
  `setup.js`; `ecosystems/npm/install.py`).
- **Delta:** each version is compared with its `change.previous` (the base, or an earlier
  version in the batch). A capability is attributed to the version that gained it, even if a
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
| `code.capability-gained` | an update's code gains capabilities. MEDIUM if it gains `env-all` or `dynamic-code`, or `network` together with `process`, `env-all` or `dynamic-code` | LOW / MEDIUM | per capability ≤ 0.5% / n/a | env-all 70.9%, dynamic-code 57.3%, network 57.6% / n/a |
| `npm.install-script-code` | a file an install hook runs uses `network`, `process`, `env-all`, `dynamic-code` or `dynamic-require`. On updates, only capabilities new to the install code count | MEDIUM | ≤ 0.9% / 0.2% | 70.2% / 33.7% |

New packages get no `capability-gained` finding: with no previous version everything is
"gained", and 34% of benign new packages would fire. They are covered by what their install
scripts run.

`npm.install-script-code` also covers a case Stage 1 cannot see: the command stays
`node setup.js` and only `setup.js` changes.

**`npm.install-script-changed`** (MEDIUM, weight 3; 2026-10-30) compares the files the install
hooks name with the previous version's, byte for byte, and puts the changed lines in the
evidence as a unified diff (one line of context, 40 lines and 200 characters a line at most;
reports render it as a `diff` block). It fires when such a file changed or is newly run. A file
whose only change is its own version string (`workerd`'s `install.js` downloads
`${pkg}@<version>`) is unchanged. A file over 2,000 lines is reported changed without a diff:
`difflib` is quadratic on lines that repeat without being junked (20,000 lines cycling 150
values took 45 s). Each file is kept up to 256 KiB for the comparison. Stage 1 forwards every
update with an install hook so this rule sees them. On the first VM day it fired on 47 of the
601 hook updates whose two tarballs were captured (7.8%), and not on `@pulumi/*`, whose
`install-pulumi-plugin.js` didn't change.

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
