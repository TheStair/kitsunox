# Stage 2: Static diff heuristics

> **Status:** in progress (2026-10-27). Design below; measured results are added as each part
> lands.

## Purpose

Look at the code that a release actually adds, cheaply: regular expressions and simple
statistics over **new file contents only**. It catches what metadata can't, e.g. a payload that
runs when the package is imported (42% of first-release DataDog shape-B samples have no
metadata signal). Parsing JS properly is Stage 3.

## Input and output

- **Input:** `PackageBatch` from Stage 1 (every version of one package in a run, plus the base).
- **Fetch:** each version's tarball and the base's tarball, via `Ecosystem.fetch_artifact`
  (integrity-verified, extracted in memory by `extract_tar_gz`, never executed).
- **New contents:** every file content (by SHA-256) that is in some version of the batch but
  not in the base. Each is analysed once, and its findings are attributed to the first version
  that contained it. A version that adds malicious code and is reverted within the burst is
  still analysed.
- **Output:** the batch's candidates with Stage 2 findings and a `StageDecision`. A batch is
  forwarded if any finding is MEDIUM or above.

## Content cache

Rules only see a file's content, so their result is a pure function of
**(content SHA-256, rule ids and versions)**. Results are cached on disk under
`data/cache/static/<rules fingerprint>/`. A file already analysed in any earlier version or
package costs a hash lookup. Changing any rule's version changes the fingerprint, so nothing
stale is reused. Findings are stored without the path, and the path is added when they are
attributed.

## Rules (first set, ecosystem-agnostic, `rules/static.py`)

| Rule | Looks for | Starting severity |
|---|---|---|
| `static.exfil-endpoint` | Discord/Slack webhooks, Telegram bot API, pastebins, request bins, OAST and tunnelling hosts | HIGH |
| `static.sensitive-path` | `.npmrc`, `.ssh/id_*`, `.aws/credentials`, `.git-credentials`, shell history, browser credential stores, crypto wallets | MEDIUM |
| `static.env-harvest` | the whole of `process.env` serialised or enumerated | MEDIUM |
| `static.hardcoded-ip` | URLs with a public IPv4 literal | MEDIUM |
| `static.encoded-blob` | base64 or hex runs ≥ 200 characters (excluding image and font data URIs) | MEDIUM |
| `static.dynamic-code` | `eval(`, `new Function(`, `vm.runIn*` (excluding the common `Function("return this")` polyfill) | MEDIUM |
| `static.obfuscated` | many `_0x`-style identifiers (javascript-obfuscator output) | MEDIUM |
| `static.npm-publish` | npm token use or `npm publish` from code (worm behaviour) | MEDIUM |
| `static.process-exec` | `child_process` | LOW |
| `static.network` | `http`, `https`, `net`, `dns`, `dgram` modules | LOW |

These are starting points. Every rule is measured on benign new contents versus malicious ones,
and noisy rules are downgraded or removed, as in Stage 1.

## Evaluation

- **Malicious:** the DataDog samples. Package files come from the encrypted zip, decrypted in
  memory only. The base for shape A is the previous version's tarball from npm (benign
  versions usually still exist). If it is gone, all files count as new, and those samples are
  counted.
- **Benign:** the dataset's benign samples; the new and base tarballs come from npm and are
  cached immutably under `data/eval/tarballs/`.
- **Predictors:** `stage2-rules` (Stage 2 alone) and `stage1+2-rules` (either stage flags).
  Recall on follow-on releases stays in its own cell.

## Tarball retention

Tarballs fetched by the pipeline go into `data/blobs` and follow
[0006](../decisions/0006-scheduled-collection-and-retention.md): 7 days, and indefinitely for
packages named in OSV records (their run's snapshot pins them). Evaluation tarballs live in
their own store and are not pruned.

## Safety

Contents are decoded as text with replacement characters and only ever matched against regular
expressions. Evidence snippets are truncated and are untrusted data for any renderer. Files over
2 MB are skipped and recorded, since minified bundles that large are Stage 3's job.
