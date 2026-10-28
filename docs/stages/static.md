# Stage 2: Static diff heuristics

> **Status:** engine, rules and evaluation done (2026-10-27). Not yet wired into the pipeline:
> there is no `kitsunox static <run_id>` command and `collect` does not capture tarballs. How
> much of the stream Stage 2 should see is an open decision (see [Results](#results)).

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

| Rule | Looks for | Severity |
|---|---|---|
| `static.exfil-endpoint` | Discord/Slack webhooks, Telegram bot API, pastebins, request bins, OAST and tunnelling hosts | HIGH |
| `static.sensitive-path` | `.npmrc`, `.ssh/id_*`, `.aws/credentials`, `.git-credentials`, shell history, browser credential stores, crypto wallets | LOW (v2; was MEDIUM) |
| `static.env-harvest` | the whole of `process.env` serialised or enumerated | LOW (v2; was MEDIUM) |
| `static.hardcoded-ip` | URLs with a public IPv4 literal | MEDIUM |
| `static.encoded-blob` | base64 or hex runs ≥ 200 characters (excluding image and font data URIs) | LOW (v2; was MEDIUM) |
| `static.dynamic-code` | `eval(`, `new Function(`, `vm.runIn*` (excluding the common `Function("return this")` polyfill) | LOW (v2; was MEDIUM) |
| `static.obfuscated` | many `_0x`-style identifiers (javascript-obfuscator output) | MEDIUM |
| `static.npm-publish` | npm token use or `npm publish` from code (worm behaviour) | LOW (v2; was MEDIUM) |
| `static.process-exec` | `child_process` | LOW |
| `static.network` | `http`, `https`, `net`, `dns`, `dgram` modules | LOW |

Five rules started at MEDIUM and were downgraded to LOW after the first evaluation, because
on their own they fire about as often on benign releases as on malicious ones (numbers in the
comment on each rule in `rules/static.py`). LOW findings are still recorded as evidence and
are inputs for combination scoring in Stage 4; they just don't forward on their own.

## Evaluation

- **Malicious:** the DataDog samples. Package files come from the encrypted zip, decrypted in
  memory only. The base for shape A is the previous version's tarball from npm (benign
  versions usually still exist). If it is gone, all files count as new, and those samples are
  counted.
- **Benign:** the dataset's benign samples; the new and base tarballs come from npm and are
  cached immutably under `data/eval/tarballs/`.
- **Predictors:** `stage2-rules` (Stage 2 alone) and `stage1+2-rules` (either stage flags).
  Recall on follow-on releases stays in its own cell.

## Results

Dataset `day1` (sha256 `d99626981ae6`): 1,500 benign samples from our runs, 3,444 DataDog
samples. A sample is forwarded if any new file content has a finding at MEDIUM or above.

| Predictor | A | A follow-on | B | B follow-on | Benign pass-through (weighted) |
|---|---|---|---|---|---|
| `stage2-rules`, first set (2 MB file cap) | 19.5% | 31.0% | 74.4% | 67.7% | 11.5% |
| `stage2-rules`, tuned (16 MB cap, five rules → LOW) | **71.5%** | 84.0% | **49.9%** | 50.7% | **1.0%** |
| `stage1-rules` (for reference) | 80.1% | 2.7% | 58.2% | 21.7% | 0.6% |
| `stage1+2-rules`: either stage, tuned | **91.4%** | 85.4% | **66.1%** | 55.6% | **1.5%** |

What changed between the first and the tuned run:

- **The 2 MB file cap hid most shape-A payloads.** 698 of 965 shape-A samples had a new file
  over 2 MB. In many attacks the payload is appended to the package's existing (large, bundled)
  main file. At 16 MB, A recall went from 19.5% to 71.5%. Shai-Hulud's payload is about 10 MB.
- **Five rules were too noisy at MEDIUM.** `npm-publish` alone fired on 6.4% / 8.0% of benign
  A / B releases (release tooling mentions `NPM_TOKEN`). Downgrading the five took benign
  pass-through from 11.5% to 1.0%, and cost B recall (74.4% → 49.9%): many first-release
  payloads show only those signals.
- **Stage 2 catches many follow-ons that Stage 1 can't, mostly by accident.** A follow-on's
  metadata often matches the previous (also malicious) release, so Stage 1 sees nothing
  (2.7%). Stage 2 gets 84.0%, but mainly because the malicious base has been taken down, so
  every file counts as new. In live collection the base would still be there, and an
  unchanged payload would not be new content. Treat the follow-on numbers as optimistic.

Data gaps, counted per sample: the base tarball was gone from npm for 1,542 samples (all
files counted as new; mostly follow-ons, whose malicious base was taken down), and the
sample's own files were unavailable for 32 (not forwarded).

### Caveat: the union row assumes Stage 2 sees everything

`stage1+2-rules` flags a sample if either stage's rules fire, so Stage 2 has to analyse every
release, not only what Stage 1 forwards. With Stage 2 behind the Stage 1 gate (rules or
watched), almost all malicious samples that only Stage 2 catches are dropped first: they are
unwatched and have no metadata signal. End-to-end recall would then stay near Stage 1's.

Running Stage 2 on every release means fetching every tarball: about 109k releases a day plus
bases. Evaluation tarballs have a median size of 62 KB but a mean of 2.1 MB (p90 2.8 MB), so a
naive estimate is hundreds of GB a day. A size cap from the packument (`dist.unpackedSize`) or
running Stage 2 on all new packages (shape B, ~4k a day, no base needed) but only on gated
updates are cheaper options. This is an open decision.

## Tarball retention

Tarballs fetched by the pipeline go into `data/blobs` and follow
[0006](../decisions/0006-scheduled-collection-and-retention.md): 7 days, and indefinitely for
packages named in OSV records (their run's snapshot pins them). Evaluation tarballs live in
their own store and are not pruned.

## Safety

Contents are decoded as text with replacement characters and only ever matched against regular
expressions. Evidence snippets are truncated and are untrusted data for any renderer. Files over
16 MB are skipped (`MAX_FILE_BYTES`), and so are files with a NUL byte in their first 8 KB
(binaries).
