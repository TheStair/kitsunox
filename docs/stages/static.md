# Stage 2: Static diff heuristics

> **Status:** running in the pipeline (2026-10-27). `kitsunox collect` runs it every hour, and
> `kitsunox static <run_id>` runs it on a triaged run. Routing: [0008](../decisions/0008-stage2-routing-and-tarball-capture.md).

## Purpose

Look at the code that a release actually adds, cheaply: regular expressions and simple
statistics over **new file contents only**. It catches what metadata can't, e.g. a payload that
runs when the package is imported (42% of first-release DataDog shape-B samples have no
metadata signal). Parsing JS properly is Stage 3.

## Usage

```sh
uv run kitsunox triage <run_id>    # Stage 1: writes batches.jsonl
uv run kitsunox static <run_id>    # Stage 2: fetches tarballs, writes static.jsonl + static-snapshot.json
uv run kitsunox eval run <dataset> --predictor pipeline   # end to end: what the pipeline flags
```

## Input and output

- **Input:** `PackageBatch` from Stage 1 (every version of one package in a run, plus the base).
  Stage 1 routes a package here if it is flagged, watched, new, or its declared unpacked size
  grew by 64 KiB or more (see [Routing](#routing-what-stage-2-reads)).
- **Fetch:** each version's tarball and the base's tarball, via `Ecosystem.fetch_artifact`
  (integrity-verified, extracted in memory by `extract_tar_gz`, never executed). Versions that
  declare more than 16 MB unpacked (`MAX_ARTIFACT_BYTES`) are not fetched. Tarballs go into
  `data/blobs` (immutable, so each is downloaded once) and are recorded in the run's
  `static-snapshot.json`.
- **Unavailable files** (too large, fetch or integrity failure, no artifact): the version gets
  no Stage 2 findings, and its decision says why (`files unavailable: ...`). An unavailable base
  counts as empty, so every file is new; the decision notes it (`base unavailable: ...`).
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
| `static.exfil-endpoint` (v2) | Discord/Slack webhooks with an id, Telegram bot API, pastebins, request bins, OAST and tunnelling hosts | HIGH |
| `static.sensitive-path` | `.npmrc`, `.ssh/id_*`, `.aws/credentials`, `.git-credentials`, shell history, browser credential stores, crypto wallets | LOW (v2; was MEDIUM) |
| `static.env-harvest` | the whole of `process.env` serialised or enumerated | LOW (v2; was MEDIUM) |
| `static.hardcoded-ip` | URLs with a public IPv4 literal | MEDIUM |
| `static.encoded-blob` | base64 or hex runs ≥ 200 characters (excluding image and font data URIs) | LOW (v2; was MEDIUM) |
| `static.dynamic-code` | `eval(`, `new Function(`, `vm.runIn*` (excluding the common `Function("return this")` polyfill) | LOW (v2; was MEDIUM) |
| `static.obfuscated` | many `_0x`-style identifiers (javascript-obfuscator output) | MEDIUM |
| `static.npm-publish` | npm token use or `npm publish` from code (worm behaviour) | LOW (v2; was MEDIUM) |
| `static.process-exec` | `child_process` | LOW |
| `static.network` | `http`, `https`, `net`, `dns`, `dgram` modules | LOW |

### Metadata vs. tarball (npm, `ecosystems/npm/rules/artifact.py`)

These rules see a version's registry metadata and its whole extracted tarball (the
`ArtifactRule` contract in `core/rules.py`). The npm registry doesn't check that the two agree
("manifest confusion"), and Stage 1 only reads the metadata:

| Rule | Looks for | Severity |
|---|---|---|
| `npm.artifact.hidden-install-script` | an install hook in the tarball's `package.json` that the metadata lacks or shows differently (`npm install` runs the tarball's) | HIGH |
| `npm.artifact.size-mismatch` | files total more than `dist.unpackedSize` by over 1 KiB and 1% (understated only: overstating gains an attacker nothing) | MEDIUM |

On 1,069 live versions (run `20261028T004851Z-npm`), declared and real size matched exactly
every time, and no tarball hid an install hook. The 9 script differences were npm's own
normalisation (a stripped `node_modules/.bin/` prefix; `install: node-gyp rebuild` added to
the metadata for `binding.gyp` packages; a default `start`), which the rule ignores. The file
count differed in 17 versions with identical sizes, so it is not used.

On `day1` (all samples, files decrypted in memory): neither rule fired on any of 1,468 benign
samples, and `hidden-install-script` fired on no malicious one either. A two-sided size check
fired on 236 malicious samples, mostly shape-A follow-ons, but every one was *overstated*
(e.g. `@tushar-br/desktop`: 47 MB declared, 13 KB in the zip). That is files missing from the
dataset's zips, not attacker behaviour, and it is why only understatement is flagged. Neither
rule can be validated on DataDog data: they guard against evasions the dataset doesn't contain.
Their cost, measured on benign traffic, is zero.

**Limit:** these rules only see what Stage 2 downloads. An update that understates its growth
below 64 KiB is never routed here, so the size check catches a lie only on routed versions
(watched, new, flagged, or still grown). Closing that would need a size signal that doesn't
come from the publisher, e.g. the tarball's `Content-Length`. That is an open item.

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

### Routing: what Stage 2 reads

`stage1+2-rules` above assumes Stage 2 reads every release, which is about 114k tarballs a
day. Behind the original Stage 1 gate (rules or watched), almost everything only Stage 2
catches was dropped first. The user chose a hybrid. The details came from simulating routings
on the saved per-sample results, and are recorded in
[0008](../decisions/0008-stage2-routing-and-tarball-capture.md):

- every **new package** (cheap: 4k a day, 0.2 GB);
- every **update whose declared unpacked size grew by ≥ 64 KiB** (71% of malicious updates,
  8.3% of benign). Routing *small* updates instead added nothing: payloads make packages bigger;
- watched and flagged packages, as before;
- **no version over 16 MB declared** (9% of releases, 86% of bytes, mostly binaries).

End to end (`pipeline` predictor: flagged by Stage 1 rules, or routed to Stage 2 and flagged
there), measured on `day1`:

| | A | A follow-on | B | B follow-on | Benign (weighted) |
|---|---|---|---|---|---|
| Stage 1 rules alone | 80.1% | 2.7% | 58.2% | 21.7% | 0.6% |
| Old gate (simulated) | 83.5% | 18.9% | 58.2% | 21.8% | 1.0% |
| **`pipeline` (hybrid)** | **86.0%** | 38.0% | **66.0%** | 22.5% | **0.9%** |
| **`pipeline`, `exfil-endpoint` v2** | **86.0%** | 38.0% | **66.0%** | 22.5% | **0.7%** |
| Upper bound: Stage 2 reads everything | 91.4% | 85.4% | 66.1% | 55.6% | 1.5% |

The simulation predicted the `pipeline` numbers exactly. Stage 1's routing passes 25.8% of
releases to Stage 2 (weighted; `stage1` predictor), about 24k versions a day after the cap.

### Live trial

Run `20261028T004851Z-npm` (3,687 changes, about 80 minutes of publishes):

- Stage 1 forwarded 1,124 changes: 596 watched, 259 new packages, 256 grown, 13 flagged.
- These formed 749 batches (1,243 versions).
- Stage 2 took 2 min 20 s and downloaded 794 MB (about 14 GB a day).
- 173 versions were over the size cap, and 1 tarball was already gone (404).

Six versions were flagged, all by `exfil-endpoint` or `obfuscated`, and all looked benign on
inspection. Two were real false-positive patterns, which v2 of `exfil-endpoint` fixes:

- **A docs placeholder:** `hooks.slack.com/services/...` in `@bike4mind/cli`. Webhook URLs now
  need an id.
- **An identifier match:** `requestbin` inside `OscoreRequestBinding`. It now needs a dot.

The rest were:
- a Telegram bot client (`woml-cli`);
- a tunnel-host allow-list (`agentiqa`);
- an obfuscated asset bundle (`interboard-assets`).

These are the expected cost of HIGH-recall rules; Stage 3 and Stage 4 scoring are where they
should be separated.

## Tarball retention

Tarballs fetched by the pipeline go into `data/blobs` and follow
[0006](../decisions/0006-scheduled-collection-and-retention.md): 7 days, and indefinitely for
packages named in OSV records (pruning pins them from the run's `static-snapshot.json`). The
immutable index is a fetch cache only: an entry whose blob no run references is deleted with
the blob. Evaluation tarballs live in their own store and are not pruned.

## Known limits

- `dist.unpackedSize` is declared by the publisher, so an attacker can understate growth to
  skip routing, or overstate size to skip the download. A rule comparing declared and real size
  after download is a candidate.
- Updates over 16 MB are seen by Stage 1 only.
- Regular expressions don't understand code: a URL in a comment and one in a `fetch` look the
  same. That is Stage 3's job.

## Safety

Contents are decoded as text with replacement characters and only ever matched against regular
expressions. Evidence snippets are truncated and are untrusted data for any renderer. Files over
16 MB are skipped (`MAX_FILE_BYTES`), and so are files with a NUL byte in their first 8 KB
(binaries).
