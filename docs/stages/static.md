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
- **Not new, or never run** (2026-10-30, `static.content_matches`): a changed file is matched
  whole, so its old matches would fire again every release (a Telegram bot's
  `api.telegram.org/bot`, an obfuscated commercial build, in every version). A match the base
  version's file at the same path already had (same rule, same explanation with numbers
  aside) is LOW, weight 1, and says "Also in the previous version's file". A bundler's
  content-hashed chunk gets a new name whenever its content changes, so it is compared with
  the base's chunks of the same name without the hash (`dist/registry-BX6j2lnF.mjs` with
  `dist/registry-CFQBxtE2.mjs`; `static.BaseFiles`; every base chunk of that name since 2026-10-31, worked out once per name: esbuild calls all its chunks `chunk-<HASH>.js`, and the first four rarely held the match, so `@wirecat/*` CLIs' bundled ngrok region table was HIGH in each release): a doc comment naming
  `*.trycloudflare.com` in `@camstack/*` addons was HIGH again on every release. Vite's
  8-character hash may have no digit and may contain `-` or `_` (`settings-panel-Bkki_GMk.js`,
  `-CnQC9-zc.js`); since 2026-10-31 such a suffix counts as a hash when it doesn't read as a
  word (a digit, `_` or `-`, or a capital past the first letter). Before, `glimmervoid`'s
  settings panel was a "new" file, HIGH, in about 25 queued releases. A file with no
  counterpart at all (a chunk renamed in a way `unhashed` can't see, such as Bun's
  `chunk-eevqxagd.js`; code moved to a new path or a versioned directory) is compared, since
  2026-10-31, with what any of the base's code files matched (`BaseFiles.anywhere`; docs,
  types, source maps and tests don't count) and says "Also in another of the previous
  version's files". A file with a counterpart is still compared with that counterpart only.
  On `vm-day1` this cost one malicious sample (`esoftplay@0.0.248`, which moved its Telegram
  code into new files; 8 other releases of the family are still reported); in the live queue
  about 27 of 46 exfil-endpoint reports with a base had the literal in another base file. A match
  only in a file that never runs (`NON_EXECUTING`: README and other docs, `.md`, `.d.ts`,
  source maps, `docs/`, `examples/`, `test/`) is LOW as well; at first only for
  `exfil-endpoint`, for every rule since the second pass (no malicious `vm-day1` sample lost;
  `@atairo/qixi` was MEDIUM for an IP in a bundled dependency's README). Findings
  are kept, so a reviewer still sees them and they still add to the score. On `vm-day1` it
  cost 8 malicious samples, all follow-on releases of a series whose first malicious release is
  still reported (`esoftplay@0.0.142-m`, then 0.0.152 and others with the same Telegram
  exfiltration), for 3 benign.
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
| `static.exfil-endpoint` (v3) | Discord webhooks with a 17-20-digit id, Slack webhooks with `T…/B…` ids (not placeholders such as `123/abc`, `xxx/xxx` or `T00000000`), Telegram bot API, pastebins, request bins, OAST and tunnelling hosts | HIGH |
| `static.webhook-placeholder` | Discord/Slack webhook URLs whose id is a placeholder (`/services/xxx/xxx`, `/webhooks/123/abc`, `T00000000`): what v2 matched and v3 doesn't call an endpoint | MEDIUM (weight 3) |
| `static.encoded-url` | a whole string literal that is an `http(s)://` or `ws(s)://` URL in base64 (standard or URL-safe) or hex, e.g. `"aHR0cHM6Ly9..."`; the finding shows the decoded URL | MEDIUM (weight 3) |
| `static.function-require` | a function compiled from a string with `require` as its first parameter: `new Function("require", body)`, also via `Function.constructor` | MEDIUM (weight 3) |
| `static.sensitive-path` | `.npmrc`, `.ssh/id_*`, `.aws/credentials`, `.git-credentials`, shell history, browser credential stores, crypto wallets | LOW (v2; was MEDIUM) |
| `static.env-harvest` | the whole of `process.env` serialised or enumerated | LOW (v2; was MEDIUM) |
| `static.hardcoded-ip` (v2) | URLs with a public IPv4 literal, other than well-known public DNS resolvers (`1.1.1.1`, `8.8.8.8`, ...: connectivity checks; 29 of 56 live MEDIUM findings, none of 159 malicious) | MEDIUM |
| `static.encoded-blob` | base64 or hex runs ≥ 200 characters (excluding image and font data URIs) | LOW (v2; was MEDIUM) |
| `static.dynamic-code` | `eval(`, `new Function(`, `vm.runIn*` (excluding the common `Function("return this")` polyfill) | LOW (v2; was MEDIUM) |
| `static.obfuscated` | many `_0x`-style identifiers (javascript-obfuscator output) | MEDIUM |
| `static.npm-publish` | npm token use or `npm publish` from code (worm behaviour) | LOW (v2; was MEDIUM) |
| `static.process-exec` | `child_process` | LOW |
| `static.network` | `http`, `https`, `net`, `dns`, `dgram` modules | LOW |

### Known-family signatures (`static.known-signature`, `rules/signatures.py`, 2026-11-01)

A repost of malware we have already confirmed should be known on arrival, not rediscovered: the
tavern LLM-credential stealer came back three times under new names and scored 5-6 each time,
from `static.obfuscated` alone. Each signature is taken from our own malicious verdicts (never
from a takedown or an outside list, decision 0016) and names them: a family's endpoints,
accounts and wallets, or strings its payload always carries. It fires (HIGH, weight 6) when all
of its patterns match the file's text plus the strings its obfuscation hides
(`decoded_strings`: one-byte-XOR base64 string tables, javascript-obfuscator's base64 arrays in
files with its `_0x` identifiers, and plain base64 literals of 16+ characters). Unlike other
Stage 2 matches it is never demoted as "also in the previous version" (`static.ALWAYS_NEW`); a
match only in documentation, types or tests is still demoted. `SIGNATURES_VERSION` is the
rule's version, so changing the set changes the rules fingerprint (and Stage 2's cache).

| Id | Family | Matches on | Taken from |
|---|---|---|---|
| KX-0001 | tavern LLM-credential stealer | `/create-foundation-model-agreement`, `AWSInvoicingService.ListInvoiceSummaries` and `Action=GetCallerIdentity&...` together (decoded) | `tavern-ai-sdk`, `char-ai-sdk`, `character-ai-sdk`, `persona-ai-sdk` |
| KX-0002 | the same family's TRON wallets | two addresses | the same |
| KX-0003 | `claims-*` install-time recon | `GamerD11/ping_test` | `claims-acct-unlock`, `claims-ac1` |
| KX-0004 | depconf probe (user, host, directory) | `38.242.235.206` | `internal-renderers`, `ms-client-portal`, `pandafortunerush` |
| KX-0005 | notsemz probes | their webhook.site token, `130.162.231.177` | `@pcb-dp/qa-commons`, `ssite-mock-server` |
| KX-0006 | probe authors' out-of-band beacon ids | an interactsh and a Burp Collaborator id | `@mobile-platform/magnetic-components`, `dependencykfeg` |
| KX-0007 | `calculator-preinstall-hook-demo`'s Discord webhook | its webhook id | `calculator-preinstall-hook-demo@1.1.2` |
| KX-0008 | Baileys forks following hard-coded channels | a `...@newsletter` id, `FOLLOW` and `newsletterWMexQuery` in one file | `@chatbridgeworld/baileys`, `kevinx-baileys`, `@bil-rgb/baileys` |
| KX-0009 | Baileys forks fetching their channel list | `noxXza/data`, `push-saurus.yorunime.sbs` | `luna-baileys`, `sauruspro-bail` |

Measured on 2026-11-01 over every captured tarball with a verdict and every 18th other captured
tarball (6,004): each family's captured malicious versions match (KX-0001 and KX-0002: 4 of 4,
KX-0003: 4, KX-0004: 6, KX-0005 and KX-0006: 2 each, KX-0008: 1; the other Baileys forks
weren't captured), no benign (814) or inconclusive (26) version matches except
`calculator-preinstall-hook-demo@1.1.1`, the benign predecessor that posts fixed text to the same
webhook, and among the others only `dependencykfeg@25.1.9`, a release of the `weqwe` probe family
the pipeline never reported. No file took over 5 s. The upstream Baileys API
(`newsletterFollow` calling `newsletterWMexQuery(jid, FOLLOW)`) doesn't match KX-0008: it has no
channel id of its own.

Adding one: take the family's endpoints or the strings every sample decodes to (not decoy
padding, not a library's), add the verdicts to `seen_in`, bump `SIGNATURES_VERSION`, and measure
again over the captured tarballs before deploying.

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

### `exfil-endpoint` v3 and the placeholder rule (2026-10-30, `vm-day1`)

v3 requires real-looking webhook ids: a 17-20-digit Discord snowflake (every real webhook in
the DataDog samples has 19 digits), upper-case Slack `T…/B…` ids, and no repeated or
counting-up ids. Measured before adopting it:

- **v3 alone:** benign flags 11 → 10, but malicious shape B 1,006 → 963. The 43 lost samples
  (42 also lost end to end through `pipeline+3`) are a `chai-as-*` typosquat family whose
  only Stage 2 match was a Slack placeholder (`/services/xxx/xxx/xxx`) in a bundled notifier
  template; v2 matched it because its `[A-Z0-9]` was case-insensitive. Losing 42 attacks for
  one benign package (`@zerodot/discord`) is the wrong trade.
- **Adopted:** v3 plus `static.webhook-placeholder` (MEDIUM, weight 3) for exactly what v2
  matched and v3 rejects. Stage 2 flags the same samples as v2 (0 differences out of 4,943),
  and placeholder findings now say what they are and score 3 instead of 5.

### `exfil-endpoint` v4: written Telegram placeholders (2026-10-31)

`api.telegram.org/bot` followed by `<`, `[`, `YOUR_` or `...` (`bot<token>`,
`botYOUR_BOT_TOKEN`) is documentation, not code that sends anywhere, and no longer matches.
`glimmervoid`'s settings help ("open https://api.telegram.org/bot<token>/getUpdates in a
browser") was HIGH in every release. A URL built from a variable (`bot${token}`) still matches,
for the reasons below. `vm-day1`: no malicious sample lost; with the Vite-hash change, two
benign `glimmervoid` releases are no longer reported.

### `exfil-endpoint` forms checked against the first live day (2026-10-30; no change)

On `20261029T221803Z-npm`, 128 reported versions were HIGH through this rule alone, and live
benign code mostly matched it as `api.telegram.org/bot${token}`, a bare `".trycloudflare.com"`
or a list of ngrok's region hosts. Measured on `vm-day1`'s 1,181 samples with a match:

- **Telegram only with a literal bot token, tunnels only as a concrete host:** 30 malicious
  samples no longer match, 29 of them caught by nothing else, against 4 benign. Rejected:
  malware builds the URL from a variable just as often as benign code does.
- **ngrok's region hosts only** (`ap`, `au`, `eu`, `in`, `jp`, `sa`, `us` before
  `.ngrok.io`; nobody can register them as a tunnel): would clear 9 live reported versions
  (6 packages), and was briefly adopted as v4. The `stage2-rules` evaluation then lost 11
  malicious samples (2,169 -> 2,158 forwarded; `gina`, `cro-pricing`, `edgeone`, ...) that
  carry such lists and nothing else Stage 2 sees. The per-sample scan that said "no sample has
  one" only counted host labels of 3 or more characters. Reverted to v3.

### Hidden URLs and code handed `require` (2026-10-30, `vm-day1`)

The 43 samples above (pino clones named `chai-as-*`, `chai-await-*`, `aligners`,
`argon-web3-chain`, `core-pino`, ...; all new packages, no install hook except `js-prettier`)
were caught by Stage 2 only through the Slack placeholder in a template they copied. Read
statically, what they do is a remote loader, in two variants:

- **28 samples** (`lib/caller.js` or `lib/initializeCaller.js`, called from `main`, or
  spawned detached by it; in `loading-session` the loader is missing from the sample): a URL
  stored as base64 (`atob("aHR0cHM6Ly9...")`, dressed up as
  `process.env.DEV_API_KEY`), fetched with axios, and the response run with
  `new Function.constructor("require", body)(require)`. The hosts are JSON bins
  (`jsonkeeper.com`, `npoint.io`, `jsonsilo.com`, `mocki.io`, `jsonstorage.net`).
- **14 samples** (`lib/writer.js`): strings hex-encoded behind a small decoder (`require`,
  `axios`, `post` and the URL), `{...process.env}` plus host name, user and MAC addresses
  posted (mostly to a `*.vercel.app` host), and the response passed to `eval`.
- **1** (`jsonlogbundler`) has neither: it runs `npm install` of a second package at runtime.

Neither variant matched a MEDIUM rule: `dynamic-code` is LOW and its pattern misses
`Function.constructor(`; `env-harvest` misses a spread with more keys. Two general rules were
added rather than a family signature:

- **`static.encoded-url`**: a whole string literal that decodes (base64, URL-safe base64 or
  hex) to printable `http(s)://` / `ws(s)://` text. Code has no reason to hide an address it
  means to use. The literal must be the whole string, so the same bytes inside a longer blob
  (inline source maps, SVG data URIs) don't count; a scan without that condition matched
  28 benign samples, all of them such blobs. The finding shows the decoded URL.
- **`static.function-require`**: `Function("require", ...)`, including `Function.constructor`
  and `new (Function.constructor)(...)`. Runtime-compiled code that is given the module
  loader can load `child_process` or `https` itself; that is what a second-stage loader needs.

Measured on `vm-day1` (before = the rules without these two):

| Predictor | A | A follow-on | B | B follow-on | Benign A / B (flagged) |
|---|---|---|---|---|---|
| `stage2-rules`, before | 71.5% | 84.0% | 49.9% | 50.7% | 8 / 3 |
| `stage2-rules`, after | 71.6% | 84.0% | **52.4%** | **53.9%** | 8 / 3 |
| `pipeline+3`, before | 89.4% | 29.5% | 66.0% | 22.8% | 5 / 14 |
| `pipeline+3`, after | 89.4% | 29.5% | **67.6%** | 22.8% | 5 / 14 |

- **End to end: 15 more first releases caught (597 → 612), no benign added.** The 43 were
  already forwarded through the placeholder; the gain is other families with the same
  loader: `encoded-url` alone 9 (`tailwindcss-setfavicon`, `vite-support-kit`,
  `vite-ts-icon`, `terminalcolor256`, `graphflowx`, ...), `function-require` alone 5
  (`alpha-replicator`, `express-session-handler`, `mongos-api`, `tw-modern-ui`,
  `vite-plugin-chunk-chop`), both 1 (`vite-enhancer-config`).
- **Of the 43, `encoded-url` matches 42 and `function-require` 27.** `webhook-placeholder`
  is now the only Stage 2 catch for one of them (`jsonlogbundler`), against one benign
  package (`@zerodot/discord`); whether it stays MEDIUM is open.
- **Stage 2 alone: +58 samples (1 A, 22 B, 35 B follow-on), no benign sample added and none
  lost.** Of the 1,500 provisional benign samples, neither rule fires on a forwarded one that
  wasn't already forwarded. The live day is the larger benign test; an encoded-URL literal in
  benign code (a config test, an obfuscated telemetry endpoint) is the expected false positive.
- `function-require` uses possessive quantifiers: the first version backtracked quadratically
  on `Function` followed by a long whitespace run (a stall a package could cause).

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
