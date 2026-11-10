# Proposal: precision round 6, agent P: Stage 2 content rules that report alone

> **Status:** built 2026-11-11, before the rule freeze (2026-11-12 00:00Z). Cluster: the Stage 2
> content rules that report benign versions on their own (`static.obfuscated`,
> `static.hardcoded-ip`, `static.exfil-endpoint`, `static.function-require`,
> `static.encoded-blob`, `static.webhook-placeholder`, `static.encoded-url`;
> `rules/static.py`). Base: `main` `79958e6`. Five commits, one per fix, all zero-loss.
> **Result (real code, today's verdicts, every live version the change can touch): 1,349 →
> 1,331 reported, all 18 removed versions benign, none newly reported; no malicious, unwanted
> or unverified version changes its decision, and no positive's `exfil-endpoint` or
> `hardcoded-ip` finding changes at all. Precision 35.48% → 35.97%. `vm-day1`: on the 1,950 malicious samples where the cluster's
> rules fire (5,169 matches), one match changes (P3, `@pixui-dev/pxw@0.1.23`, unreported by
> `pipeline+4` with either code); 0 lost.**
> **Builds on:** [round 5, agent L](precision-round5-L.md) (Emscripten glue, `exfil-endpoint`
> v9, `hardcoded-ip` v6, test files), [round 4, agent D](precision-round4-D.md) (v8's "what is
> sent"), decision [0015](../decisions/0015-reviewer-verdicts.md) with all addenda.

## Summary

What `exfil-endpoint` and `hardcoded-ip` still report alone is mostly a host or IP that is
named but never connected to: a suffix a host check compares with, a service in a sentence, a
catalog of other people's servers, a default the user overrides, an allow-list entry. Each fix
names that use; the match becomes LOW (weight 1) with a note, never on an install hook's line,
and whatever else the file does (unlike v8, these don't ask whether the file collects).

| # | Rule (version) | What becomes LOW | Benign removed | Positives at risk → lost | `vm-day1` rule level → lost |
|---|---|---|---|---|---|
| P1 | `exfil-endpoint` v10 | a bare tunnel suffix in a host check or allowed-hosts setting (`hostname.endsWith(".trycloudflare.com")`, `allowedHosts: ['.trycloudflare.com']`, `ALLOWED_HOSTS=.trycloudflare.com`) | 4 | 0 → 0 | 0 → 0 |
| P2 | `exfil-endpoint` v10 | a bare service host in a parenthesised prose list (`collectors (webhook.site, requestbin, ngrok, interact.sh)`) | 1 | 0 → 0 | 0 → 0 |
| P3 | `hardcoded-ip` v7 | an environment variable's fallback (`process.env.X \|\| 'http://…'`, `os.environ.get("X", "…")`, `${X:-http://…}`) | 6 | 0 → 0 | 1 → 0 |
| P4 | both | a match in a JSON document with URLs on 20+ hosts (`CATALOG_HOSTS`) | 5 | 0 → 0 | 0 → 0 |
| P5 | `hardcoded-ip` v7 | a literal compared (`=== "http://…"`, `["http://…"].includes(`) or hashed (`.update("http://…")`) | 2 | 0 → 0 | 0 → 0 |
| | **All** | | **18** | **0** | **1 → 0** |

Removed, by fix: **P1** `@ishlabs/cli@0.40.0` (Vite `allowedHosts` advice in its `connect`
errors and docs), `@mostra/runtime@0.7.0` (`hostname.endsWith(".trycloudflare.com")` before a
share-tunnel probe), `@textjs/next@1.0.0` (`allowedHosts: ["my-laptop.local", ".ngrok.app"]`),
`loclyn@0.1.0` (`reqHost.endsWith(".trycloudflare.com")` and the `allowedHosts` hint); **P2**
`@ulkoro/skillsentry@0.6.1` (its exfiltration rule's description); **P3**
`@yiarce/dsh-chat@0.1.0`, `dino-a8-login@0.1.3`, `dsh-ant@0.5.12`, `dsh-ragflow-mcp@0.2.0`,
`opencorax-cli@0.1.2`, `yanspace@1.0.0` (`process.env.X || 'http://ip'` defaults of the
vendor's own server, each documented and overridable); **P4** `@khalidsaidi/ragmap-mcp@1.1.0`
(an MCP server catalog listing two quick tunnels), `@lnng/dsh-ai-pentest-pathfinder@0.9.0` (a
fingerprint library), `dsh-blackhole-radio-lab@1.0.0` (radio stream URLs),
`dsh-pick@0.5.0` (a plugin catalog's third-party repo URL), `tradingagentstack-mcp@0.6.0` (an
IOC table); **P5** `@my-life-buddies/cli@0.29.0` (an origin allow-list and a hashed account
key), `@sleep2agi/agent-network@2.3.0-preview.220` (a legacy-hub migration check,
`['http://47.77.216.1:9200']['includes'](…)`). Each removed version is lowered by one fix
only, so dropping any commit restores exactly its versions.

## 1. Data and method

- **Harness:** agent K's (`~/kitsunox-scratch/r5/K/scripts/`), copied to
  `~/kitsunox-scratch/r6/P/scripts/`. `replay.py SRC CANDS OUT` runs Stages 1-4 with `SRC`'s
  real code per verdicted version; tarballs are read in memory with `extract_tar_gz`.
  Baseline: `~/kitsunox-scratch/r6/shared/base.jsonl` (rules identical to `79958e6`),
  counted with `r5/final/relabel.py` (today's verdicts). Replaying `79958e6` itself on the 18
  changed versions reproduced the baseline's decisions and reasons exactly (18 of 18).
- **Exhaustive subset.** Every change lowers a match of `exfil-endpoint` or `hardcoded-ip`
  (the `CONTEXT_NOTES` change only strips a note from the "not new" key of such a match). A
  version where none of the cluster's rules fires at any severity in the baseline has the
  same findings with either code: 499 versions do (`live-touch.keys`), all replayed with the
  final code (`sub-fix5.jsonl`), and the live table is the baseline with those 499 replaced
  (`merged-fix5.jsonl`).
- **Shapes first** (`p_ctx.py`): the 200 characters before and 120 after every accepted match
  of the cluster's rules in the 499 live versions and in 1,949 `vm-day1` malicious samples
  (`ctx-*.jsonl`), to find shapes and to check each against the samples before building it.
- **`vm-day1`, two steps.** (1) Rule level (`p_s2cmp.py`): every file of the 1,949 malicious
  samples where `exfil-endpoint`, `hardcoded-ip`, `obfuscated` or `function-require` fires
  (round 5's `dd-mine.keys`), decrypted in memory, matched by `79958e6`'s rules and the
  fix's in one process. (2) `pipeline+4` (`p_dd.py`, my own hard-linked data dir with a fresh
  Stage 2 cache) with both codes on every sample whose rule output changed.

## 2. The fixes

### P1. `exfil-endpoint` v10: a tunnel suffix in a host check

`@mostra/runtime` runs `if (!hostname.endsWith(".trycloudflare.com")) return;` before probing
its own share tunnel; `loclyn` tests `reqHost.endsWith(".trycloudflare.com")` for its phone
preview; `@ishlabs/cli` and `@textjs/next` tell the user to add `'.trycloudflare.com'` /
`'.ngrok.app'` to Vite's `server.allowedHosts`. v8 lowered a bare suffix only in a file that
collects nothing; these are agent runtimes and CLIs whose bundles also run processes. A
suffix after `.endsWith(`/`.endswith(`, inside an `allowedHosts: [...]` list or after
`ALLOWED_HOSTS=` is compared with a host the code was given; nothing connects to it. A suffix
joined to a name (`'https://' + id + TUNNEL`), a named tunnel and the install hook's line stay
HIGH. Round 4's tests that kept `endsWith` HIGH in a collecting file now use a suffix that is
concatenated into a URL, the shape they meant to keep.

### P2. `exfil-endpoint` v10: a service named in prose

`@ulkoro/skillsentry`'s rule text, "Short-lived collectors (webhook.site, requestbin, ngrok,
interact.sh) or raw IP endpoints are classic exfiltration infrastructure". A bare service host
(no subdomain, scheme or path: no id anyone registered) that is a whole entry of a
comma-separated list in parentheses opened after a space, every entry a short word or host.
Code never writes an unquoted host in such a list; `post(webhook.site, data)` (no space before
`(`), an id in the list (`(abcd1234.oast.fun, interact.sh)`) or a URL stays HIGH.
`retrohound` has the same sentence but stays reported for its Sigma YAML lists
(`- '//hastebin.com'`), which this doesn't touch.

### P3. `hardcoded-ip` v7: an environment variable's fallback

`process.env.SEEYON_BASE_URL || "http://120.35.0.67:28101"`,
`process.env.ANT_MARKET_URL?.trim() || 'https://8.160.178.245'`,
`'process.env.RAGFLOW_MCP_URL || "https://8.166.138.255/api/v1/mcp"'`: the default of a
documented setting, the vendor's own server. Also `??`, Python's `os.environ.get("X", "…")`
and `os.getenv`, and a shell `${X:-http://…}`. A constant handed to `process.env.X || C2` (the
URL elsewhere), a hook line's `${U:-http://…}` and a URL used directly stay MEDIUM. Round 5
declined this unmeasured ("a stealer can write the same"); measured, no live positive and no
`vm-day1` sample is decided differently (one sample, `@pixui-dev/pxw@0.1.23`'s
`process.env.PFBS_DOWNLOAD_SITE || 'http://9.134.150.252:8090/…'`, changes at rule level; it
is unreported by `pipeline+4` with either code, its IP already "not new"). **Owner question 1.**

### P4. Both rules: JSON catalogs

A file that parses as JSON and lists URLs on at least 20 different hosts: internet radio
stations (`dsh-blackhole-radio-lab`'s `data/catalog.v1.json`), an MCP server directory
(`@khalidsaidi/ragmap-mcp`, whose catalog lists `favor-skilled-ben-plugin.trycloudflare.com`
among thousands of servers), an IOC table (`tradingagentstack-mcp`), a fingerprint library,
a plugin catalog. A program's configuration names its own few servers: the unwanted
`dsh-model-pipeline@0.10.4` hardcodes its provider IP in a YAML patch with nothing else, and
stays MEDIUM. `package.json` hooks never reach 20 hosts.

The notes of all five fixes join `CONTEXT_NOTES` (Stage 2's "not new" key leaves them out):
without that, `dsh-pick@0.5.2` was **newly** reported, because 0.5.1's catalog (76 hosts)
lowered the IP with the note and 0.5.2's (14 hosts; its other entries moved to GitHub) did not,
so the same match looked new.

### P5. `hardcoded-ip` v7: compared or hashed

`["https://47.116.168.81", "http://47.116.168.81:8788", …].includes(url.origin)` and
`createHash("sha256").update("https://47.116.168.81")` (`@my-life-buddies/cli`), and the
obfuscated `['http://47.77.216.1:9200']['includes'](hub)` that rewrites a node's legacy hub
(`@sleep2agi/agent-network` preview.220; preview.217 calls `includes` through the string
array, `[_0x584254(0x5e1)]`, and stays reported). An array the code iterates and connects to
(`@ifasn/mmdd-doc-mcp`'s `for (const host of hosts)`, malicious) and
`'http://…/cb'.indexOf('https:')` (`file-saver-bg`'s protocol pick, malicious) stay MEDIUM.

## 3. Live result (real code, today's verdicts)

| | Reported | Benign | Unwanted | Malicious | Unverified | Precision |
|---|---|---|---|---|---|---|
| `main` `79958e6` (shared baseline) | 1,349 | 851 | 421 | 47 | 30 | 35.48% |
| P1-P5 (this branch) | 1,331 | 833 | 421 | 47 | 30 | 35.97% |

The brief's 1,017 benign / 255 unwanted were the verdicts of its writing; the re-review since
moved many to unwanted. `relabel.py` lists no malicious, unwanted or unverified version whose
decision changed; no benign version is newly reported.

## 4. DataDog check (`vm-day1`)

- **Rule level** (`s2dd-b-*.jsonl`, the final rules but for P5's `['includes'](` form;
  `s2dd-eip5-*.jsonl` reran the 1,202 `hardcoded-ip` samples with the final rules): all 1,950
  malicious samples where `exfil-endpoint`, `hardcoded-ip`, `obfuscated` or
  `function-require` fires read (`nofiles` 0); 5,169 matches, one changes:
  `@pixui-dev/pxw@0.1.23`'s `process.env.PFBS_DOWNLOAD_SITE || 'http://9.134.150.252:8090/…'`
  (P3). No host check, prose list, catalog or comparison matches on any sample: the Telegram
  stealers, tunnel, `webhook.site` and OAST samples, every `hardcoded-ip` sample are
  unchanged.
- **`pipeline+4`** (`dd-pxw-*.jsonl`, both codes, fresh Stage 2 cache): `@pixui-dev/pxw@0.1.23`
  is unreported before and after (score 3; its IP is "not new").
- **0 malicious samples lost.** Every other sample's Stage 2 output is identical, so its
  `pipeline+4` decision is too (the `CONTEXT_NOTES` change only touches matches carrying a
  round-6 note).

## 5. Rejected or not built

- **A Telegram token read from the environment** (`bot${process.env.TELEGRAM_BOT_TOKEN}`,
  `bot${env["…"]}`, a shell `bot$TELEGRAM_BOT_TOKEN`; built, then removed before commit): 2
  benign (`zipy-agent`, `heyphony`). The rule reads one file; the token can sit in another
  one the same package controls: a hook line `TG=123:AA… node x.js`, a shipped `.env` the code
  parses. A stealer then reads "its user's" variable. v8's decision to keep a shell
  `bot$TOKEN` HIGH stands for the same reason.
- **`static.obfuscated` (61 benign alone, 3 malicious):** all but one benign file
  (`@amoshydra/oktoso`'s hashed Vite asset, round 4's rejected D6) carry obfuscator.io's
  string array, as the `vm-day1` chalk/debug wave does; the `*-ai-sdk` stealers have no
  install hook and their main entry loads the obfuscated files, like the vendor products.
  Nothing per file separates them. "The whole package is obfuscated by its own declared
  build (`javascript-obfuscator` in `devDependencies`, an `obfuscate` script)" is a package
  signal, not a file rule; see owner question 2.
- **`static.function-require` (10 / 1):** benign loaders pass a variable
  (`Function('require', result.code)(require)`), the shape of the `chai-as-*` second stage
  (`Function("require", runnable)`). The malicious `nzjdb-cfzol-util@1.0.1` passes an empty
  body. Nothing to build.
- **`static.encoded-url` (3 / 0):** `decodeOrigin("aHR0cHM6Ly9…")` (PayerMax), hex type ids
  (`prism-code`), a base64 login redirect (`wangka-panel`): the same literal the `chai-as-*`
  family `atob`s and fetches.
- **`static.webhook-placeholder` (3 / 1, by score only):** `hub-launch@1.44.2` (unwanted) has
  the same rule set; the rule exists for `jsonlogbundler`.
- **A bare OAST name followed by words** (`propelix-cli`'s WAF rule `name: "Interact.sh OOB
  domain"`): the `@goparrot-dashboard/app` malicious comment "sends hostname + username + cwd
  to an interact.sh callback server" has the same shape (its real `.oast.fun` host keeps it
  reported, but the shape doesn't separate). Not built.
- **Sigma YAML substring lists** (`retrohound`'s `- '//hastebin.com'`): one version; v5's
  whole-literal test would need to accept `//` and a leading space. Not built.
- **SSRF test vectors** (`172.32.0.1`, "outside 172.16/12", `@exponential_app/engine`): one
  version.

## 6. Owner questions

1. **P3 (environment fallbacks).** Round 5 declined it without measuring because a stealer can
   write `process.env.X || 'http://C2'`. Measured: 6 benign removed, nothing lost live or on
   `vm-day1`. Keep, or drop commit `078ef38`?
2. **Vendor obfuscation as a package signal.** The 61 benign `obfuscated`-alone reports are
   real obfuscator.io output. A Stage 2 package-level note ("every JS file of the package is
   obfuscated the same way and `javascript-obfuscator` is a declared devDependency or build
   step") would separate most from the `*-ai-sdk` stealers (custom XOR tables, no build
   declaration), but it is a provenance-like explanation, which the owner has refused for
   install code. Worth measuring after the freeze?

## 7. How to reproduce

Scripts in `~/kitsunox-scratch/r6/P/scripts/` (read-only on `data/`; Python `-I`, `nice -n 19`,
`systemd-run --user --scope -p MemoryMax=4G`). Outputs in `~/kitsunox-scratch/r6/P/out/`;
frozen sources `base/` (`79958e6`) and `fix5/` (this branch's code, identical to the commits).

- `p_alone.py`, `p_show.py`: the rule sets that report alone; `p_ctx.py` → `ctx-*.jsonl`,
  `p_grepctx.py`: shapes, live and `vm-day1`.
- `replay.py fix5/src CANDS out/sub-fix5.jsonl 2 @out/live-touch.csv`; `p_merge.py`,
  `relabel.py`, `p_diff.py`: the live table and the changed versions.
- `p_s2dd.sh FIX TAG [KEYS]` → `s2dd-*.jsonl` (rule level, `vm-day1`); `p_ddpair.sh FIX KEYS
  TAG` → `dd-*.jsonl` (`pipeline+4`, both codes).
- `p_split.py`: the five commit states from the final files.
