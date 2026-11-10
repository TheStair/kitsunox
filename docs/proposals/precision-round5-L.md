# Proposal: precision round 5, agent L: Stage 2 content rules

> **Status:** built 2026-11-10, before the rule freeze (2026-11-12 00:00Z). Cluster: Stage 2's
> content rules (`rules/static.py`) and the Stage 2 engine's "doesn't run" demotion
> (`stages/static.py`). **Owner decisions (2026-11-10): L1, L2 (with the quick-tunnel naming
> test), L3 and L5 kept, with the `LoadedFiles` guard; L4 rejected and removed before merge
> (section 2, L4).** Branch rebased on `main` `06ea392` (docs only since `31e96fa`).
> **Result on `main` `31e96fa`, real code, every live version the changes can touch (520 of
> the 3,716 verdicted; the rest can't change, see section 1): 1,428 → 1,411 reported, all 17
> removed versions benign (17 packages); no malicious, unwanted or unverified version changes
> its decision. Precision 21.17% → 21.43%. Of the 52 versions verdicted since, 3 more benign go
> (41 → 38) and `hauntview@0.2.9` stays reported. `vm-day1`: the touched rules fire on 1,950
> malicious samples; at the rule level 2 change (an `e.g.` comment beside a real endpoint),
> both still reported by `pipeline+4`, as are the 4 with a finding in a test-named file, the 17
> padded-code samples and all 18 Telegram stealers: 0 lost.** All kept changes are zero-loss.
> **Builds on:** [round 4, agent D](precision-round4-D.md) (v8's "what is sent", the harness
> for Stage 2), [round 3](precision-round3.md) (method), [round 2](precision-round2.md)
> sections 6-8, decision [0015](../decisions/0015-reviewer-verdicts.md) with all addenda.

## Summary

What the four rules still report after round 4 is mostly what the owner has ruled on:
javascript-obfuscator output in vendors' products (61 of `static.obfuscated`'s 61 benign
decisive reports are real obfuscator.io string arrays), vendors' own backend IPs in code
(`hardcoded-ip`, ~25 of 34), and Telegram notifiers in files that also run processes or walk
directories. None of that is touched. This round looks for what is *provably* not the thing
the rule names: a host no one else can serve, text shown to a user as an example, Emscripten's
renamed locals, a file a test runner loads and npm never does.

| # | Rule (stage) | What becomes LOW (weight 1, with a note) | Benign removed | Positives at risk → lost | `vm-day1` rule level → lost |
|---|---|---|---|---|---|
| L1 | `obfuscated` v2 (2) | `_0x` names in Emscripten glue: its runtime (20+ of `getCFunc`, `HEAP8`/`HEAP32`, `Module["_"+…]`, ...), fewer than 100 distinct names, no obfuscator string array | 0 (+1 of the 52 newer: `emulatorjs-build@4.2.301`) | 0 → 0 | 0 of 722 change |
| L2 | `exfil-endpoint` v9 (2) | a `trycloudflare.com` host that is not a quick tunnel's name (`demo.`, `api.`, `a.b.`, `abc-def.`, `word-word-word-word.`) or whose label is an ellipsis; `pastebin.com/` with no paste or API after it; `api.telegram.org/bot,` in a list of prefixes; a host literal among three services' names; `bot&lt;token&gt;` (dropped, as v4's `bot<token>`) | 13 (+2 of the 52) | 0 → 0 | 0 change |
| L3 | `exfil-endpoint` v9, `hardcoded-ip` v6 (2) | a URL that is a UI placeholder or `example:` value, or follows `e.g.` / `for example` | 2 | 0 → 0 | 2 change (`@mep-exp/api-tools@2.0.3`, `@abb-ux/commonux-web-components@5.0.0`: the `e.g.` URL only), still reported → 0 |
| ~~L4~~ | `exfil-endpoint` (2) | **rejected by the owner, removed:** in a file over 64 KiB, v8's "collects nothing" asked only the 16 KiB around the match | (4) | 0 → 0 | 0 change |
| L5 | Stage 2 engine | a match only in a test-named file (`*.test.js`, `*.spec.ts`, `*.stories.tsx`, `__mocks__/`, `test_*.py`, `*_test.go`); and neither that nor `NON_EXECUTING` applies to a file the install hooks or entry points load (`LoadedFiles`) | 2 | 0 → 0 | 4 samples have a MEDIUM+ match in such a file; all reported before and after → 0 |
| | **All kept (L1-L3, L5)** | | **17** (+3 of the 52) | **0** | **0** |

Removed, by fix: **L2** `@agimon-ai/po-native` (`travel-calm.`, in a Storybook story),
`@aglit-ai/server` (`demo.`), `@guowenzhang/dsh-pocket` and `dsh-remote-hub` (`api.`),
`dsh-meme` (`a.b.`, `evil.`), `tuinnel-plus` (`word-word-word-word.`), `bom-pi` (`https://….`),
`awesome-lite-mcp` (`pastebin.com/doc_api`), `dsh-sherlock` (`pastebin.com/`, `/u/{}`),
`forward-nexus` (`…,api.telegram.org/bot,hooks.slack.com/…`), `shield360` (`"webhook.site",
"requestbin", "pipedream", "ngrok", …`), `loopengine` (`bot&lt;token&gt;`); **L3** `@denofy/cli`
(`example: "curl https://webhook.site/…"`), `@syndew/oluso-admin-ui` (`placeholder=\"…
webhook.site\"`), and `domaintrail` (`https://….`, L2); **L5** `@aws-blocks/hosting`
(`dist/*.test.js`), `@feasibleone/blong-gogo` (`chatPorts.test.ts`). Of the 52 newer versions:
`emulatorjs-build@4.2.301` (L1), `@aswless_854771076/newapi-cli@2026.11.10` (`demo.`, L2),
`@thorcollective/hearth-mcp@0.0.1` (`api.`, L2).

The only positive whose findings change at all: `gebangautoupload@1.1.4` (unwanted) loses a LOW,
already "not new", `bot&lt;token&gt;` in its settings page's help text; it stays reported by
`npm.install-persistence` (score 6), its Telegram calls unchanged.

## 1. Data and method

- **Harness.** Round 4's (`~/kitsunox-scratch/r4/B/scripts/`, `replay.py` with agent C's
  watchlist change), copied to `~/kitsunox-scratch/r5/L/scripts/`. `replay.py SRC CANDS OUT`
  runs Stages 1-4 with `SRC`'s real code per verdicted version; tarballs are read in memory
  with `extract_tar_gz`, nothing runs. The only harness change: Stage 2's `content_matches`
  gets the version's `LoadedFiles`, as `analyse_batch` and the eval predictor now pass it.
- **Baseline = `main` `31e96fa`** (`r5/shared/baseline-main.jsonl`), verdicts re-joined from
  `data/verdicts/npm.jsonl` (last record per version; 15 relabelled since the shared file:
  1,428 reported, 1,102 benign, 249 unwanted, 47 malicious, 30 unverified, precision 21.17%).
- **Exhaustive subset, as round 4 did.** Every change only lowers a match of
  `exfil-endpoint`, `hardcoded-ip` or `obfuscated`, or a Stage 2 match in a test-named path;
  the one raise is L5's guard, which can only affect a match already carrying the docs note.
  A version with none of these in the baseline has the same findings with either code. That
  is 520 versions (`subset.py`); all were re-run with the fix (`sub-fix2-*.jsonl`), and the
  first 238 with `main` too, which reproduces the baseline on all 238 exactly. The live table
  is the baseline's with the 520 replaced. A full replay was started and dropped: six other
  heavy jobs were queued on the shared lock and two of my small runs were OOM-killed at 4 GB
  with two workers, so the subset ran with one worker per process.
- **The 52 versions verdicted since the shared candidates** (`extract_extra.py`, same harness,
  `main` and fix): reported separately, as they are not in the 3,716.
- **`vm-day1`, two steps.** (1) Rule level (`s2cmp.py`): every file of every malicious sample
  where any of the four rules fires at any severity in the round-4 dump (1,950 samples),
  decrypted in memory by the predictor, matched by `main`'s `rules/static.py` and the fix's in
  one process; any difference is printed. (2) `pipeline+4` (`dd.py`, fresh in-memory Stage 2
  cache, agent F's data dir) with both codes on every sample whose rule output changed, on
  the 4 samples with a MEDIUM+ Stage 2 finding in a test-named path, and with the fix on the
  17 padded-code samples.

## 2. The fixes

### L1. `static.obfuscated` v2: Emscripten glue

`emulatorjs-build@4.2.301` (benign, verdicted after the shared candidates) is reported for two
old asm.js Emscripten workers (`compression/extract7z.js`, `extractzip.js`): 94 `_0x` names,
25 distinct, all locals of Emscripten's `getCFunc` (`function getCFunc(_0x222174){var
_0x54cf7b=Module["_"+_0x222174]; … eval("_"+_0x222174)`), renamed by a minifier, with 119 to
128 Emscripten runtime markers in the file and none of javascript-obfuscator's string-array
machinery. Every other live file the rule fires on (3,523 in 114 versions) has the string array
(`const _0x…=['…']`, lookups `_0x1a2b(0x1f3)`, the `while(!![])` rotation) or, for the
`xgis-cog-*` builds, an object-key transform with no Emscripten runtime: they stay MEDIUM, as
the owner ruled. On `vm-day1` no obfuscated file of the 722 samples has an Emscripten marker
(118 checked by features, all 722 by the rule-level run). Pasting obfuscator output into glue
brings its string array (MEDIUM); renaming every name of a payload gives more than 100 (MEDIUM).

### L2. `static.exfil-endpoint` v9: hosts that can't be the endpoint

- **Not a quick tunnel's name.** `trycloudflare.com` serves only quick tunnels, and Cloudflare
  names each with hyphen-joined words: every one seen is four
  (`diameter-coins-limitations-parents`, `dean-earnings-directed-aside`,
  `gtk-optimize-webpage-tc` on `vm-day1`; `favor-skilled-ben-plugin` in a live MCP catalog).
  The test asks for at least three, digits allowed, for margin; a written host with one word
  (`demo`, `name`, `api`, `u8bcd`), more labels (`a.b`), fewer words (`abc-def`,
  `travel-calm`) or one word repeated (`word-word-word-word`) can't be a tunnel. A name built
  in code (`${id}.`, `id + "-x.`) is not judged; v6's placeholder test and v8's bare-suffix test
  still apply to those. This also covers `api.trycloudflare.com` in a file that collects
  (`@guowenzhang/dsh-pocket`), which v8 left HIGH.
- **`pastebin.com/` with no paste.** A paste is read or written through an id (8 characters;
  5-16 taken), `raw/`, `dl/`, `embed`, `print` or the API (`api/api_post.php`). The site
  itself, `/u/<user>` and `/doc_api` (Sherlock's site list in `dsh-sherlock`, an awesome-list
  index in `awesome-lite-mcp`) hold nothing anyone else wrote. No `vm-day1` sample has a HIGH
  pastebin match at all.

### L3. Placeholders and examples (`exfil-endpoint` v9, `hardcoded-ip` v6)

A URL that is the value of a `placeholder` (`placeholder: 'cezar.ngrok.app'`, the HTML
attribute, `tunnelUrlPlaceholder:"https://demo…"`) or an `example:` field, at most 80
characters into the string, or that follows `e.g.` / `for example`
(`# e.g. http://62.84.188.166:30080`, `e.g. cezar.ngrok.app`). Not `const example = '…'`
(a variable the code may use), never on an install hook's line. On `vm-day1` only two matches
change: `// e.g., 'https://webhook.site/your-unique-id'` after a real bin URL on the same line
(`@abb-ux/commonux-web-components`) and `// e.g. xyz.burpcollaborator.net` after
`hostname: "webhook.site"` (`@mep-exp/api-tools`); the real endpoints stay HIGH and both
samples are reported by `pipeline+4` with `static.exfil-endpoint` among their MEDIUM+ rules.

### L4. In a bundle, the code near the notifier (rejected by the owner, removed)

**Owner decision, 2026-11-10: dropped.** A bundled drainer's Telegram send naturally sits far
from the code that collects what it sends, so "collects nothing" keeps asking the whole file,
however large (test `test_a_bundle_s_notifier_far_from_its_collection_stays_high`). The 4
benign versions it removed (`@kvali/cli`, `@mostra/runtime`, `nottoday`,
`kings-never-miss-wallet-sdk`) stay reported. What was measured, for the record:

v8 lowers a Telegram URL with a handed token, a bare `webhook.site` and a tunnel's bare suffix
in a file that collects nothing. In a bundle that is almost never true: `@kvali/cli`'s
`dist/kvali.mjs` (329 KB) sends phone alerts with the user's own bot 19,605 characters from
the bundle's directory walk; `@mostra/runtime`'s `hostname.endsWith(".trycloudflare.com")` is
32,475 characters from a `child_process` import in a 727 KB instance chunk. In a file over
64 KiB, `_collects_near` asks the 16 KiB on either side of the match. The `vm-day1` Telegram
stealers are all small files (the largest, `@crysnovax/baileys`' `antiban.cjs`, is 138 KB with
its directory walk 4,737 characters away and stays HIGH; the eooce family's 35 KB files read
as a whole). Files that keep HIGH: `zipy-agent` (walk 6,230 away), `aggregate-finance` (5,866),
`@textjs/next` (9,454), `loclyn` (12,227).

### L5. Test files, and files the package loads

Round 3 deferred "test-named files don't run" because it changes every Stage 2 rule at once.
Measured per rule on the reported live versions (`testsim2.py`, then the real code): MEDIUM+
Stage 2 matches in test-named files are 12 findings, all in benign versions
(`function-require` 8, `exfil-endpoint` 4; no other rule has one), and making them LOW
unreports 3, all benign: `@aws-blocks/hosting`
(`dist/*.test.js` sandboxes, `function-require`), `@feasibleone/blong-gogo`
(`chatPorts.test.ts`) and `@agimon-ai/po-native` (a Storybook story, also L2). On `vm-day1`, 4
malicious samples have such a match, all `hardcoded-ip` in `test_callback.py`
(`byteplus-platform-runtime`, `c-monitor-dashboard`, round 4's D4 samples), none decided
differently.

Attackers do put payloads in `test/` and run them from a hook, so a file the version's install
hooks or entry points load (`LoadedFiles`: npm's `install_sources`, which follows hooks, the
files they load and the scripts they start, and `load_sources`, the entry points and what they
load) is never taken for a test, nor for documentation (`NON_EXECUTING`, which had no such
guard). It is worked out only when a MEDIUM or higher match is in such a path. Live and on
`vm-day1`, no loaded file had a demoted match, so the guard changes nothing measured today.

## 3. Live result (real code)

| | Reported | Benign | Unwanted | Malicious | Unverified | Precision |
|---|---|---|---|---|---|---|
| `main` `31e96fa` (verdicts re-joined) | 1,428 | 1,102 | 249 | 47 | 30 | 21.17% |
| L1-L3, L5 (this branch) | 1,411 | 1,085 | 249 | 47 | 30 | 21.43% |
| (with the rejected L4) | (1,407) | (1,081) | (249) | (47) | (30) | (21.50%) |
| 52 newer versions, `main` | 41 | 33 | 7 | 1 | 0 | 19.51% |
| 52 newer versions, this branch | 38 | 30 | 7 | 1 | 0 | 21.05% |

With the shared file's verdicts (not re-joined), `main` is 1,112 benign and this branch 1,095:
the same 17 versions. No version is newly reported; no malicious, unwanted or unverified version
changes its decision (`cmp2.py`). The remaining benign decisive reports of the four rules:
`obfuscated` 61 (vendor products), `hardcoded-ip` 34 (vendors' backends, catalogs),
`exfil-endpoint` 30 (Telegram notifiers in files that run processes, vendors' tunnel features,
detection-rule prose), `function-require` 10.

## 4. DataDog check (`vm-day1`)

- **Rule level** (`s2cmp-*.jsonl`): 1,950 malicious samples where `exfil-endpoint`,
  `hardcoded-ip`, `obfuscated` or `function-require` fire. All 1,950 read (`nofiles` 0). 2 change: `@abb-ux/commonux-web-components@5.0.0` and `@mep-exp/api-tools@2.0.3` (L3, the `e.g.` URL only). `obfuscated`: 0 of 722. The 18 Telegram stealers, the tunnel and `webhook.site` samples, every `hardcoded-ip` and `function-require` sample: no change.
- **`pipeline+4`** (`dd-p4-*.jsonl`, both codes): `@abb-ux/commonux-web-components@5.0.0`
  (score 14), `@mep-exp/api-tools@2.0.3` (17), `byteplus-platform-runtime@99.99.99` (18),
  `c-monitor-dashboard@99.99.99` (19): reported before and after, `static.exfil-endpoint`
  still MEDIUM+ in each. The 17 padded-code samples (agent F's `dd-gain.keys`): all reported
  with the fix (`dd-pad-fix.jsonl`). The 18 Telegram stealers: no rule-level change.
  `hauntview@0.2.9` (live, in the 52 extra versions): reported before and after.
- **After removing L4** (`fix4/`): the rule-level run over the 1,101 `exfil-endpoint`
  samples again (`s4-*.jsonl`) gives the same 2 changes and nothing else; `obfuscated`,
  `hardcoded-ip` and `function-require` are unchanged by the removal.
- **0 malicious samples lost.**
- **Score-only positives (agent K's note):** no LOW rule is touched (`process-exec`,
  `network`, `npm-publish` unchanged); `hub-launch@1.44.2` and
  `@hithink-tech/hithink-finance-cli@0.2.0` stay reported at score 6.

## 5. Rejected or not built

- **Bare OAST service names** (`interact.sh`, `oastify.com` with no id label: `propelix-cli`'s
  WAF rule name, `@ulkoro/skillsentry`'s and `retrohound`'s rule prose, 3 benign decisive).
  `atlas-websocket@8.8.0` on `vm-day1` sets `hostname: "burpcollaborator.net"` bare, and
  `rank4222wun@1.0.35` prints `https://oastify.com`. Not built.
- **Vendor obfuscation** (61 benign): owner's ruling; every file is real obfuscator.io output
  (`obfeat-live.jsonl`: string arrays in all but `@univer-cli/doc-markdown-facade`, the
  `xgis-cog-*` builds and `@amoshydra/oktoso`'s Vite asset, which round 4's rejected D6 covered).
- **Telegram notifiers in small files that run processes** (`@cakagus/codeclaw` posts through
  `exec("curl …")`, `candle-bot-core`, `vallenemperor`, `vibelog.md`): the stealer's shape at
  the same scale; v8's rule stands.
- **Vendor backend IPs with an environment override** (`process.env.X || 'http://ip'`: 6
  benign): a stealer can write the same; D's `@pwnedshell/nn`, `@typescript_eslinter/eslint`
  and `akasearch` are reported by their IP alone.
- **Data catalogs** (an IP or tunnel URL among many URLs in a large JSON: `dsh-blackhole-radio-lab`,
  `@lnng/dsh-ai-pentest-pathfinder`, `dsh-pick`, `tradingagentstack-mcp`, `@khalidsaidi/ragmap-mcp`,
  ~5 benign): an app loads its config from JSON (round 3's `dsh-model-pipeline`), and nothing
  here proves a catalog is never read as one. Not built.
- **Compiled sources a hookless package never builds** (`@warpstack/wallet`'s Rust unit tests in
  `native/rust/src/*.rs`): its `vectors/native.json` has the same `test-warpstack.ngrok.io`
  host, so it would stay reported; not built.
- **`static.shell-startup` on printed advice** (`@ornexus/neocortex` `install.sh:1482`, via
  `lang.shell.mask_script_messages`): the form there is `shell` (LOW); no LOW shell-startup
  finding decides a live report (`lowfill.py`), and `neocortex` 4.61.5 is unwanted for its
  user-wide agent writes. Not built.

## 6. Owner questions

1. ~~L2's quick-tunnel naming test?~~ Kept (owner, 2026-11-10).
2. ~~L5's guard on `NON_EXECUTING`?~~ Kept (owner, 2026-11-10).
3. ~~L4 (a window around the match in bundles)?~~ Rejected (owner, 2026-11-10): removed.

## 7. How to reproduce

Scripts in `~/kitsunox-scratch/r5/L/scripts/` (read-only on `data/`; Python with `-I` through
the `py` wrapper with `nice -n 19`; small runs in `systemd-run --user --scope -p MemoryMax=4G`).
Outputs in `~/kitsunox-scratch/r5/L/out/`; frozen sources `base-src/` (`main`), `fix3/` (with
L4) and `fix4/` (this branch: L4 removed; `sub-fix4-*.jsonl`, `s4-*.jsonl`).

- `rejoin.py`, `analyze.py`, `dec.py`, `brief.py`: the decisive buckets (`dec-*.txt`).
- `exfwhy.py`, `hosts.py`, `snipcheck.py`, `bareoast.py`, `obfeat.py`, `testsim2.py`,
  `lowfill.py`: shapes and features, live and `vm-day1`.
- `subset.py` → `sub.keys`; `small.sh SRC CANDS OUT 1 @KEYS` → `sub-fix2-*.jsonl`,
  `sub-base.jsonl`; `extract_extra.py` → `cands-extra.jsonl.zst`, `extra-*.jsonl`;
  `cmp2.py BASE FIX`: tables and changed versions.
- `s2cmp.py FIX KEYS i/n` → `s2*.jsonl` (rule level, `vm-day1`); `ddrun.sh SRC OUT KEYS` →
  `dd-p4-*.jsonl`, `dd-pad-fix.jsonl` (`pipeline+4`).
