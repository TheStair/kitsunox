# Proposal: precision round 7, agent X: Stage 2 content rules that report alone

> **Status:** built 2026-11-11, before the rule freeze (2026-11-16 00:00Z). Cluster: the Stage 2
> content rules that still report benign versions on their own after round 6
> (`static.exfil-endpoint`, `static.hardcoded-ip`, `static.function-require`,
> `static.webhook-placeholder`, `static.encoded-url`; `code.function-constructor` looked at).
> `static.obfuscated` is out of scope (the owner measures "obfuscated by its own declared
> build" after the freeze). Base: `main` `8ee117c`. Two commits, both zero-loss.
> **Result (real code, today's verdicts): 1,469 → 1,461 reported, all 8 removed versions
> benign, none newly reported; no malicious, unwanted or unverified version changes its
> decision, and no positive's `exfil-endpoint` or `hardcoded-ip` finding changes at all.
> Precision 46.42% → 46.68%. `vm-day1`: all 1,202 malicious samples where either rule fires (and 121 more) read, 1,881 matches of the cluster's rules, none changes; 0 lost.**
> **Builds on:** [round 6, agent P](precision-round6-P.md) (P1-P5, kept), round 5's
> [L](precision-round5-L.md), round 4's [D](precision-round4-D.md), decision
> [0015](../decisions/0015-reviewer-verdicts.md) with all addenda. (Round 3 also used the
> labels X1-X5; here they always mean round 7's.)

## Summary

After round 6, what these rules report alone is mostly a URL that is shown, not connected
to: sample data inside an `example`, the default of a setting the user fills in, a
constant that is only an environment variable's fallback, a legacy address only checked for
membership. Each fix names that use; the match becomes LOW (weight 1) with a note, never on
an install hook's line.

| # | Rule (version) | What becomes LOW | Benign removed | Positives at risk → lost | `vm-day1` rule level → lost |
|---|---|---|---|---|---|
| X3 | both (`exfil-endpoint` v11, `hardcoded-ip` v8) | a URL inside the value of an `example` / `examples` field (`example: { server: "http://…" }`, an OpenAPI `"examples": {…}` holding a `webhook.site` log) | 2 | 0 → 0 | 0 → 0 |
| X2 | `hardcoded-ip` v8 | the default of a declared option or field (`{ name, type, default: 'http://…' }`, `.default('http://…')`) | 2 | 0 → 0 | 0 → 0 |
| X5 | `hardcoded-ip` v8 | an entry of a `new Set([...])` only asked `.has(` (a legacy-address check) | 1 | 0 → 0 | 0 → 0 |
| X4 | `exfil-endpoint` v11 | the Telegram API prefix assigned to a name on its own (`BASE_URL='https://api.telegram.org/bot',`), in a file that collects nothing (v8's handed token over two statements) | 1 | 0 → 0 | 0 → 0 |
| X1 | `hardcoded-ip` v8 (own commit) | a constant used, everywhere else in the file, only as an environment variable's fallback (`const DEFAULT_API_BASE = 'http://…'` + `process.env.X \|\| DEFAULT_API_BASE`) | 2 | 0 → 0 | 0 → 0 |
| | **All** | | **8** | **0** | **0** |

Removed, by fix: **X3** `@ohos-ports/nocodb-daily@0.255.2-pr-8513-…` (NocoDB's bundled
OpenAPI document: a webhook log example with a `webhook.site` bin, escaped JSON inside
`"examples"`), `gisviewer-vue3-arcgis@1.0.357` (`showSumoFromFile: { schema, example: {
server: "http://116.196.98.229:8000/…" } }`); **X2** `chuxin-agentdesk@0.1.0` (a workflow
form input `{ name: "bugUrl", label: "…", default: "http://121.40.16.93:8090/…" }`),
`n8n-nodes-c15_lotus_agent@0.1.0` (an n8n credential type's `{ displayName: 'B46 URL', name,
type: 'string', default: 'http://114.114.114.46:8000' }`); **X5**
`@zerowall/dsh-plugin-mcp@0.1.0-preview.1` (`TOOLUNIVERSE_LEGACY_URLS = new
Set(["http://103.217.185.141:8099/…"])`, used only as `.has(raw)` to rewrite the legacy URL to
its trusted host); **X4** `colana@1.0.0-beta.133` (its Telegram bot bridge,
`BASE_URL='https://api.telegram.org/bot',` in a file that collects nothing); **X1**
`@omni-center/omni-plugin-cli@1.0.28` (`DEFAULT_API_BASE`, used only in
`process.env.OMNI_API_BASE_URL || DEFAULT_API_BASE`), `vibe-showcase-mcp@1.0.0`
(`process.env.VIBE_SHOWCASE_URL ?? DEFAULT_BASE_URL`). Each removed version is lowered by one
fix only. Two more benign versions lose their only `exfil-endpoint` MEDIUM+ match but stay
reported for other rules (`@claude-flow/aidefence@3.1.0`, `oc-workers@1.0.0`).

## 1. Data and method

- **Harness:** agent K's (`~/kitsunox-scratch/r5/K/scripts/`), copied to
  `~/kitsunox-scratch/r7/X/scripts/` with round 6 P's helpers (`p_*.py`, paths moved to
  `r7/X`). `replay.py SRC CANDS OUT` runs Stages 1-4 with `SRC`'s real code per verdicted
  version; tarballs are read in memory with `extract_tar_gz`. Baseline: the shared
  `~/kitsunox-scratch/r7/shared/base.jsonl` (rules = `8ee117c`), counted with
  `r5/final/relabel.py` and today's verdicts.
- **Clusters.** `my/alone.py` lists the versions each rule reports alone with their matches
  and the reviewer's note; `scripts/x_file.py` / `x_files.sh` show a file's context
  (what makes `_collects` true, how a constant is used) without running anything.
- **Exhaustive subset, then the full replay.** Every change lowers a match of
  `exfil-endpoint` or `hardcoded-ip`, so only a version where one of them fires (any
  severity) can change: 395 versions (`out/live-touch.keys`), replayed with the code
  (`sub-fix2.jsonl`; X5 and X1's final form on the 100 `hardcoded-ip` versions,
  `sub-fix3-ip.jsonl`). The final number is one full replay of all 3,716 versions with the
  committed code (`out/full-head.jsonl`).
- **`vm-day1`, rule level** (`p_s2cmp.py`, `out/s2dd-f3-*.jsonl`): every file of the 1,949
  malicious samples where `exfil-endpoint`, `hardcoded-ip`, `obfuscated` or
  `function-require` fires (round 5's `dd-mine.keys`), decrypted in memory, matched by
  `8ee117c`'s rules and the final ones in one process. The run was restarted after 170 samples, on round 5's `dd-eip.keys` (the 1,202 samples where `exfil-endpoint` or `hardcoded-ip` fires: only those can change), so 1,323 samples were read in all (`s2dd-part1/`, `s2dd-f3r-*.jsonl`).

## 2. The fixes

### X3. Both rules: inside an `example`

v9 (L3) lowered a URL right after `example: "` or `e.g.` on its line. Sample data is often a
nested value: GIS viewer's parameter schema `example: { server: "http://…", file: "…" }`, an
n8n node's `examples: [['http://114.114.114.39:80/', 'what it opens'], …]`, NocoDB's OpenAPI
document `"examples": {"Example 1": {"value": {"list": [{"notifications": "{\"payload\":
{\"path\": \"https://webhook.site/6eb4…\"}}"}]}}}`. `_in_example` counts brackets outwards
from the URL (2,000 characters at most) and asks whether any enclosing object or array is
the value of an `example` / `examples` / `x-examples` key. An open call in between (`example:
{ x: get("http://…") }`) ends the search: a URL passed to a function is used.
`const example = {…}` (a variable) is not a key and stays.

### X2. `hardcoded-ip` v8: a declared option's default

The same kind of setting as P3's environment fallback, declared instead of read: an n8n
credential type's properties (`{ displayName, name, type: 'string', default: 'http://…' }`),
a workflow form's inputs (`{ name, label, default }`), zod's `.default('http://…')`. A
`default:` key counts only in an object that also declares the option (a `name`, `type`,
`label`, `displayName`, `description`, `title`, `describe` or `help` key before or after it,
within the object); `{ default: 'http://…' }` alone, a lookup table, stays MEDIUM.

### X5. `hardcoded-ip` v8: a set only asked `.has(`

P5 lowered an array of literals searched with `.includes(`. The same check written as a set:
`TOOLUNIVERSE_LEGACY_URLS = /* @__PURE__ */ new Set(["http://103.217.185.141:8099/…"])`,
the name used only as `TOOLUNIVERSE_LEGACY_URLS.has(raw)`. Any other use of the name
(`for (const u of S)`, `[...S]`, `S.forEach`, never asked) keeps it MEDIUM.

### X4. `exfil-endpoint` v11: the Telegram prefix as a constant

v8 lowers `"https://api.telegram.org/bot" + token` in a file that collects nothing. Colana's
bot bridge writes the prefix as a constant and joins the token later:
`BASE_URL='https://api.telegram.org/bot',POLL_TIMEOUT_S=0x1e,…`. X4 accepts the prefix
assigned to a name on its own (`NAME = '…/bot'` followed by `,`, `;` or a line end), under
v8's conditions (nothing collected anywhere in the file, not on a hook's line). An entry of
an obfuscator's string array (`[…,'https://api.telegram.org/bot','includes',…]`, which is
how `@eooce/sbx@2.0.8` writes it on `vm-day1`, its collection hidden in the array too) is not
assigned and stays HIGH (v9's test `const BASE = ['x', '…/bot', 'y']` still holds).

### X1. `hardcoded-ip` v8: P3's fallback through a constant (its own commit)

`const DEFAULT_API_BASE = 'http://150.158.162.17:9501';` and, the only other use of the name,
`(process.env.OMNI_API_BASE_URL || DEFAULT_API_BASE).trim()`. That is P3's
`process.env.X || 'http://…'` with the literal named. Conditions: the literal is the whole
value of the declaration (`= 'http://…' + path` doesn't count), and every other occurrence
of the name in the file (member accesses included, conservatively) is right after
`process.env.X ||`/`??` or `os.environ.get("X", `. A constant also used directly
(`get(C2 + '/p')`) stays MEDIUM. Round 6 kept `const C2 = '…'; fetch(process.env.X || C2)`
MEDIUM in a test, as a scope line rather than from a measured loss; X1 changes that test
(it keeps the "also used directly" and "more than the literal" forms MEDIUM), so it is a
separate commit. **Owner question 1.**

## 3. Live result (real code, today's verdicts)

| | Reported | Benign | Unwanted | Malicious | Unverified | Precision |
|---|---|---|---|---|---|---|
| `main` `8ee117c` (shared baseline) | 1,469 | 771 | 620 | 48 | 30 | 46.42% |
| X2-X5 (`de28078`; subset replays) | 1,463 | 765 | 620 | 48 | 30 | 46.62% |
| X1-X5 (`d867e7a`, full replay) | 1,461 | 763 | 620 | 48 | 30 | 46.68% |

`relabel.py` lists no malicious, unwanted or unverified version whose decision changed; no
benign version is newly reported. Finding level, on the 395 versions where the two rules
fire: only the ten benign versions above change any `exfil-endpoint` / `hardcoded-ip`
finding. `teleton@0.11.8` gains `npm.dependency.non-registry` in every replay, also with
`8ee117c`'s own code (`teleton-base.jsonl`): a difference between today's replay and the
shared baseline, not this change. The full replay shows the same Stage 1 drift on 12 more
benign versions (`npm.dependency.non-registry` added: `package-registry-manager` ×3,
`@blockrun/franklin` ×2, `trac-peer` ×2, `slack-axi`, …); this change touches no Stage 1 rule
and every one of them is reported before and after.

## 4. DataDog check (`vm-day1`)

- **Rule level** (`s2dd-part1/*.jsonl`, `s2dd-f3r-*.jsonl`, final rules = `d867e7a`): every
  one of the 1,202 malicious samples where `exfil-endpoint` or `hardcoded-ip` fires, plus 121
  more from `dd-mine.keys`, decrypted in memory (`nofiles` 0). 1,881 matches of the six
  cluster rules, **none changes**: no sample's URL sits in an `example` value, an option
  declaration, a `.has(`-only set or a fallback-only constant, and the one Telegram prefix
  written as a bare literal (`@eooce/sbx@2.0.8`'s string-array entry) is not assigned and is
  in a collecting file.
- **`pipeline+4`** (`dd-pair-*.jsonl`, both codes, own hard-linked data dir): `@eooce/sbx@2.0.8`
  (the X4 near-miss) and `@optimystic99/dev-utils@1.0.21` (a `function-require` loader):
  reported with the same score, reasons and findings by both.
- **0 malicious samples lost.** Every sample's Stage 2 output is identical, so its
  `pipeline+4` decision is too.

## 5. Rejected or not built

- **Telegram notifiers in a file that collects** (18 of the 22 remaining `exfil-endpoint`-alone
  benign: `@kvali/cli`, `nottoday`, `zipy-agent`, `rbzz-backup`, …). Each file really does
  one of v8's collection things (`child_process` for a CLI's other commands, `sendPhoto` of
  the user's own photos, `os.hostname()` in an alert title, `readdirSync`). The owner kept
  "collects nothing" over the whole file (L4 rejected) and rejected the environment-token and
  templated-token exemptions; nothing narrower separates them from `@eooce/sbx` or
  `github-badge-bot`.
- **A named `DEFAULT_*` constant by its name alone** (`dsh-pond`'s `POND_DEFAULT_BASE`,
  `n8n-nodes-c14`'s `DEFAULT_B46_BASE_URL`, `@yun_zhan/cockpit`'s `PROD_BACKUP_BASE_URL`):
  these are probed or assigned, not environment fallbacks; a name is what a stealer
  chooses too. X1 asks how the constant is used instead.
- **Config and data files by type** (`@gdpisen/idock-cli`'s `config/release.json`,
  `@us_momo`'s `company-public.json`, `bbf-mint-cli`'s `release.json`, `oa`'s one-host
  `sources/*.json`, `@humanode-hyperlane/registry`'s chain metadata): `.json`/`.yml` stay out
  of `IP_DATA_FILES` on purpose (`dsh-model-pipeline@0.10.4`, unwanted, hardcodes its
  provider in YAML); each file names too few hosts for P4's catalog.
- **`function-require`** (10 benign alone): as round 6 found, the benign loaders pass a
  variable (`Function('require', result.code)`, `new Function("require", source)`), the
  `chai-as-*` shape. Narrowing v2's "loads remote" test (`\bresponse\b` matched
  `@locus-ui/mail`'s HTTP *server* handler) would remove 1 version and weaken the test for
  request-style HTTP clients; the bundles (`@roundertools/sdk`, `durerjs`) load remote
  somewhere in the bundle, which is the rejected L4 question again. Not built.
- **`webhook-placeholder`** (3 benign alone, 1 unwanted alone): `hub-launch@1.44.2` (unwanted)
  is reported by exactly this rule, for `_EXAMPLE_LINE = '// updateNotificationUrl:
  "https://hooks.slack.com/services/T0/B0/secret"'`, the same shape as `@rebasepro/cli`'s
  help example. Any lowering loses it.
- **`encoded-url`** (3 benign): round 6's reason holds (the same literal the `chai-as-*`
  family `atob`s).
- **`code.function-constructor`** (Stage 3; 1 benign alone, 5 positives alone): not this
  stage.
- **One-version shapes left alone:** SSRF test vectors (`@exponential_app/engine`), a URL
  paired with a pinned CA (`@yanjijinxiao/agent-bridge`), BigCommerce sample payloads under
  no `example` key (`@prismatic-io/components-bigcommerce`), an obfuscated array called
  through an unknown method (`@sleep2agi/agent-network` preview.217, which P kept on purpose),
  a shell `bot$t` after `t=<bot_token>` (`@todoforai/tfa-webfetch`).

## 6. Owner questions

1. **X1 (constant fallback), commit `d867e7a`.** It reverses round 6's choice to keep
   `const C2 = '…'; fetch(process.env.X || C2)` MEDIUM; measured, it removes 2 benign
   versions and touches no positive live or on `vm-day1`. Keep, or drop the commit
   (`de28078` stands alone)?

## 7. How to reproduce

Scripts in `~/kitsunox-scratch/r7/X/scripts/` and `my/` (read-only on `data/`; Python `-I`,
`nice -n 19`, `systemd-run --user --scope -p MemoryMax=4G`, the full replay under
`r4/heavy.lock`). Outputs in `~/kitsunox-scratch/r7/X/out/`; frozen sources `base/`
(`8ee117c`), `fix2/`, `fix3/` (final code) and `head/` (`d867e7a`).

- `my/alone.py BASE RULE`: the versions a rule reports alone, with matches and notes.
- `k_replay.sh SRC OUT KEYS.csv|full`; `p_merge.py`, `relabel.py`, `my/diff.py`: the live
  table and every changed version.
- `p_s2dd.sh FIX TAG` → `s2dd-*.jsonl` (rule level, `vm-day1`); `p_ddpair.sh` for
  `pipeline+4` with both codes on any sample whose rule output changes.
