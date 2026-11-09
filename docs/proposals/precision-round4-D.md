# Proposal: precision, round 4, agent D (Stage 2 content rules)

> **Status:** built 2026-11-10, before the rule freeze (2026-11-12 00:00Z), for the owner's
> review. Two Stage 2 commits: `2fe6805` (D1-D5: `static.exfil-endpoint` v8,
> `static.hardcoded-ip` v5, `static.function-require` v2) and `c256721` (D6:
> `static.obfuscated` v2, kept separate so it can be dropped on its own). **Both are
> zero-loss as measured. Live, real code: 1,787 → 1,727 reported, all 60 removed versions
> benign (60 packages); 0 malicious, unwanted or unverified version stops being reported.
> `vm-day1`: of the 1,216 malicious samples on which a touched rule fires at MEDIUM or above,
> 5 change at the rule level and all 5 are still reported by `pipeline+4`: 2,708 reported
> before and after.** Precision of a report (malicious + unwanted, unverified left out)
> 15.42% → 15.97%.
> **Builds on:** [round 3](precision-round3.md) (method, harness, its rejection of Telegram
> F3a), [round 2](precision-round2.md) sections 6-8, decision
> [0015](../decisions/0015-reviewer-verdicts.md) with all addenda.

## Summary

Round 3 rejected lowering Telegram `bot${token}` because the malicious samples often hide
the token (XOR, base64, environment). The question this round asks instead is *what is
sent*. Every `vm-day1` sample with a Telegram bot API URL, and every sample with a bare
`webhook.site` or a tunnel's bare suffix, collects something in the same file: it reads the
hostname or public IP, runs commands, walks directories or uploads files, names a credential
store or a wallet secret, dumps the environment, or writes a token literal. The live benign
notifiers do none of that: they post a message the caller wrote to the caller's own bot.

| # | Rule | What becomes LOW (weight 1, with a note) | Benign removed | Positives at risk → lost | `vm-day1` at rule level → lost |
|---|---|---|---|---|---|
| D1 | `exfil-endpoint` v8 | Telegram bot API URL with a handed token (`bot${cfg.token}`, `"…/bot" + t`, `bot{{T}}`, PHP `'…/bot'.$t`) in a file that collects nothing | 30 | 1 unwanted loses the HIGH (`@phigon/superagent@0.1.0`), stays reported → 0 | 0 of 18 Telegram samples change |
| D2 | `exfil-endpoint` v8 | `webhook.site` with no bin id (UUID) within 300 characters, no subdomain, in a file that collects nothing | 2 | 0 → 0 | 2 change (`@rdateam/godbles@0.1.2`, `node-calculator-7b82@2.4.0`), still reported → 0 |
| D3 | `exfil-endpoint` v8 | a tunnel's bare suffix (`endsWith(".trycloudflare.com")`, `allowedHosts: [".ngrok-free.app"]`, `https://….trycloudflare.com`) and `api.trycloudflare.com`, in a file that collects nothing | 4 | 0 → 0 | 0 change |
| D4 | `hardcoded-ip` v5 | a URL on a comment line (`//`, `# `, an open block comment, `<!--`) | 5 | 0 → 0 | 3 change (`awetz@99.9.18`, `byteplus-platform-runtime`, `c-monitor-dashboard`), still reported → 0 |
| D5 | `function-require` v2 | a module wrapper (`"require", "module", "exports", code`) in a file that neither fetches nor decodes | 13 | 0 → 0 | 0 of 38 change |
| D6 | `obfuscated` v2 | obfuscation in a bundler's hashed chunk under `assets/` (stage path test) | 6 | 0 → 0 | no sample's obfuscated finding is in such a path |
| | **All** | | **60** | **0** | **0** |

"In a file that collects nothing" is `_collects` in `rules/static.py`: none of machine identity
(`os.hostname()`, `userInfo()`, `networkInterfaces()`, `whoami`, `$(hostname)`, public-IP
services), a directory walk or a file upload (`readdirSync`, `createReadStream`,
`sendDocument`/`sendPhoto`/...), a process (`child_process`, `execSync`, `subprocess`, ...),
a wallet secret (`mnemonic`, `seed phrase`, `private key`, `keystore`), a Telegram token
literal, `static.sensitive-path`'s credential stores or `static.env-harvest`'s whole
environment. A match on an install hook's line in `package.json` is never lowered.

## 1. Data and method

Round 3's harness, unchanged except where noted (`~/kitsunox-scratch/r4/D/scripts/`):

- **Live.** `replay.py SRC CANDS OUT` runs Stages 1-4 with `SRC`'s real code per verdicted
  version (3,716 in 118 runs; candidates in `r4/shared/cands.jsonl.zst`). Baseline =
  `round4-base` (round 3's `fix.jsonl`).
- **Exhaustive subset.** Every change here only lowers a match of the four rules, so a
  version can change only if one of them has a finding there in the baseline: at MEDIUM or
  above (274 versions: 219 benign, 28 malicious, 16 unwanted, 11 unverified), or LOW only
  (209 more), where a different "not new" comparison could raise it. A version where none of
  the four fires has the same findings with either code. All 483 were re-run with the fix
  code (`union-fix2.jsonl`); the 274 were also re-run with the base code under the same
  conditions (`sub-base.jsonl`), which reproduces round 3's `fix.jsonl` on all 274 exactly.
  The live table below is the baseline's with these 483 replaced.
- **One bug the LOW-only versions found.** v8's notes depend on the whole file, and Stage 2
  compared a match with the previous version's by rule and explanation, note included. In
  `@stacksjs/ts-cloud@0.16.75` the base's notifier chunk was quiet (LOW, with the note) and
  the new chunk also imports `child_process` (HIGH, no note), so the old URL read as new and
  the version was newly reported. `_key` now leaves the file-dependent notes out
  (`CONTEXT_NOTES`), as it leaves out numbers; with that, 0 versions are newly reported.
- **`vm-day1`, two steps.** (1) The rule itself (`s2rule.py`: the rule's `analyse` on every
  file of the sample, decrypted in memory by the predictor, nothing run) with the base and the
  fix code on every malicious sample where `exfil-endpoint` (1,101), `hardcoded-ip` (80) or
  `function-require` (38) fires at MEDIUM or above (1,216 distinct samples). (2) `pipeline+4`
  (`dd.py`, fresh in-memory Stage 2 cache, as the brief asks) with the fix code on every
  sample whose rule output changed. For D6, the recorded paths of every sample's obfuscated
  findings (E's round-4 baseline `dd-r4base.jsonl`).

## 2. The fixes

### D1-D3. `static.exfil-endpoint` v8: what is sent

The 18 `vm-day1` malicious samples with a Telegram bot API URL, and what their file does
besides (`cosig.py`):

| Samples | Token | Same file also |
|---|---|---|
| `@eooce/idx` 1.0.3/1.0.6, `@eooce/sbx` 2.0.5/2.0.8, `node-navsbx@1.0.0` | from the environment | `child_process` (downloads and runs proxy binaries), `.ssh`/key paths |
| `foundry-toolkit@1.0.12` (`cast.js`, `postinstall.js`) | base64 | `os.hostname()`, `child_process`, the environment |
| `github-badge-bot` 1.5.5/1.6.9/1.7.8 | XOR+base64 in another file | `sendDocument` of session files, `createReadStream` |
| `web3js-wallet` 1.0.28/1.0.36, `axcors@12.7.8`, `isood@13.4.6`, `@toprank/partner` | literal | directory walks from `process.cwd()`, `sendDocument`, `whoami` |
| `pa-marked@99.1.8`, `@phoenix-common/angular-frontend-library` | literal, in a hook | `.env` or `/etc/passwd` in the hook |
| `base-x-64@0.0.5` | in an obfuscated string array | (not a handed token: stays HIGH) |
| `@crysnovax/baileys@2.7.6` | the user's alert config | reported by other rules |

None of them is lowered: 0 of 18 change at the rule level. The live benign ones are SDKs and
notifiers (`@quecue/notify-core`, `*/sendkit-core` ×4, `homebridge-goodwe-es`,
`release-radar`, `@plaios/telegram`, `xminal`'s bridge...). Telegram files that collect stay
HIGH even when benign (`agouti` sends `hostname()` in its alert, `rbzz-backup` uploads photos,
`candle-bot-core` imports `child_process`): the rule can't tell the user's own bot from
someone else's, and it doesn't try.

D2: on `vm-day1`, 450 of the 503 samples naming `webhook.site` write a bin id right after it,
and 27 more name the host alone (`hostname: 'webhook.site'`), typically with the id as a
separate `path: '/<uuid>'` a line later (hence the 300-character window); the 2 that change name it in prose or as `YOUR_WEBHOOK_ID_HERE`
and are reported by their install code anyway. D3: `api.trycloudflare.com` is Cloudflare's
own registration API (`dsh-remote-hub`), a bare suffix is a host check; a quick tunnel's
name, a `0.tcp.in.ngrok.io` TCP tunnel and a bare suffix in a file that collects stay HIGH.

### D4. `static.hardcoded-ip` v5: comment lines

Commented-out base URLs (`// return 'http://47.108.170.69:5401'`, `// baseURL: '…'`), JSDoc
alternatives (`@fnndsc/stratus`), vendored C header comments (`@literm/...` mbedtls). Not a
shebang, a CSS `#id` selector, code after `/*! … */` on the same line or a trailing `// prod`
comment after code. On `vm-day1` 77 of 80 samples have their IPs in code; `awetz` has one in
a comment only and is reported by its install code.

### D5. `static.function-require` v2: module wrappers

`Function("require", "module", "exports", code)` hands the code its own `module`/`exports`:
the shape of a CommonJS loader (config loaders, esbuild/sucrase sandboxes, parity tests). In a
file with no network call and no decoding (`_LOADS_REMOTE`: `fetch(`, `axios`, `http(s).get`,
`XMLHttpRequest`, `.json()`, `response`, `base64`, `atob(`, `decrypt`, `decipher`,
`fromCharCode`) it is LOW. All 38 `vm-day1` samples keep MEDIUM: 32 pass `require` alone
(`chai-as-*`, `aes-decode-runner-pro`, `express-session-handler`), and the 6 module wrappers
(`alpha-replicator`, `mongos-api`, `odds-analyzer`, `tw-modern-ui`, `velora-kit`, `@subql/
common`) fetch or decode in the same file.

### D6. `static.obfuscated` v2: hashed browser assets (separate commit)

`hel_dist/assets/index-C6-GNDFy.js` (`@melt-js/comps-*` ×5), `dist/apps/even-g2/assets/
index-BKW-Hu3E.js` (`@amoshydra/oktoso`): Vite build output a site serves; Node never loads it.
A path test in `stages/static.py` (`_browser_asset`: an `assets/` directory and a content hash
`unhashed` recognises), like `hardcoded-ip`'s data files. **Recall risk, the reason it is a
separate commit:** a drainer injected into a CDN-served asset of a UI package (the 2025 `chalk`
/`debug` wave targeted browsers, though through `index.js`) would be LOW here. Not `.html`:
`dzcvhfruwluwe@1.0.1` and `mobiwaefhxc3@1.0.0` are an obfuscated `index.html` and nothing else.
`@amoshydra/oktoso@0.1.0` would go too in production; the replay keeps its recorded finding
(tarball gone).

## 3. Where the benign reports come from after D1-D6

Decisive for (dropping the rule to LOW unreports), on the 274 versions, before → after:
`exfil-endpoint` 81 → 46 benign (1 unwanted unchanged), `obfuscated` 61 → 55 (3 malicious, 8
unverified unchanged), `hardcoded-ip` 38 → 33 (3 malicious), `function-require` 24 → 11 (1
malicious). What is left: Telegram and tunnel code in files that collect (agent frameworks'
bundled `cli.js`, `agouti`), lists and prose that v5-v7's list tests don't see
(`@ulkoro/skillsentry`, `retrohound`, `shield360`), vendors' own backend IPs in code, vendor-
obfuscated products, module sandboxes in files that also fetch.

## 4. Live result (real code)

| | Reported | Benign | Unwanted | Malicious | Unverified | Precision |
|---|---|---|---|---|---|---|
| `round4-base` (round 3's `fix.jsonl`) | 1,787 | 1,486 | 224 | 47 | 30 | 15.42% |
| D1-D5 (`2fe6805`) | 1,733 | 1,432 | 224 | 47 | 30 | 15.92% |
| D1-D6 (`c256721`) | 1,727 | 1,426 | 224 | 47 | 30 | 15.97% |

Removed per fix: D1 30, D2 2, D3 4, D4 5, D5 13, D6 6. No version is newly reported (all 483
checked); positives whose touched findings changed: only `@phigon/superagent@0.1.0` (unwanted, a
global-install skill copier), whose Telegram channel adapter is now LOW; it stays reported by
`npm.install-hook` and `npm.install-script-code`. No unverified version changes at all.

## 5. DataDog check (`vm-day1`)

- **Baseline** (`round4-base`, E's `dd-r4base.jsonl`): 2,708 of 3,444 reported.
- **At risk:** 1,216 samples with `exfil-endpoint`, `hardcoded-ip` or `function-require` at
  MEDIUM+. Rule level, base vs fix: exfil 2 of 1,101 change, IP 3 of 80, function-require 0
  of 38. D6: none of the 722 samples with an obfuscated finding has one in an `assets/` chunk.
- **`pipeline+4` with the fix on the 5 that change** (`ddfix2.jsonl`): all 5 reported
  (`@rdateam/godbles` score 6 and `awetz` score 6 by `npm.install-script-code`;
  `node-calculator-7b82`, `byteplus-platform-runtime`, `c-monitor-dashboard` by their install
  hooks). **2,708 → 2,708, 0 lost.** The `_key` change can't make a sample worse than the
  base: it compares matches across versions exactly as the base code did.

## 6. Rejected or not proposed

- **`hardcoded-ip`: LOW in a file that collects nothing (D1's test for IPs).** Would remove
  most vendor-backend IPs, but loses 3 `vm-day1` samples the IP alone reports:
  `@pwnedshell/nn@1.0.13` (browser exfiltration through `window.location = http://IP?q=
  ${btoa(...)}`), `@typescript_eslinter/eslint@1.0.0` (screenshots and keystrokes posted to
  `http://178.63.70.109:5050`), `akasearch@0.6.1`. What they collect (screens, clipboard,
  fetched page data) is not a capability a regex names reliably.
- **`obfuscated`: install-hook or load reachability, newness.** The 3 live malicious
  (`char-ai-sdk`, `character-ai-sdk`, `tavern-ai-sdk`) have no install hook (their main entry
  imports `build-cache.mjs`) and are new packages, like most vendor products; 16 `vm-day1`
  samples of the 2025 `chalk`/`debug` wave, reported by this rule alone, obfuscate the main
  `index.js`. "The previous
  version was obfuscated identically" is already LOW (`_demoted`, same rule and explanation up
  to numbers). Decoding obfuscator.io's base64 string arrays (its alphabet is base64 with the
  cases swapped) to look for capabilities is possible but needs a vocabulary for browser
  drainers too; not built before the freeze.
- **`obfuscated` in `.html`/`.svg`:** loses `dzcvhfruwluwe@1.0.1`, `mobiwaefhxc3@1.0.0`.
- **`function-require` without the module-wrapper condition (any parameter list in a quiet
  file):** `aes-decode-runner-pro` and `postcss-minify-selector-parser` would then be kept only
  by the word "decode" in their helper names; `Function("require", code)` alone is the
  second-stage loader's shape. Not measured further.
- **A whole literal `'https://api.telegram.org/bot'` (a base-URL constant) as a handed
  token:** would add `colana`, but `base-x-64@0.0.5` keeps exactly that literal in an
  obfuscated string array with no co-signal.

## 7. For agent E (score-only reports from Stage 2 LOWs)

On round 3's live replay, 42 reported versions have no severe finding (score-only): 40
benign, 2 unwanted. **19 benign and 1 unwanted (`hub-launch@1.44.2`) fall below
`REPORT_SCORE` without the Stage 2 LOWs**; all 20 are a weak-alone MEDIUM
(`publish-method.downgrade` 16, `webhook-placeholder` 4) plus `process-exec`, `network`,
`npm-publish`, `dynamic-code`, `env-harvest` LOWs. On `vm-day1` no reported malicious sample
is score-only through Stage 2 LOWs (1 score-only sample, which stays without them). Not
changed here (`decide` and `LOW_CAP` are E's).

## 8. Owner questions

1. Keep D1-D5 for the freeze (54 benign, 0 positives, 0 `vm-day1`)?
2. D6 (6 benign): is a hashed browser asset's obfuscation LOW acceptable, given the CDN
   drainer risk? It is its own commit.
3. The v8 note says what the file does *not* do. A stealer that sends from one file and
   collects in another (a `tg.js` helper) gets LOW for the URL; its collecting file still has
   `sensitive-path`/`env-harvest` LOWs and Stage 3's capability findings. Acceptable?

## 9. How to reproduce

Scripts in `~/kitsunox-scratch/r4/D/scripts/` (read-only on `data/`; Python with `-I` through
the `py` wrapper, `nice -n 19`, `systemd-run --user --scope -p MemoryMax=4G`; full runs under
`r4/heavy.lock` with 8G). Outputs in `~/kitsunox-scratch/r4/D/out/`.

- `mine.keys` (the 274), `mine-low.keys` (the 209), `union.keys`; `run_sub.sh` →
  `sub-base.jsonl`; `replay.py SRC CANDS OUT 2 @union.keys` → `union-fix2.jsonl` (frozen copy
  of the fix in `r4/D/fix2/src`); `compare.py`, `touched.py`, `posdiff.py`, `analyze.py`,
  `show.py`: sections 2-4.
- `s2rule.py SRC RULE dd KEYS` and `s2diff.py`/`changed.py`: rule-level `vm-day1` check
  (`s2-exfil-*.jsonl`, `s2-ip-*.jsonl`, `s2-fr-*.jsonl`); `dd.py SRC OUT 2 ddrisk.keys` →
  `ddfix2.jsonl`; `obfpath.py`: D6's paths.
- `cosig.py`, `cosigs.py`, `cosigs_fr.py`, `ddctx.py`, `ddtail.py`, `lshow.py`: what the
  samples' files do besides (sections 2 and 6); `lowacc.py`: section 7.
