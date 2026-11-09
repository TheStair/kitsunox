# Proposal: precision, round 3 (narrow benign shapes, measured with the real code)

> **Status:** built 2026-11-09, before the rule freeze (2026-11-12 00:00Z), for the owner's
> review: X1-X5 in Stage 2 (`static.exfil-endpoint` v7, `static.hardcoded-ip` v4), X6 in
> Stage 3 (`npm.install-build-tool` v2), X7 in Stage 4 (`npm.dependency.fresh-foreign` v3).
> Owner's instruction: "keep improving the rules to reduce false positives"; on severity, "do
> whatever preserves accuracy while reducing false positives". **Result, with the real code on
> all 3,716 verdicted live versions: 1,834 → 1,787 reported, all 47 benign (46 packages,
> 3.1% of the 1,533 benign reports); 0 malicious, unwanted or unverified version stops being
> reported, and no positive's findings for the touched rules change at all. `vm-day1`: all
> 1,312 malicious samples a fix could touch, re-run with `pipeline+4`: 1,309 reported before
> and after, 0 lost ([section 5](#5-datadog-check-vm-day1)).** Precision of a report
> (malicious + unwanted, unverified left out) 15.02% → 15.42%.
> **Commits:** Stage 2 `cc02437`, Stage 3 `fb511b7`, Stage 4 `874bf74`.
> **Builds on:** [round 2](precision-round2.md) (its sections 7 and 8: rejected ideas and owner
> decisions), [round 1](stage1-precision.md), decisions
> [0015](../decisions/0015-reviewer-verdicts.md) (what counts as a positive, all addenda) and
> [0019](../decisions/0019-live-evaluation.md).

## Summary

The benign reports left after rounds 1-2 and the S1-S3 explanations are mostly shapes the
owner has already ruled on: install code that changed (F1, rejected), any hook without a risky
capability (rejected), Telegram `bot${token}` (F3a, rejected), own-owner git dependencies
(F6a, rejected) and vendor-obfuscated products (rejected). What is left to cut without losing
a positive is a set of small, narrow shapes. X1-X6 each name a thing that cannot be what the
rule looks for (a paste nobody else can edit, a host nothing connects to, a header lookup),
not a thing that is merely usually benign; X7 follows the downgrade rule's precedent for
prereleases, which npm installs only when asked.

| # | Rule (stage) | What becomes LOW (or no finding) | Benign reports removed | Positives at risk → lost | `vm-day1` at risk → lost |
|---|---|---|---|---|---|
| X1 | `static.exfil-endpoint` v7 (2) | `pastebin.com/N21QzeQA`: the paste core-js cites in a comment | 8 (`@mnykj/alleditor*` ×6, `@streamlayer/web-polyfills`, `dh-vue-poster`) | 0 → 0 | 1,101 (exfil, X1-X4 together) → 0 |
| X2 | `static.exfil-endpoint` v7 (2) | a host pattern `*.oastify.com`, `*.m.pipedream.net` | 3 (`@pinnacleplugins/*` ×2, `@ritualdev-lab/agentshield`) | 0 → 0 | (with X1) |
| X3 | `static.exfil-endpoint` v7 (2) | a whole entry of a newline/tab/comma-separated domain list | 3 (`disposable-check`, `is-temp-email`, `utalis-desk`) | 0 → 0 | (with X1) |
| X4 | `static.exfil-endpoint` v7 (2) | an OAST host whose own label is a placeholder (`YOUR-COLLABORATOR-ID.oastify.com`) | 1 (`@ohhaiohhai/burp-widgets`) | 0 → 0 | (with X1) |
| X5 | `static.hardcoded-ip` v4 (2) | example addresses (`1.2.3.4`, `123.45.67.89`, `93.184.216.34`, ...) LOW; AliDNS, DNSPod, 114DNS no finding | 10 (`pocket-harness`, `dsh-zen-remote`, `@ojcp/conformance`, `my-singbox`, ...) | 0 → 0 | 80 → 0 |
| X6 | `npm.install-build-tool` v2 (3) | a `binding.gyp` that only looks up `node-addon-api`/`nan` headers counts as running no command | 9 (`@lakutata/*` ×3, `@ohos-ports/*` ×4, `@memoryprocess/bindings`, `@mongodb-js/macos-export-certificate-and-key`) | 0 → 0 | 4 → 0 |
| X7 | `npm.dependency.fresh-foreign` v3 (4) | the dependent is a prerelease | 13 (`@sparkelf/dsh-*` ×4, `@doubao-dev/*` ×3, `@paean-ai/harness-profile`, `@hatk/hatk`, ...) | 0 → 0 | 131 fire, none a prerelease → 0 |
| | **All seven** | | **47** (46 packages) | **0** | **1,312 → 0** |

Rejected, each with the measurement that rules it out (section 6): Telegram templated tokens
without a token literal (loses `github-badge-bot`, `foundry-toolkit`, `@eooce/sbx`); echo-only
install hooks (loses 4 DataDog samples reported only by their `echo` hook); a narrower
downgrade co-signal (loses the unwanted `@hithink-tech/hithink-finance-cli@0.2.0`); revived with
only popular dependencies (loses `xrpl@2.14.2`); GitHub-release / codeload / `pkg.pr.new`
dependencies (the same trust as the git dependencies 13 positives use).

## 1. Data and method

- **Versions.** Every version with a reviewer verdict (`data/verdicts/npm.jsonl`, last record
  per version): 3,716 in 118 runs (Oct 29 to Nov 9). Their recorded candidates were copied
  out of each run's `correlate.jsonl` first, so later prunes don't matter.
- **The real code, end to end, per version** (`replay.py`, scripts below): Stage 1 `triage`
  with the run's `as_of` and live routing (`code_route`, `fetch_limit`); Stages 2-3 on the
  version's tarball against its previous version's (Stage 2 file and artifact rules through
  `new_contents`/`content_matches`, Stage 3 `code_change` + `CODE_RULES`, as
  `evaluation.static_eval` does); Stage 4 `correlate` with `CORRELATION_RULES`, which runs
  `explained` and `decide`. Tarballs come from the run's captured blobs, else from the registry
  through a scratch fetch store (integrity-checked by `fetch_artifact`), read in memory with
  `extract_tar_gz`; nothing is run. 2,975 versions were recomputed this way, 642 were not
  routed to Stage 2 (Stage 1 and 4 only), 99 kept their recorded Stage 2/3 findings (tarball
  gone from the registry, or a base that was read at run time and is gone now).
- **Stage 4 context.** Findings that need outside records (dependency lookups, known malware,
  repository comparison) are taken from the recorded candidate. `fresh-foreign` (X7) is
  regenerated by the rule's own code from registry records rebuilt out of its evidence (first
  version and time, the dependency's accounts): on the baseline code it reproduces all 34
  recorded findings exactly.
- **Baseline = today's `main` (`cdcb90c`), fix = this branch, same harness.** Fidelity: on the
  239 verdicted versions of the 20 runs scored with today's Stage 4 rules, the replay agrees
  with the run's own decision on 234; the 5 others (all benign) the run reported and the replay
  doesn't (in-batch diff bases, files over a limit). Both sides use the same replay, so this
  cancels in the comparison.
- **Positives** are `malicious` and `unwanted` verdicts; `unverified` is left out of precision
  but every one is still checked for loss (decision 0015).
- **DataDog (`vm-day1`).** The real `pipeline+4` predictor (`evaluation.static_eval.Correlated`)
  on every one of the 3,444 malicious samples, one process per sample, in a hard-linked scratch
  data directory, repository comparison off (it can only add findings while the clearing
  switches are off): 2,708 reported. A fix can only unreport a sample on which its rule fires at
  MEDIUM or above (exfil, IP, fresh-foreign) or whose hooks are all build tools (X6): 1,312
  samples, re-run with the fix code; a sample that falls below the bar would be re-decided with
  the repository findings of the last full dump.

## 2. Where the benign reports come from now

Today's code on the 3,716 verdicted versions reports 1,834: 1,533 benign, 224 unwanted, 47
malicious, 30 unverified (precision 15.0%). For each rule, the reported versions it is
*decisive* for (dropping it to LOW unreports them):

| Rule | Benign | Positives (unverified) | Benign shapes (verdict notes) |
|---|---|---|---|
| `npm.install-script-changed` | 340 | 65 unwanted (2) | cosmetic edits of install files; the 65 unwanted are user-wide agent installers caught the same way (F1, rejected) |
| `npm.install-hook` | 247 | 11 unwanted, 1 mal. (4) | 125 hooks `node <file>` with no recognised shape (rejected class); native builds 29; `echo` 5; tools (`playwright install`, `prisma`, `npm run ...`) |
| `npm.dependency.non-registry` | 152 | 9 mal., 4 unwanted (3) | git URLs 52 and `github:` 32 (where the positives are too), codeload 27, GitHub releases 16, `pkg.pr.new` 10 |
| `static.exfil-endpoint` | 96 | 1 unwanted | Telegram `bot${token}` 50, bare tunnel suffixes and help text 13, `webhook.site` 11, core-js's pastebin comment 8, lists and patterns |
| `static.obfuscated` | 61 | 3 mal. (8) | vendor-obfuscated products (rejected: same test as the `*-ai-sdk` stealers) |
| `npm.combination.revived-with-new-dependency` | 55 | 0 | 51 add only popular or own-scope packages; 24 of those add a maintainer too |
| `npm.publish-method.downgrade` | 48 | 1 unwanted | a maintainer's hand publish: MEDIUM with `dependency.added` plus LOWs at exactly 6; watched `gitHead` drops |
| `static.hardcoded-ip` | 47 | 3 mal. | vendors' own backends (a raw IP is the finding), `1.2.3.4`-style examples 8, public resolvers 3 |
| `npm.dependency.fresh-foreign` | 33 | 0 (1) | 13 prereleases depending on their ecosystem's newest package; DeepSeek / Earendil / W3C packages |
| `static.function-require` | 24 | 1 mal. | module sandboxes, build scripts, 3 tests |
| `npm.version.suspicious` | 22 | 1 mal. | dependency-confusion placeholders `99.x` with no code (OSV labels these malware) |

## 3. The fixes

### X1-X4. `static.exfil-endpoint` v7: what cannot be an endpoint (Stage 2)

LOW, weight 1, with a note (like v6's placeholders; a LOW match doesn't count toward the
three-a-file cap, so it never hides a real one):

- **X1, core-js's paste.** `pastebin.com/N21QzeQA`, exactly (paste ids are case-sensitive; a
  paste can be changed only by its author): core-js's comment about a Safari debugger crash,
  bundled into editors and polyfill builds. Any other paste, or this one through `/raw/`,
  stays HIGH.
- **X2, host patterns.** A host written as `*.host` (`"*.oastify.com"`,
  `` `*.m.pipedream.net` ``): allow and deny lists. Nothing connects to a `*`. Markdown
  emphasis (`**webhook.site**`) is not a pattern.
- **X3, separated lists.** v6's list test for unquoted entries: the host is a whole entry
  between newlines, tabs or commas (written out, or as `\n`/`\t` escapes inside one string),
  with at least two other entries within 400 characters that are domains and not endpoints
  themselves. Disposable-mail lists and the Public Suffix List (`...\nap.leg.br\nap.ngrok.io\n
  aparecida.br\n...`). A table of nothing but ngrok region hosts stays HIGH, as v5 decided.
- **X4, OAST placeholders.** An OAST host (`oastify.com`, `burpcollaborator.net`,
  `interact.sh`) whose own label is a written placeholder (`_OAST_PLACEHOLDER`: `your-…`,
  `xxx…`, `example`, `<…>`), with no digit and no template. Stricter than v6's tunnel test on
  purpose: the first version used that test and lowered
  `YourServer929w1e528by00hxp38ah5mh1asgj4bs0.oastify.com` in `@frontend-clients/core@99.0.8`
  (`vm-day1` malicious; still reported through other matches), a registered id behind a word;
  and `${id}.oastify.com` is how DNS exfiltration builds its host. A registered id
  (`94bp9h8f….oastify.com`, `dependencykfeg@2.1.3`, unwanted) stays HIGH.

Live: 15 benign removed (X1 8, X2 3, X3 3, X4 1), 2 more lose the finding but stay reported.
No positive's `exfil-endpoint` finding changes.

### X5. `static.hardcoded-ip` v4: example addresses and more resolvers (Stage 2)

- Example addresses (`EXAMPLE_IPS`: `1.2.3.4`, `4.3.2.1`, `12.34.56.78`, `123.45.67.89`,
  `11.22.33.44`, and `93.184.216.34`, example.com's long-standing address) are LOW, weight 1:
  input placeholders (`placeholder: 'https://1.2.3.4:8443'`), help strings, redaction tests.
- The public-resolver exemption (v2) gains OpenDNS's second address and the big Chinese
  resolvers (AliDNS `223.5.5.5`/`223.6.6.6`, DNSPod `119.29.29.29`, 114DNS), written in DoH and
  proxy configs as `https://223.5.5.5/dns-query`.

Live: 10 benign removed, 1 more loses the finding. The 3 malicious it is decisive for
(`38.242.235.206`, `121.199.24.94`) are untouched.

### X6. `npm.install-build-tool` v2: header lookups are no command (Stage 3)

F2 (round 2) explains `npm.install-hook` when every hook is a build tool and `binding.gyp`
runs no command. Most native add-ons' `binding.gyp` has one kind of command: asking `node`
where `node-addon-api`'s or `nan`'s headers are (`<!(node -p "require('node-addon-api').include")`,
`<!@(node -p "require('node-addon-api').gyp")`, `<!(node -e "require('nan')")`). v2 does not
count a command that is exactly one of those (`HEADER_LOOKUP`, a full match); any other
expansion or gyp action still counts (`@atedone/workspace-bootstrap@0.0.1`, unwanted, ran its
payload from a gyp action; `@lakutata/barcode`'s `node scripts/sources.mjs` keeps its hook
MEDIUM). The hook list is unchanged.

Live: 9 benign removed, 1 more loses the MEDIUM but stays reported. `vm-day1`: 4 malicious
samples have build-tool-only hooks (`duckdb@1.3.3`, `@mastra/node-speaker@0.1.1`,
`n8n-nodes-zalo-fevox@0.6.8`, `tree-sitter-iec61131-3-st@0.1.0`); none has `install-hook`
firing on a header-lookup-only gyp file (section 5).

### X7. `npm.dependency.fresh-foreign` v3: prereleases are LOW (Stage 4)

As `publish-method.downgrade` v3 decided for the same reason: npm installs a prerelease only
when asked for it by version or tag. The finding stays, LOW, weight 1, with a note. Alphas,
release candidates and canaries that depend on their ecosystem's newest package
(`@sparkelf/dsh-*@0.2.2-alpha.2` on DeepSeek's `@deepseek-ai/dsh-*`, `@doubao-dev/cli` canaries
on `mcp-apps-inspector`) were 13 of the 33 benign reports this rule carried alone. Not a
prerelease: `tailwind-animora@2.0.1` (unverified, still reported) and every `vm-day1` malicious
sample the rule fires on (131 of them: `@mastra/*` with `easy-day-js`, `axios@1.14.1`, ...).
**Recall risk:** a dependency-chain attack published as a prerelease and tagged `latest`
(Stage 1 can't see dist-tags) is LOW here; its other signals must catch it.

## 4. Live result (real code)

| | Reported | Benign | Unwanted | Malicious | Unverified | Precision |
|---|---|---|---|---|---|---|
| `main` today | 1,834 | 1,533 | 224 | 47 | 30 | 15.02% |
| X1-X7 | 1,787 | 1,486 | 224 | 47 | 30 | 15.42% |

47 benign versions (46 packages) are no longer reported; no version is newly reported. Of the
versions whose touched findings changed (exfil, IP, install hook / build tool, fresh-foreign),
none is a positive: not one malicious, unwanted or unverified version loses even a finding.

## 5. DataDog check (`vm-day1`)

- **Baseline.** Today's `pipeline+4` on all 3,444 malicious samples, per sample, repository
  comparison off: 2,708 reported (1,606 first releases, 1,102 follow-ons). The last full
  report (2026-10-31, with repository comparison) had 2,505; rules added since account for the
  difference.
- **At risk: 1,312 samples**: `exfil-endpoint` at MEDIUM or above on 1,101, `fresh-foreign` on
  131, `hardcoded-ip` on 80, build-tool-only hooks on 4. 1,309 of them are reported in the
  baseline; the other 3 (`duckdb@1.3.3`, `n8n-nodes-zalo-fevox@0.6.8`,
  `tree-sitter-iec61131-3-st@0.1.0`, all build-tool hooks) are not, with or without X6.
- **With X1-X7: 1,309 reported, 0 lost, 0 gained.** The touched findings changed on 4 samples,
  each a written placeholder lowered by X4 beside a real endpoint that stays HIGH
  (`hops-preset-jest@1.0.0` and `microsoft-cms-client` 99.0.0/999.0.0:
  `const COLLAB_DOMAIN = "your-collab-domain.oastify.com"` next to a real `webhook.site` id;
  `node-vfs-polyfill@2.0.5`: `e.g. http://xxxxxxxxx.oastify.com` in a comment, then a real
  collaborator id). No sample's `hardcoded-ip`, install-hook or `fresh-foreign` finding changes:
  none of the 131 samples `fresh-foreign` fires on is a prerelease, and `duckdb@1.3.3`'s
  header-lookup-only `binding.gyp` doesn't matter because its hook is unchanged from 1.3.2
  (`npm.install-hook` doesn't fire).
- **The first X4 lowered a real id.** With v6's tunnel placeholder test,
  `YourServer929w1e528by00hxp38ah5mh1asgj4bs0.oastify.com` in `@frontend-clients/core@99.0.8`
  became LOW (the sample stayed reported through two other HIGH matches); the stricter OAST
  test (section 3) keeps it HIGH. The final run used a fresh Stage 2 cache (see the devlog).

## 6. Rejected or not proposed

- **Telegram URLs with a templated token and no token literal in the package (a guarded F3a).**
  49 of the 50 benign Telegram reports have no literal `123456789:AA…` token anywhere. But on
  `vm-day1` the token is often not written out: `github-badge-bot` 1.5.5/1.6.9/1.7.8 keep it
  XOR- and base64-encoded in another file (`lib/encryption.js`), `foundry-toolkit@1.0.12`
  base64-decodes it, `@eooce/sbx@2.0.5` and `node-navsbx@1.0.0` read it from the environment.
  Also requiring "no base64 decoding in the package" keeps those only by coincidence and halves
  the gain (23 of 50). F3a stays rejected.
- **Echo-only install hooks (`"postinstall": "echo ..."`).** 5 benign live (`@cyrus-test/*`,
  `lilia-mcp`, `@buoy-gg/bug-links`, `@sriinnu/portpilot`), but 4 `vm-day1` malicious samples
  are reported only by such a hook: `contentful-app-entry-localization-matrix@7.7.7`,
  `node-pdfmake@7.7.7`, `surpaonchainagent@7.7.7` (`echo "code injection possible by golu"`)
  and `openwhisk-probot-builder@1.0.0` (`echo "takeover poc"`). Fails the DataDog bar.
- **Downgrade: count `npm.dependency.added` as a co-signal only for a foreign, unwatched
  dependency.** 26 benign reports would go (a maintainer's hand publish adding `@sentry/node`,
  own-scope packages), but `@hithink-tech/hithink-finance-cli@0.2.0` (unwanted: a postinstall
  installs skills user-wide) is reported only by the downgrade at exactly score 6, and the
  dependency it adds, `openid-client`, is watched.
- **Revived: LOW when every added dependency is popular (watched).** 34 benign; loses
  `xrpl@2.14.2` on `vm-day1`, still reported only by this rule (score 5; 3 without it): its 2.x
  line was dormant, its new dependencies (`@scure/*`, `@xrplf/*`, `eventemitter3`) are popular.
  Measuring dormancy from the package's last publish instead of the diff base loses it the
  same way. **For the owner, after the freeze:** the same with "no maintainer added" too keeps
  `xrpl` (4 maintainers added) and `@mastra/*` (`easy-day-js` is not watched) and removes 10
  benign; measured on the replay's notes, not built.
- **Non-registry: GitHub releases, codeload archives, `pkg.pr.new`, registry tarball URLs.**
  55 benign, 0 positives today, but a release asset or a commit archive carries the same trust
  as the git dependencies that 9 malicious and 4 unwanted live versions (and
  `@opensearch-project/opensearch` on `vm-day1`) use; F6a stays rejected.
- **Version placeholders `99.x` with no code (15 benign).** OSV labels these malware, and the
  reviewers' benign verdicts rest on behaviour; not proposed.
- **Test-named files (`*.test.js`, `*.spec.ts`) as files that don't run, for every Stage 2
  rule.** 4 benign; it changes every Stage 2 rule's demotion at once (a stage-level change
  without a rule version). After the freeze.
- **Install-script-changed, any hook without a risky capability, comments, obfuscated vendor
  products:** unchanged from rounds 1-2.

## 7. Owner questions

1. Keep X1-X7 for the freeze (47 benign, 0 positives)?
2. X7 makes a prerelease's fresh dependency LOW, as the downgrade rule does: acceptable, given
   that the rule can't see dist-tags?
3. After the freeze: revived with only popular dependencies and no maintainer added (+10)?

## 8. How to reproduce

Scripts in `~/kitsunox-scratch/agent-r3/scripts/` (read-only on `data/`; Python with `-I`
under `systemd-run --user --scope -p MemoryMax=8G`; outputs in `~/kitsunox-scratch/agent-r3/out/`):

- `extract.py`: copies the verdicted versions' recorded candidates (`cands.jsonl.zst`).
- `replay.py SRC CANDS OUT`: Stages 1-4 with `SRC`'s code per version (section 1);
  `analyze.py`, `show.py`, `rows.py`, `hooks.py`, `added.py`, `nrclus.py`: section 2;
  `compare.py`, `touched.py`: section 4; `ffcheck.py`: the fresh-foreign rebuild check.
- `mkdata.py`: the hard-linked scratch data directory; `dd.py SRC OUT N [KEYS]`: `pipeline+4`
  per sample; `atrisk.py`, `ddhooks.py`, `ddgrep.py`, `ddchange.py`: section 5 and the
  rejections.
