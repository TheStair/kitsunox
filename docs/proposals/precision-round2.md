# Proposal: precision, round 2 (what still reports benign versions, and fixes)

> **Status:** pre-freeze set implemented 2026-11-08 (owner's approval the same day: F5, F7,
> F6b, F3b+F3c, F4b, F2; not F1, F3a, provenance as an explanation or the `CLEAR_*`
> switches). Stage 1 F5 + F6b in commit `2a1d1cd`, Stage 3 F2 signal in `d4bba1a`, Stage 4 F7
> + F2 explanation in `16676fc`, Stage 2 F3b + F3c + F4b in the commit after. Re-measured with
> the real code, not the simulation: on the 3,032 versions below, 2,208 → 1,985 reported
> (-223, all benign; precision 5.8% → 6.4%) where content was available, -253 (6.5%) with
> the rules applied to stored snippets for versions without a tarball; 0 malicious, unwanted
> or unverified lost; every `vm-day1` sample at risk still reported. Two deliberate
> differences: F5's minor-0 shape only in `as_of`'s own year (as proposed it exempts 15 OSV
> malware versions such as `2000.0.0`), and F3b never counts endpoint hosts as the other
> domains (keeps v5's region tables). F2 lives in Stages 3 and 4 (an INFO finding and
> `correlate.EXPLAINED`). Per fix: [stages/triage.md](../stages/triage.md),
> [ast.md](../stages/ast.md), [correlate.md](../stages/correlate.md),
> [static.md](../stages/static.md); [evaluation.md](../evaluation.md) results log.
> Owner decisions are in [section 8](#8-owner-questions). Fixes marked **pre-freeze** are small
> and local enough to build before the rule freeze (2026-11-12 00:00Z); the rest should wait and
> be validated afterwards on window B's held tarballs.
> **Builds on:** [stage1-precision](stage1-precision.md) (round 1, implemented today),
> decisions [0015](../decisions/0015-reviewer-verdicts.md) (verdicts, all addenda),
> [0017](../decisions/0017-repository-trust.md), [0018](../decisions/0018-commit-history.md),
> [0019](../decisions/0019-live-evaluation.md); [correlate.md](../stages/correlate.md#decision-and-score).

## Summary

The owner's goal (2026-11-08): "Keep cutting down the benign category. Ideally we are left with
only unwanted and malicious." Truth is the reviewer verdict (`data/verdicts/npm.jsonl`, the last
record per version; rank > 0 = it was reported).

- **3,032 reported versions have a verdict**: 2,895 benign, 60 malicious, 77 inconclusive (88
  runs, Oct 29 to the 4-day run of Nov 7). Re-decided with **today's rules** (the four Stage 1/4
  rules changed this morning recomputed with the worktree's code, Stage 2/3 findings as recorded,
  today's `decide`): **2,079 benign, 60 malicious and 69 inconclusive are still reported.** Of
  the other 816 benign, 736 go with round 1's rule changes (314 of them `@haybarn/*` calendar
  versions) and 80 had already gone with earlier re-scores; the 8 inconclusive no longer
  reported are `redis-tracker` ×7 (since the LOW cap) and `@fabricorg/cli@0.7.6` (round 1).
  Precision of a report today: 129 / 2,208 = **5.8%**.
- **60% of the remaining benign reports are install code** (1,254 of 2,079): a hook on a new
  package (349), a hook added or changed on an update (265), the hook's files changed (507), or
  install code gaining a capability (133). Then endpoint text (266), non-registry dependencies
  (166), obfuscation (138), revived packages (115), version numbers (66).
- **The recommended pre-freeze set (F5, F7, F6b, F3b+F3c, F4b, F2) removes 227 benign reports
  (10.9%, 175 packages) and loses no positive**, live or among the `vm-day1` malicious samples it
  could affect. Precision 5.8% → 6.5%.
- **F1 (quiet cosmetic edits of install files) is the one big lever that is cheap: +185 benign
  (412 together, 7.1%), but it costs 7 `esoftplay` follow-on releases on `vm-day1`** (their
  only reported change is a build-config edit; the family stays reported through 1 of its 22
  samples) and `hyrox@0.1.6` live (inconclusive). The owner's call.
- With the "explained install" shapes and the commit-hash diff base (after the freeze): ~453
  without F1 (7.4%), ~613 with it. Going much further needs content-level explanation of
  install code (section 6c). Provenance is **not** an explanation: trusting it would remove 285
  benign reports and lose 37 `vm-day1` malicious samples published through trusted publishing.

| # | Cluster (why reported → why benign) | Benign reports | Fix (stage) | Benign removed | Positives lost (live) | `vm-day1` malicious lost | When |
|---|---|---|---|---|---|---|---|
| 1 | Install file changed, same hook; the diff adds nothing risky | 507 (R3) | F1 `install-script-changed` v4: a hook's own file counts only if its added lines hold a risky use, a URL/IP, a blob or credential path (Stage 3) | **185** (155 pkgs) | `hyrox@0.1.6` (inc.) | **7 `esoftplay` follow-ons** | owner |
| 2 | Calendar versions `2026.1107.0`, `2611.5.1` | 66 (R10) | F5 `version.suspicious` v4: year major with an MMDD/MDD/0 minor, or a YYMM major (Stage 1) | **47** | 0 | 0 of 6 at risk | pre-freeze |
| 3 | Revived package now released by CI with provenance | 115 (R7) | F7 `revived-with-new-dependency` v3: LOW when the release has provenance (Stage 4) | **65** | 0 | 0 of 1 at risk | pre-freeze |
| 4 | `xlsx` from SheetJS's own CDN | 50 of 166 (R6) | F6b `non-registry` v4: `https://cdn.sheetjs.com/` is the vendor's registry (Stage 1) | **50** (11 pkgs) | 0 | 0 of 15 at risk | pre-freeze |
| 5 | Endpoint text: placeholder hosts (`example.ngrok.app`, `xxx.trycloudflare.com`), list entries | 266 (R5) | F3b+F3c `exfil-endpoint` v6 (Stage 2) | **33** | 0 | 0 of 63 at risk | pre-freeze |
| 6 | Raw IP in HTML/XML/CSV, tests, NOTICES, package.json `repository` | 85 (R5) | F4b `hardcoded-ip` v3 (Stage 2) | **20** | 0 | 0 of 2 at risk | pre-freeze |
| 7 | Build-tool-only hooks (`node-gyp-build`, `husky`, `only-allow`) | ~60 | F2 + S4: LOW when every hook is a build tool and `binding.gyp` runs no command (Stage 3/4) | **12** | 0 | 0 of 433 at risk | pre-freeze |
| 8 | Telegram `bot${token}` from the user's config | 45 | F3a (Stage 2) | 45 | with F1: `@leonoremods/baileys@1.10.1` (mal.) | `@eooce/sbx@2.0.5`, `node-navsbx@1.0.0` | no |
| 9 | Hash-named prereleases diffed against an unrelated one (`@astryxdesign/cli` canaries) | 135 (R2-R4) | F8 diff base 5 (Stage 0 packument) | ≤ 135 (est.) | 0 | n/a | after |
| 10 | Platform-binary launchers, own-release downloaders with a checksum, agent-skill copiers | 1,254 (R1-R4) | S1-S3 "explained install" (Stage 3 signal, Stage 4 decision) | 99 of 591 with tarballs (strict) | 0 | 0 of 149 checked (of 433) | after |
| 11 | Non-registry dependency from the package's own GitHub owner | 79 | F6a | 79 | 0 | **`@opensearch-project/opensearch` 3.7.0, 3.8.0** | rejected (again) |
| - | `CLEAR_ESTABLISHED` / `CLEAR_HISTORY` / both | - | turn on (Stage 4) | 20 / 65 / 66 | 0 | `gina@0.7.1` (each) | owner |
| - | Trusted publisher + provenance clears install MEDIUMs | - | structural (Stage 4) | 285 | 0 | **37** (`autotel-*`, `awaitly-*`, `executable-stories-*`, ...) | rejected |

Counts are versions. "Positives" are malicious and inconclusive verdicts (the inconclusive
ones are being split into `unwanted` and `unverified`; every one lost is named).

## 1. Data and method

- **Join.** Every latest verdict with rank > 0 (3,032) was found in its run's
  `correlate.jsonl` (all 88 runs still have it), streamed line by line. For each version:
  its findings (rule, version, severity, weight, explanation, evidence snippets), the manifest
  facts (hooks, optional dependencies, repository, publisher, provenance), and the verdict note.
- **Today's rules.** Stored findings are those of the last re-score. The four rules changed on
  2026-11-08 (`npm.publish-method.downgrade` v4, `npm.dependency.non-registry` v3,
  `npm.version.suspicious` v3, `npm.combination.revived-with-new-dependency` v2) are
  recomputed with the worktree's code, exactly as `agent-stage1/scripts/verify_live.py` does,
  and the version re-decided with `stages.correlate.decide`. Stage 2/3 rules changed since a
  run's re-score are not re-run (they need tarballs); where a fix depends on content, it is
  measured on the captured tarballs (half of the versions have one).
- **Simulating a fix** = transforming those findings (a severity or weight change under the
  fix's exact condition) and calling the same `score`/`decide` logic (re-implemented in
  `lib.py` and checked against `decide` on all 3,032: 0 mismatches).
- **DataDog recall.** For each fix, the `vm-day1` malicious samples that the fix *could*
  unreport (those unreported if the rule it touches were dropped to LOW outright: 520 samples,
  from the last full dump `vm-day1-findings-rot.jsonl`) were re-run through `pipeline+4` with
  today's code in a hard-linked scratch data dir, keeping full evidence and install-code
  features, and the fix applied to them. A sample outside that set can't be lost by the fix.
  Re-run in full: every at-risk sample of the non-install fixes (105) and 141 of the 433 at
  risk through the install rules (228 in all; repository comparison off for 98 of them, the
  GitHub API being slow without a token, with their `repo.*` findings taken from the rot
  dump). For the rest of the 433, only the install-code features were computed (section 4,
  S1-S3). The whole-set dump of `vm-day1` was OOM-killed at 10 GB twice, hence the subset.

## 2. Why benign versions are reported

Each benign report is put in the first cluster that matches the rules that reported it
(MEDIUM and above, or the score), then given a "why benign" from its verdict note (keyword
classes, 70% classified; the rest are notes like "no install script; X is its documented
feature").

| Why reported | Benign | Mal. | Inc. | Why benign (top classes from the notes) |
|---|---|---|---|---|
| R3 install code changed, same hook (`install-script-changed`) | 507 | 2 | 27 | own-release download 94, platform launcher 87, agent-skill/MCP installer 72, trivial change 27 |
| R1 install hook on a new package (`install-hook` MEDIUM) | 349 | 22 | 15 | own-release download 63, platform launcher 51, native build 46, print/check only 35, agent skill 33, cargo-dist 14 |
| R5 endpoint text (`exfil-endpoint`, `hardcoded-ip`) | 266 | 9 | 2 | lists/docs/tests/placeholders 101, user's own token or endpoint 35 (Telegram bots), agent tools 48 |
| R2 hook added or changed on an update (`install-hook` HIGH) | 265 | 8 | 5 | platform launcher 39, agent skill 29, print/check only 29, native build 25, own-release download 20 |
| R6 non-registry dependency | 166 | 11 | 6 | own org's GitHub 79-104, SheetJS CDN 50, pkg.pr.new previews 14 |
| R8 obfuscated / `Function("require")` | 138 | 6 | 12 | vendor-obfuscated products 42, tests/bundles 50 |
| R4 install code gains a capability (`install-script-code` on an update) | 133 | 0 | 0 | 118 are one package: `@astryxdesign/cli` canaries diffed against unrelated canaries |
| R7 revived with a new dependency | 115 | 0 | 0 | CI release with provenance 65, maintainer back with a co-maintainer 48 |
| R10 version number | 66 | 1 | 0 | CalVer `YYYY.MMDD.n` 47, dependency-confusion placeholders by researchers 19 |
| R9 score only (a weak-alone MEDIUM + three LOWs) | 36 | 0 | 0 | downgrade + LOWs 31, webhook placeholder 5 |
| R11 dependency reputation (`fresh-foreign`, `known-malware`) | 27 | 1 | 1 | the same author's new package under another account |
| R12 downgrade on a watched package (HIGH) | 11 | 0 | 0 | maintainer publishing by hand (kept: `axios@1.14.1`) |

Two facts shape every fix below:

- **No positive is on a watched package** (246 benign are), and **72 of 129 positives are new
  packages**. A new package with an install hook is how the Baileys forks are caught today:
  they keep upstream's `preinstall: node ./engine-requirements.js` (18 positives, 15 benign).
  That hook does nothing harmful; the catch is coincidental, but it is the only one. Any change
  that makes "a hook with no risky capability" quiet loses them (15 of the 21 positives reported
  by `install-hook` alone). So no fix below touches a hook that has no recognised benign shape.
- **Trusted publishing is nearly absent from positives**: 662 benign reports have a trusted
  publisher, 1 positive does (`@yalehwang/cloudpit@2.0.0`, inconclusive, not lost by anything
  below).

## 3. Rule by rule: what each rule contributes on the live reports

On the 2,208 versions reported today. "MEDIUM+" = the rule fired at MEDIUM or above (TP =
positive, FP = benign); "decisive" = dropping this rule alone unreports the version; "any" =
fired at any severity.

| Rule | MEDIUM+ FP | TP | Precision | Decisive FP | TP | Any FP | TP |
|---|---|---|---|---|---|---|---|
| `npm.install-script-changed` | 654 | 35 | 5.1% | 459 | 3 | 654 | 35 |
| `npm.install-hook` | 614 | 50 | 7.5% | 268 | 21 | 614 | 50 |
| `npm.install-script-code` | 439 | 23 | 5.0% | 132 | 0 | 439 | 23 |
| `static.exfil-endpoint` | 188 | 16 | 7.8% | 177 | 1 | 192 | 16 |
| `npm.dependency.non-registry` | 167 | 20 | 10.7% | 166 | 16 | 170 | 20 |
| `static.obfuscated` | 113 | 20 | 15.0% | 111 | 16 | 115 | 24 |
| `npm.combination.revived-with-new-dependency` | 117 | 0 | 0% | 115 | 0 | 118 | 0 |
| `static.hardcoded-ip` | 85 | 16 | 15.8% | 80 | 5 | 92 | 16 |
| `npm.version.suspicious` | 66 | 1 | 1.5% | 66 | 1 | 66 | 1 |
| `npm.publish-method.downgrade` | 42 | 0 | 0% | 42 | 0 | 48 | 0 |
| `static.function-require` | 28 | 1 | 3.4% | 27 | 1 | 29 | 1 |
| `npm.dependency.fresh-foreign` | 23 | 1 | 4.2% | 23 | 1 | 23 | 1 |
| `code.capability-gained` | 20 | 0 | 0% | 5 | 0 | 195 | 10 |
| `static.webhook-placeholder` | 7 | 0 | 0% | 5 | 0 | 9 | 0 |
| `npm.repo.install-script-not-in-repo` | 5 | 1 | 17% | 0 | 0 | 40 | 1 |
| `npm.dependency.known-malware` | 4 | 2 | 33% | 4 | 1 | 4 | 2 |
| `static.encoded-url` | 2 | 4 | 67% | 2 | 0 | 2 | 4 |
| `npm.install-script-obfuscated` | 0 | 21 | **100%** | 0 | 0 | 0 | 21 |
| `static.known-signature` | 0 | 6 | **100%** | 0 | 1 | 0 | 6 |
| LOW-only rules (`process-exec` 997 / 34, `network` 594 / 35, `dependency.added` 386 / 9, `npm-publish` 251 / 9, `sensitive-path` 225 / 2, ...) | - | - | - | ≤ 16 each | 0 | | |

Reading it: the three install rules carry most of the noise and most of the catches. The two
rules with no false positive at all (`install-script-obfuscated`, `known-signature`) are the
model for what a precise rule looks like: they name a *shape*, not a capability. Severity
calibration that follows from the table: `revived` (0 TP) and `version.suspicious` (1 TP,
`template-projection-map@99.1.3`, a probe) are the cheapest to quiet further; `static.process-exec`
is the most frequent finding (997 benign versions) but is decisive on only 10, so it is not a
lever.

## 4. Fixes, in priority order

Each fix gives its stage, the exact condition, and the cost. "Pre-freeze" means a few lines in
one rule, a test each, no contract change, and no positive lost anywhere we can measure.
"`vm-day1` at risk" counts the malicious samples that would no longer be reported if the
rule the fix touches were dropped to LOW outright; only those can be lost, and each was re-run
with today's code and the fix applied.

### F1. `npm.install-script-changed` v4: an unremarkable edit of a hook's own file is LOW (Stage 3) — owner decision

- **Condition.** v3 already counts a *loaded* install file only when its change adds a risky
  line (`_adds_risky`). v4 applies a wider test to the files the hooks name too: the file
  counts (MEDIUM, weight 3, as today) if it is newly run, binary, too long to diff, or any
  added line matches a risky use (process, network modules, `fetch`, whole `process.env`,
  `eval`/`Function`/`import()`/computed `require`), a URL or raw IP, a 100+ character
  base64/hex run, `Buffer.from`/`atob`/`fromCharCode`/`\x..` escapes, a credential path
  (`.npmrc`, `.ssh`, `.aws`, `id_rsa`, `credentials`), `NPM_TOKEN`, `homedir`, file writes,
  `curl`/`wget`/`powershell`. Otherwise the finding is LOW, weight 1, and its diff stays in the
  evidence.
- **Compared with the variant rejected on 2026-10-31** ([evaluation.md](../evaluation.md),
  "counting a hook's own file only when its change adds a risky line": −9 `vm-day1`
  malicious, 8 `esoftplay` and `fooobar@1.0.14`): that one used only Stage 3's capability
  lines. The wider terms keep `fooobar` and one `esoftplay`, but not the other seven.
- **Live:** 185 benign removed (155 packages), measured from the stored diffs; a diff cut at 40
  lines counts as risky, so this is a lower bound. On the 299 findings with both tarballs, the
  full-diff test explains 107 (36%). Lost: `hyrox@0.1.6` (inconclusive: its only install-code
  change is a reformatted Node-version check; the reason it was inconclusive is an obfuscated
  dependency, which no install rule sees). With F3a also on, `@leonoremods/baileys@1.10.1`
  (malicious, hidden channel follow) is lost too: its reasons are the same reformatted check
  and a templated Telegram URL.
- **`vm-day1`:** 18 at risk; **loses 7**: `esoftplay` 0.0.142-m, 0.0.143-w, 0.0.183,
  0.0.185, 0.0.212, 0.0.256, 0.0.262. All are follow-on releases of one family (22 samples, 8
  reported today, 1 after F1), and each is reported only because `bin/build.js`, which its
  `postinstall` runs, changed; in 0.0.183 the change is build-profile JSON (`"bun": "1.1.0"`
  removed). The Telegram code that makes the family malicious is in other files and unchanged,
  so it is LOW ("also in the previous version"). Requiring, in addition, that no endpoint,
  obfuscation or credential finding be present at any severity (F1g) still loses 5 and keeps
  only 138 of the 185.
- **Recommendation:** owner. It is the largest cheap cut, and what it loses are catches by
  coincidence (a cosmetic edit of a file that runs at install, in a package that is malicious
  elsewhere); but under decision 0007 follow-on releases are reported in their own right, and
  this would cost 0.6 points of `vm-day1` A follow-on recall.

### F5. `npm.version.suspicious` v4: more calendar shapes (Stage 1) — pre-freeze

- **Condition.** Exempt, besides v3's: a year-like major (1990 to `as_of` year + 1) whose minor
  is 0, a month (1-12), or a month-day `MDD`/`MMDD` (`2026.1107.0`, `2026.706.0`,
  `2026.0.1`); and a `YYMM` major (`2611.5.1`: 20 ≤ YY ≤ next year, 1 ≤ MM ≤ 12).
- **Live:** 47 benign removed (all `@4fu/arbor-*`, `@burdenoff/*`, `@runstructure/*`,
  `@beehexa/*` style CalVer), 0 positives. The 19 left are researchers' `99.x` placeholders.
- **`vm-day1`:** 0 of the 6 at-risk samples lost. Dependency-confusion attacks use `99`, `999`, `9999` and up, which none
  of these shapes accepts (round 1 found no calendar-shaped major among 53,389 OSV malware
  versions).

### F7. `revived-with-new-dependency` v3: LOW when the release carries provenance (Stage 4) — pre-freeze

- **Condition.** As v2's same-account case: LOW, weight 1, when the release has a provenance
  attestation (`has_provenance`). A takeover with provenance needs the repository's CI as well
  as the npm account.
- **Live:** 65 benign removed (65 packages), 0 positives (the rule has no positive at all).
  The own-scope variant (every added dependency in the package's own scope) adds 14 more; not
  proposed (a scope owner's token is exactly what a takeover has).
- **`vm-day1`:** 0 of 1 at risk lost. The known takeovers it catches (`xrpl@2.14.2`, `@mastra/*`) have no
  provenance.

### F6b. `npm.dependency.non-registry` v4: SheetJS's CDN (Stage 1) — pre-freeze

- **Condition.** A spec under `https://cdn.sheetjs.com/` is LOW: SheetJS left the npm
  registry and distributes `xlsx` only there. One literal host, no pattern.
- **Live:** 50 benign removed (11 packages), 0 positives. **`vm-day1`:** 0 of 15 at risk lost.
- Not proposed: other hosts (`pkg.pr.new` previews, 14; vendors' own CDNs). Each is one
  owner decision.

### F3b, F3c. `static.exfil-endpoint` v6: placeholder hosts and list entries (Stage 2) — pre-freeze

- **F3c condition.** LOW when the matched host has a placeholder label
  (`example.`, `xxx.`, `your-...`, `foo.`, `<...>`, `*.`, `${...}`, `my-app.`) before
  `.ngrok(-free).io/app`, `.trycloudflare.com` or `.serveo.net`. Real quick-tunnel names (`purple-river-1234.trycloudflare.com`)
  are not placeholders and stay HIGH.
- **F3b condition.** v5's deny-list test needs three *exfiltration services* nearby; a
  disposable-mail list has `webhook.site` among thousands of mail domains. LOW when the match is
  a whole host literal with at least two other quoted domain literals around it. (Measured on
  the ±60-character snippet; in code, the same 400-character window v5 uses.)
- **Live:** F3c 27, F3b 7, together 33 benign removed; 0 positives. **`vm-day1`:** 0 of the 63
  at-risk samples lost.
- **Dropped from it:** matches on a comment line (+15 benign) lose
  `elf-stats-piney-pinecone-203@1.0.0`, whose only `webhook.site` match is the comment
  `// Exfiltration via webhook.site` above code that builds the URL.
- Kept on purpose, as v5 decided: bare suffixes (`host.endsWith(".trycloudflare.com")`) and
  lists of ngrok region hosts (`gina`, `cro-pricing`).

### F4b. `static.hardcoded-ip` v3: IPs that don't run (Stage 2) — pre-freeze

- **Condition.** LOW when every match is in markup or data that isn't loaded as code (`.html`,
  `.htm`, `.xml`, `.svg`, `.csv`, `.tsv`, `.txt`, lockfiles), a `NOTICE`/`THIRD_PARTY_NOTICES`
  file, a test file (`*.test.js`, `*.spec.ts`: also worth adding to `NON_EXECUTING` for every
  rule), or `package.json`'s `repository`/`homepage`/`bugs` URL. A match in a hook command in
  `package.json` stays MEDIUM (`internal-renderers`, `ms-client-portal`, `pandafortunerush`,
  `teick`).
- **Live:** 20 benign removed, 0 positives. The wider variant that also includes `.json` and
  `.yml` (F4, 31 removed) **loses `dsh-model-pipeline@0.10.4`** (inconclusive: an undisclosed IP
  as an LLM provider in a config file the app loads). Not proposed.
- **`vm-day1`:** 0 of 2 at risk lost.

### F2 + S4. Build-tool-only hooks (Stages 3/4) — pre-freeze

- **Condition.** `npm.install-hook` is LOW when every install hook is one of a fixed list of
  build tools (`node-gyp-build`, `node-gyp rebuild`, `prebuild-install`, `node-pre-gyp install
  --fallback-to-build`, `husky`, `npx only-allow pnpm|yarn|bun`, `patch-package`) **and**
  `binding.gyp` runs no command (`install.gyp_commands` empty). `node-gyp rebuild` with a gyp
  action stays MEDIUM: `@atedone/workspace-bootstrap@0.0.1` (inconclusive) ran its payload that
  way. npm adds `node-gyp rebuild` itself for any package with a `binding.gyp`, so an explicit
  one adds nothing.
- **Live:** 12 benign removed (`husky`/`only-allow`/`patch-package` hooks, and `node-gyp` hooks whose `binding.gyp` was checked on a captured tarball), 0 positives.
  Small, but it removes a whole class from the queue. **`vm-day1`:** none of the 433 malicious
  samples reported only through install rules has build-tool-only hooks (checked on their
  manifests), so none can be lost.

### F3a. Telegram URLs whose token comes from a variable (Stage 2) — owner

- **Condition.** `api.telegram.org/bot` followed by `${`, `" +`, `{` or `%s` (the token is the
  caller's), LOW; a literal token (`bot123456789:AA...`) stays HIGH.
- **Live:** 45 benign removed (38 packages: notification bots, agent tools), 0 positives alone;
  with F1 (230 together), loses `@leonoremods/baileys@1.10.1` (malicious, above).
- **`vm-day1`:** loses `@eooce/sbx@2.0.5` and `node-navsbx@1.0.0` (63 at risk): both send to a
  bot whose token is a constant elsewhere in the file (`bot${BOT_TOKEN}`), which a template
  test can't tell from a user's token. v1-v5 had found the same. **Not recommended** unless the
  owner accepts that loss.

### F8. Diff base for commit-hash prereleases (Stage 0, `Packument.previous_version`) — after the freeze

- **Problem.** `0.7.6-canary.2936b07` is diffed against the highest semver below it,
  `0.7.6-canary.2782f99`: commit hashes sort as strings, so the base is an arbitrary canary,
  possibly weeks older, and `install-script-code` reports install capabilities as "new" on
  each one. 135 benign reports have a hash-named version and base (118 `@astryxdesign/cli`,
  `react-native-executorch` nightlies, `@agoric/xsnap`), 0 positives.
- **Fix.** Diff base 5: when the version's prerelease part contains a hex commit id, the base
  is the most recent earlier publish of the same release line (time order, as the fallback
  already does). It changes the diff of every stage, so it needs `stage_version`s and must be
  validated on window B. Up to 135 removed (estimate: not every one would be unreported).

### S1-S3. "Explained install": a recognised benign shape of install code (Stage 3 signal, Stage 4 decision) — after the freeze

The large install clusters (R1-R3) are mostly three shapes the notes name again and again. A
Stage 3 INFO finding `npm.install-explained` (shape + evidence) would let Stage 4 make the
install MEDIUMs (`install-hook`, `install-script-changed`, `install-script-code`) LOW, the way
`CLEARED_BY_REPO` works, never touching HIGH content findings (`install-script-obfuscated`,
`exfil-endpoint`, `known-signature`) or any other MEDIUM.

| Shape | Condition (all on the install files `install_sources` finds) |
|---|---|
| S1 platform-binary launcher | ≥ 2 `optionalDependencies` that are this package's platform builds (`<name>-<os>-<arch>`, same scope); no network, or network only to `registry.npmjs.org`; no whole-env, no dynamic code, no shell hook, no gyp command |
| S2 own-release download | every URL literal (after substituting `const` strings) is the package's own GitHub repository's releases (or GitHub's asset hosts, the registry, `example.com`); cargo-dist's `artifactDownloadUrls` count; a checksum check (`createHash("sha256"`, `SHA256SUMS`, `checksums.txt`); no whole-env, no dynamic code |
| S3 agent-skill copier | no network, no process; the code names an agent directory (`.claude`, `.agents`, `.cursor`, `.codex`, `SKILL.md`, `.mcp.json`) |
| S4 build tool | as F2 |

- **Measured on the 591 install-cluster benign reports with a captured tarball:** strict S1-S4
  explain 99 (S1 35, S2 34, S3 25, S4 5), 0 of the 39 positives with a tarball. A looser
  variant (S1 allowing whole-env, S2 without a checksum, S3 allowing processes) explains 203,
  and loses `wkappbot-code@0.3.7` (inconclusive: it runs an unpinned `install.sh` from
  GitHub Pages and writes Claude Code hooks).
- **Combined with the pre-freeze set:** 321 benign removed live without F1, 483 with it
  (tarballs exist for only half the versions, so the shapes' share would roughly double with
  full capture).
- **`vm-day1`:** 433 malicious samples are reported only through the install rules (would go if
  all three were LOW). Install-code features were computed for 149 of them so far (the
  encrypted DataDog zips decrypt slowly in pure Python): **none has a strict or loose shape**.
  Only 19 of the 433 have two or more optional dependencies, so S1 can match at most those.
  The rest must be checked before the signal is built; that is part of why it waits.
- **The owner's view on S3 (2026-11-08):** an AI-development package that installs its own
  skills, hooks or agent settings is benign as a *verdict* (decision 0015), but the *rule* may
  only stay quiet when the code proves the plain shape; a package's name or description never
  counts. Three guards added to S3 for the post-freeze build:
  1. **What gets installed is scanned too.** A `settings.json` hook runs a shell command on every
     prompt or tool call (persistent code execution): a hook command beyond a constant `echo`
     or a script shipped in the package (network tools, downloaded scripts, env reads) is not
     explained, and installed hook scripts go through Stages 2-3 like install code.
  2. **Permission widening is never explained.** Settings that auto-approve tools (`Bash(*)`
     allow-lists, bypass/"dangerously skip permissions" modes) or add a remote MCP server stay
     reported (the 2025 nx compromise ran users' AI CLIs with permission-bypass flags to search
     for secrets).
  3. **Instructions aimed at the agent are flagged.** Installed skills or `AGENTS.md` text telling
     the agent to hide activity, read credentials (`~/.ssh`, `.env`) and send them, or ignore
     prior instructions makes the release reported.
  Updates keep the normal diff rules: a new version whose hook does something new still fires
  `code.capability-gained` / `install-script-changed`.
- **Why after the freeze:** it is a new signal with three detectors, it needs the owner's view on
  S3 (an agent-skill copier is also how a prompt-injection payload would be installed), and it
  can be validated on window B's held tarballs without touching the frozen rules.

## 5. The built-but-off clearings, re-measured

On today's 2,208 reported versions (live) and decisions 0017/0018 (`vm-day1`):

| Option | Benign removed (live) | Positives lost (live) | `vm-day1` malicious lost |
|---|---|---|---|
| `CLEAR_ESTABLISHED` | 20 | 0 | `gina@0.7.1` |
| `CLEAR_HISTORY` | 65 | 0 | `gina@0.7.1` |
| both | 66 | 0 | `gina@0.7.1` |

Small: most reported versions have no compared, matching repository (no GitHub repository,
no tag or `gitHead`, over the comparison budget, or code that differs). `gina@0.7.1`'s code
is in its own 2013 repository, committed by its maintainer, so no repository-based clearing
can keep it. 65 is about the size of F7 and costs a known malicious sample; not recommended
over the fixes above.

## 6. Structural options

**(a) One queue entry per publisher and shape.** Grouping reported versions by (publisher, or
repository/scope for CI publishes; the set of reporting rules; the hook commands) takes the
1,529 per-package queue entries to 1,370 (−10%). One group would mix a positive with benign
siblings (`@fcjplugins/*`: `hooks` inconclusive, `storages`, `pwutils` benign), so a group
must show its members and never auto-dismiss. With an install-file content hash in the key it
would be tighter (8 `ngwlh` scopes × versions with the same `install.cjs`). It reduces
reviewing, not reported versions, so it doesn't change the confusion matrix. Report and viewer
change, after the freeze.

**(b) Severity calibration.** From section 3: keep `install-script-obfuscated` and
`known-signature` HIGH (no FP); `revived` and `downgrade` have no TP live and are already weak
(F7 makes revived weaker still); `version.suspicious` after F5 carries only researchers'
placeholders (19 benign, 1 probe). The install rules can't be re-weighted without losing the
Baileys forks and probes (15 of 21 `install-hook`-alone positives are Baileys forks); they need explanations, not
weights.

**(c) What an "explained" signal looks like.** S1-S3 above, plus two trust facts already in
the data:
- **Trusted publisher + provenance** making install MEDIUMs LOW (never HIGH) would remove 285
  benign reports live and lose no live positive (1 positive has a trusted publisher), **but it
  loses 37 of the 98 `vm-day1` malicious samples that carry both**: the `autotel-*`,
  `awaitly-*`, `executable-stories-*`, `eslint-plugin-*`, `node-env-resolver*` wave, published
  from the projects' own compromised CI with valid provenance (and 53 `@redhat-cloud-services/*`
  and others are at risk the same way; the rest stay reported through HIGH findings). A week of
  live data simply had no such attack. Rejected; it is also why F7 uses provenance only on a
  rule with no true positive at all.
- **Repository match** (`CLEAR_*`, section 5): small and costs `gina`.

## 7. Rejected or not proposed

- **Trusted publisher + provenance as an explanation:** 285 benign vs 37 `vm-day1` malicious
  (section 6c).
- **Exfil-endpoint matches on comment lines:** +15 benign, loses
  `elf-stats-piney-pinecone-203@1.0.0`.
- **Non-registry dependency from the package's own GitHub owner (F6a):** 79 benign removed, 0
  live positives, but loses `@opensearch-project/opensearch` 3.7.0 and 3.8.0 on `vm-day1`
  (their payload came from their own repository). Rejected in round 1 for the same reason;
  still rejected.
- **Making any hook with no risky capability quiet** (e.g. `install-hook` on a new package LOW
  unless `install-script-code` fires): loses the Baileys forks reported only through upstream's
  Node-version `preinstall` (`luna-baileys`, `lyxe-baileys`, `felicia-baileys`,
  `@nerxa/socketon`, `@gopyr/baileys`, `vp-baileys`, `sauruspro-bail`, ...).
- **`hardcoded-ip` in `.json`/`.yml` as data (F4):** loses `dsh-model-pipeline@0.10.4`.
- **Revived: all added dependencies in the package's own scope:** +14 benign, but a stolen scope
  token is the takeover case.
- **`static.obfuscated` in browser bundles:** too few (4) to be worth a rule; vendor-obfuscated
  products (42, e.g. `dudu-converter-cli`, `@univerjs-pro/*`) are indistinguishable from the
  malicious `*-ai-sdk` family by the rule's own test.

## 8. Owner questions

1. Build the pre-freeze set (F5, F7, F6b, F3b+F3c, F4b, F2) before 2026-11-12? It removes
   227 benign reports (175 packages) and loses no positive live or on `vm-day1`.
2. F1 (cosmetic install-file edits LOW): +185 benign for 7 `esoftplay` follow-on samples on
   `vm-day1` and `hyrox@0.1.6` (inconclusive) live. Pre-freeze if accepted; it is one rule.
3. F3a (Telegram `bot${token}`): 45 benign for `@eooce/sbx@2.0.5` and `node-navsbx@1.0.0` on
   `vm-day1` and, with F1, `@leonoremods/baileys@1.10.1` live. Recommendation: no.
4. After the freeze: F8 (diff base for hash prereleases) and the S1-S3 "explained install"
   signal, validated on window B. Is S3 (agent-skill copiers) an explanation at all, given
   that agent-config writes are also a prompt-injection vector?
5. Confirm that provenance is not an explanation for install code (285 benign vs 37 `vm-day1`
   malicious samples published with provenance).
6. Leave `CLEAR_ESTABLISHED`/`CLEAR_HISTORY` off (66 benign vs `gina@0.7.1`)?
7. The Baileys forks are caught today only because they keep upstream's install hook. A rule
   for the channel auto-follow itself (being built elsewhere) would make that catch
   deliberate, and would also cover `hyrox`/`@leonoremods`-style losses above.

## 9. How to reproduce

Scripts in `~/kitsunox-scratch/agent-fp/scripts/` (read-only on `data/`; Python with
`systemd-run --user --scope -p MemoryMax=4G`, the eval subset with 8G):

- `extract.py`: joins verdicts to `correlate.jsonl`, recomputes the four rules, re-decides →
  `joined.jsonl` (3,032 rows).
- `lib.py`, `fixes.py`: score/decide re-implementation and the fixes; `simlive.py`,
  `combo.py`: live numbers; `rules_table.py`: section 3; `clusters.py`: section 2.
- `avail.py`, `shape.py`, `shapelive.py`, `shapesim.py`: tarball availability and the install
  shapes (tarballs read in memory with `extract_tar_gz`); `iscreplay.py`: F1 on both tarballs.
- `atrisk.py`, `dumpsub.py`, `simdd.py`: the `vm-day1` subset re-run (scratch data dir
  `~/kitsunox-scratch/agent-fp/data`, hard links) and the fixes applied to it.
