# Proposal: precision, round 4, agent E (Stage 4 decision; what no single rule explains)

> **Status:** built 2026-11-10, before the rule freeze (2026-11-12 00:00Z), for the owner's
> review. Agent E owns Stage 4's decision (`correlate.decide`, `WEAK_ALONE`, `REPORT_SCORE`,
> `explained`), the combination rules other than `revived-with-new-dependency`, and the
> known-malware and repository rules. **Result, with the real code on all 3,716 verdicted live
> versions: E1+E2 (zero-loss) remove 68 benign reports (61 packages) on round4-base and
> 52 (S5 36, S2 16) on `main` (`829dd41`, after A's content-aware `install-script-changed` v5 took 16 of
> them); no malicious, unwanted or unverified version loses a report or even a finding;
> `vm-day1`: 0 lost on round4-base (344 at risk) (on `main` not re-run in time, see section 5).** Precision (malicious + unwanted,
> today's verdicts) on round4-base 16.14% → 16.80%.
> **Owner decisions (2026-11-10):** E1+E2 kept; E3 (inline `node -e` hooks, a trade-off)
> **dropped**; `CLEAR_*` stay off; install code that patches other packages stays reported
> (the `OTHER_PACKAGE` guard is kept); explaining `npm.repo.install-script-not-in-repo` is not
> decided, not built.
> **Commit:** Stage 3 `b42327d` (E1+E2), on `main` `c3daf00`.
> **Builds on:** [round 3](precision-round3.md), [round 2](precision-round2.md) (S1-S4,
> section 5 on the clearings), decision [0015](../decisions/0015-reviewer-verdicts.md) with
> all addenda.

## Summary

Most of what Stage 4 decides is settled by one rule: 1,054 of the 1,482 benign reports (on
the round-3 extract's verdicts) have exactly one severe finding (a MEDIUM outside
`WEAK_ALONE`, or a HIGH), and those rules belong to agents A-D. What is left for the decision
itself is small (40 score-only reports) or costs real attacks: `REPORT_SCORE` 7 loses
`axios@1.14.1`; the repository clearings now lose 9 unwanted user-wide installers as well as
`gina`; no rule can join `WEAK_ALONE` without losing `vm-day1` samples. **The one place no
single rule can act is the install cluster:** 388 benign reports carry two or three severe
install findings at once (`install-hook` + `install-script-code` 146, `install-hook` +
`install-script-changed` 94, all three 76, `changed` + `code` 42), so a demotion of
`install-hook` (B) or `install-script-changed` (A) alone cannot unreport them. Stage 4's
`explained` lowers all three when Stage 3 proves a benign shape of the install code, so E's
built change is two more shapes and one guard for all of them.

| # | Change (`npm.install-explained` v3, Stage 3) | Benign removed | Positives lost | Unverified lost | `vm-day1` lost |
|---|---|---|---|---|---|
| E1 | **S5 inert install code** | 51 | 0 | 0 | 0 (of 344 at risk) |
| E2 | **S2 without a checksum for cargo-dist** | 17 | 0 | 0 | 0 (no sample has `artifactDownloadUrls`) |
| E1/E2 | **every shape needs readable, plain UTF-8 install code** (`hauntview@0.2.9`) | 0 (none of the 140 versions S1-S3 explain today is refused) | 0 | 0 | 0 |
| E3 | *trade-off, **dropped by the owner**:* S5 also for inline `node -e` hooks | +12 | 0 | 0 | 1: `shoal-cli@0.4.5` |
| H1 | harness: `known-malware` regenerated with today's rule (measurement only) | 4 stale v1 findings | - | - | - |

Measured and not built (section 6): `REPORT_SCORE` 7 (−39 benign, loses `axios@1.14.1`,
`hub-launch@1.44.2`, `@hithink-tech/hithink-finance-cli@0.2.0`); every `WEAK_ALONE` candidate
(each carries `vm-day1` samples alone); suppressing unchanged evidence (0 benign, 4
positives); `CLEAR_ESTABLISHED`/`CLEAR_HISTORY` (−58 benign vs 9 unwanted and `gina`);
counting only non-generic LOWs (−19 benign, loses `hub-launch`); letting an explanation lower
`npm.repo.install-script-not-in-repo` (+2, owner's call).

## 1. Data and method

- Round 3's harness (`replay.py SRC CANDS OUT`) on the same 3,716 verdicted versions; tables
  use today's verdicts (`data/verdicts/npm.jsonl`, last record per version; 12 benign became
  unwanted during the day, none of them touched here).
- **H1, a harness correction.** The replay copies the context rules' findings from the
  recorded candidate. `npm.dependency.known-malware` was recorded at v1 for four benign
  versions (`victor-nest-resource@1.1.16`, `com.hidano.shadow-only-shader@0.10.0`,
  `modulus-security@0.1.0`, `modulus-firewall@0.1.1`), HIGH; today's v3 makes them LOW (npm's
  `0.0.1-security` holder, a Unity module). E's replay regenerates the finding with SRC's rule
  from the OSV records the recorded explanation names (as round 3 did for `fresh-foreign`).
  **Baseline = round4-base with H1: 1,783 reported**; round 3's `fix.jsonl` differs on
  exactly those 4 versions.
- **Decision changes** (`REPORT_SCORE`, `WEAK_ALONE`, clearings) were measured by calling
  round4-base's real `correlate.decide` on each replayed version's final findings: it agrees
  with the replay's own decision on 3,716 of 3,716 live versions and on 3,444 of 3,444
  `vm-day1` samples (round 3's `ddbase.jsonl` with its `ddfix.jsonl` rows).
- **E1-E3** change a Stage 3 rule, measured end to end: a full replay with the code (all
  3,716), then, as guards were added (each can only narrow the shapes), the versions the
  previous step removed. Against `main` (`4cd4e8a`): the 1,118 reported versions whose severe
  rules are install rules plus any of C's or D's changed rules, replayed with `main` and with
  `main` + E. `vm-day1`: `pipeline+4` (`dd.py`, one process per sample, fresh hard-linked data
  directory) on all 344 malicious samples that demoting the three install rules would
  unreport, then on the ones a step changed.
- The decomposition of every benign report is in `~/kitsunox-scratch/r4/shared/decomposition.md`
  (shared with agents A-D during the round).

## 2. Where the benign reports come from (round4-base, the extract's verdicts)

| Why reported | Benign | Positives | Unverified |
|---|---|---|---|
| a HIGH finding | 379 | 79 | 7 |
| MEDIUM(s) only | 1,063 | 190 | 23 |
| score only (a `WEAK_ALONE` MEDIUM + LOWs at the cap) | 40 | 2 | 0 |

| Severe rules on the report | Benign | Positives | Unverified |
|---|---|---|---|
| 1 | 1,054 | 116 | 20 |
| 2 | 303 | 110 | 7 |
| 3+ | 85 | 43 | 3 |

Decisive (demoting just that rule to LOW unreports the version), benign / positive:
`install-script-changed` 341 / 65, `install-hook` 238 / 12, `non-registry` 152 / 13,
`exfil-endpoint` 81 / 1, `obfuscated` 61 / 3, `revived` 55 / 0, `downgrade` 48 / 1,
`hardcoded-ip` 38 / 3, `function-require` 24 / 1, `version.suspicious` 22 / 1,
`fresh-foreign` 20 / 0. `npm.install-script-code` is decisive for 1 benign but sits beside
`install-hook` or `install-script-changed` in 271 benign reports (and is the only severe
finding of 106 `vm-day1` follow-on samples).

Why the 1,092 reports carried only by install rules have no explained shape today (Stage 3
diagnostic on their tarballs): no shape matches 345 benign / 56 positive; `env-all` in the
install code 205 / 48; no install file 79 / 2; a capability new to the update 70 / 15;
`dynamic-require` 35 / 4; a `binding.gyp` command 46 / 1; agent-file concerns 14 / 9.

## 3. The fixes

### E1. S5, inert install code

The install code (every file the hooks run, followed) has only the `filesystem` and `os-info`
capabilities (no network, process or native code; as for every shape no `env-all`, dynamic
code or dynamic `require`) and loads no package by name. Such code can print and touch files;
the guards make sure that is all, and that the analysis saw all of it:

| Guard | Why (the version that made it necessary) | Benign kept |
|---|---|---|
| no home-directory reference (S3 v2's test), no agent directory | user-wide agent writes and shell rc edits are unwanted (decision 0015) | - |
| no system path (`/etc/`, `/usr/`, `/tmp`, `tmpdir`, `C:\`, ...) | `cesium-native@0.56.0`, `dep-graph-gen@1.0.0` (`vm-day1` malicious) write an "RCE proof" to `/tmp` | 0 |
| no other installed package (`require.resolve(`, a path into `node_modules`) | a hook that rewrites a dependency is tampering, which decides a verdict (0015) | 34 (`node-pty` spawn-helper `chmod`, `fastmcp` and `@opentui/core` patches) |
| no text naming the network or running code (`fetch`, `import(`, `"node:https"`, `child_process`, `eval`, `spawn(`) | `@openrouter/sdk@1.5.59` passes the global `fetch` as a default parameter, which the analysis doesn't see | 15 (with the next two) |
| hooks are plain `node <file>`, install files JavaScript in plain UTF-8 | `@eisland/windows-startup-helper` runs `dotnet build`; `@onescience/onecode`'s postinstall is UTF-16, which parses as nothing, and downloads a binary | (above) |
| deletes nothing (`unlink`, `rmdir`, `rm`, `rmSync`) | `@uselagoon/ui-library@2.0.2` (`vm-day1` malicious) empties its directory under yarn | 2 |
| the package has code besides its install code (`placeholder`) | `wc@1.5.0`, `coldbox@6.7.71`, `pmcrypto@0.1.0`, `grab-service-worker@1.0.1` (`vm-day1` malicious): dependency-confusion placeholders whose whole package is a printing `postinstall` | 6 |
| not upstream Baileys's `engine-requirements.js` | `kevinx-baileys@1.2.2` (unwanted) auto-follows channels from an unchanged file Stage 2 doesn't read again; its inert preinstall is what reports it (also `hyrox@0.1.6`, `@lunabotv6/luna-baileys@8.1.0`, unverified) | 15 Baileys forks |
| no inline `node -e` code (E3 lifts it) | `shoal-cli@0.4.5` (`vm-day1` malicious, a follow-on) is reported only through its changed inline banner | 12 |

51 benign reports go, 44 packages: banners and setup hints (`sealkeep`, `@petercjl/*` ×7,
`codeam-cli`, `react-lottie@2.0.0`, `morphimg-cli`, `feloapi-cli`, `envpouch` ×2), Node-version
checks (`productmaxxing`, `teamclaws`, `bsmnt` ×2, `dobby-ai`), copies of a bundled binary
into the package (`@cerebrixos/pulselake*`), project scaffolders (`vibeshield-nodejs-backend`
×5, `@packrd/roxterjs-domains`).

### E2. S2 without a checksum for cargo-dist

S2 (own-release download) required a checksum check. cargo-dist's npm installer
(`binary-install.js`, `binary.js`) checks none; it downloads what `package.json` names in
`artifactDownloadUrls`. When every one of those is the package's own GitHub releases (and
every URL literal in the code is too, or a page, the registry or GitHub's asset hosts, as
before), S2 now holds without one: a checksum shipped in the same release says nothing about
its author, and S2's trust is in the repository's own releases. 17 benign (`larpcop`,
`meiose`, `@toantranmei/cli` and `/mcp`, `snouty`, `x86mcp`, `@vixide/vix`,
`near-business-cli`, ...); no positive is a cargo-dist installer, and none of the 3,444
`vm-day1` malicious manifests has `artifactDownloadUrls`.

### E1/E2. Every shape: code a reader and the parser can see

Install files must be plain UTF-8, with no line over 1,000 characters and no code after 64+
spaces or tabs. `hauntview@0.2.9` (malicious, arrived after the round's snapshot) hides an
obfuscated C2 loader after 266 tabs on one 12,699-character line of its postinstall; the
capability analysis sees only the legitimate `child_process` beside it. It stays reported
with every variant here (only by `install-script-changed`, score 6), but a loader without
that `child_process` would have looked inert. None of the 140 live versions S1-S3 explain
today is refused by the guard (longest live S5 line: 406 characters, longest padding 31).

### E3 (trade-off, measured, dropped by the owner 2026-11-10). S5 for inline `node -e` hooks

12 benign more (`puppet-mcp`, `@muhgholy/next-drive` ×2, `@zintrust/core`, `ezsnmp-data-logger`
×2, `@webship.co/workspace`, `@h1stealthy/gh046-npm-transfer-9421a2`, ...), for
`shoal-cli@0.4.5`: DataDog labels it malicious, a follow-on of 0.4.3; what it does at install
is print a banner (`node -e "console.log(...)"`), and its `shoal setup` writes MCP config
user-wide only when the user runs it, which the owner rules benign. Probably a label the owner
would not uphold, but it is a `vm-day1` loss, so E3 is separate.

## 4. Live result (real code)

| | Reported | Benign | Unwanted | Malicious | Unverified | Precision |
|---|---|---|---|---|---|---|
| round4-base (+H1), today's verdicts | 1,783 | 1,470 | 236 | 47 | 30 | 16.14% |
| + E1 + E2 | 1,715 | 1,402 | 236 | 47 | 30 | 16.80% |
| + E3 (dropped) | 1,703 | 1,390 | 236 | 47 | 30 | 16.92% |

No version is newly reported. No malicious, unwanted or unverified version's findings change
at all (the full replay with the first, looser S5 compared every positive's findings: none
had an `npm.install-explained` finding).

**Marginal on `main` (`829dd41`: A, C, D merged; the 52 re-checked on `c3daf00`, with F's and
G's rules: all 52 still reported there, all 52 removed by E).** Replayed with `main` and with `main` + E1/E2
on the 1,623 versions S5 or S2 could touch there (every version with an install finding, plus
those whose severe rules are install rules and C's or D's changed rules): **52 fewer reports,
all benign (S5 36, S2 16; 52 packages)**; no malicious, unwanted or unverified version's
findings change. A's `install-script-changed` v5 already lowers 16 of the 68 (cosmetic edits:
`bsmnt` ×2, `vibeshield-nodejs-backend` ×4, `@kerno/cli`, `@truss-harness/cli`, ...), and
with A's spawned scripts counted as install code nothing else changes. `a4f2e02` adds F's Stage
2 `static.padded-code` and evidence-only changes, which S5 does not interact with (S5 refuses
padded code itself).

## 5. DataDog check (`vm-day1`)

- **At risk:** the 344 malicious samples (of 2,708 reported) that demoting all three install
  rules would unreport. Nothing else can change: explanations only lower the install rules.
- **First S5** (without the `/tmp`, delete, placeholder and inline guards): 8 lost
  (`@uselagoon/ui-library@2.0.2`, `cesium-native@0.56.0`, `coldbox@6.7.71`,
  `dep-graph-gen@1.0.0`, `grab-service-worker@1.0.1`, `pmcrypto@0.1.0`, `shoal-cli@0.4.5`,
  `wc@1.5.0`); 336 stayed reported. Each lost one was read (in memory, through the harness):
  six print a line or write a proof file, one deletes files, one prints a banner.
- **E1+E2 as built:** 344 of 344 stay reported (the 8 re-run with the final code: each now
  fails a guard and keeps its `install-hook` MEDIUM; the other 336 stayed reported with the
  looser first S5, and every guard only narrows it).
- **On `main` (`829dd41`):** not re-run before the hand-off (the shared heavy lock was busy for hours). On
  round4-base the final guards keep all 344 at-risk samples; `main`'s changes can only add
  install files (A's spawned scripts) and text for S5 to refuse, or make more samples rely
  on the install rules (C's and D's demotions). The run that covers the second case, the
  745 `vm-day1` samples with node-only hooks that demoting the install rules plus C's and
  D's rules would unreport, is queued: `~/kitsunox-scratch/r4/E/out/dd-m2A.jsonl` (code
  `829dd41` + E). A sample there with `forwarded: false` is a loss to check.
- **E3 (dropped):** 343 of 344: `shoal-cli@0.4.5` is S5 and not reported (score 3); the last full dump
  has no repository finding for it (no GitHub repository), so nothing re-reports it.

## 6. Measured and not built

- **`REPORT_SCORE`.** Every score-only report is a `WEAK_ALONE` MEDIUM (weight 3) plus LOWs at
  `LOW_CAP` (3). At 5: +3 benign, no positive gained. At 7 or more: −39 benign, but loses
  `@hithink-tech/hithink-finance-cli@0.2.0` and `hub-launch@1.44.2` (both unwanted, user-wide
  installs reported by coincidence) and, on `vm-day1`, **`axios@1.14.1`**, reported at exactly
  6 (downgrade 3 + `githead-dropped` 2 + `dependency.added` 1 + `name-embeds-popular` 1).
  **6 stays.**
- **Only non-generic LOWs count toward the score** (Stage 2's generic regex LOWs excluded):
  −19 benign with ≥ 3 non-generic points required, but `hub-launch@1.44.2` reaches 6 only
  through generic LOWs.
- **`WEAK_ALONE` additions.** Live (benign / positive decisive) and `vm-day1` decisive:
  `revived` 55 / 0 but `xrpl@2.14.2`; `fresh-foreign` 20 / 0 (1 unverified) but 12 samples;
  `encoded-url` 3 / 0 but 32; `install-script-code` 1 / 0 but 106; `load-fingerprint` 1 / 0
  but 42; `dependency.missing` 2 / 0 but 2 unverified. Every other rule carries live
  positives alone. Nothing joins.
- **Suppressing unchanged evidence** (every severe finding has the same rule, file, snippet and
  explanation in the previous version). Stages 1-3 already diff against the previous version,
  so among the verdicted pairs it removes **0 benign** and loses 4 positives
  (`internal-renderers@10.0.0`, `pandafortunerush@10.0.0`, `ms-client-portal@1.0.0`, all
  malicious; `@civitas-cerebrum/achilles@0.1.9`, unwanted). Decision 0007 splits follow-ons in
  DataDog's metrics; it doesn't drop them live.
- **`CLEAR_ESTABLISHED` / `CLEAR_HISTORY`** on today's verdicts: established −17 benign / 6
  unwanted lost, history −57 / 9, both −58 / 9 (`@minhspark/codex-mcp-bridge` 2.3.0 and 2.3.1,
  `openyida` ×2, `tfv@6.2.0`, `triflux@10.96.0`, `@easyhaloo/afk-opencode@1.2.1`,
  `dcs-command-system@0.16.0`, `@codexverified/baileys@2.19.18`): the user-wide installers the
  owner now rules unwanted are their repositories' own code. Not clearing a version with the
  `npm.install-agent-user-wide` note: −54, still loses `tfv@6.2.0` and
  `@codexverified/baileys@2.19.18`, and `gina@0.7.1` on `vm-day1`. **Leave both off.**
- **`npm.repo.install-script-not-in-repo` explained too.** HIGH on 8 benign reports, always
  beside `install-hook`; with S5 two are inert (`rlm-harness@0.1.1`, `tzero-mcp@10.7.2`) and
  stay reported only through the repository rule. The tarball-vs-repository mismatch is a
  first-class signal, so this is the owner's call (question 3).
- **Relaxing "nothing new in an update's install code" for S5** (an update gaining only
  `filesystem`): 40 benign more in the diagnostic, 3 positives in that group, and the owner's
  rule for every shape. Not built.

## 7. Interactions with agents A-D

- **A (`install-script-changed`) and B (`install-hook`).** E1 explains all three install rules
  on the same versions a "cosmetic edit" (A) or "hook without a risky capability" (B)
  demotion targets: the removals overlap, the code doesn't (E touches only
  `install_shapes.py`). If either builds such a demotion, the guards of section 3 are the
  measured cost of keeping the positives: `kevinx-baileys@1.2.2` (Baileys engine check),
  `hauntview@0.2.9` (hidden loader), and on `vm-day1` the placeholders, `/tmp` proofs, the
  deleting hook and `shoal-cli`.
- **D (Stage 2).** `static.channel-follow` is `ALWAYS_NEW`, but Stage 2 never re-reads an
  unchanged file, so a follow-on of an auto-following fork is caught only by its hook.
  Rescanning unchanged files for the `ALWAYS_NEW` rules would make that catch deliberate and
  free the 15 Baileys forks E1 keeps.
- **Capability analysis (Stage 3 extractor, nobody's this round).** It misses the global
  `fetch` used as a value and reads UTF-16 files as empty; S1-S3 rely on it too.
- **C.** No interaction: `WEAK_ALONE` and `REPORT_SCORE` are unchanged.

## 8. Owner decisions (2026-11-10, through the integrator)

1. E1+E2: kept.
2. E3 (12 benign for `shoal-cli@0.4.5`): **dropped**; its commit was removed from the branch.
3. Explaining `npm.repo.install-script-not-in-repo` (+2): not decided; not built.
4. `CLEAR_ESTABLISHED` / `CLEAR_HISTORY`: stay off.
5. Install code that patches other packages in `node_modules`: keep reporting it (the
   `OTHER_PACKAGE` guard stays).

## 9. How to reproduce

Scripts in `~/kitsunox-scratch/r4/E/scripts/` (outputs in `../out/`), Python with `-I` under
`systemd-run --user --scope -p MemoryMax=...`, full replays and DataDog runs under
`flock ~/kitsunox-scratch/r4/heavy.lock`:

- `replay.py SRC CANDS OUT [WORKERS] [@KEYS]`: round 3's harness plus H1 (`known_malware()`);
  `base.jsonl` (round4-base), `fixfull.jsonl` (first S5), `fixA-sub.jsonl` (E1+E2),
  `fix8-sub.jsonl` (+E3), `main-sub.jsonl` / `mainE-sub.jsonl` (against `main`).
- `decomp.py`, `decomp2.py`, `dddecomp.py`: section 2 and the shared decomposition;
  `diag.py`, `diagsum.py`: why install-only reports have no shape; `thresh.py`,
  `scoreonly.py`, `clear.py`, `unchanged.py`, `stale.py`: section 6; `cmp.py`: decisions
  changed, by verdict; `s5check.py`, `s5probe.py`, `guardcheck.py`, `lineshape.py`: the guards.
- `dd.py SRC OUT N KEYS` (data dir `~/kitsunox-scratch/r4/E/data`, hard links, fresh caches),
  `ddmanifest.py`, `ddpeek.py`, `ddgrep2.py`: section 5. `mkcand.py`: `hauntview@0.2.9`'s
  candidate from its run.
