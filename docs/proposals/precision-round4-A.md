# Proposal: precision round 4, agent A (`npm.install-script-changed` and install persistence)

> **Status:** built 2026-11-09/10, before the rule freeze (2026-11-12 00:00Z), for the owner's
> review. Four commits: two new rules that name what the positives do and an
> `npm.install-script-code` v3 for hidden install code (**zero-loss**), and a content-aware
> `npm.install-script-changed` v5 (**a trade-off**, measured below).
> **Builds on:** [round 3](precision-round3.md) (method and harness), [round 2](precision-round2.md)
> (F1, rejected for the same losses), decision [0015](../decisions/0015-reviewer-verdicts.md)
> and its addenda of 2026-11-09 (user-wide agent installs, shell rc edits, persistent PATH,
> system packages and Baileys media tagging are unwanted).

## Update 2026-11-10: rescues for V's losses (commit `81b99d7`), rebased on `main` `4cd4e8a`

The integrator asked for three follow-ups after the first report.

**R1. The install code includes the scripts it starts** (`install.spawned_scripts`, Stage 3,
zero-loss). A shell, PowerShell or batch script the install code names by a constant relative
path (`path.join(__dirname, "install.sh")`), by the constant tail of a `join`
(`join(adapterDir, "claude-code", "scripts", "install.sh")`), or by an unambiguous bare name
(`"setup-ziniao-cli.sh"`, at most three package files with it) is read as data and becomes
install code for every install rule. `npm.install-persistence`'s agent form also matches an
agent's own CLI installing user-wide (`claude plugin install`, `claude plugin marketplace add`,
`claude mcp add --scope user`, `codex mcp add`, `"$CLAUDE_BIN" plugin install`). Three of V's
four lost unwanted versions are caught again for what their scripts do:
`@ornexus/neocortex@4.60.77` (`install.sh` writes `${HOME}/.claude/agents`),
`@ziniao-open/cli@0.1.0-beta.175` (`setup-ziniao-cli.ps1` sets the user PATH),
`anolisa-tokenless@0.9.3` (`install.sh` runs `"$CLAUDE_BIN" plugin marketplace add`).
`tmailcli@0.1.5` stays lost: its Go binary does the install (out of scope). Cost: 2 benign
reports, both of the ruled-unwanted shape (owner question 3): `@hsusulist/luc@0.3.1` (its
`install.ps1` adds LUC to the user PATH) and `stock-analyzer-skill@1.30.0` (the postinstall runs
`claude plugins marketplace add`).

| Live (real code, subset replay merged as before) | Reported | Benign | Unwanted | Malicious | Unverified | Precision |
|---|---|---|---|---|---|---|
| round4-base | 1,787 | 1,486 | 224 | 47 | 30 | 15.42% |
| this branch before R1 | 1,603 | 1,304 | 222 | 47 | 30 | 17.10% |
| **this branch with R1** | **1,608** | **1,306** | **225** | 47 | 30 | **17.24%** |
| with R1 + B's install-hook (simulated, section 4b) | 1,489 | 1,189 | 224 | 47 | 29 | 18.56% |

With R1, the branch against round4-base: 187 benign unreported (152 packages), 7 benign newly
reported; positives lost: `tmailcli@0.1.5` (unwanted) and `hyrox@0.1.6` (unverified); gained: 2
unwanted (`@myclaw163/clawclaw-cli@0.10.2`, `@phigon/superagent@0.1.4`) and 1 unverified
(`wkappbot-code@0.3.19`). `vm-day1`: unchanged, 12 of the 18 at-risk samples reported, the 6
`esoftplay` follow-ons lost (R1 only adds install code, so it can only add findings).

**R2. The 6 `esoftplay` follow-ons: no precise install-path signal.** The install hook is
`bun ./bin/build.js install`; `bin/build.js` runs `router.js`, `locale.js`, `bun install` and
`eas update:configure`, never `bin/cli.js`. The install code has no exfil endpoint: its only
Telegram text is a default project config (`"errorReport": {"telegramIds": ["-1001212227631"]}`).
The Telegram-bot code (`os.hostname()` and files to `api.telegram.org/bot923808407:...`) is in
`bin/cli.js`, the package's CLI, which runs only when the user runs `esoftplay`. So "install-run
code still contains a HIGH exfil match" does not hold for them. The wider guard, "keep V's
MEDIUM when any file of the package has a HIGH `static.exfil-endpoint` match", was measured on
the 193 versions V unreports: it keeps 4 benign reported (3 live `esoftplay` 0.0.269 betas,
reviewed benign though one still carries the same hard-coded bot token, and `colana`'s Telegram
bridge) and rescues the 6 `vm-day1` samples. It needs the whole package's text in Stage 3
(today Stage 2 reads only changed files and Stage 3 has no file text outside the install code),
a cross-stage change; not built. Owner question: the live `esoftplay` betas are benign and
`vm-day1`'s older versions malicious for the same CLI code.

**R3. `npm.install-persistence` on every version (`ONLY_WHEN_CHANGED = False`)**, replayed
with the real code on the same subset: 1,654 reported (benign 1,332, unwanted 243, malicious
47, unverified 32), precision 17.88%, against 17.24% with the default. That is **+18 unwanted,
+2 unverified and +26 benign**. The benign ones are mostly help text: `glimmervoid` x14
nightlies (a `SetEnvironmentVariable("PATH", ...)` line pushed into a printed array),
`agentiqa` x4 staging builds, `@mearl/native-host@3.0.5`, `common-context-mcp@3.6.2`. Over the
verdicted set P then fires on 114 unwanted, 103 benign and 4 unverified versions. Not built.

Commits after the rebase: `15781cf` (P), `47b9cac` (T), `7ffa26e` (H), `ce10495` (V, trade-off),
`d12c265` (this proposal), `81b99d7` (R1). Gates pass on the rebased tip (2,688 tests). Spot
check on the rebased code: `hauntview@0.2.9` reported (score 9, two MEDIUMs); all must-keeps
above reported except `tmailcli@0.1.5` and `hyrox@0.1.6`, as measured.

## Summary

`npm.install-script-changed` was the decisive rule for 341 benign live reports and for 65
unwanted (and 2 unverified) ones. It fires on any change to a file an install hook runs: a
refactor, an option, a reworded error. The unwanted ones are mostly user-wide agent installers,
shell rc and PATH editors and system-package installers, whose change happened to be cosmetic:
they were caught because their installer changed, not for what it does. Round 2's F1 (cosmetic
edits LOW) was rejected because it lost 7 `esoftplay` follow-ons on `vm-day1` and
`hyrox@0.1.6`.

This round names what those positives do, and then makes the old signal content-aware:

| # | Commit (stage) | What | Benign reports removed | Positives lost (live) | `vm-day1` lost | Kind |
|---|---|---|---|---|---|---|
| P | `15781cf` `npm.install-persistence` v1 (3), new | install code (new or changed) that works on an AI agent's user-wide configuration, writes a shell start-up file or the persistent PATH, or installs system packages: MEDIUM | 0 (adds 6 benign, 2 unwanted, 1 unverified) | 0 | 0 | **zero-loss** |
| T | `47b9cac` `static.channel-tagging` v1 (2), new | a Baileys fork that writes a fixed channel into the forwarded-newsletter context of the user's messages: MEDIUM | 0 (adds none) | 0 | 0 | **zero-loss** |
| H | `7ffa26e` `npm.install-script-code` v3 (3) | also code hidden past the edge of the screen (100+ spaces or tabs, then code) in new install code: MEDIUM. For `hauntview@0.2.9` (malicious, after the snapshot) | 0 (fires on no live version in the set) | 0 | 0 | **zero-loss** |
| V | `ce10495` `npm.install-script-changed` v5 (3) | the finding stays MEDIUM only when the change touches what an attack needs (processes, network, URLs/hosts, encoded data, credentials, home directory, shell or package-manager commands, whole environment, dynamic code, hidden code, a 4 KB+ literal), or the install code names an agent directory and the home directory; otherwise LOW | **188** (153 packages) | 4 unwanted, 1 unverified | 6 (`esoftplay`) | **trade-off** |
| | **All four** | | **-182 net** | 4 unwanted (+2 gained), 1 unverified (+1 gained) | 6 | |

Live, all four: 1,787 → 1,603 reported, benign 1,486 → 1,304, unwanted 224 → 222, precision
15.42% → 17.10% ([section 4](#4-live-result-real-code)). P, T and H alone: 1,787 → 1,796 (6
benign, 2 unwanted, 1 unverified more), precision 15.42% → 15.47%. V is a trade-off and is its
own commit. Without P and T it would lose 5 more positives, each now caught for what it does:
`@xfe-repo/cli@2.2.5` (shell rc, P), `arbentia-mcp-server@2.4.1` (VS Code user settings, P),
`gebangautoupload@1.1.4` (system packages, P), `@codexverified/baileys` 2.19.18/2.19.19 (T), and
`@lunabotv6/luna-baileys@8.1.0` (unverified, T). **Joint with agent B's install-hook change
(simulated, [section 4b](#4b-joint-measurement-with-agent-bs-install-hook-simulated)):
1,787 → 1,484 reported, 299 benign fewer net, precision 18.42%.**

## 1. Data and method

As round 3 ([section 1](precision-round3.md#1-data-and-method)): the real code of each `src/`
tree through `replay.py` (Stages 1-4 per version, tarballs read in memory with
`extract_tar_gz`, nothing run), on the 3,716 verdicted live versions; baseline = round 3's
`fix.jsonl` (the round4-base code, same harness). Positives are malicious + unwanted (last
verdict per version, checked against `data/verdicts/npm.jsonl` on 2026-11-09: no label differs
from the replay's); unverified is left out of precision and checked for loss.

- **Subset replay.** The changes can only change versions with an install hook or an
  install file (P, H, V) or WhatsApp library code (T). The fix side was replayed on those: 1,743
  versions with an install hook, 3 more with an install finding, and 35 more whose name, note or
  findings mention Baileys, WhatsApp, newsletters or channels (1,781). The other 1,935 rows are
  the baseline's. T was also run on every verdicted version's whole tarball (`tagscan.py`).
- **Offline analysis.** To find the shapes, every verdicted version with an install finding
  or hook (1,710 with a tarball) had its Stage 3 `CodeChange` rebuilt exactly as the replay
  builds it and pickled
  (`cc.py`); `proto*.py`, `pers2.py`, `pvar.py`, `evalcc*.py` ran the rule code on those (the
  estimate in `evalcc*.py` swaps in the Stage 3 findings and re-runs Stage 4's real `explained`
  and `decide`). Every number in the tables is from the replay unless marked "estimate".
- **DataDog (`vm-day1`).** P, T and H only add findings, so they can't unreport a sample; V can
  only lower `npm.install-script-changed`, which unreports only the samples it is decisive for
  (18). Those were re-run with the real `pipeline+4` predictor (section 5).
- **`hauntview@0.2.9`** (malicious, reviewed after the snapshot) and its earlier versions were
  copied out of their runs' `correlate.jsonl` and replayed the same way, base and final code.

## 2. Why the 341 benign reports, and what the positives do

Every one of the 341 benign versions has an install file that changed, and in most the change is
ordinary maintenance of an installer: a refactor (`@airwallex/airi-cli`: imports reorganised),
an option (`@aziron/atlas`: `ATLAS_SKIP_DOWNLOAD`), error handling (`@deepseekbuddy/cli` and the
`ngwlh` multi-scope CLIs, 30 versions of one `install.cjs`), a Node or platform check
(`bsmnt`, `@siteglide/siteglide-cli`), a template copied into the project (`vibeshield-nodejs-
backend`, `@squareboat/nest-mailman`), a rebuilt bundle (`@bjia56/portable-python-*`,
`scarwise`), the text of a build script (`node-sword-interface` x5, `esoftplay` betas). None of
these touches anything an attack needs. The ones that stay MEDIUM under V touch it: processes
(68 of the reported ones), URLs or hosts (49), the whole environment (45, mostly the
environment handed to a child process), the home directory (42), the network (33).

The 65 unwanted versions this rule carried alone (decision 0015's 2026-11-09 rulings) are,
by verdict note: user-wide agent installers (49: skills, hooks, settings or MCP servers into
`~/.claude`, `~/.codex`, `~/.cursor`, `~/.agents`, `~/.config/opencode`, `~/.claude.json`,
VS Code's user settings), shell rc and PATH editors (`tfv`, `@xfe-repo/cli`,
`@ziniao-open/cli`), system-package installers (`gebangautoupload`), Baileys media tagging
(`@codexverified/baileys` x2). Their changes were mostly cosmetic: caught because the
installer changed, not for what it does. That is what P and T replace: P names the behaviour
of 51 of them, T of 2; V keeps its MEDIUM on 8 (their changes touch a kind, or their install
code names an agent directory and the home directory); 4 are lost (section 4).

`vm-day1`: the rule is decisive for 18 malicious samples. 12 change risky lines and stay
MEDIUM under V (`@emilgroup/*` x7: the worm's `deploy.js` and a base64 payload in `index.js`;
`aicp-tracker@1.0.7`: a `spawnSync`; `fooobar@1.0.14`: `sudo touch`; `gina@0.7.1`:
`getUserHome()`; `esoftplay` 0.0.196 and 0.0.212: an `execSync` and an `npx expo install`
command). The other 6 are `esoftplay` follow-ons whose change is build configuration in
`bin/build.js` (section 5).

## 3. The changes

### P. `npm.install-persistence` (Stage 3, new, MEDIUM weight 3)

See [ast.md](../stages/ast.md#install-code-that-changes-the-machine-beyond-the-project-npminstall-persistence-2026-11-09).

### T. `static.channel-tagging` (Stage 2, new, MEDIUM weight 3)

See [static.md](../stages/static.md#whatsapp-channel-tagging-staticchannel-tagging-2026-11-09).

### H. `npm.install-script-code` v3 (Stage 3)

`hauntview@0.2.9` (malicious, 2026-11-09) put an obfuscated loader on line 14 of
`scripts/postinstall.mjs`, behind 266 tabs: it finds its C2 through an Ethereum transaction,
fetches JavaScript and evals it through `Function` reached by a computed key. Stage 3 saw only
the file's honest `child_process` import, so no capability finding fired; it was reported by
`npm.install-script-changed` alone (and under V only because one line had `fromCharCode`). H
makes the hiding itself the finding: a run of 100+ spaces or tabs followed by code that is no
comment, message or string (`hidden_code`, tree-sitter checked), in a new install file or one
whose previous version had none. Of the 1,710 verdicted live versions with install code and the
18 `vm-day1` samples, only `hauntview@0.2.9` has it. V counts the same thing, and a 4 KB+ string
literal, as touched kinds, and `_adds_risky` counts both in loaded files (the diagnosis'
suggestion in `review10/work_hv/diagnosis.md`); neither changes a live finding. 0.1.4-0.1.9
carry no loader (their install code is 0.1.3's, byte for byte), so nothing was missed there.
Agent F's Stage 2 padding rule and evidence rendering are separate.

### V. `npm.install-script-changed` v5 (Stage 3)

See [ast.md](../stages/ast.md) (the v5 paragraph).

## 4. Live result (real code)

| | Reported | Benign | Unwanted | Malicious | Unverified | Precision |
|---|---|---|---|---|---|---|
| round4-base (round 3's `fix.jsonl`) | 1,787 | 1,486 | 224 | 47 | 30 | 15.42% |
| P + T + H (`15781cf`, `47b9cac`, `7ffa26e`) | 1,796 | 1,492 | 226 | 47 | 31 | 15.47% |
| P + T + H + V (`ce10495`) | **1,603** | **1,304** | 222 | 47 | 30 | **17.10%** |

(The replay of the final code was run before H and V's two hidden-code/long-literal kinds were
added; re-running Stage 3 offline on every dumped `CodeChange` with the final code changes no
finding's severity and no decision on any live version, so the table holds for the final code.)

- **No longer reported (V): 188 benign (153 packages)**; 4 unwanted:
  `@ornexus/neocortex@4.60.77` (its `postinstall.js` spawns `install.sh --yes`, which writes
  `~/.claude/agents`), `@ziniao-open/cli@0.1.0-beta.175` (spawns `setup-ziniao-cli.sh`/`.ps1`,
  which add a PATH entry; 0.1.0-beta.170 and 1.3.0 stay reported), `anolisa-tokenless@0.9.3`
  (`execFileSync("bash", [install.sh])` runs `claude plugin install`), `tmailcli@0.1.5`
  (`spawnSync(binary, ["install-skill"])`): in each, the persistence is in a script or binary the
  install code spawns, which no install rule reads; their install JS changed only error
  messages or a flag. 1 unverified: `hyrox@0.1.6` (a reformatted Node-version check; unverified
  because of an obfuscated dependency no install rule reads).
- **Newly reported (P): 2 unwanted** (`@myclaw163/clawclaw-cli@0.10.2`,
  `@phigon/superagent@0.1.4`: user-wide skills; v4 had made the first one's change LOW as
  printed text, and the second's change is in a loaded file without a new risky use),
  **1 unverified** (`wkappbot-code@0.3.19`), **6 benign**: `common-context-mcp` 3.7.0 and 3.9.1
  (interactive opt-in, writes only what the user picks), `@usebitl/cli` 0.1.32/0.1.33 (its
  bundled CLI has a Codex-config writer the postinstall doesn't reach), `warp-agent-mcp@0.24.0`
  (a Claude Desktop config path in the loaded bundle), `@follenfang/fupload@1.1.0` (an
  `~/.agents/skills` default in its options module).
- **Where each rule fires** (the 1,781 replayed versions): P on 87 unwanted, 2 unverified and 72
  benign versions; it is the only MEDIUM on 9 unwanted, 1 unverified and 7 benign (with V). T on
  17 unwanted, 1 unverified and 2 benign versions (whole tarballs: 27 unwanted, 1 unverified, 2
  benign of the 3,716; the benign two are `@shanks-dev/baileys@0.1.2` and `shanks-dev@0.1.3`,
  whose note says "one hard-coded newsletter JID is branding in forwarded-message context",
  i.e. media tagging: owner question 4). H fires on none of the 1,710 verdicted versions with
  install code and on `hauntview@0.2.9` (replayed from its run: reported with
  `npm.install-script-changed` and `npm.install-script-code` MEDIUM, score 9; before, score 6
  on `install-script-changed` alone).
- **Of the 65 unwanted versions V's predecessor carried alone**, 51 are now caught by P, 2 by T,
  8 keep V's MEDIUM (their changes touch a kind, or their install code names an agent directory
  and the home directory), 4 are lost (above).
- **Replay fidelity:** on the 1,781 replayed versions no finding of any rule other than the
  changed ones differs from the baseline's. 99 versions keep their recorded Stage 2/3 findings
  in both (tarball gone), as in round 3.
- **Side effect for agent B:** with V, `npm.install-hook` becomes the decisive rule for about 60
  more benign reports (238 → 298): versions where both fired at MEDIUM. They are reported as
  before; a fix to the hook rule now removes them (section 4b).

## 4b. Joint measurement with agent B's install-hook (simulated)

At the integrator's request, B's intended `npm.install-hook` change is **simulated** (not B's
code; `scripts/joint.py`) on top of this branch's replay: an `install-hook` finding (MEDIUM or
HIGH) becomes LOW (weight 1) when the version's install code has no risky capability (network,
process, whole environment, dynamic code/require), no hook is shell beyond `node <file>`,
`binding.gyp` runs no command, the hooks name a file that was read, and the install code is not
upstream Baileys's `engine-requirements.js` (the forks B rescues with a dedicated rule stay
reported: 13 benign and 2 unwanted depend on that rescue). Capabilities come from the dumped
`CodeChange` of each version; then the real `decide`.

| | Reported | Benign | Unwanted | Malicious | Unverified | Precision |
|---|---|---|---|---|---|---|
| round4-base | 1,787 | 1,486 | 224 | 47 | 30 | 15.42% |
| B (simulated) alone | 1,718 | 1,425 | 217 | 47 | 29 | 15.63% |
| this branch alone | 1,603 | 1,304 | 222 | 47 | 30 | 17.10% |
| **this branch + B (simulated)** | **1,484** | **1,187** | 221 | 47 | 29 | **18.42%** |

- **Joint vs base:** 305 benign unreported, 6 benign newly reported; positives lost: the 4
  unwanted and `hyrox@0.1.6` above, plus `@ywabgl/musepool-html-mcp@0.2.0` (unwanted) and
  `@yalehwang/cloudpit@2.0.0` (unverified) through the B part; gained: 2 unwanted, 1 unverified.
- **P rescues B's losses:** B alone loses 7 unwanted new or hook-added installers whose install
  code is file-system only (`join-com-cli@0.0.0`, `ha-integration-skill@0.1.0`,
  `install-anything-skill@1.0.0`, `mxcad-skill@1.0.0`, `@easyhaloo/afk-opencode@1.2.0`,
  `dsh-yunpa@0.10.1`, `@ywabgl/musepool-html-mcp@0.2.0`); with P, 6 of them stay reported for
  what they do. `musepool` 0.2.0 is not routed to Stage 2/3 in the live run (its `postinstall` was
  added on an update: Stage 1's HIGH), so no Stage 3 rule sees its code: B should not demote a
  hook whose install code wasn't read. `cloudpit@2.0.0`'s tarball was never captured (same).
- **`npm.install-script-code` (now this agent's):** in the joint state it is decisive for 1
  benign report. It is MEDIUM beside `install-hook` in 143 benign reports (`hook + code`), 66
  (`hook + changed + code`) and 37 (`changed + code`), but there it fires because the install
  code really uses the network or processes, which is exactly what keeps B's hook MEDIUM too. A
  demotion of `install-script-code` alone frees nothing; those need an explanation of the risky
  install code itself (agent E's S1/S2/S5 shapes). H (v3) is the only change built here.

## 5. DataDog check (`vm-day1`)

P and T only add findings, so they can't unreport a sample. V only lowers
`npm.install-script-changed`, which unreports a sample only where that rule is decisive: 18 of
the 2,708 reported malicious samples (round4-base = round 3's `ddbase.jsonl` with its
`ddfix.jsonl` rows; the same 18 as before round 3). Those 18 were re-run with the real
`pipeline+4` predictor and the final code (`ddA.py`, one process, own data directory with a
fresh Stage 2 cache, repository comparison off as in round 3):

- **12 stay reported**, each through V's MEDIUM: `@emilgroup/*` x7 (the worm's rewritten
  `scripts/deploy.js`: processes, the network, credentials; `index.js`'s new base64 payload:
  encoded data), `aicp-tracker@1.0.7` (a new `spawnSync` of its setup wizard; P fires too, on
  `path.join(os.homedir(), ".claude", "projects")`, the Claude Code session logs it reads), `fooobar@1.0.14` (`exec('sudo touch /gotfoo')`), `gina@0.7.1`
  (`getUserHome()`), `esoftplay` 0.0.196 (`execSync`) and 0.0.212 (`npx expo install`).
- **6 are lost**: `esoftplay` 0.0.142-m, 0.0.143-w, 0.0.183, 0.0.185, 0.0.256, 0.0.262 (score
  2-3). Their only change is in `bin/build.js`, the project scaffolding the `postinstall` runs:
  a `bun.lock` line in a `.gitignore` template, `JSON.parse` guards, an Expo build profile
  (`"bun": "1.1.0"` removed), a Babel plugin list. What makes the family malicious is in
  `bin/cli.js` (a CLI command that sends the hostname and files to a hard-coded Telegram bot),
  unchanged, so Stage 2 never reads it in these follow-ons. 2 of the family's 22 samples stay
  reported. Round 2's F1 lost 7 of them for the same reason; the live `esoftplay` versions are
  reviewed benign (they read the bot token from the user's config).

Note: the brief asks for DataDog runs under the shared lock; with five agents' full replays
queued on it for hours, this 18-sample run used one worker under `MemoryMax=4G` outside it, as
the brief allows for small targeted runs.

## 6. Rejected or not built

- **Set-based v5 (only matches the previous install code didn't have count, for every file).**
  It would also lower refactors of risky code, but it loses the `@emilgroup/*` worm follow-ons
  on `vm-day1`: `scripts/deploy.js` 1.0.3 rewrites the previous version's worm (`npm publish`,
  `NPM_TOKEN`, `-/whoami`, `-/v1/search?text=maintainer:`) with no new token. V is line-based;
  only files too long to diff are compared as sets.
- **Dropping "the home directory" from V's kinds** (42 decisive benign keep the MEDIUM through
  it): loses `gina@0.7.1` on `vm-day1`, whose only touched kind is `getUserHome()`.
- **Keeping V's MEDIUM when the install code runs a shell script** (`spawnSync("powershell.exe",
  [...])`, `execFileSync("bash", [script])`): keeps `@ziniao-open/cli@0.1.0-beta.175` and
  `anolisa-tokenless@0.9.3` (unwanted) for 8 benign kept reported (`@abacus-ai/cli`,
  `@sluisr/corex`, `cs-devtest` x2, `locus-cli`, `universal-plugin-hub` x3); a shell script
  is no sign of persistence. Any `.sh`/`.ps1` named in the install code: 52 benign for 3.
- **Keeping V's MEDIUM when the install code has the process capability:** 92 of 195 benign
  stay, to keep 4 unwanted.
- **P with a file write within 3 or 10 lines of the agent path:** loses 53 or 35 of 87 unwanted
  user-wide writers (the path is computed in a helper, the write is elsewhere:
  `@minhspark/codex-mcp-bridge`, `aptly`, `pantheon-opencode`, `toga-ai`, ...).
- **P skipping install code that prompts** (`readline`, `prompts`, `inquirer`, `.question(`):
  loses 20 of 80 unwanted (`@linkquejs/card-craft`, `@phnx-labs/agents-cli`,
  `@promethea-research/sundial`: they ask something else, then write anyway) to drop 28 benign.
- **The child-process environment (`env: { ...process.env }`) as no "whole environment":** 2
  benign (`qdd-framework` x2), not worth a re-measurement before the freeze.
- **P on every version (`ONLY_WHEN_CHANGED = False`):** see owner question 2.

## 7. Owner questions

1. **V is a trade-off:** 188 benign reports for 4 unwanted installers whose persistence lives in
   a spawned script or binary, `hyrox@0.1.6` (unverified) and 6 `esoftplay` follow-ons on
   `vm-day1` that were caught only because a build-config file changed (the family's live
   versions are reviewed benign, and drop the hard-coded tokens). Take it, or keep P and T only?
2. **P on every version (`ONLY_WHEN_CHANGED = False`)** (estimate before P's last agent-home additions, the real rule code with
   Stage 4's real decision on the dumped changes): +18 unwanted and +2 unverified reported
   (misses today: `@aswless_854771076/ai_short_studio_cli`, `@cartanova/qgrid-cli`,
   `@essentialai/cogent-bridge`, `pantheon-opencode` 2.0.0 betas, `toga-ai`, `karajan-code`,
   `openyida@2026.11.9`, ...), +4 benign more (`@mearl/native-host@3.0.5`, `great-cto@3.76.1`,
   `shieldcortex@5.19.0`, `common-context-mcp@3.6.2`). On the 9 runs of 2026-11-09, which the
   reviewers labelled completely for the user-wide note, it adds 17 unwanted, 3 unverified and
   7 benign: about 7 benign per 9 hourly runs, over the ~5-a-day bar. Not built.
3. **Benign verdicts that look like the 2026-11-09 unwanted rulings** (with R1 also
   `@hsusulist/luc@0.3.1`, user PATH from `install.ps1`, and `stock-analyzer-skill@1.30.0`,
   `claude plugins marketplace add` at install) (P fires on them; most
   verdicts predate the rulings): `0xray` 4.1.5/4.2.0 (hooks into Grok/Cursor/Codex configs under
   home), `@finebi/finebi-cli@2.0.9` and `@kopplin-co/claude-web-design-skill@0.2.0` (skills
   into `~/.claude/skills`), `agy-statusblocks@0.1.0` (`~/.gemini/antigravity-cli`),
   `novahiz@0.12.1` (`~/.opencode`), `@civitas-cerebrum/achilles@0.1.8` (0.1.9 is unwanted),
   `pantheon-opencode` 1.6.2-beta.4/1.6.3-beta.4/2.0.0-beta.1 and `triflux` 10.88.2/10.90.0 and
   `@muggleai/works@5.28.0-staging.252` (other versions of each are unwanted), `zn-gate@1.15.0-rc.1`
   (agent hook launchers), `emtypyie-cli@3.5.1` (sets the user PATH through PowerShell),
   `@ohos-ports/gifsicle@4.0.1-beta.1` (`execSync('brew install gifsicle')`), `warp-agent-mcp@0.24.0`.
   Re-review?
4. **Baileys media tagging:** `@shanks-dev/baileys@0.1.2` and `shanks-dev@0.1.3` (benign, "a
   hard-coded newsletter JID is branding in forwarded-message context") and
   `@lunabotv6/luna-baileys@8.1.0` (unverified, "media uploads carry a Luna-Botv6 newsletter
   attribution") have the shape the 2026-11-09 ruling calls unwanted.
5. **Done in R1 (update above):** follow shell scripts the install code runs by a constant path into the
   install code (`ecosystems/npm/install.py`, a shared helper): it would let P see 3 of the 4
   lost installers (`neocortex`, `ziniao`, `anolisa`); `tmailcli`'s Go binary stays unseen.
6. **For B and the integrator:** in the joint simulation, `@ywabgl/musepool-html-mcp@0.2.0`
   (unwanted) and `@yalehwang/cloudpit@2.0.0` (unverified) are lost only through the hook
   demotion: their install code was never read by Stage 3 (not routed / tarball not captured).
   A hook whose install code wasn't read should keep its severity.
7. `npm.install-agent-user-wide` (INFO) stays as the broad note (and is V's guard: install code
   that names an agent directory and the home directory keeps its MEDIUM). Retire it once P is
   accepted?

## 8. How to reproduce

Scripts in `~/kitsunox-scratch/r4/A/scripts/` (read-only on `data/`; Python with `-I` under
`systemd-run --user --scope -p MemoryMax=4G`/`8G`, nice 19; outputs in `out/`): `cc.py` and
`ddcc.py` (CodeChange dumps), `proto2.py`, `persist.py`, `pers2.py`, `pvar.py`, `pwin.py`,
`attrs*.py`, `evalcc.py`/`evalccA.py` (offline shapes and estimates), `replay.py` (round 3's,
unchanged) on `out/final.csv`, `merge.py`, `compare.py`, `analyze.py`, `tagscan.py`, `ddA.py`
(round 3's `dd.py` on this agent's data directory) on `out/dd-isc.keys`.
