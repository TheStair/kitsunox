# Proposal: precision round 4, agent B: install hooks that do nothing

> **Status:** built 2026-11-10, before the rule freeze (2026-11-12 00:00Z), for the owner's
> review. Cluster: `npm.install-hook` and `npm.install-build-tool` (Stages 1 and 3), plus one
> Stage 4 `EXPLAINED` entry. **Result on `main` `bd222bd` (rounds 1-4 of A, C, D, E, F and G
> merged), real code on all 3,716 verdicted live versions: 1,444 → 1,428 reported, all 16
> benign (16 packages); 0 malicious, unwanted or unverified version stops being reported, and
> neither new explanation fires on any positive. `vm-day1`: the rules fire on 6 of the 2,319
> malicious samples with an install hook; all 6 are decided as before (3 reported, 3 not),
> 0 lost.** Precision (malicious + unwanted) 20.23% → 20.46%. Both changes are zero-loss.
> **Builds on:** [round 3](precision-round3.md) (method, harness), [round 2](precision-round2.md)
> sections 6-8, decision [0015](../decisions/0015-reviewer-verdicts.md) with all addenda, and
> agent E's S5 in [round 4 E](precision-round4-E.md) (same population as B1).

## Summary

`npm.install-hook` (Stage 1) sees a hook's command line, never what it runs. On round4-base
it was decisive for 254 reported live versions (238 benign). Since then, agent E's S5
("inert install code", `npm.install-explained` v3) explains most of the inert `node <file>`
hooks, and agents A and G name what intrusive install code does (`npm.install-persistence`,
`static.channel-tagging`, `npm.install-script-loader`). What B adds on top of that:

| # | Rule (stage) | What changes | Benign removed on `main` | Positives at risk → lost | `vm-day1` fired → lost |
|---|---|---|---|---|---|
| B3 | `npm.install-build-tool` v3 (3) | more exact tool lines (`npx only-allow npm`, `-y`, `bunx ... bun`, `opencollective-postinstall`, `node-gyp-build \|\| node-gyp rebuild`, `npx @mapbox/node-pre-gyp ...`); Playwright's browser download when Playwright is a dependency (never `--with-deps`); a tool the package's own `bin` names is its own code; tree-sitter's `src/scanner.c` test and `node-addon-api`'s `.targets` in `binding.gyp` are lookups | **12** | 0 → 0 | 4 → 0 |
| B1 | `npm.install-inert` (3, new INFO) + `EXPLAINED` (4, stage version 16) | `npm.install-hook` LOW on a *new* package whose hooks only run inert package code or a constant `echo`; carries every S5 guard (shared from `install_shapes`) and refuses probes | **4** (inline `node -e`/`-p` 2, echo-only 2) | 0 → 0 | 2 → 0 (before the Baileys guard; 0 fire after) |
| | **Both** | | **16** (16 packages) | **0** | **6 → 0** |

**Commits** (on `worktree-agent-a08b13791a8ac13b4`, rebased on `bd222bd`): see the final
report; B3 is one Stage 3 commit, B1 is Stage 3 + one Stage 4 wiring commit, then docs.

Built and then dropped while measuring (section 6): an empty-hook change (B2) and a channel
tagging branch of `static.channel-follow` (B4, duplicate of A's `static.channel-tagging`).

## 1. Method

Round 3's harness (`replay.py SRC CANDS OUT`: Stages 1-4 with the real code per version,
tarballs read in memory with `extract_tar_gz`, nothing run), today's verdicts. **Baseline =
`main` `bd222bd`, fix = `main` + B**, same harness, both full (3,716 versions). Round 3's
context-finding staleness (E's note: 4 `known-malware` v1 findings) is in both sides alike.

**`vm-day1`.** B can only change a sample on which `npm.install-inert` or
`npm.install-build-tool` fires. `ddfire.py` evaluates both rules (Stage 3 `code_change` on the
predictor's in-memory files) on every one of the 2,319 malicious samples with an install hook:
they fire on 6. Those 6 were run with `pipeline+4` (`dd.py`, one process per sample,
repository comparison off) with `main` and with `main` + B.

**What can't be measured.** 36 benign and 3 positive or unverified live versions that `npm.install-hook`
carries have no tarball any more (taken down or never captured); the replay keeps their
recorded findings. `luna-baileys@1.0.0` (unwanted) and `testbail@1.0.0` (unverified) are
among them; B1 refuses upstream Baileys's `engine-requirements.js`, so it would not explain
them even live. Versions over Stage 2's size cap (`charape@1.0.20`) are never read, and
unrouted ones (`@ywabgl/musepool-html-mcp@0.2.0`, `@yalehwang/cloudpit@2.0.0`) have no Stage 3
run: B1 needs Stage 3 to have read the code, so `npm.install-hook` keeps its severity for all
of them (checked: both stay reported).

## 2. Where the install-hook-only benign reports are now

On `main` most inert `node <file>` hooks are E's S5. Of the round4-base cluster (238 benign),
what is still reported only through `npm.install-hook` falls into: another program (`npm run x`
13, `nuxt prepare` 5, `git config core.hooksPath`, `bash x.sh`, `dotnet build`, `cmake-js`,
`pip install`), a hook naming a file the tarball doesn't have at that path (12), writes outside
the package (`INIT_CWD`, `node_modules` patches, DSH profiles, `require.resolve` + chmod: the
owner keeps these reported), `binding.gyp` commands, home or agent directories, Baileys forks
with upstream's Node check (S5's and B1's guard), and 36 without a tarball. B3 and B1 take the
two shapes S5 doesn't: exact tool lines, and new packages whose hooks are inline code, chains
of node files, or echoes.

## 3. The fixes

### B3. `npm.install-build-tool` v3 (Stage 3)

The rule (INFO, an explanation Stage 4 applies to `npm.install-hook` only) needs every hook to
be an exact tool line and `binding.gyp` to run no command but lookups. v3:

- hook lines `npx only-allow npm`, `npx -y only-allow npm|pnpm`, `bunx only-allow bun`,
  `opencollective-postinstall`, `node-gyp-build || node-gyp rebuild`,
  `npx @mapbox/node-pre-gyp install --fallback-to-build`;
- `playwright install [chromium]` and `npx playwright install [chromium]` only when the
  manifest depends on `playwright`, `playwright-core` or `@playwright/test`; `--with-deps`
  (system packages through `apt-get`, decision 0015) is never on the list;
- `tool_shadowed`: a tool the package's own `bin` names is the package's code (npm links a
  package's bins before its hooks run), for every tool line, old and new;
- `binding.gyp`: tree-sitter's `fs.existsSync('src/scanner.c')` (ternary and `has_scanner`
  forms, the latter as `gyp_commands` cuts it at the first `)` before a quote) and
  `require('node-addon-api').targets` count as lookups.

Removed (12, all benign): `@evgeni_design_84/ai-pdp-ds`, `@orochibraru/ui`, `@tentrucks/ui`
(only-allow), `docsify@5.1.0` (Open Collective), `@itc-steve/pi-web-complete`,
`@pierdigital/arraia-web`, `autorunqa-runner`, `phloem-ai` (Playwright),
`@ohos-ports/nodejieba` (node-pre-gyp), `electron-win11-snap-overlay`,
`tree-sitter-javascript-orchard`, `tree-sitter-swi-prolog`. `vm-day1`: it fires on 4 malicious
samples, all decided as before (`@mastra/node-speaker@0.1.1` reported through
`fresh-foreign`/`revived`; `duckdb@1.3.3`, `n8n-nodes-zalo-fevox@0.6.8`,
`tree-sitter-iec61131-3-st@0.1.0` not reported with or without it, as in round 3).

### B1. `npm.install-inert` (Stage 3, new) explains `npm.install-hook` (Stage 4)

INFO, weight 0, `ecosystems/npm/rules/install_inert.py`; with it present Stage 4 makes
`npm.install-hook` LOW, weight 1, with a note (stage version 16). It explains nothing else.
Conditions (all; details in [ast.md](../stages/ast.md#inert-install-hooks-npminstall-inert-round-4)):
a new package; hook lines that only run `node <file>`, `node -e|-p`, constant `echo`, `true`,
`exit` (split with `shlex`; no pipe, redirect, substitution, other program, `node -r`); all
of it read and readable; no risky capability, package load or risky text; nothing outside the
package; none of S5's guards (`BAILEYS_ENGINE_CHECK`, `OTHER_PACKAGE`, `SYSTEM_PATH`,
`DELETES`, `RISKY_TEXT`, `placeholder`, `plain_text`/`unreadable`, imported from
`install_shapes`); no probe text in an echo, the code or a file name (`PROBE_TEXT`).

Removed on top of S5 (4, all benign, all new packages): `@8-interactive/parse-server@2.8.20-upsert-db-cors`
(`node -p 'require("./postinstall.js")()'`: a banner and a Node check), `@focus-at/zs3@0.0.36`
(`node -e` star-on-GitHub message), `@buoy-gg/bug-links@7.0.80` and `lilia-mcp@0.1.0`
(echo-only hints).

**How it got there** (each step measured; the integrator's and other agents' notes drove most):

| Step | Live (round4-base) | Why |
|---|---|---|
| first version | 31 benign | `..` anywhere counted as outside |
| `..` by depth, completeness only for loaded code | 36 | |
| + echo-only (non-probe) | 40 | |
| + another package resolved and written | 37 | `@personai/agent-ui-terminal` rewrites `@xterm/xterm`'s bundle (the `blue-crab` mechanism) |
| new packages only | 34 | `kevinx-baileys@1.2.2` (unwanted): follow code in an unchanged file, only the hook points at it once A lowers `install-script-changed` |
| `vm-day1` check: probe text in install code | 33 | `wc@1.5.0`, `grab-service-worker@1.0.1`, `coldbox@6.7.71`, `pmcrypto@0.1.0` (`poc.js`), malicious-labelled PoCs, were lost |
| S5's guards (Baileys engine check, `require.resolve`, placeholder, ...) | **4 on top of S5** | integrator: the Baileys and patcher exclusions are owner-relevant; E's S5 already takes the rest |

`shanks-dev@0.1.3` and `@shanks-dev/baileys@0.1.2` (relabelled unwanted 2026-11-10: channel
tagging) were explained by an earlier B1; with the Baileys guard they no longer are, and A's
`static.channel-tagging` reports them anyway.

## 4. Live result (real code, all 3,716 verdicted versions, today's verdicts)

| | Reported | Benign | Unwanted | Malicious | Unverified | Precision |
|---|---|---|---|---|---|---|
| `main` `bd222bd` | 1,444 | 1,128 | 239 | 47 | 30 | 20.23% |
| + B3 + B1 | 1,428 | 1,112 | 239 | 47 | 30 | 20.46% |

16 versions no longer reported, all benign; none newly reported. `npm.install-inert` and the
changed `npm.install-build-tool` fire on no malicious, unwanted or unverified version. Joint
check for the integrator (`joint.py`): with A's rules on `main` already, no further version is
unreported only once `install-script-changed`/`install-script-code` are also LOW.

## 5. DataDog check (`vm-day1`)

`ddfire.py`: of the 3,444 malicious samples, 2,319 have an install hook; `npm.install-inert`
or `npm.install-build-tool` (B's code) fires on 6. `pipeline+4` on those 6 with `main` and
with `main` + B: identical decisions (3 reported, 3 not), **0 lost**. The two Baileys forks it
first fired on (`@web2apk/baileys@7.7.7`, `@xayz/baileys@1.0.0`, both reported through
`channel-follow`/`channel-tagging` too) are refused by the Baileys guard now.

Earlier runs on the 81 samples `npm.install-hook` was decisive for on round4-base (`dd.py`
base: 81 reported) found what the final version guards against: 6 lost through B2 (empty
hooks) and 4 through B1 before the probe-code guard (section 6).

## 6. Rejected or dropped

- **B2: an empty hook (`""`) is no finding.** 3 benign live, but 6 `vm-day1` malicious samples
  are reported only by an empty hook (`@hemihatchlings/shared@1.0.0`,
  `cordova-plugin-globalization.moment@1.0.0`, `francium-utils@1.0.0`,
  `third-party-library@1.0.0`, and the emptied follow-ons `@speedshop/sdk-api@21.4.4`,
  `rank4222wun@1.0.13`). Nothing runs at install there, but the bar is the bar. Dropped.
- **B4: channel tagging as `static.channel-follow` v2.** Measured (a literal `newsletterJid`
  channel in 30 live versions, 26 unwanted), then dropped: A's `static.channel-tagging` does
  the same and is merged.
- **B1 for Baileys forks with upstream's Node check** (12 benign on round4-base, new packages
  only, the unwanted ones all reported through `channel-follow`/`channel-tagging`): refused,
  as S5 does, on the integrator's request; an owner question (7.2).
- **B1 for `require.resolve` + `chmod`** of `node-pty`'s `spawn-helper` (4 benign: `coban`,
  `@easyx/ucode`, `unfold-deploy`, `@setupsworks/office`): the owner keeps patchers reported.
- **B1 on updates**: `kevinx-baileys@1.2.2` (above).
- **`npm run <script>` hooks** (13 benign): Stage 3 doesn't follow `npm run` to the script it
  names, and `vm-day1` malware uses exactly this (`eslint-config-sdk@99.0.0`:
  `npm run payload`; `pino-*`, `marked-*`).
- **Hooks naming a missing file** (12 benign): Node also tries `x.js.js` and `x.js/index.js`;
  "missing" could be evaded without the tarball's file list.
- **Project writes (`INIT_CWD`)** (~8 benign): a project write can plant git hooks, editor tasks
  or CI files that run later.
- **`nuxt prepare`, `cmake-js`, `simple-git-hooks`, `git config core.hooksPath`** as tools: they
  run the package's own config or build files, or install git hooks in the user's project.

## 7. Owner questions

1. Keep B3 (12 benign) and B1 (4 benign) for the freeze? Both zero-loss live and on `vm-day1`.
   B1 is a new rule for 4 reports on top of S5; take it or leave it on its own.
2. B1 (and S5) refuse every package whose hook runs upstream Baileys's
   `engine-requirements.js`. For **new** packages Stage 2 reads every file, so the follow and
   tagging rules see the fork's code; 12 benign forks (round4-base: `@barzenv404/baileys`,
   `@estehmd/baileys`, `@yui-bails/*`, `mfsavana-baileys`, ...) could go, losing nothing
   measurable (`luna-baileys@1.0.0` can't be checked: tarball gone). After the freeze?
3. B1 takes inline `node -e` hooks on new packages; you dropped E3 (S5 for inline code) for
   `shoal-cli@0.4.5`, an update, which B1 never explains. Fine for new packages?
4. **A gap found on the way (not changed):** `install.gyp_commands` only extracts an expansion
   `<!(...)` whose `)` is followed by a quote on the same line, so
   `"<!(node payload.js):target"` is never extracted: neither `npm.install-build-tool`'s "no
   command" test nor the install-code rules see it. A paren-matching extractor would close it
   (shared helper).
5. After the freeze: let `install_sources` follow `npm run <script>` (recall for the install-code
   rules; `vm-day1` payloads run through it).

## 8. How to reproduce

Scripts in `~/kitsunox-scratch/r4/B/scripts/` (Python with `-I`, read-only on `data/`; heavy
runs under the shared lock): `replay.py` (round 3's), `cmp.py`, `attrib.py`, `touchedB.py`,
`joint.py`; `hookrows.py`/`hookcmds.py`/`diag.py` (section 2); `ddfire.py` (which `vm-day1`
samples B's rules fire on), `dd.py` (round 3's `pipeline+4`), `ddcmp.py`, `ddcmds.py`,
`ddshow.py`; `tagscan.py` (B4). Final outputs: `out/fullF-base.jsonl`, `out/fullF-fix.jsonl`,
`out/ddF-base.jsonl`, `out/ddF-fix.jsonl`, `out/ddfire.jsonl`; chain `heavyF.sh`.
