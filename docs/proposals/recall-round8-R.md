# Proposal: recall round 8, agent R (three unreported positives from the daily samples)

> **Status:** built 2026-11-11/12, before the rule freeze (2026-11-16 00:00Z), for the owner's
> review. Three commits, one per target, each with its tests and docs. Not merged.
> **Builds on:** decision [0019](../decisions/0019-live-evaluation.md) (the label-blind daily
> samples that found the misses), decision [0015](../decisions/0015-reviewer-verdicts.md)
> (what counts as a positive), [round 6 R](precision-round6-R.md) (`npm.install-download`,
> its `ONLY_WHEN_CHANGED` measurement), [round 4 A](precision-round4-A.md)
> (`npm.install-persistence`), [round 6 U](precision-round6-U.md) (`correlate.follow-on`).

## Summary

The label-blind daily samples found 13 unreported positives (the integrator's
`sample-misses.cands.jsonl.zst`). Replaying current `main` (`d3ce1f1`) on them, 8 are caught by
`npm.install-download`; this round targets three of the other five, narrowly. The other two
(`local-operator-ui`, `lumen-lib`) are routing misses Stage 2 never reads (decision 0008, out
of scope). A fourteenth sampled miss sent during the round, `@plannotator/opencode@0.28.45`
(unwanted: an unchanged postinstall that copies skills into `~/.config/opencode`), is out of
scope too: its declared unpacked size (63.9 MB) is over Stage 2's 32 MB install-hook cap, so
neither the live run nor the replay reads it.

| # | Commit (stage) | What | Sample misses caught (of 13) | Replay set (3,716): benign / positives added, lost | Other sets |
|---|---|---|---|---|---|
| 1 | `npm.install-download` v2 (3) | `tool` form: `webdriver-manager update` | +1 (`@percy/protractor@2.0.4-beta.0`) | 0 / 0, 0 lost (fires nowhere else) | none |
| 2 | `npm.install-persistence` v6 (3) | the `agent` form counts on unchanged install code too | +1 (`@aswless_854771076/ai_short_studio_cli@0.1.236`) | **+2 benign** (owner's call) / +14 unwanted, +2 unverified, 0 lost | whole runs: +55 versions, 27 packages in two days |
| 3 | `static.channel-follow-on-connect` (2, new) | a hardcoded channel id followed when the socket connects, in any file of any version | +1 (`@risacakep/risayap@7.0.0-rc25.7`) | 0 / 0, 0 lost (fires on 1 version, already reported) | Baileys set: +5 unwanted, 0 benign (largely covered live by `correlate.follow-on`) |

With all three: the sample misses go from 8 to **11 of 13** caught. Replay set, today's
verdicts: 1,423 → 1,441 reported, precision **47.95% → 48.40%**, 0 positives or unverified
lost. `vm-day1`: see section 6.

## 1. Data and method

As rounds 3-7: `replay.py SRC CANDS OUT` (agent K's corrected harness) reruns Stages 1-4 with
`SRC`'s code on each recorded candidate (tarballs read in memory with `extract_tar_gz`, nothing
run). Inputs:

- **Sample misses:** the integrator's 13 keys, plus `@plannotator/opencode@0.28.45` built the
  same way from run `20261102T093924Z-npm`'s `correlate.jsonl`.
- **Replay set:** the 3,716 verdicted live versions (`~/kitsunox-scratch/r5/shared/cands.jsonl.zst`);
  baseline `~/kitsunox-scratch/r7/shared/integ.jsonl` (rules = `main`); one full replay with
  all three targets, counted by `relabel.py` with the verdicts of 2026-11-12. Each change is
  attributed to its target by the finding that reports it.
- **Baileys set:** all 118 verdicted versions whose name or note says Baileys (60 unwanted, 48
  benign, 10 unverified), candidates copied from their runs (most are newer than the replay
  set).
- **Whole runs (target 2):** the 47 runs since `20261110T040000Z` (234,995 versions), read-only.
- **`vm-day1`:** `pipeline+4` per sample (`dd.py`, repository comparison off, as rounds 3-7),
  `main` and the final code, on the malicious samples these changes can act on.

The replay does not run Stage 4's follow-on pass (`correlate.follow-on`, round 6 U), which is a
run-level pass; see target 3.

## 2. Target 1: `webdriver-manager update` (`npm.install-download` v2)

`@percy/protractor@2.0.4-beta.0` (run `20261111T121953Z-npm`, unwanted by the owner's
2026-11-10 ruling): its `install` hook is `webdriver-manager update --no-chrome
--no-standalone`, Protractor's driver manager, which downloads geckodriver (and by default
chromedriver and the Selenium server) from their projects' hosts. The `tool` form now names
`webdriver-manager update` (as a command, also behind `npx`, or a command string handed to a
runner), the same way as `playwright install`. Other `webdriver-manager` commands (`status`)
and messages naming it don't count.

Only obviously equivalent fetchers seen on real data: across every recorded run's install-hook
lines (`changes.jsonl` of all 176 runs) the only driver fetchers are `@percy/protractor`'s
`webdriver-manager update` and `electron-chromedriver`'s own `node ./download-chromedriver.js`
(not a `webdriver-manager` call; left to the other forms). `selenium-standalone install` never
occurs and is not added; `chromedriver`'s own install is a dependency's script, never read.

**Measured.** Sample misses: `@percy/protractor@2.0.4-beta.0` now reported (score 3,
`npm.install-download`, `[tool] webdriver-manager update ...`). Replay set: the new form fires
on no other version; no decision changes. 29 tests in `test_install_download.py` (one new:
`test_webdriver_manager_update_fetches_browser_drivers`).

## 3. Target 2: user-wide agent installs in unchanged install code (`npm.install-persistence` v6)

`@aswless_854771076/ai_short_studio_cli@0.1.236` (run `20261108T151126Z-npm`, unwanted): its
postinstall `scripts/postinstall.mjs` calls `autoInstallSkills(defaultSkillsRoot('codex'))`,
copying the bundled skill into `~/.codex/skills` on every install. The install code is the
same as 0.1.235's, and `npm.install-persistence` has `ONLY_WHEN_CHANGED = True`, so nothing
fired (only the INFO `npm.install-agent-user-wide`).

Two variants, measured with the real code on the 1,384 replay-set updates that have an install
hook (the only versions where `ONLY_WHEN_CHANGED` can matter):

| Variant | Unwanted added | Benign added | Unverified added | Lost |
|---|---|---|---|---|
| A: `ONLY_WHEN_CHANGED = False` (every form, as round 6 R did for downloads) | 14 | 24 | 2 | 0 |
| **B (built): only the `agent` form counts on unchanged install code (`ALWAYS_FORMS`)** | 14 | 2 | 2 | 0 |

Variant A's 22 extra benign versions are all non-agent forms in unchanged install code:
`glimmervoid` 0.48.2-next.316 ... 0.52.3-next.901 (17 prereleases, `path` form: a PATH help text
in a bundled chunk) and `agentiqa` 1.1.50-staging.* (4, `system-package`: an install hint
string). Variant B keeps every positive A adds and drops those. The positives both add (the
same 14 unwanted): `@aswless_854771076/ai_short_studio_cli` 0.1.236 and 0.1.239,
`@cartanova/qgrid-cli` 2.19.0 and 2.19.1, `@karajan-family/code@5.11.0`, `karajan-code@5.11.0`,
`@mearl/native-host@3.0.5`, `aum-framework@1.8.2`, `onadit@1.0.21`, `pantheon-opencode`
2.0.0-beta.2/.3/.4, `toga-ai` 1.0.1318 and 1.0.1319; unverified: `wkappbot-code` 0.3.16 and
0.3.17.

**Benign added by B (the owner's call):**

- `common-context-mcp@3.6.2`: the reviewer's note: its postinstall skips local installs,
  honours `CONTEXT_MCP_NO_SETUP`, writes nothing without a terminal and only configures the
  agents the user picks at an interactive prompt. The rule counts a write behind a prompt by
  design (round 4 A: "a write behind an interactive prompt ... counts too"), as it already did
  for this package's changed versions.
- `shieldcortex@5.19.0`: runs only on `npm -g` and refreshes plugin files only when a
  ShieldCortex hook already exists in `~/.openclaw`. Global-only writes count by the owner's
  ruling (round 4 A); the refresh-only shape is not something the rule can see.

**Whole-run estimate (queue growth).** In the last two days' runs (47 runs since
`20261110T040000Z`, 234,995 versions) the versions Stage 3 read, that the run did not report,
with the INFO `npm.install-agent-user-wide` (install code naming an agent directory and the
home directory, changed or not) and no `npm.install-persistence` finding: 195 (187 distinct).
Replayed with `main` and with variant B: B newly reports **55 versions of 27 packages**
(variant A: the same 55; `main`'s replay already reports 23 of the 187, which the recorded
runs, on older code, did not), about 27 a day. This is a lower bound for the `agent` form (an
agent CLI command such as `claude mcp add --scope user` with no home reference has no INFO
finding to pre-filter on). None is verdicted yet. The packages:

`@agentgates/cli` (0.87.0); `@archangel70/cosmo` (1.16.0, 1.16.1); `@aswless_854771076/ai_short_studio_cli` (0.1.240, 0.1.241, 0.1.242); `@cartanova/qgrid-cli` (2.19.2, 2.19.3, 2.20.0, 2.21.0); `@cliangdev/conductor` (0.54.0, 0.55.0, 0.56.0); `@getfrontline/cli` (1.8.3); `@karajan-family/code` (5.14.0, 5.15.0, 5.16.0, 5.17.0, 5.18.0); `@klingai/plugin-global` (1.0.3); `@mearl/native-host` (3.0.10, 3.0.11, 3.0.8, 3.0.9); `@myclaw163/clawclaw-cli` (0.10.5, 0.10.6); `@polymorphism-tech/morph-spec` (10.10.0, 10.10.1); `@qzhuli/qzhuli-cli` (0.7.0); `@social-data/social-neuron-metadata-query` (1.0.0-beta.7, 1.0.7); `@social-data/social-neuron-opinion-query` (1.0.0-beta.18, 1.0.9); `@social-data/social-neuron-rank-query` (1.0.0-beta.6, 1.0.5); `@social-data/social-neuron-subscription` (1.0.0-beta.31, 1.0.16); `@social-data/social-neuron-user-query` (1.0.0-beta.8, 1.0.6); `@telora/mcp-products` (0.23.28, 0.23.29); `@volter/supercode` (0.5.486); `dynamsoft-dsh-plugin` (1.0.1); `hub-launch` (1.46.0); `install-anything-skill` (2.0.0); `karajan-code` (5.14.0, 5.15.0, 5.16.0, 5.17.0, 5.18.0); `pantheon-opencode` (2.0.0-beta.6, 2.0.0-rc.1); `parqet-cli` (1.1.0); `superskill` (0.18.1); `wkappbot-code` (0.3.22)

Most are skill or plugin installers that copy into `~/.claude`, `~/.codex` or `~/.config/opencode`
on every release (the shape the owner rules unwanted); `@mearl/native-host` was verdicted unwanted
at 3.0.5. Variant B fires on each release of a frequently published package (`karajan-code`,
`@karajan-family/code`: 5 releases each in two days; `@social-data/*`: 10).

**Measured.** Sample misses: `@aswless_854771076/ai_short_studio_cli@0.1.236` now reported
(score 3, `npm.install-persistence`, `dist/skill/skill-manager.js`). Full replay set (3,716,
final code): exactly the 18 decision changes of the subset (14 unwanted, 2 unverified, 2
benign above), 0 lost. New test:
`test_unchanged_install_code_counts_only_for_user_wide_agent_installs`.

## 4. Target 3: WhatsApp channel follows in unchanged files (`static.channel-follow-on-connect`)

> **Pending:** built and measured in the next commit of this round.

## 5. Live replay (all three, today's verdicts)

`relabel.py integ.jsonl full-final.jsonl`, verdicts of 2026-11-12:

| Replay | Reported | Benign | Unwanted | Malicious | Unverified | Precision |
|---|---|---|---|---|---|---|
| `main` (`integ.jsonl`) | 1,423 | 725 | 620 | 48 | 30 | 47.95% |
| all three (`full-final.jsonl`) | 1,441 | 727 | 634 | 48 | 32 | 48.40% |

Every non-benign change is a gain (`CHANGED ... reported`); benign unreported 0, newly
reported 2. All 18 changes are target 2's (section 3); targets 1 and 3 change no decision on
this set (their positives are newer than the set).

## 6. `vm-day1`

VMDAY1

## 7. Rejected or not built

- **Variant A for target 2** (`ONLY_WHEN_CHANGED = False` for every form): +22 benign more
  than B for no positive (`glimmervoid` ×17, `agentiqa` ×4).
- **Tagging on unchanged files:** fires on `aunubaileys` 1.0.53-1.0.58 (benign).
- **`selenium-standalone install`, `electron-chromedriver`'s downloader in the `tool` form:**
  never seen as a hook command / not a `webdriver-manager` call (brief: only fetchers shown on
  real data).
- **`local-operator-ui`, `lumen-lib`, `@plannotator/opencode`:** Stage 2 routing (decision
  0008), out of scope.

## 8. Owner questions

1. Target 2: take variant B with its 2 benign (`common-context-mcp@3.6.2`, `shieldcortex@5.19.0`)
   and an estimated ~27 more reports a day (unverdicted, mostly user-wide skill installers)?
2. Target 3: keep the rule given that `correlate.follow-on` already carries most same-shape
   follow-ons live? It costs no benign on the Baileys set and the replay set.

## 9. How to reproduce

Scripts in `~/kitsunox-scratch/r8/R/s/` (data only; tarballs read in memory, nothing run):
`extract_keys.py` (candidates of verdicted keys from their runs), `jidscan.py` and
`ruleScan.py` (the Baileys set), `subcmp.py` (a subset replay against the baseline),
`wholerun.py` + `wcmp.py` (target 2's whole-run estimate), `dd_atrisk.py` (`vm-day1` samples
these changes can act on); the harness is `~/kitsunox-scratch/r8/R/scripts/` (`replay.py`,
`r_replay.sh`, `dd.py`).
