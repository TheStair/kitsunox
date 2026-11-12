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

> **Pending:** built and measured in the next commit of this round.

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
