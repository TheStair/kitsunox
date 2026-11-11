# Proposal: precision round 6, agent U (follow-on releases, `correlate.follow-on`)

> **Status:** built 2026-11-11 for the owner's review, on `main` `6bfe0c3` (round 6 Q merged; measured on `6137971` and again on `6bfe0c3`: identical for parts A-C), before the rule
> freeze (2026-11-16). A recall round: one Stage 4 rule and the run-level pass it needs.
> **Builds on:** decision [0007](../decisions/0007-datadog-samples-and-follow-on-releases.md)
> (follow-on releases kept in their own cells), decision
> [0015](../decisions/0015-reviewer-verdicts.md) with its addenda (what counts as a
> positive), the round-4 / round-6 briefs.

## Summary

A follow-on release that keeps a reported release's payload unchanged was invisible to every
stage (they judge changes). Stage 4 now runs a **follow-on pass** after correlating a run: a
version whose previous release the run reported, and which still holds that report's
**payload evidence** byte for byte, gets `correlate.follow-on` (MEDIUM) naming the earlier
release. Deterministic from the run's inputs (no clock, no verdicts); `STAGE_VERSION` 18.

| # | Commit (stage) | What is carried | Live, same run: newly reported | Positives lost | `vm-day1` | Kind |
|---|---|---|---|---|---|---|
| A | `e299b3f` (4) | the pass; known-signature, channel-follow, channel-tagging | +10 unwanted, 0 benign | 0 | +0 | **zero-cost** |
| B1 | `40808d3` (4) | + a hard-coded IP / exfil endpoint in a file that also reads secrets or runs at install | +3 malicious (`pdf-html5-page-flip@2.0.2`, `template-cards@16.1.2`, `template-pictogram@9.1.3`), +2 benign | 0 | +12 (`@operato/*`, `@things-factory/email-base`) | trade-off |
| B2 | `b860f17` (4) | + `npm.install-persistence` | +22 unwanted, +4 benign, +1 unverified | 0 | +0 | trade-off |
| C | `e68620e` (4) | the same from earlier runs within 7 days (pinned per run) | +27 unwanted, +1 benign, +1 unverified (over A-B2; +5 unwanted, 0 benign over A) | 0 | (same) | trade-off |

Live, A-B2 together: **+3 malicious, +32 unwanted, +6 benign, +1 unverified** among 812
follow-ons of reported releases; on the 3,716-version replay set 1,248 → 1,250 reported,
precision 38.42% → 38.44%. `esoftplay@0.0.269-beta96052d3` is not a follow-on case (section 6).

## 1. The problem

A diffing pipeline sees a release through what it changes. When a release keeps an earlier
release's payload unchanged, nothing in Stages 1-3 fires on it:

- **Stage 2** reads only file contents the base doesn't have; inside a batch, a content is
  attributed to the first version that holds it. A byte-identical payload file is never read
  again, so even `ALWAYS_NEW` (known signatures, WhatsApp channel follow/tagging, which the
  owner wants on every release) never fires on it.
- **Stage 3** counts only capabilities new to the install code (`npm.install-script-code`
  for updates, `install-script-changed` by definition).
- **Stage 1** fires on an install hook or a non-registry dependency when it is added or
  changed.

Cases:

| Release | Truth | What happened |
|---|---|---|
| `pdf-html5-page-flip@2.0.2` | malicious | 15 minutes after 2.0.1, same stealer `dist/lib/fonts/fa-solid-400.woff2` (byte-identical). 2.0.1 reported at score 6 (`static.hardcoded-ip`); 2.0.2 score 3 (two LOW encoded blobs and a LOW capability gain) |
| `template-cards@16.1.2`, `template-pictogram@9.1.3` | malicious (inherited) | same second as the reported 16.1.1 / 9.1.1, same install-time `beacon.cjs` to a hard-coded IP; score 0 |
| Baileys forks (`@zaidevx/baileys@1.0.4`, `lyxe-baileys@1.0.1`, ...) | unwanted (inherited) | second release with the same channel-follow code; score 0 |
| `esoftplay@0.0.269-beta96052d3` | malicious | **not a follow-on case**: see section 6 |

## 2. Design

### 2.1 Where the history comes from: the run itself

The pass runs inside `correlate_run`, after every version of the run has been correlated. The
only history it uses is the run's own Stage 4 decisions: a version's previous release must be
**in the same run**. That keeps it a pure function of the run's inputs (`triage.jsonl`,
`ast.jsonl`, the release files through the run's fetcher), so:

- `ingest replay` is untouched (Stage 0 only);
- a re-score (`collect.rescore_run`, seeded snapshots) and `kitsunox correlate <run>` give
  the same output; the release files a check reads are recorded in `correlate-snapshot.json`;
- nothing reads the clock (the window is between the two releases' publish times) or a
  verdict.

The run order is not publish order (`triage.jsonl` follows the change feed: in
`20261110T205323Z-npm`, 129 of 707 versions whose previous release is in the run come before
it), so the pass doesn't stream: it waits until the first pass is done, then settles the
versions in dependency order (a version waits until its previous release is settled), each
pass taking the ready versions in run order. Tested with 1 and 4 workers and with the chain
written backwards (`tests/stages/test_follow_on.py`).

### 2.2 What is carried

`reported_release` takes from a reported release only its **payload evidence**
(`payload_evidence`):

- a MEDIUM-or-above finding of `static.known-signature`, `static.channel-follow`,
  `static.channel-tagging` or `npm.install-persistence` (`FOLLOW_ON_ALONE`): what the owner
  wants on every release;
- a MEDIUM-or-above `static.hardcoded-ip` / `static.exfil-endpoint` in a file that a LOW-or-
  above `static.sensitive-path` / `static.env-harvest` or an install-code rule
  (`npm.install-script-code`, `-loader`, `-exfil`, `npm.install-persistence`) of the same
  release also names: a destination in a file that reads secrets or runs at install.

A follow-on holds an item when it has the same bytes at the same path (a file) or the same
value (a manifest field). The finding is MEDIUM (weight 3), names the earlier release, its
decision and the hours between them, and lists each item; its items become the follow-on's
own payload evidence, so chains carry on. Window: 7 days between publish times.

### 2.3 Part C: follow-ons in a later run

Each run's Stage 4 writes its reported releases with payload evidence to `follow-on.jsonl`
(`FOLLOW_ON_INDEX`, with `run_id`). A run's pass also reads the indices of the runs of the
same ecosystem whose `as_of` is within 7 days before its own (`review.follow_on_history`; a
later run's entry for the same release wins) and checks a version whose previous release is
only there. The entries it used go to `follow-on-history.jsonl` (`FOLLOW_ON_HISTORY`), and a
seeded re-score (`collect.rescore_run`) reads exactly those: the run's answer doesn't change
when an earlier run is re-scored or pruned later. What isn't deterministic across *live*
operation, only recorded: an earlier run whose Stage 4 finished after this run's (a Stage 2
retry) is missing from this run's history.

## 3. Method

- **Pairs (live).** `u_pairs.py` reads every live run's recorded `correlate.jsonl` (149 runs,
  2026-10-29 to 2026-11-11): 3,646 reported versions, plus the 17 the main replay reports that
  no run did; 2,163 versions whose previous release is one of them. Kept: the 812 whose
  previous release the main replay reports (or that no replay holds) and that the main replay
  doesn't report itself (a reported follow-on can't be gained).
- **Real code.** `u_follow.py` replays both releases of each pair through Stages 1-4 exactly as
  `replay.py` does (Stage 2/3 recomputed from the tarballs, read in memory with
  `extract_tar_gz`; 1,562 replays, tarballs from the blob store or the scratch registry
  store), then applies this branch's `reported_release` (per carry policy), `ReleaseFollowOn`
  and `correlate` with `ctx.follow_on`; chains in publish order. "Same run": the pair's
  releases were in one recorded run (parts A-B2); "any run": also an earlier run's release
  within 7 days (part C).
- **Truth.** Today's verdicts. Most follow-ons were never reported, so never reviewed: their
  truth is the earlier release's verdict ("inherited"), which is sound only because the
  carried evidence is the same bytes; the three with their own verdict are named.
- **Replay set.** `u_patch.py` sets, in the main replay, the decision of every version the
  pass reports, then `relabel.py` (main vs patched).
- **Real pass, recorded data.** `u_e2e_all.py` runs this branch's `correlate_run` with and
  without the pass (part C off) over every live run's recorded `triage.jsonl` + `ast.jsonl`
  (hard links into scratch, read-only), no repository or dependency lookups, and diffs the
  outputs line by line.
- **`vm-day1`.** `u_ddfollow.py`: `pipeline+4` (`dd.py`'s setup, repository comparison off)
  on every follow-on sample whose previous version is also a malicious sample and that round
  3's full run didn't report, plus each previous sample on its chain; the previous sample's
  candidate goes through `reported_release`, both samples' files are read from their zips by
  the predictor's own `_new_tree`, then `ReleaseFollowOn`, `FollowOnRelease`, `explained`,
  `decide`. Samples have no runs: the figure is what the pass gains when both releases fall
  in one run (or with part C).

## 4. Live results

Newly reported follow-ons (the main replay doesn't report them), by carry policy:

| Policy | Same run (A-B2) | Any run within 7 days (C) |
|---|---|---|
| A: always-new rules | **+10 unwanted, 0 benign** | +15 unwanted, 0 benign |
| A+B1: + destination with a companion | +3 malicious, +10 unwanted, +2 benign | +3 malicious, +15 unwanted, +2 benign |
| A+B1+B2: + install persistence (payload) | +3 malicious, +32 unwanted, +6 benign, +1 unverified | +3 malicious, +60 unwanted, +8 benign, +2 unverified |
| rejected: every severe content finding | +65 positives, +64 benign, +3 unverified | +120, +119, +5 |
| rejected: payload + an added (HIGH) install hook | +45 positives, +65 benign, +1 unverified | +93, +122, +3 |
| rejected: content + install hook + non-registry dependency | +80 positives, +171 benign, +4 unverified | +150, +301, +9 |

Measured on `6137971`; re-measured on `6bfe0c3` (Q merged) the built rows A-C are identical,
and the rejected rows a little lower (Q's `install-explained` v5 no longer reports some
earlier releases): content 65 / 62 / 3, payload + added hook 45 / 57 / 1, content + hook +
dependency 80 / 162 / 4 (same run). (Any-run counts a version that sits in two runs once per run it was in; distinct, part C adds
27 unwanted, 1 benign and 1 unverified over A-B2.)

**Every version newly reported, same run, A+B1+B2:**

- **Malicious (3):** `pdf-html5-page-flip@2.0.2` (own verdict; 0.25 h after 2.0.1;
  `dist/lib/fonts/fa-solid-400.woff2`, `static.hardcoded-ip` with secrets read in the same
  file), `template-cards@16.1.2` and `template-pictogram@9.1.3` (published the same second as
  16.1.1 / 9.1.1; `beacon.cjs`, install code to a hard-coded IP).
- **Unwanted, part A (10):** `@zaidevx/baileys@1.0.4`, `@bil-rgb/baileys@1.0.1`,
  `lyxe-baileys@1.0.1`, `@ikyerza/baileys@1.1.1`, `felicia-baileys@1.0.4`,
  `@yannajah/baileys@1.0.1`, `gxinztech-baileys@1.0.1`, `@zaiinlin/bails@1.0.3`,
  `@risacakep/risayap@7.0.0-rc25.7`, `@risacakep/risayap@7.0.0-rc25.11` (channel follow /
  tagging unchanged).
- **Unwanted, part B2 (22):** `join-com-cli@1.0.0`, `openyida@2026.10.30`,
  `@muggleai/works@5.28.0-staging.253`, `5.34.0-staging.308`, `5.34.0-staging.311`,
  `@karajan-family/code@5.0.3`, `karajan-code@5.0.3`, `@ai-kbos/kbas-kit@3.1.1`,
  `enlighten-agent-tool@1.0.4`, `pantheon-opencode@1.6.3-beta.5`,
  `@ziniao-open/cli@0.1.0-beta.171`, `@minhspark/codex-mcp-bridge@2.3.2`,
  `@myclaw163/clawclaw-cli@0.10.3`, `dcs-command-system@0.16.1`, `anolisa-tokenless@0.9.4`,
  `@phigon/superagent@0.1.1`, `signoff-cli@4.1.3`, `@phnx-labs/agents-cli@1.23.47`,
  `dsh-yunpa@0.10.2`, `@xfe-repo/cli@2.2.6`, `aum-framework@1.8.2` (own verdict),
  `dynamsoft-dsh-plugin@1.0.1` (install persistence unchanged).
- **Benign (6), with why:** B1: `chuxin-agentdesk@0.1.1` (own verdict; `dist/runtime.mjs`
  keeps a hard-coded IP next to an environment read, as 0.1.0 did) and
  `@prismatic-io/components-bigcommerce@0.1.0` (`dist/index.js`: a BigCommerce endpoint the
  exfil rule flags HIGH, beside `process.env` reads). B2: `agy-statusblocks@0.1.1`,
  `repilot@0.3.1`, `basinfy@1.3.14`, `@c0dingbear/termius-mcp@0.6.2`: follow-ons of benign
  releases that `npm.install-persistence` v5 still reports (a setup the user agreed to, or a
  write behind a prompt; section 2 of round 6 S), the same install file unchanged.
- **Unverified (1):** `wkappbot-code@0.3.8` (B2; 0.3.7 is unverified).
- **Positives lost: 0** (the pass only adds a finding; an added MEDIUM can't unreport).

**Replay set (3,716 verdicted versions), `relabel.py`, main vs main + the pass**
(`u_patch.py`, same run; the replay harness correlates one version at a time, so the pass is
applied from `u_follow.py`'s results; almost all follow-ons are outside the set). Main with
round 6 Q merged (Q's replay `final2.jsonl`); against `main-6137971.jsonl` the same two
versions change (1,269 → 1,271, 37.77% → 37.79%):

| Replay | Reported | Benign | Unwanted | Malicious | Unverified | Precision |
|---|---|---|---|---|---|---|
| main `6bfe0c3` | 1,248 | 750 | 421 | 47 | 30 | 38.42% |
| + A | 1,248 | 750 | 421 | 47 | 30 | 38.42% |
| + A, B1 | 1,249 | 751 | 421 | 47 | 30 | 38.39% |
| + A, B1, B2 | 1,250 | 751 | 422 | 47 | 30 | 38.44% |

Changed in the set: `chuxin-agentdesk@0.1.1` (benign, B1) and `aum-framework@1.8.2`
(unwanted, B2) become reported; no positive or unverified version stops being reported.

**Real pass over the recorded runs** (part C off; recorded Stage 2/3 findings, older rules
for older runs): 20 lines change, 16 newly reported: `pdf-html5-page-flip@2.0.2`,
`template-cards@16.1.2`, `template-pictogram@9.1.3`, `@yannajah/baileys@1.0.1`,
`@zaiinlin/bails` 1.0.3-1.0.6 (a chain of four), `@risacakep/risayap` 7.0.0-rc25.7, .8, .9,
.11 (chains), `dynamsoft-dsh-plugin@1.0.1`, and two benign, `@prismatic-io/components-bigcommerce@0.1.0`
and `@thorcollective/hearth-mcp@0.1.0` (its 0.0.1's `data/hunts-data.json` names a webhook
host and `.npmrc`; under today's rules that file is no longer severe, which is why the replay
doesn't gain it). Four already-reported versions gain the finding as context
(`chuxin-agentdesk@0.1.1`, `template-projection-map@99.1.3`, `@mearl/native-host@3.0.7`) or a
"not evaluated" note where a release was taken down (`calculator-preinstall-hook-demo@1.1.2`,
`@goparrot-dashboard/app@0.0.3`). On `20261110T205323Z-npm` (5,016 versions) the pass
changed one line and took 0.85 s.

## 5. `vm-day1`

Targets: the 82 malicious follow-on samples (all shape A) whose previous version is also a
`vm-day1` malicious sample and that round 3's full run (`ddbase.jsonl`) didn't report; 165
samples evaluated with their chains. Code: this branch rebased on `6bfe0c3`.

- Main reports 2 of the 82 already; the previous sample is reported for 38.
- **A: +0. A+B1: +12**, all Shai-Hulud-style follow-ons published 6-27 minutes after a
  reported release with the same `bundle.js` (`static.exfil-endpoint` HIGH in install code):
  `@operato/board@9.0.43`, `@operato/graphql@9.0.43`, `9.0.44`, `9.0.45`,
  `@operato/help@9.0.43`, `@operato/input@9.0.43`, `@operato/popup@9.0.43`, `9.0.44`,
  `9.0.45`, `@operato/utils@9.0.43`, `@things-factory/email-base@9.0.50`, `9.0.51` (the
  9.0.44/45 and 9.0.51 ones through chains). **B2: +0.**
- Rejected policies, for comparison: + an added (HIGH) install hook 26 (`@postman/pm-bin-*`,
  `@asyncapi/studio`, `@antv/li-aiearth-assets`, `vant`...); every content finding 32
  (adds `@tanstack/*` through `router_init.js`, `static.obfuscated`); content + hooks +
  dependencies 46. Live they cost 57-162 benign follow-ons (section 4).
- **Lost: 0.** The pass only adds a MEDIUM finding (it can't unreport), and the evaluation
  predictor never runs it (`correlate.follow-on` fires only with `ctx.follow_on`), so every
  other `vm-day1` result is unchanged except the Stage 4 rules fingerprint.
- Samples have no runs: with hourly runs and these gaps, about 55-90% of such pairs fall in one
  run (A-B2); part C covers the rest.

## 6. Not rescued, and why

- **`esoftplay@0.0.269-beta96052d3`** (malicious since the owner's ruling of 2026-11-10: `esp
  bcl` / `bcd` in `bin/cli.js` upload the app's config): not a follow-on of a *reported*
  release. Of its betas only three were ever reported (96052d3, eaa40be, 91d8a14), each for
  `npm.install-script-changed` on `bin/build.js`, never for `bin/cli.js`, whose Telegram calls
  are LOW "not new" in every version Stage 2 read (they predate collection). Carrying
  `install-script-changed` would be carrying a *change* to a follow-on that didn't change, and
  would cost 80 benign follow-ons in the same run for 79 positives (recorded data). The fix belongs to a
  content rule for `bin/cli.js` itself (credential-file upload to a bot API), not to
  carry-forward.
- **DataDog follow-ons whose previous version was reported only by metadata** (an added
  install hook: `@postman/pm-bin-*`, `vant`, `@asyncapi/studio`; a GitHub dependency:
  `@tanstack/*`): carrying the hook or the dependency gains them but costs 65 or more benign
  live follow-ons (section 4). `@tanstack/*` also carry `router_init.js`, flagged
  `static.obfuscated`, which the rejected "content" policy carries.
- **Follow-ons whose payload changed.** Byte identity is the bar; a re-minified payload is a
  new content and goes through Stages 2-3 again (with "not new" notes for matches the base had).

## 7. Rejected ideas

| Idea | Why (the sample that rules it out) |
|---|---|
| Carry every severe content finding | 64 benign same-run follow-ons for 65 positives (replay): `wrkos-local-agent` x2, `esbuild-wasm-strapkit` x2, `vallenemperor`, `wangka-panel`, `repilot`, ...; on recorded data also `@wirecat/cli-memo` (a bundled ngrok table, HIGH every release), `@open-mercato/cezar`, `qafind` / `airlockqa` |
| Carry `npm.install-hook` / `npm.dependency.non-registry` | with content: 171 benign for 80 positives; an added (HIGH) hook only, over the payload: 65 benign for 45 positives (`@bitfun-test/bitfun` x11, `dns-worker` x10, `@tianshu-ai/tianshu` x4) |
| Carry `npm.install-script-code` | recorded data, same run: 46 benign for 56 positives (`@wjqserver/opencode` x3, `bothub-code`, `morfeo`) |
| Carry `install-script-changed` / `code.capability-gained` | rules about a change; an unchanged follow-on has none (`@anthropic-ai/claude-code`, `react-lottie`) |
| A time window as the only noise control | within 1 hour of a reported release, benign follow-ons are as common as positive ones (recorded data: 37 vs 40) |
| Use verdicts of the earlier release | the brief forbids it; it would also make the decision depend on review timing |
| Read earlier runs' `report.json` as the history | Stage 5 rewrites reports after the fact, and rescoring replaces them: a later run's answer would change; part C writes and pins its own index |

## 8. Owner questions

1. **Parts B1 and B2.** B1: +3 malicious for +2 benign. B2: +22 unwanted for +4 benign and 1
   unverified, all four benign being follow-ons of releases `install-persistence` already
   reports as benign: they leave with any precision fix to that rule. Take both?
2. **Part C** (earlier runs within 7 days): +27 unwanted, +1 benign, +1 unverified over A-B2
   (+5 unwanted over A alone), and two small files per run. Take it, or keep the pass within a
   run?
3. **Already-reported follow-ons get the finding too** (it raises their score by 3 and names
   the earlier release). Keep, or add it only where it changes the decision?
4. **The evaluation predictor** scores `vm-day1` samples one at a time, so `pipeline+4` cells
   don't show the pass. Should the follow-on cells (decision 0007) get a follow-on-aware
   predictor (previous sample's result as the history)?

## 9. Decision 0007 addendum (draft, for the integrator)

> **Addendum (2026-11-11, round 6 U): follow-ons are reported in operation.** A follow-on
> release that keeps a reported release's payload unchanged is reported by Stage 4's
> follow-on pass (`correlate.follow-on`, `STAGE_VERSION` 18): the previous release, in the same
> run (and, with part C, in an earlier run within 7 days, read from that run's
> `follow-on.jsonl` and pinned in the run's `follow-on-history.jsonl`), was reported with
> payload evidence (always-new rules; with B1 a hard-coded destination in a file that reads
> secrets or runs at install; with B2 install persistence), and the release holds the same
> bytes at the same path. Deterministic from the run's inputs; never the clock or a verdict.
> Live: +3 malicious, +32 unwanted, +6 benign (A-B2, same run). The `vm-day1` follow-on cells
> still use `pipeline+4` per sample; the round-6 harness measured what the pass adds there
> (82 unreported malicious follow-ons whose previous version is a sample: +12 with B1). Not carried: install hooks, non-registry dependencies, generic content rules
> (measured: about one benign follow-on per positive or worse).

## 10. Reproduce

```sh
S=~/kitsunox-scratch/r6/U/scripts; PY=/home/thestair/kitsunox/.venv/bin/python
$PY -I $S/u_pairs.py reported pairs && $PY -I $S/u_lines.py extra pairs BASE.jsonl
$PY -I $S/u_pairs.py followers pairs && $PY -I $S/u_lines.py lines pairs
# (pairs2: followers whose previous release the main replay reports and that it doesn't report)
$PY -I $S/u_follow.py SRC pairs2 out/follow-live.jsonl 2 && $PY -I $S/u_followsum.py out/follow-live.jsonl payload
$PY -I $S/u_patch.py BASE.jsonl out/follow-live.jsonl payload out/patched.jsonl && $PY -I relabel.py BASE.jsonl out/patched.jsonl
$PY -I $S/u_e2e_all.py SRC e2e out/e2e-all.jsonl
$PY -I $S/u_ddprev.py SRC ddbase.jsonl out/ddprev.jsonl && $PY -I $S/u_ddfollow.py SRC out/ddprev.jsonl out/ddfollow.jsonl 2
```
