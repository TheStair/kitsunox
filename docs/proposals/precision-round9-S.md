# Precision round 9, agent S

Base: main `2baac25`. Replay set: the 3,716 verdicted live versions, Stages 1-4 replayed per
version with the real code (`replay.py`), counted with today's verdicts (`relabel.py`) against
round 8's `~/kitsunox-scratch/r8/integ-out/full.jsonl`. Live: every run on disk (186 runs,
2026-10-29..11-12), re-decided from the recorded candidates; tarballs read from the blob store
as data. `vm-day1`: the 3,444 malicious samples (`pipeline+4` and rule-level scans, files
decrypted in memory). Scripts and outputs: `~/kitsunox-scratch/r9/S/{s,out}/`.

| # | Target | Stage | Benign removed, replay set | Benign removed, live | Positives lost | Unverified lost | `vm-day1` lost |
|---|---|---|---|---|---|---|---|
| S1 | `npm.artifact.install-stub`: dependency-confusion placeholders | 2 (+ `EXPLAINED`) | 0 (fires on none) | 10 | 0 | 0 | 0 (fires on none) |
| S2 | Stage 2 compares each version with its own previous release | 2 | 0 (by construction) | 83 (+2 unverdicted; 2 unverdicted newly reported) | 0 | 0 | 0 (by construction) |
| S3 | `npm.version.suspicious` v6: trusted publishing or provenance is LOW | 1 | 2 | 15 | 0 | 0 | 0 of 131 |

Replay set, today's verdicts (full replay of the final tree, `out/full-final.jsonl`,
`relabel.py` against round 8's `full.jsonl`; 0 errors):

| replay | reported | benign | unwanted | malicious | unverified | precision |
|---|---|---|---|---|---|---|
| main (`2baac25`) | 1,425 | 719 | 645 | 49 | 12 | 49.12% |
| S1 + S2 + S3 | 1,423 | 717 | 645 | 49 | 12 | 49.18% |

2 benign unreported (both S3), 0 newly reported; no malicious, unwanted or unverified version
changes decision. The replay set is a lower bound here: S1's cluster, most of S3's and all of
S2's are live only (verdicted after the set was frozen, or a live-only Stage 2 batch effect).
Live runs on disk, distinct versions no longer reported, all benign: S1 10, S2 83, S3 15 (2 of
them also in the replay set): 108.

## S1. Dependency-confusion placeholders (`npm.artifact.install-stub`, Stage 2)

**Cluster.** Run `20261112T132432Z-npm`: 10 JetBrains packages at `999.9.9` (`kotlinconf`,
`kotlinconf-2019`/`2020`/`2023`/`2024`, `jetbrains-icons`, `jetbrains-logos`,
`jetbrains-security-stub-stage-test`, `ides-perf`, `jquery-astabs`), each three files:
`README.md` ("a stub published on npmjs.com designed to mitigate risks from Dependency
Confusion"), `package.json` with `preinstall: node fail.js` (not in the registry's metadata,
so `npm.artifact.hidden-install-script` HIGH) and `fail.js`, whose whole text is
`throw new Error("Installation terminated!" + "\n" + "This is stub package ..." + ...)`.
Score 8 (hidden script 5 + `npm.version.suspicious` 3), all verdicted benign.

**Change.** A Stage 2 artifact rule, INFO weight 0, fires when, on the whole package (`_whole`:
nothing skipped, no tar anomaly, files add up to the declared size):

1. every install hook in the tarball's `package.json` is exactly `node <file>` (`hook_target`,
   and no `||` tail: the placeholder must stop the install);
2. each file is `.js`/`.cjs`/`.mjs` (the path or `<path>.js`) whose whole text matches one
   `throw` of a constant: `throw new Error(<c>)`, `throw Error(<c>)` or `throw <c>`, where
   `<c>` is string literals or `${}`-free templates joined by `+`; comments, a `#!` line and
   `"use strict"` allowed. Any other identifier, call, argument or statement is not a stub
   (a regular expression over the whole file, so anything left over fails it);
3. the package ships nothing but `package.json`, the stub files and text (README, licence,
   changelog, notice, `.md`, `.txt`): nothing a `require` or `--ignore-scripts` install could
   load.

`correlate.EXPLAINED` (stage version 21) then makes `npm.artifact.hidden-install-script`,
`npm.install-hook` and `npm.version.suspicious` LOW, weight 1, with a note. Nothing else.

**Measured.**

- Live (all 866 captured versions on disk with one of the three explained findings,
  `livestub.py`): fires on exactly the 10 JetBrains stubs, all benign; score 8 -> 2, all
  unreported.
- Replay set (825 versions with one of the three findings, keyed replay): the rule fires on none; no decision changes.
- `vm-day1` (all 3,444 malicious samples' files, `ddstub.py`): of the 1,382 malicious samples with one of the three explained findings (round 8's full `pipeline+4` dump), 947 have tarball hooks that are all `node <file>`; in none of them is a hook file a constant throw, even without the whole-package and text-only conditions, and the rule fires on none, so `pipeline+4` is unchanged. The 131 confusion
  probes the version rule fires on all run code that reports back (`curl ... $(whoami)`,
  `node index.js` collecting `os`/`env`), which a constant throw cannot do. No sample fires
  `npm.artifact.hidden-install-script` at all (round 8's full dump).

**Residual risk.** A placeholder can claim a name now and publish a payload later; the later
release is analysed on its own. An attacker gains nothing from a throw-only hook: it runs
nothing and stops the install.

## S2. Stage 2 compares a batch's later versions with their own previous release

**Problem (round 8 P's finding).** Stage 2 reads a package's versions in a run as one batch and
judged every match against the batch's **base** (the release before the batch). A later
version that rebuilt the version before it got its matches MEDIUM again; the replay and
`vm-day1` (one version against its own previous release) have them LOW. Live 2026-11-12:
`@blod-nm/{ak@0.1.1, base-cb@0.2.4, base-ctx@0.1.3, nuxt-mcp@0.1.7-0.1.10}`. Worse, a
package that publishes two release lines in one run (`@aglit-ai/cli`: `1.0.x-staging` builds
beside `5.0.x-runtime.part-NN` binaries) gets the other line's release as its base, so every
staging build was compared with a 64 MB runtime that is never read (an empty base): the
target's 5 `@aglit-ai/cli` reports, obfuscated anew by every build.

**What could not be removed safely.** The first obfuscated release after a clean one is the
`@duckdb/node-api@1.3.3` shape and stays reported: `@blod-nm/base-cb@0.2.3` (0.2.2 has no
obfuscated file), `base-ctx@0.1.2`, `nuxt-mcp@0.1.6`, `@aglit-ai/cli@1.0.19350-staging...`
(1.0.19338 is plain; `obf.py`). The new packages of the cluster (`@blod-nm/ak@0.1.0`,
`deep-attributation-rn@1.0.0`/`1.0.1`, `vue-juan-form@0.1.0`, `@medwand/mwsdk-javascript@3.2.2`,
`xgis-cog-maplibre@0.0.1`) are round 8 P1's: P1 clears those with a repository or homepage and
no install script; the rest are its owner options P1b/P1c.

**Change.** `analyse_batch` keeps new contents and attribution as before (each content once,
to the first version that has it), but compares each version's matches with its own previous
release (`Change.previous`): the version before it in the batch (already in memory), the
base, or a release outside the batch (fetched through the same `ArtifactFiles`, recorded in
the snapshot). When that release's files are unavailable, the base is used as before, and the
decision says `previous <version> unavailable: ...` (`will retry` for a network failure, so
the hourly tick retries it).

**Measured (live runs on disk only: the replay set and `vm-day1` already compare one version
with its own previous release, so they are unchanged by construction).** `batchsel.py` picks
the 13,096 batches (186 runs) where a version whose own previous release is not the base has
a recorded `static.*` match at LOW or above (only a MEDIUM+ match's demotion depends on the
base); `s2live.py` re-runs `analyse_batch` with main's and with this code on tarballs from the
blob store (absent ones unavailable for both) and re-decides each of the 72,891 versions with
its recorded Stage 1, 3 and 4 findings (`npm.obfuscation-only` re-run). Distinct versions:

- 83 benign unreported: `dudu-converter-cli` x25, `@pomelolabs/leads` x10, `dsh-wire` x6,
  `@blod-nm/*` x7 (`ak@0.1.1`, `base-cb@0.2.4`, `base-ctx@0.1.3`, `nuxt-mcp@0.1.7`-`0.1.10`),
  `@aglit-ai/cli` staging x4 (`1.0.19354`, `19358`, `19365`, `19371`),
  `@martindong-dhy/dsh-ui-design-studio{,-internal}` x8, `@melt-js/comps-vue3-ele-pure` x4,
  `luban-dev-mcp` x3, `@open-mercato/cezar` x2, `gridcity` x2, `oc-workers` x2,
  `safepassai` x2 (0.3.5, 0.3.6), and one each of `@formio/appserver-core`,
  `@hsm0529/cocos3-framework`, `@prismatic-io/components-{bigcommerce,slack}`,
  `bbang-react-editor`, `dsh-pick`, `glimmervoid@0.52.3-next.901`, `zerolytics-setup@1.0.1`.
- 2 without a verdict unreported: `@heyvamz/carry@0.4.4` (owner question 3),
  `dns-worker@1.1.9-canary.e098c93` (a hardcoded IP its sibling canaries, verdicted benign,
  also ship).
- 2 without a verdict newly reported: `safepassai@0.3.8`, `0.4.0` (their own previous builds
  are not obfuscated; the batch's base was).
- 0 malicious, unwanted or unverified versions change.

The 5th `@aglit-ai/cli` report of the target (`1.0.19350`) is the first obfuscated build and
stays reported, as above.

## S3. `npm.version.suspicious` v6 (Stage 1)

**Cluster.** `@humanode-hyperlane/*` (a Hyperlane fork numbering its packages upstream's
version plus 1,000: `utils@1045.2.0` after `30.0.0`, `core@1012.3.0` after `11.2.0`): 23 benign
live reports by this rule (+ `npm.publisher.unfamiliar`, `npm.dependency.added` LOWs).
Round 8 P3's v5 (a sibling declared at the same major) already removes 9 of them on the live
runs (measured again here with `livever.py`: `aleo-sdk`, `cosmos-sdk`, `deploy-sdk`,
`helloworld`, `radix-sdk`, `sdk`, `sealevel-sdk`, `tron-sdk`, `widgets`).

**What the rest share.** 13 of the 14 left were published by `GitHub Actions` with npm trusted
publishing (`trusted_publisher: github`) and a provenance attestation. None of the 131
`vm-day1` malicious samples the rule fires on has either (`ddver.py`); the 21 of them that
are updates (`baglass@99.99.2` after `1.0.0`, `workflows-templates@99.98.9`, ...) were all
published by the researcher's own account with a token. Round 6 C1 already reads trusted
publishing and provenance this way for `npm.combination.revived-with-new-dependency`.

**Change (v6).** LOW, weight 1, with "Published with trusted publishing (github): from a
repository's CI, not by hand", when the release has a trusted publisher or provenance. LOW,
not exempt: the number stays in the score and in front of a reviewer.

**Measured.**

- `vm-day1`: 0 of 131 samples change (none has a trusted publisher or provenance), so
  `pipeline+4` is unchanged.
- Replay set (the 23 versions the rule fires on, keyed replay): 2 benign unreported
  (`picard-code@1701.4.0`, `@spear-ai/trino-pulumi-aws@484.0.0-0.20261103204256-bfde6f0`,
  both trusted publishing without provenance, score 5 -> 3); the 2 positives
  (`template-projection-map@99.1.3`, `@gsas/gsas-sdk@99.99.99`) have neither and keep MEDIUM.
- Live runs on disk (`lives3.py`, main vs v6, re-decided with the recorded findings): 15
  benign unreported: `@humanode-hyperlane/{cli, core, cosmos-types, forking-sdk, metrics,
  provider-sdk, rebalancer, relayer, starknet-core, starknet-sdk, utils, warp-widget}`,
  `@ai-ecoverse/gcloud-cli@593.0.0-1`, and the two replay-set versions above. The 2 malicious
  versions the rule fires on live are unchanged. No other decision changes.
- Left: `@humanode-hyperlane/registry@1026.3.0`, published by hand (`mozgiii`, no
  provenance); no narrow, safe signal separates it from a confusion probe that was an update.

**Residual risk.** A confusion attacker who first publishes a normal version, configures
trusted publishing for their own name and then publishes `999.x` from a public repository's
workflow gets LOW here (score 1 from this rule). That costs them a public, attributable
repository; none of the 131 samples does it.

## Owner questions

1. S1 explains `npm.version.suspicious` too (the stub's `999.9.9` is the point of the
   placeholder). Keep, or explain only the hidden hook (then the stubs stay reported at
   score 4 by the version rule alone)?
2. S3 lowers on trusted publishing *or* provenance. Requiring both would keep `picard-code`
   and `@spear-ai/trino-pulumi-aws` reported (trusted publishing without provenance), and
   lose nothing either way on `vm-day1`.
3. S2 makes live Stage 2 judge "not new" the way the evaluation always has. It unreports
   `@heyvamz/carry@0.4.4` (no verdict; its 0.3.0 and 0.3.1 are unwanted for their install
   code, and 0.4.3, which added the `static.shell-startup` match 0.4.4 rebuilt, stays
   reported). A malicious burst that re-obfuscates its payload in every version is reported
   once, at the first version, as in the evaluation. Keep?

## Reproduce

```sh
S=~/kitsunox-scratch/r9/S; PY=/home/thestair/kitsunox/.venv/bin/python
$PY -I $S/s/livestub.py $S/src-s1/src                      # S1 live
$PY -I $S/s/ddstub.py $S/src-s1/src malicious              # S1 vm-day1
bash ~/kitsunox-scratch/r8/R/scripts/k_replay.sh $S/src-s1/src $S/out/s1-sub.jsonl $S/out/s1.keys
python3 -I $S/s/batchsel.py $S/out/s2-sel.tsv               # S2: batches it can change
$PY -I $S/s/s2live.py $S/src-main/src $S/out/s2-sel.tsv $S/out/s2-full-main.jsonl 2
$PY -I $S/s/s2live.py $S/src-s2/src $S/out/s2-sel.tsv $S/out/s2-full-s2.jsonl 2
python3 -I $S/s/s2cmp.py $S/out/s2-full-main.jsonl $S/out/s2-full-s2.jsonl
$PY -I $S/s/ddver.py $S/src-s3/src                          # S3 vm-day1
$PY -I $S/s/lives3.py $S/src-main/src; $PY -I $S/s/lives3.py $S/src-s3/src   # S3 live
```
