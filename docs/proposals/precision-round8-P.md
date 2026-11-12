# Precision round 8, agent P

Base: main `d3ce1f1`. Replay set: the 3,716 verdicted live versions
(`~/kitsunox-scratch/r7/shared/integ.jsonl` = main), Stages 1-4 replayed per version with the
real code (`replay.py`), counted with today's verdicts (`relabel.py`). `vm-day1`: `pipeline+4`
per malicious sample (`dd.py`, repository comparison off): a full dump of all 3,444 samples
with main's code (`out/dd-main-full.jsonl`), then each change's at-risk samples with the fix.
Scripts and outputs: `~/kitsunox-scratch/r8/P/{s,out}/`.

| # | Target | Stage | Benign removed (replay set) | Positives lost | Unverified lost | `vm-day1` lost |
|---|---|---|---|---|---|---|
| P1 | `npm.obfuscation-only` explains `static.obfuscated` | 4 | 15 | 0 | 0 | 0 of the 9 it reports alone |
| P2 | `npm.install-download` v3 (v2 at proposal time; renumbered at integration after round 8 R's v2): a command word only shown is no network | 3 | 0 (2 lose the finding, still reported); live +2 | 0 | 0 | 0 of 24 at risk |
| P3 | `npm.version.suspicious` v5: another declared package at the same major | 1 | 1; live 12 | 0 | 0 | 0 of 131 the rule fires on |

Replay set, today's verdicts (full replay of the final tree, all three changes,
`out/full-final.jsonl`, `relabel.py` against main's `integ.jsonl`):

| replay | reported | benign | unwanted | malicious | unverified | precision |
|---|---|---|---|---|---|---|
| main (`d3ce1f1`) | 1,423 | 725 | 620 | 48 | 30 | 47.95% |
| P1 + P2 + P3 | 1,407 | 709 | 620 | 48 | 30 | 48.51% |

16 benign unreported (P1 15, P3 1), 0 newly reported, no malicious, unwanted or unverified
version changes decision. P2 changes no replay-set decision (its two examples are live only).

## P1. `static.obfuscated` alone

**Cluster.** On the replay set, 21 versions are reported by `static.obfuscated` and nothing
else above INFO: 20 benign, 1 unverified (`@fcjplugins/hooks@1.0.0-bate.1`), 0 positives.
19 are new packages, 1 an update (`@monkeysfromah/core@0.0.4`). On `vm-day1`, 9 malicious
samples are reported by it alone too: 6 updates (`@duckdb/node-api@1.3.3`, `akasearch@6.0.1`,
`dreame-claude@1.2.14`, `dzcvhfruwluwe@1.0.1`, `web3rpcs@1.0.2`, `webpikes@1.2.2`) and 3 new
packages (`mobiwaefhxc3@1.0.0`, `mad-1.2.6.2.2.8@1.0.0`, `multi-cloud-data-migrator@1.256.25`).
(Full main dump of all 3,444 samples: 723 reported with a MEDIUM `static.obfuscated`, these 9
alone.) So "obfuscated alone" or `WEAK_ALONE` loses 9 (`WEAK_ALONE` also `tavern-ai-sdk@1.0.0`,
malicious, score 5, and 6 unverified with one or two LOWs: `whybug` x5, `codexunlimit`,
`system-tracker`).

**Change.** A Stage 4 rule, `npm.obfuscation-only` (INFO, weight 0, run after every other
correlation rule), notes a version when all of these hold, and `EXPLAINED` then makes
`static.obfuscated` LOW, weight 1, with a note (score 1, not reported):

1. a new package (no previous release): keeps the 6 `vm-day1` updates and
   `@monkeysfromah/core@0.0.4`;
2. `static.obfuscated` MEDIUM on at least one file and no other finding above INFO: keeps the
   `*-ai-sdk` family (Stage 2 LOWs or `known-signature`/`padded-code`) and every version with a
   repository-comparison LOW;
3. no obfuscated file is an HTML page and the manifest's entry fields name none: keeps
   `mobiwaefhxc3` (`main: index.html`);
4. no script npm runs at some install (`preinstall`, `install`, `postinstall`, `prepare` and its
   pre/post, `prepublish`): keeps `multi-cloud-data-migrator` (`prepare: npm run build`);
5. a declared `repository` or `homepage`: keeps `mad-1.2.6.2.2.8` (a fake "verification" page:
   `index.html`, `script.js`, `styles.css`; the registry's manifest strips `files`, so Stage 4
   cannot see the page) and `multi-cloud-data-migrator`.

**Removed (replay set, 15 benign):** `@cloudigniter/cli@0.3.0`, `@numbors/cli@1.7.0`,
`@oddsockets/cli@1.1.16`, `@oddsockets/js@2.0.2`, `@univerjs-pro/{docs-chart-thread-comment,
docs-drawing-thread-comment, sheets-chart-thread-comment, sheets-drawing-thread-comment}@1.4.0`,
`@univerjs-pro/{sheets-slicer, sheets-slicer-ui, slicer}@1.3.0`,
`xgis-cog-{cesium,mars3d,openlayers}@0.0.1`, `zerolytics-setup@1.0.0`. 0 positives, 0
unverified (the 81 versions with a MEDIUM `static.obfuscated`, replayed with the fix).
`vm-day1`: the rule can only note a sample reported by `static.obfuscated` alone; all 9 such
samples, run with the fix (`dd-alone-p1.jsonl`), are noted by none and stay reported.

**Kept reported (benign, by clause 5):** `@afilimax/link-builder@0.1.0`,
`@fcjplugins/{pwutils,storages}`, `@univer-cli/doc-markdown-facade@1.3.0`, and the unverified
`@fcjplugins/hooks@1.0.0-bate.1`; `@monkeysfromah/core@0.0.4` (clause 1).

**Live examples of 2026-11-12.** `@blod-nm/ak@0.1.0` (no repository or homepage) and
`deep-attributation-rn@1.0.1` (`prepare`, no repository) stay reported: they have exactly the
shapes of `mad-1.2.6.2.2.8` and `multi-cloud-data-migrator`. The `@blod-nm` *updates*
(`ak@0.1.1`, `base-cb@0.2.4`, `base-ctx@0.1.3`, `nuxt-mcp@0.1.7`-`0.1.10`) are not reported in
the replay even on main: their obfuscated files are in their own previous release's files, so
Stage 2 makes the match LOW ("not new"). Live they were MEDIUM because of the Stage 2 batch
base, below.

**Options (not built; each loses a `vm-day1` sample, the owner's call):**

- **P1b, drop clause 5:** +4 benign and +1 unverified removed (`@afilimax/link-builder`,
  `@fcjplugins/pwutils`, `@fcjplugins/storages`, `@univer-cli/doc-markdown-facade`;
  `@fcjplugins/hooks`, unverified: "its hidden code opens WebSockets to addresses I can't
  see"), live `@blod-nm/ak@0.1.0`; loses `mad-1.2.6.2.2.8@1.0.0` (measured: noted, score 1).
- **P1c, drop clause 4 too:** also live `deep-attributation-rn@1.0.1`; loses
  `multi-cloud-data-migrator@1.256.25` as well. Read as data, that sample is a Salesforce CLI
  plugin obfuscated by its own declared build (`javascript-obfuscator`, `webpack-obfuscator`
  devDependencies) with no visible network host beyond Salesforce's own libraries; DataDog
  labels it malicious.

**Earlier rulings this touches.** Rounds 2-3 rejected lowering vendor-obfuscated products
("indistinguishable from the malicious `*-ai-sdk` family by the rule's own test");
`docs/stages/static.md` (round 5) says vendor-obfuscated products keep `static.obfuscated` at
full strength. P1 leaves Stage 2's finding as it is and separates the `*-ai-sdk` family by
clause 2 (each has at least one more finding), but it is a reversal for new packages and the
owner's call. It is not the rejected "obfuscated by its own declared build" signal: no clause
reads the build.

## P2. `npm.install-download` on printed command text

**Problem.** `@gloom-sh/terminal@0.20.8` and `gloomberb@0.20.8` (benign, 2026-11-12) were
reported only by `npm.install-download` (`own`): their preinstall `bin/without-bun.cjs` has a
function that *returns* the help line "Install Bun (curl -fsSL https://bun.sh/install | bash)
..., or install Gloom with: irm https://gloom.sh/install.ps1 | iex". The command strings are
not handed to a runner, so the command forms don't fire; but the word `curl` in that string
made the install code "reach the network" (`NETWORK_TEXT`), and then the URL the code keeps
(`https://gloom.sh/install.ps1`, a script extension on the vendor's host) counted as an own
download.

**Change (v2).** In JavaScript install files, a `curl`, `wget`, PowerShell-cmdlet or
`DownloadFile` word counts as network only in code or in a string that is not only shown or kept
as data (`lang.javascript.shown_not_run`, the test `npm.install-persistence` already uses).
`fetch` and HTTP-client imports count as before; hook lines and shell/PowerShell/batch scripts
are unchanged.

**Measured.**

- Replay set, all 427 versions where the rule fires (`p2a-sub.jsonl`): it stops firing on 2,
  `@gloom-sh/terminal@0.20.5` and `gloomberb@0.20.5` (benign), both still reported by their
  new preinstall's other rules. 0 of the 378 unwanted, 2 malicious and 3 unverified change.
- Live: both 0.20.8 versions replayed from run `20261112T061732Z-npm`: score 5 -> 2, no longer
  reported.
- `vm-day1` (full main dump): the rule fires on 838 reported malicious samples; 24 would stop
  being reported without it (`ddrisk.py`: `esoftplay` x20, `aicp-tracker` 1.1.7 and 1.3.4,
  `n8n-nodes-zalo-fevox@0.6.8`, `overstock-health-express@1.4.4`). With v2 all 24 keep the
  same `npm.install-download` evidence and stay reported: 0 lost.

**Known limit.** A table of command strings the code later hands to `exec` (`shown_not_run`
does not follow the table) no longer makes the code "reach the network" by its words, so a URL
kept beside it counts only with another network sign (the capability, `fetch`, an HTTP
client). The command itself, when handed to a runner, still fires.

## P3. `npm.version.suspicious` on pnpm 11's `1100.x` numbering

**Problem.** pnpm 11 versions its packages `1100.x` (`@pnpm/error@1100.2.2`). Ports of them
(`@ohos-ports/fs.hard-link-dir@1100.0.9-beta.1`, `@ohos-ports/pnpm-worker@1100.4.10-beta.1`,
verdicted benign 2026-11-12) are new packages whose major is above 90, so the rule fires and
reports them alone.

**Change (v5).** A release that declares another package (runtime, optional or peer
dependency; never itself) whose range starts at the release's own major is exempt
(`metadata.family_major`). Both ports declare `@pnpm/*` at `1100.x`.

**Why not narrower or wider.**

- A self-dependency must keep firing: `@ikeacn/ui@99.9.9` declares `@ikeacn/ui: ^99.9.9` and
  `slack-sns@100.0.0` declares `slack-sns: ^100.0.0`, both `vm-day1` malware.
- "Any high-major dependency" would exempt `dep-b@99.1.0` (`vm-day1` malware, declares
  `gql-test-client@^100.99.99`); the same major is required, so it still fires.
- A pnpm-only exemption (`@pnpm/*` at `11xx`) would leave the `@humanode-hyperlane/*` fork
  (same shape, its packages declare each other at `1045.x`/`1026.x`, all benign) reported, and
  is a name list.

**Measured.**

- `vm-day1` (rule level, all 131 malicious samples the rule fires on, `ddver.py`): 0
  exempted. The rule's finding is unchanged on every sample, so `pipeline+4` is too.
- Replay set: the rule fires on 24 versions; v5 exempts 1
  (`@ohos-ports/pnpm-fs.indexed-pkg-importer@1100.0.37-beta.0`, benign, reported -> not
  reported). The 2 positives (`template-projection-map@99.1.3`, malicious, alone;
  `@gsas/gsas-sdk@99.99.99`, malicious) declare no dependencies and stay reported.
- Live runs on disk (179 runs, `livever.py`, re-decided with each version's other recorded
  findings): main's rule fires on 51 versions; v5 exempts 12, all benign verdicts, all
  unreported after (`@humanode-hyperlane/*` x9 from `20261111T121953Z`, `@ohos-ports/*` x3
  including both brief examples).

**Residual risk.** A dependency-confusion probe that declares a sibling at the same placeholder
major (`@corp/a@99.9.9` on `@corp/b@99.9.9`) is exempt. None of the 131 `vm-day1` samples does.

## Found on the way: the Stage 2 batch base (live differs from the replay)

Stage 2 reads a package's versions in a run as one batch and compares every file content new
in the batch with the batch's **base** (the release before the batch's first version), not
with each version's own previous release (`stages/static.analyse_batch`, `new_contents`).
A later version of a batch that re-obfuscates (javascript-obfuscator renames on every build)
or keeps any other match of the version before it therefore gets the match MEDIUM again,
where the replay (one version at a time, its own previous release as the base) gets it LOW.
Live, 2026-11-11..12 (`batchart.py`, 54 runs): 50 reported versions that are not first in
their batch and have a Stage 2 MEDIUM; replayed one at a time with main's code, 18 are not
reported (7 with the per-version base, all `@blod-nm/*` from the brief, and 11 that Stage 1
alone wouldn't route to Stage 2 at all: `@aglit-ai/cli` staging builds x7, `luban-dev-mcp` x4),
all benign; the 2 unwanted (`elaina-baileys@1.0.0`, `@xzvbailss/baileys@1.0.0`) stay reported.
Not built (Stage 2, outside this round's targets): comparing a batch's later version with the
version before it would make live match the replay for the first part. The replay-set numbers
above are therefore a lower bound on what live reports for multi-version batches.

## Owner questions

1. P1 reverses the round 2-3 "vendor-obfuscated products keep full strength" rejection for new
   packages only, separated from the `*-ai-sdk` family by "no other finding". Keep?
2. P1b / P1c remove 4-5 more benign versions (and the brief's live `@blod-nm/ak@0.1.0`,
   `deep-attributation-rn@1.0.1`) for one `vm-day1` sample each (`mad-1.2.6.2.2.8`,
   `multi-cloud-data-migrator`). Not built.
3. The Stage 2 batch base (above): fix after the freeze?

## Reproduce

```sh
S=~/kitsunox-scratch/r8/P; K=~/kitsunox-scratch/r5/K/scripts; PY=/home/thestair/kitsunox/.venv/bin/python
$PY -I $K/replay.py $S/p1/src ~/kitsunox-scratch/r5/shared/cands.jsonl.zst $S/out/p1-sub.jsonl 2 @$S/out/p1.keys
$PY -I $K/dd.py $S/p1/src $S/out/dd-p1.jsonl 2 $S/out/dd-p1alone.keys
python3 -I $S/s/cmp.py ~/kitsunox-scratch/r7/shared/integ.jsonl $S/out/p1-sub.jsonl static.obfuscated
```
