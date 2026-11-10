# Proposal: precision round 6, agent N (Stage 1 account and publish signals)

> **Status:** built 2026-11-10, before the rule freeze (2026-11-12 00:00Z), for the owner's
> review. Four commits, each measured on its own: D1 and D2 in Stage 1
> (`npm.publish-method.downgrade` v5, v6), C1 and C2 in Stage 4
> (`npm.combination.revived-with-new-dependency` v4, v5). **Result with the real code:
> 1,349 → 1,316 reported, all 33 removed benign (33 packages); not one malicious, unwanted or unverified version stops being reported or changes a finding of these rules. Precision (today's verdicts, 2026-11-10 evening) 35.48% → 36.39%.**** `vm-day1`: the 74 malicious samples where these changes can act (every sample the revived combination fires on, every downgrade by the previous publisher), re-run with `pipeline+4`: 74 reported before and after, 0 lost; one finding changes (`@antv/data-set@0.12.8`, C2). `vant@2.13.3`, `vant@3.6.13` and `xrpl@2.14.2` keep the revived MEDIUM.
> **Builds on:** [round 5 K](precision-round5-K.md) (G1, the `gitHead` numbers D1 uses),
> [round 4 C](precision-round4-C.md) (R1, rejected by the owner), [round 3](precision-round3.md)
> (method, harness), [round 2](precision-round2.md) sections 6-8, decision
> [0015](../decisions/0015-reviewer-verdicts.md) (what counts as a positive).

## Summary

The account and publish signals exist for account takeovers. On current `main` they fire on
far more benign reported versions than positives (benign / positive where each fires on a
reported version, today's verdicts): `npm.dormant-revived` 69/4, `revived-with-new-dependency`
61/0, `publisher.unfamiliar` 55/20, `maintainer.added` 50/4, `githead-dropped` 43/16,
`publish-method.downgrade` 41/5, `version.suspicious` 22/2. Only three are *decisive* for many reports (removing the rule
unreports the version): the revived combination (56 benign, 0 positives), the downgrade (39
benign, 1 unwanted: `@hithink-tech/hithink-finance-cli@0.2.0`) and the suspicious version (22
benign, 1 malicious: `template-projection-map@99.1.3`). The LOW ones (dormant, unfamiliar,
maintainer added, `gitHead`) are decisive for 1-6 each and only as score.

This round cuts four shapes, each named by a fact of the release's publish record, each with
no `vm-day1` takeover lost and `vant` untouched:

| # | Rule (stage) | What becomes one step lower / LOW | Benign removed | Positives at risk → lost | `vm-day1` touched → lost |
|---|---|---|---|---|---|
| D1 | `npm.publish-method.downgrade` v5 (1) | a dropped `gitHead` is no co-signal for a watched package | 9 (`@daytona/*`, `@daytonaio/*` 0.231.0 x6, `claude-mem`, `@adea-ai/themes`, `@react-native-kakao/user`) | 0 → 0 | 0 of 149 downgrades → 0 |
| D2 | `npm.publish-method.downgrade` v6 (1) | an added dependency alone is no co-signal when the previous release came from token CI (provenance, no trusted publisher) by the same account | 13 (`@volter/*` x2, `@wenathlan/*` x3, `@oliverames/*` x2, `@godown/cli`, `@infernetprotocol/cli`, `@profullstack/profile`, `moshcode`, `opencode-github-release`, `pi-graphnav`) | 0 → 0 | 0 of 149 (38 same-account, all with an install hook) → 0 |
| C1 | `revived-with-new-dependency` v4 (4) | published through trusted publishing (as v3's provenance) | 2 (`productenv@2.0.0`, `@musedesignsystem/tokens@2.12.2`) | 0 → 0 | 0 of 36 → 0 |
| C2 | `revived-with-new-dependency` v5 (4) | the previous publisher publishes, even with maintainers added | 9 (`@rbbn/distant-*` x3, `@coorpacademy/update-node`, `@iqb/eslint-config`, `@biodiv-platform/naksha-gmaps-draw`, `@terrahq/design-system`, `docx-populator`, `pockethost`) | 0 → 0 | 1 of 36 lowered (`@antv/data-set@0.12.8`, still reported) → 0 |

All four are zero-loss on the live set and on `vm-day1`. C2 is the one that touches a
takeover sample (`@antv/data-set@0.12.8`, still reported); see section 5.

## 1. Data and method

As rounds 3-5: `replay.py SRC CANDS OUT` (agent K's corrected harness) reruns Stages 1-4 with
`SRC`'s code on the recorded candidate of each verdicted live version, tarballs read in memory
with `extract_tar_gz`, nothing run, live routing (`code_route`, flagged versions), the run's
watchlist. Baseline: the shared replay of `main` (`79958e6`),
`~/kitsunox-scratch/r6/shared/base.jsonl` (1,349 reported: 1,017 benign, 255 unwanted, 47
malicious, 30 unverified; precision 22.90%). Each commit was replayed on the versions it can
change, against the state before it:

- D1: the 789 versions where any rule of this cluster fires (any severity), D1 code vs the
  baseline: 9 differ, all listed.
- D2: the 593 versions where the downgrade or the revived combination fires, D1+D2 vs D1.
- C1, C2: the 316 versions where `npm.dormant-revived` fires (the combination needs it), each
  commit's code vs the one before.
- All four together: the baseline with these subsets' rows put in (every version a change can reach is in one), counted with today's verdicts (section 4).

Counting: `relabel.py` with today's verdicts. Positives = `malicious` + `unwanted`.

`vm-day1`: `dd.py` (`pipeline+4` per sample, repository comparison off, the round 3 scratch data dir) with `main`'s code and with the final branch on every malicious sample where a change can act (section 5): 74 samples.

## 2. What the benign reports share

The 55 benign versions the revived combination reports at MEDIUM and alone, by who published them (`shapes.py`), and the `vm-day1` samples where it fires MEDIUM:

| Shape | Benign | `vm-day1` samples of the same shape |
|---|---|---|
| a listed maintainer other than the last publisher publishes, no maintainer added (`@afosto/utils`, `vietqr`, `eslint-config-metarhia`, `@teleporthq/*` x11, `amphora-html`, ...) | 20 | `vant@2.13.3`, `vant@3.6.13`, 11 `@mastra/*` |
| a maintainer added in this release publishes (`@squareboat/*` x4, `@mchp-mcc/*` x3, `@lobehub/*` x3, `@profullstack/*` x3, `@koralabs/*` x2, `@min98/*` x2, ...) | 22 | `@mastra/vercel@1.0.1`; and it is the `event-stream` handover |
| the previous publisher publishes, maintainers added (C2) | 9 | `@antv/data-set@0.12.8` |
| trusted publishing without an attestation (C1) | 2 | none |
| a listed maintainer other than the last publisher publishes, maintainers added (`@bravura/conventional-changelog-jira`, `@livepreso/webpack-deck`) | 2 | `xrpl@2.14.2`, 14 `@antv/*`, `is@3.3.1` |

The first two rows and the last are the takeover shapes themselves, so they stay MEDIUM. What tells their
benign versions apart is what the new dependency is (popular, own scope), and that is R1,
which the owner rejected for `vant` (section 6). The 56th decisive benign version, `@godown/cli@0.3.0`, has the combination LOW already and is D2's.

The downgrade's 42 benign reported versions at the start of the round (one, `@qwen-code/cua-sdk@0.27.0`, is unwanted now; it keeps its report) by Stage 1 co-signal: none, 10 (9 watched and
HIGH only because `gitHead` dropped: D1); an added dependency only, 25 (13 by the same account
after token CI: D2; 12 after trusted publishing, beside the unwanted `hithink`); a maintainer
added or an unfamiliar publisher, 6 (`@expo/*`, `uri-scheme`, `@mingcute/mcp-server`,
`agent-batch`); a non-registry dependency, 1.

## 3. The fixes

### D1. `npm.publish-method.downgrade` v5: a dropped `gitHead` is no co-signal (Stage 1)

v4 kept a watched downgrade HIGH when the release also dropped `gitHead`. Round 5 G1 measured
that given a downgrade the drop doesn't separate: 34 of the 149 malicious `vm-day1`
downgrades have it (23%), 81 of 273 live benign verdicts with a downgrade (30%). Every one of
the 149 has a Stage 1 co-signal of its own (42 an install hook, 107 a new dependency), so v5
drops the `gitHead` clause: a watched release with no co-signal is MEDIUM weight 3 (weak
alone) and the explanation still names the missing commit. `npm.provenance.githead-dropped`
still reports it.

Live (789-version subset): exactly 9 versions change, all benign and all unreported: the six
Daytona SDK packages at 0.231.0 (one monorepo release published by hand), `claude-mem@15.8.2`,
`@adea-ai/themes@0.11.6`, `@react-native-kakao/user@3.2.0`. `axios@1.14.1` keeps HIGH through
its new dependency (unit test). **Recall risk:** a stolen token used for a code-only release
of a watched package is weak alone here; the package is still watched, so Stage 2 reads it.

### D2. `npm.publish-method.downgrade` v6: token CI by the same account (Stage 1)

When the previous release has a provenance attestation but no trusted publisher, CI published
it with an access token, and when that release's publisher is the account publishing now, a
hand publish is the same credential used a second way. An added dependency alone then no
longer keeps the downgrade at full weight (`token_ci_by_same_account`); an install hook, a
non-registry dependency, a maintainer added, an unfamiliar publisher or a suspicious version
still do.

- **Why not every added dependency:** `axios@1.14.1` (a new `plain-crypto-js`, score 6) and
  the 106 `@mastra/*` samples (`easy-day-js`) count on the dependency, and all left trusted
  publishing (`GitHub Actions` → a person). `hithink-finance-cli@0.2.0` (unwanted) too.
- **Why the same account:** another account than the previous publisher keeps the co-signal.
- **The worm:** 38 `vm-day1` samples are exactly this publish shape (the same account after
  token CI: `@ctrl/*`, `@squawk/*`, `@nx/*`, `ngx-toastr`, `synckit`), and every one adds or
  changes an install hook, which still counts.

Live (593-version subset): 13 versions change, all benign and unreported (score 6 → 2-3).
Unwatched, they are no longer flagged, so Stage 2 reads them only through `code_route`; 9 of
the 13 lost LOW Stage 2-3 findings that way. **Recall risk:** a thief holding such a token who
adds a dependency and puts the payload in the code of a large unwatched release is no longer
read by Stage 2 through this rule; the dependency's own Stage 4 findings (fresh-foreign,
known malware, non-registry, name-embeds-popular) still apply.

### C1. `revived-with-new-dependency` v4: trusted publishing (Stage 4)

v3 made the rule LOW for a release with a provenance attestation. npm records a trusted
publisher on releases that carry no attestation (`productenv@2.0.0`,
`@musedesignsystem/tokens@2.12.2`: `GitHub Actions` with `trusted_publisher` github), and
trusted publishing is the stronger tie to the repository's CI (no token stands in for it).
v4 treats it the same. Live (316-version subset): 2 versions change, both benign and unreported (score 5 → 3). No `vm-day1` sample the rule fires on has a trusted publisher without provenance (`@opensearch-project/opensearch@3.5.3` has both and was LOW already).

### C2. `revived-with-new-dependency` v5: the previous publisher returns (Stage 4)

v2 made the rule LOW when the previous release's publisher publishes again *and* no maintainer
was added. After a year or more, a team's maintainer list drifts; the account that publishes
is the same. v5 drops the maintainer clause; the explanation lists who joined and says none
of them published. A newly added maintainer who publishes (the `event-stream` handover,
`@mastra/vercel@1.0.1`), and a listed maintainer other than the last publisher (`xrpl@2.14.2`,
`vant`), keep MEDIUM. Live (316-version subset): 9 versions change, all benign and unreported (score 5 → 3). **Recall risk**, v2's: a dormant account hijacked as itself is LOW here even if the hijacker adds a maintainer; on `vm-day1` that is `@antv/data-set@0.12.8` (`atool` publishing again after 40 maintainers joined the org's packages), which stays reported through `npm.install-hook` HIGH, the install-script rules and `npm.dependency.non-registry` (score 26).

## 4. Live result (real code)

Counted with `relabel.py` and today's verdicts (re-reviewed while this round ran; the baseline's 1,017 benign at the start of the round are 851 now).

| | Reported | Benign | Unwanted | Malicious | Unverified | Precision |
|---|---|---|---|---|---|---|
| `main` (`79958e6`) | 1,349 | 851 | 421 | 47 | 30 | 35.48% |
| D1 + D2 + C1 + C2 | 1,316 | 818 | 421 | 47 | 30 | 36.39% |

33 benign versions (33 packages) are no longer reported: D1 9, D2 13, C1 2, C2 9, each version in exactly one. No version is newly reported. No malicious, unwanted or unverified version changes its decision or any finding of the downgrade or the revived combination. Besides the 33, 2 unreported benign versions get a LOW downgrade instead of MEDIUM (`@volter/cyclotron@0.5.212`, `@volter/tabnode@0.16.0`, D2).

## 5. DataDog check (`vm-day1`)

- **At risk: 74 samples.** A change can act only where its rule fires: the revived combination fires on 36 malicious samples (C1, C2), and the downgrade on 149, of which D1 needs a watched release with no Stage 1 co-signal (none: all 149 have one) and D2 a release by the previous publisher (38: `@ctrl/*`, `@squawk/*`, `@nx/*`, `ngx-toastr`, `synckit`, `@pkgr/core`, `napi-postinstall`, `@taskflow-corp/cli`, `koa2-swagger-ui`, `ts-gaussian`, `@crowdstrike/glide-core`; every one with an install hook co-signal). Run with `pipeline+4`, one process per sample, `main` (`79958e6`) and the final tree, as a small run (no heavy lock: the shared lock had a queue of six heavy jobs).
- **Result: 74 reported before and after, 0 lost, 0 gained, 0 errors.** The only finding that changes is C2's on `@antv/data-set@0.12.8` (MEDIUM → LOW; score 26, still reported). `vant@2.13.3`, `vant@3.6.13` (the maintainer's own account, a listed maintainer who was not the last publisher), `xrpl@2.14.2`, `is@3.3.1`, the 14 other `@antv/*`, the 12 `@mastra/*` and `axios@1.14.1` are unchanged.

## 6. Rejected or not built

- **R1 again, or any narrowing by what the added dependency is.** The 20 vant-shaped and 22
  new-maintainer benign reports differ from the takeovers only in their dependencies (popular
  or own scope). The owner rejected R1 because it lowers `vant`; `vant@2.13.3` adds
  `@vant/use: workspace:^` and `@vue/shared`, so **a `workspace:`/`catalog:` exemption is
  ruled out by `vant` itself** (it would also remove only 1 benign report,
  `@nodeint/migent-kernel@0.5.4`). Own-scope dependencies are the stolen-scope-token case
  (round 2).
- **A previous prerelease of the same version (`0.45.1-alpha.0` → `0.45.1`, 10 benign:
  `@teleporthq/*` x9, `@saasquatch/vanilla-components`).** No `vm-day1` sample has it, but the
  stable line behind it was dormant longer still, and an attacker publishes exactly `X` after
  `X-alpha.0` naturally. Any previous prerelease would lower 9 `@mastra/*` samples.
- **`version.suspicious` for small no-hook placeholders (15 benign `99.x` squats).** The same
  shape is malicious in `vm-day1`: `@account-portal/ui-toolkit-react@99.9.0`,
  `@sage-org/fabric-ui-root-config@99.9.0`, `adobe-appmeasurement@99.9.0`, `test-paypal@999.9.9`
  (2 files, ~250 bytes, no install hook), each reported only by this rule.
  `spain-holidays@2027.0.0` is the `amazonui@2026.0.1`-in-2025 shape; `vallenemperor@999.999.999`
  (same publisher) is the shape of the malicious `template-projection-map@99.1.3`.
- **Downgrade: own-scope dependency after trusted publishing (6 benign: `@leofcoin/*` x3,
  `@mica-js/simulator`, `@nodeint/migent-kernel`, `@yaroslavlky/mink`).** A token-theft signal
  is exactly where a stolen scope token matters. Not built.
- **Downgrade: a previous prerelease (`@expo/*`, `uri-scheme`, 4 benign).** Lowers the rule on
  5 `@nx/*` worm samples (still reported). Not built.
- **Publisher unfamiliar and maintainer added counted once when the new maintainer publishes.**
  That is the `event-stream` handover, the more suspicious combination.

## 7. Owner questions

1. Keep D1, D2, C1, C2 for the freeze (each is its own commit)? D2 and C2 carry the stated
   recall risks: a same-account token used to add a dependency (D2), an account hijacked as
   itself after maintainers joined (C2, v2's existing risk; lowers `@antv/data-set@0.12.8`,
   still reported).
2. `@hithink-tech/hithink-finance-cli@0.2.0` (unwanted for installing skills user-wide) is
   reported only by the downgrade's score: its postinstall is unchanged since 0.1.13, so no
   install rule fires. A rule for unchanged install code that is unwanted belongs to the
   install-persistence owner; until then it blocks narrowing the downgrade after trusted
   publishing (11 benign).

## 8. How to reproduce

Scripts in `~/kitsunox-scratch/r6/N/my/` (Python with `-I`, `systemd-run --user --scope -p
MemoryMax=4G`, read-only on `data/`): `feat.py` (features of every replayed version from its
candidate), `dec.py` and `compact.py` (decisive rules and shapes), `ddfeat.py`/`ddfire.py`
(the same for `vm-day1`), `sim.py` (what-if, used only to choose), `delta.py` (decision and
finding differences between two real replays). Replays with K's `k_replay.sh SRC OUT KEYS`;
`vm-day1` with `my/dd.sh SRC OUT KEYS` under the heavy lock. Outputs in `out/`.
