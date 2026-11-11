# Proposal: precision round 7, agent W (Stage 1 metadata rules that report benign versions alone)

> **Status:** built 2026-11-11, before the rule freeze (2026-11-16 00:00Z), for the owner's
> review. Two commits, both zero-loss: W3 in Stage 1 (`npm.publish-method.downgrade` v7),
> W1 and W2 in Stage 4 (`npm.combination.revived-with-new-dependency` v6). **Result with the
> real code: 14 benign reports fewer (14 packages), not one malicious, unwanted or unverified
> version changes its decision or a finding of these rules.** `vm-day1`: the 37 malicious
> samples where these changes can act, re-run with `pipeline+4`: 37 reported before and
> after, no finding of either rule changes (`vant@2.13.3`, `vant@3.6.13`, `xrpl@2.14.2`, the
> 12 `@mastra/*` and 15 `@antv/*` keep the revived MEDIUM).
> **Builds on:** [round 6 N](precision-round6-N.md) (the same rules, and its rejections),
> [round 4 C](precision-round4-C.md) (R1, rejected by the owner for `vant`),
> [round 3](precision-round3.md) (method, harness), decision
> [0015](../decisions/0015-reviewer-verdicts.md) (what counts as a positive).

## Summary

On `main` with today's verdicts, five Stage 1 / Stage 4 metadata findings report versions
with no other MEDIUM or HIGH finding beside them (benign / positive, medium+ rule set alone):

| Rule | Benign | Positive | This round |
|---|---|---|---|
| `npm.dependency.non-registry` | 61 (50 packages) | 13 (+3 unverified) | none built: no zero-loss shape (section 6); one vendor origin is an owner question (Q2) |
| `npm.combination.revived-with-new-dependency` (+ `code.capability-gained`) | 39 + 5 | 0 | **W1, W2: 12 removed** |
| `npm.version.suspicious` | 22 | 1 (`template-projection-map@99.1.3`) | none built: the placeholders are DataDog samples too (Q1) |
| `npm.publish-method.downgrade` | 17 | 1 unwanted (`@hithink-tech/hithink-finance-cli@0.2.0`) | **W3: 2 removed** |
| `npm.dependency.fresh-foreign` | 9 | 0 (+1 unverified) | none built (section 6) |

| # | Rule (stage) | What becomes LOW / one step lower | Benign removed | Positives at risk → lost | `vm-day1` touched → lost |
|---|---|---|---|---|---|
| W1 | `revived-with-new-dependency` v6 (4) | the release starts a new major version (major grows, ≥ 1) | 10 (`@capacitor/assets@4.0.0`, `@livepreso/webpack-deck@4.0.0`, `amphora-html@7.0.0`, `@squareboat/nest-storage@1.0.0`, `@hlang-org/compiler@2.0.0`, `@scioservices/upload-component@3.0.0`, `@bravura/conventional-changelog-jira@1.0.0`, `@koralabs/hal-minting-contracts@2.0.3`, `@germainapm/nodejs-monitoring@2026.3.0`, `@rocket.chat/houston@2.1.8`) | 0 → 0 | 0 of 36 → 0 |
| W2 | `revived-with-new-dependency` v6 (4) | every added dependency was a dev or peer dependency of the previous release | 2 (`imghash-cli@0.0.2`, `@saasquatch/vanilla-components@1.4.2`) | 0 → 0 | 0 of 36 → 0 |
| W3 | `publish-method.downgrade` v7 (1) | an added maintainer is a co-signal only when an added maintainer publishes the release | 2 (`@expo/plist@0.8.2`, `install-expo-modules@0.16.1`) | 0 → 0 | 1 (`@ensdomains/ensjs@4.0.3`, text only) → 0 |

## 1. Data and method

As rounds 3-6: `replay.py SRC CANDS OUT` (agent K's corrected harness) reruns Stages 1-4 with
`SRC`'s code on the recorded candidate of each of the 3,716 verdicted live versions (tarballs
read in memory with `extract_tar_gz`, nothing run). Baseline: the shared replay
`~/kitsunox-scratch/r7/shared/base.jsonl` (1,469 reported: 771 benign, 620 unwanted, 48
malicious, 30 unverified; precision 46.42%). Development: subset replays of the 593 versions
where the downgrade, `npm.dormant-revived` or the revived combination fires at any severity
(every version W1-W3 can reach), the branch's code and `main`'s (`8ee117c`). Final: one full
replay of the branch (section 4). Counting: `relabel.py` with today's verdicts.

`vm-day1`: Stage 1 of the branch and of `main` on all 3,444 malicious samples (cheap: no
tarball), then `dd.py` (`pipeline+4` per sample, repository comparison off, the round 3
scratch data dir) on every sample a change can reach: the 36 where `npm.dormant-revived` and
`npm.dependency.added` both fire (the combination's inputs), plus `@ensdomains/ensjs@4.0.3`
(the one downgrade with an added-maintainer co-signal).

## 2. What the benign reports share, and what `vant` looks like

**The revived combination** (44 benign, 0 positives) by the facts of the two releases, against
the 36 `vm-day1` samples it fires on:

| Shape | Benign | `vm-day1` samples |
|---|---|---|
| a new major (`3.0.5` → `4.0.0`, `0.5.2` → `1.0.0`, `2024.3.0` → `2026.3.0`) | 10 | **0** |
| else: every added dependency was already a dev or peer dependency | 2 (`amphora-html`, a new major, is a third) | **0** (`@mastra/speech-*` move `@mastra/core` from dev but add `easy-day-js`) |
| else: the previous release is a prerelease (`0.45.1-alpha.0` → `0.45.1`) | 11 (`@teleporthq/*`) | 9 `@mastra/*` (`1.0.1-alpha.50` → `1.0.2`) |
| else: a 0.x minor bump (`0.3.9` → `0.4.0`) | 5 | 8 `@antv/*` (`0.11.8` → `0.12.8`, `0.2.0` → `0.3.0`) |
| else: a patch or minor in the same major | 16 | 19: `vant` x2, `xrpl`, `is`, `@mastra/*`, `@antv/*` `1.6.13` → `1.7.13`, ... |

`vant@2.13.3` is the 2024 takeover: 428 days after 2.13.2, published by a listed maintainer
who did not publish 2.13.2, no maintainer added, `@vant/use` (`workspace:^`) and
`@vue/shared` added, a new `postinstall`. It is a patch: npm hands it to every project with
`^2.13.x` or `~2.13.x`, which is what a takeover publishes for. Every takeover on `vm-day1`
does the same (stays in its major); `@antv/*` bumped a middle number and kept the patch
(`1.6.13` → `1.7.13`), still inside `^1.6.13`. The benign revivals that leave the major are
rewrites announced as breaking (`@capacitor/assets` 4, `@livepreso/webpack-deck` 4: a
webpack-to-rspack migration, `amphora-html` 7). Of the 3,444 `vm-day1` malicious samples, 108
updates start a new major; all are the attackers' own packages republished within minutes or
days (`workflows-templates@9.0.0`, `zeitwerk@61.1.3`, `sirius-import-article@4.0.0`), none
dormant, so none meets this rule.

**The downgrade** (17 benign, 1 unwanted): 11 are a sole or listed maintainer publishing by
hand after an OIDC release, adding a dependency; that shape is also `hithink` (unwanted) and
100 `vm-day1` samples (`@mastra/*`, `axios@1.14.1`: `tp`, sole maintainer, no install hook,
only an added dependency), so it stays. Expo's 4 are stable releases published by hand by
`alanhughes` after a CI canary of the same version two months older; 3 of them have no
co-signal except `npm.maintainer.added` (the list grew between canary and stable), which is
what W3 reads.

## 3. The fixes

### W1. `revived-with-new-dependency` v6: a new major version (Stage 4)

LOW, weight 1, when the major grows and is at least 1 (`new_major`). The combination's
premise is a dormant package taken over to reach the projects that depend on it. npm resolves
those dependents' ranges (`^x.y.z`, `~x.y.z`, `x.y`) inside the major they name; a new major
reaches only new installs and projects that follow `latest`. 0.x minor bumps are left out on
purpose: npm treats `0.12` as outside `^0.11.8` too, but `@antv/g2-extension-3d@0.3.0` (after
`0.2.0`) and 7 more `@antv/*` 0.x bumps are takeovers. Live: 10 benign removed. **Recall
risk:** a takeover that publishes a new major now needs its other signals (install hook,
content, Stage 4 dependency rules); none of `vm-day1`'s does.

### W2. `revived-with-new-dependency` v6: dependencies the project already used (Stage 4)

LOW, weight 1, when every added runtime dependency was a `devDependencies` or
`peerDependencies` entry of the previous release (`declared_only_for_development`, Stage 1's
helper). The release brings no package new to the project: the maintainers chose those
packages before the dormancy (npm 7+ even installed the peers already). A payload would have
to be in one of them, and its compromise is its own release in the feed. One added package
that is new keeps MEDIUM (`@mastra/speech-*`). Live: 2 benign removed (`imghash-cli@0.0.2`,
`@saasquatch/vanilla-components@1.4.2`, its Apollo stack moved from dev).

### W3. `publish-method.downgrade` v7: who publishes (Stage 1)

The co-signals keep the downgrade at full weight because "what gets installed, or who
publishes it, changed too". `npm.maintainer.added` now counts only when an added maintainer
publishes the release (`publisher_was_added`): a maintainer who joined but didn't publish
changes neither; one who did is usually `npm.publisher.unfamiliar` as well. All 7 live versions
with this co-signal are benign; `@expo/plist@0.8.2` (HIGH, watched) and
`install-expo-modules@0.16.1` are no longer reported, `uri-scheme@2.2.1` is one step lower
but still reaches the score. On `vm-day1` only `@ensdomains/ensjs@4.0.3` has the co-signal,
and its install hook keeps it. **Recall risk:** a thief who adds a maintainer for persistence
and publishes as the old account, changing nothing else, is one step lower; the LOW
`npm.maintainer.added` still adds to the score.

## 4. Live result (real code)

One full replay of the branch (all 3,716 versions, 0 errors), counted with today's verdicts
(`relabel.py base.jsonl full.jsonl`):

| | Reported | Benign | Unwanted | Malicious | Unverified | Precision |
|---|---|---|---|---|---|---|
| `base.jsonl` (`main`) | 1,469 | 771 | 620 | 48 | 30 | 46.42% |
| **W1 + W2 + W3** | **1,455** | **757** | 620 | 48 | 30 | **46.88%** |

Exactly 14 versions change their decision, all benign and all unreported (14 packages: the
12 of W1/W2 and the 2 of W3), and no version is newly reported. No malicious, unwanted or
unverified version changes its decision or any finding of the two rules. The subset replays
agree: the branch against a `main` replay of the same 593 versions unreports the same 14.

## 5. DataDog check (`vm-day1`)

- **Stage 1 on all 3,444 malicious samples, `main` vs branch:** no finding changes rule,
  severity or weight; one changes text (`@ensdomains/ensjs@4.0.3`'s downgrade no longer lists
  `npm.maintainer.added` among its co-signals; `npm.install-hook` remains).
- **`pipeline+4` on the 37 samples a change can reach** (the 36 the revived combination can
  fire on, and `ensjs`), `main` and branch, one process per sample: **37 reported before and
  after, 0 lost, 0 errors; no finding of the two rules changes, and no decision reason
  changes.** `vant@2.13.3`, `vant@3.6.13`, `xrpl@2.14.2`, `is@3.3.1`, the 12 `@mastra/*` and
  the 14 MEDIUM `@antv/*` keep the revived MEDIUM.

## 6. Rejected or not built

- **Any narrowing of the revived combination by who publishes or what is added** (popular,
  own scope: R1; a listed maintainer; dependencies removed alongside). `vant`, `xrpl` and the
  `@mastra/*` remove dependencies too, are published by listed maintainers, and add popular or
  own-scope ones. The remaining 30 benign versions (`@teleporthq/*` x11, `@lobehub/*` x3,
  `@mchp-mcc/*` x3, `@profullstack/*` x3, `@squareboat/*` x3, ...) have exactly the takeover
  shapes of section 2.
- **0.x minor bumps as new majors** (5 more benign: `@squareboat/nest-queue-*`,
  `@graffiticode/tracing`, `@profullstack/viral-video`): would lower 8 `@antv/*` takeovers
  (`@antv/g2-extension-3d@0.3.0`, `@antv/f6@0.1.19`, ...; `@antv/data-set@0.12.8` is LOW
  already).
- **Package-level dormancy** (time since the package's latest publish, not the diff base's):
  needs a Stage 0 field, and it would lose `vant`: 4.x was active while the attacker published
  2.13.3 and 3.6.13 on the dormant lines.
- **A previous prerelease** (`@teleporthq/*` x11): lowers 9 `@mastra/*` takeovers
  (`1.0.1-alpha.50` → `1.0.2`). Narrowed to a prerelease of the same version (9 of the 11),
  round 6 N's objection holds: an attacker publishes `X` after a stale `X-alpha.0` as
  naturally.
- **Downgrade after OIDC by the same account adding a dependency** (11 benign): the shape of
  `hithink` (unwanted) and 100 `vm-day1` samples (`@mastra/*`, `axios@1.14.1`).
- **`version.suspicious` on a prerelease** (`@ohos-ports/*` x2, `@spear-ai/trino-pulumi-aws`):
  round 4 C, 44 OSV malware versions are high-major prereleases. **On trusted publishing**
  (`picard-code@1701.4.0`): provenance-style exemptions are on the rejected list. A
  `YYYY.0.0` of next year (`spain-holidays@2027.0.0`) is `amazonui@2026.0.1`-in-2025.
  `vallenemperor@999.999.999` is `template-projection-map@99.1.3`'s shape (an update by the
  same account jumping to 99+).
- **`fresh-foreign` by age or account:** the `vm-day1` payload dependencies are 0.1 to 142
  hours old (`aethlong` 109-139 h, `easy-day-js` 18 h, `graphconql` 14-44 h), the benign ones
  0 to 167 h; no threshold separates them. What separates them is the dependency's code, which
  Stage 4's registry records don't carry (a contract change). The rule is a context rule in
  the replay harness too (its findings come from the recorded candidates).
- **`non-registry` for packages with several dependencies, or a `repository` naming the
  dependency's account:** every live positive it reports alone is a one-dependency package
  with no real `repository` (`garaya-jiklop`: `github.com/example/...`), but the field is
  written by whoever publishes, `avantas@2.0.4` (malicious) names its dependency's account
  (`oonlyjs/mono` beside `github:oonlyjs/node-ews`), and a takeover adding a git dependency to
  a real package (`@antv/*`, `@opensearch-project/opensearch`) has many dependencies. **`pkg.pr.new`** (10 benign:
  `hotcodepush` x8, `squire-ui`, `@kasperpeulen/*`): its URLs serve builds of pull requests,
  forks included, under the parent repository's name, like a commit pin. Own-scope names for
  non-registry dependencies: the attacker's own scope qualifies.

## 7. Owner questions

1. **Researchers' empty `99.x` placeholders** (`npm.version.suspicious` alone, new package,
   no install hook, no code beyond `module.exports = {}` / `// blank`): 16 benign live
   reports (`@geneva-testing/*` x9, `@one-thd/*` x4, `@thd-eux/theme-ant`, `logosphere-ui`,
   `service-roles-registry`). `vm-day1` has the same shape labelled malicious and reported by
   this rule alone: `@account-portal/ui-toolkit-react@99.9.0` and
   `@sage-org/fabric-ui-root-config@99.9.0` (`ltidibugcrowd`), `adobe-appmeasurement@99.9.0`,
   `test-paypal@999.9.9` (`testhackerone100`). So any exemption loses 4 `vm-day1` samples,
   and it needs a content signal (Stage 2/3). Is DataDog's label for these placeholders the
   truth here, given that the owner's verdicts call the identical live ones benign? Not built.
2. **uWebSockets.js from GitHub** (`github:uNetworking/uWebSockets.js#v20.x`, a tag): the
   project publishes only there, as SheetJS publishes only on its CDN (v4's
   `VENDOR_REGISTRIES`, "each vendor an owner decision"). 3 benign reports
   (`@chubbyts/chubbyts-http-uwebsockets@1.0.0`, `@moussejs/core@1.1.0`,
   `copious-transitions@0.9.1`), no positive, no `vm-day1` sample uses it. Not built.
3. **Baseline note for the integrator:** `~/kitsunox-scratch/r7/shared/base.jsonl` carries
   `npm.dependency.non-registry` **v8** findings (274 of them; none v9), so it predates
   `697e67c`. It doesn't change the counts: replaying `main` (`8ee117c`, v9) on the 819
   versions where the non-registry rule, the downgrade, `npm.dormant-revived` or the revived
   combination fires gives the same decision as `base.jsonl` on every one of them (some
   findings differ, v8 LOW → v9 MEDIUM, all on versions reported either way). Against that
   `main` replay the branch unreports exactly the same 14 benign versions.

## 8. How to reproduce

Scripts in `~/kitsunox-scratch/r7/W/an/` (Python with `-I`, `systemd-run --user --scope -p
MemoryMax=4G`, read-only on `data/`): `clus.py` (medium+ rule sets of reported versions),
`feat.py` (facts of the versions a rule reports alone), `dds1.py` (Stage 1 on every `vm-day1`
malicious sample), `ddrev.py`, `dddg.py`, `ddver.py`, `ddnr.py`, `ffage.py` (the samples'
shapes per rule), `devdeps.py`, `nrupd.py`, `mkkeys.py` (subset keys), `cmp.py` (decision and
finding differences of two replays). Replays with `scripts/k_replay.sh SRC OUT KEYS|full`,
`vm-day1` with `scripts/w_dd.sh SRC OUT KEYS`. Outputs in `~/kitsunox-scratch/r7/W/out/`.
