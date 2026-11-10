# Proposal: precision round 4, agent C (dependency and publish-metadata rules)

> **Status:** built 2026-11-10, before the rule freeze (2026-11-12 00:00Z). **Owner's
> decision (2026-11-10): keep N1 and F1, reject R1.** N1 is in Stage 1
> (`npm.dependency.non-registry` v5), F1 in Stage 4 (`npm.dependency.fresh-foreign` v4); both
> are zero-loss. R1 (`npm.combination.revived-with-new-dependency` v4) was built and measured
> (9 benign, 0 positives) but rejected: on `vm-day1` it lowers the rule on the real `vant`
> takeover (section 6), so the rule stays at v3 and R1 is not in the branch. Result of N1 + F1
> with the real code on all 3,716 verdicted live versions: 1,787 → 1,717 reported, all 70
> benign (51 packages, 4.7% of the 1,486 benign reports); not one malicious, unwanted or
> unverified version stops being reported or has any finding of these five rules change.
> Precision 15.42% → 16.06%. `vm-day1`: all 222 malicious samples a fix could touch, re-run
> with `pipeline+4`: 222 reported before and after, 0 lost.
> **Builds on:** [round 3](precision-round3.md) (method, harness, its section 6 rejections),
> [round 2](precision-round2.md) sections 6-8, decision
> [0015](../decisions/0015-reviewer-verdicts.md) (what counts as a positive, all addenda).

## Summary

The five rules of this cluster carried about 300 benign reports alone (round 3's replay). The
earlier rounds rejected the shape-blind cuts (own-owner git dependencies, release and
`pkg.pr.new` URLs, all-popular revivals, own-scope dependencies). This round anchors each cut
in something the attacker of that rule's scenario cannot write: the *previous* release's
manifest, git's fork network, and npm scope ownership.

| # | Rule (stage) | What becomes LOW | Benign removed | Positives at risk → lost | `vm-day1` at risk → lost |
|---|---|---|---|---|---|
| N1 | `npm.dependency.non-registry` v5 (1) | on an update, a dependency the previous release took from the same account, or from the GitHub account its `repository` names, at a reference no fork can plant (not a commit id or pull ref) | 59 (40 packages: `@bitfinex/*` ×15, `@method-ai-hq/sdk` ×11, `signetai` ×6, `@buerli.io/*` ×4, `@activeledger/*`, `@aimuzov/*`, ...) | 16 → 0 | 87 → 0 |
| F1 | `npm.dependency.fresh-foreign` v4 (4) | the fresh dependency's npm scope also holds a watched package | 11 (`@earendil-works/pi-schema` dependents ×4, `@deepseek-ai/dsh-*` ×2, `@midnightntwrk` ×2, `@boundaries`, `@json-render`, `@web-kits`) | 1 (unverified) → 0 | 131 → 0 |
| | **N1 + F1 (kept)** | | **70** (51 packages) | **0** | **218 → 0** |
| R1 | `npm.combination.revived-with-new-dependency` v4 (4), **rejected by the owner 2026-11-10** | no maintainer added and every added dependency is on the watchlist | 9 (`@afosto/utils`, `@germainapm/nodejs-monitoring`, `vietqr`, `eslint-config-metarhia`, ...) | 0 → 0 | 31 → 0 (lowers `vant` ×2) |

Not built, each with the sample that rules it out (section 6): `version.suspicious` LOW on a
prerelease (44 OSV malware versions are high-major prereleases, `exodus-*@99.0.0-canary.1`);
commit-to-commit bumps in the same repository (loses `lane-m-snackager-probe@1.0.1`, unwanted,
and is how `@opensearch-project/opensearch@3.8.0` followed 3.7.0); trusting any earlier
non-registry origin (loses `dependencykfeg@25.1.3`, malicious); downgrade co-signals narrowed to
foreign or non-own-scope dependencies (the round-2 stolen-scope-token objection; and
`@hithink-tech/hithink-finance-cli@0.2.0`); dropping non-registry to LOW wholesale (section 4).

## 1. Data and method

As round 3 (its section 1): `replay.py SRC CANDS OUT` reruns Stages 1-4 with `SRC`'s code on
the recorded candidate of every verdicted live version, tarballs read in memory, nothing run.
Positives are `malicious` + `unwanted` (last record per version; the shared candidate file's
labels equal `data/verdicts/npm.jsonl` today, checked).

- **One harness change.** Stage 4 now runs with the run's own watchlist (`run_watchlist`, as
  live `correlate` does), because F1 and R1 read it; round 3's harness passed none.
  `npm.dependency.name-embeds-popular` is left out of the rules run (its recorded findings are
  already carried as context, and without dependency lookups it would re-fire where the run
  cleared it by shared accounts). On round-4-base code the changed harness reproduces round
  3's `fix.jsonl` exactly on all 275 versions where one of my rules fires MEDIUM or above (0
  differences in decision or findings), so round 3's `fix.jsonl` is the baseline.
- **Baseline = `round4-base` (= `main` + round 3), fix = this branch.**
- **DataDog (`vm-day1`).** `dd.py` (`pipeline+4` per sample, repository comparison off, round
  3's hard-linked data dir) with the fix code on every malicious sample where N1's, F1's or
  R1's rule fires MEDIUM or above in round 3's baseline (`ddbase.jsonl` + `ddfix.jsonl`): 222
  samples. A Stage 1 change can also change Stage 2 routing; the run includes that.

## 2. Where the cluster's benign reports were

From round 3's replay (decisive = dropping the rule to LOW unreports the version):

| Rule | Benign | Positives (unverified) |
|---|---|---|
| `npm.dependency.non-registry` | 152 | 9 mal., 4 unw. (3) |
| `npm.combination.revived-with-new-dependency` | 55 | 0 |
| `npm.publish-method.downgrade` | 48 | 1 unw. |
| `npm.version.suspicious` | 22 | 1 mal. |
| `npm.dependency.fresh-foreign` | 20 | 0 (1) |

Non-registry, by shape (decisive benign): 27 new packages, 125 updates; of the updates, 103
change the spec of a dependency the previous release already had (74 of them from the package's
own GitHub owner) and 22 add one. Of its 16 positive or unverified versions, 15 are new
packages or add a dependency the previous release didn't have; the one that "changes" one is
`lane-m-snackager-probe@1.0.1`, a commit bump (`#a879d11c…` → `#594fbaa1…`). Every one of
them has no `repository`, except `garaya-jiklop` (`example/garaya-jiklop`).

## 3. The fixes

### N1. `npm.dependency.non-registry` v5: what the previous release vouches for (Stage 1)

On an update, a non-registry dependency is LOW, weight 1, with a note, when the source was
already trusted by the previous release and the new reference can't have been planted from a
fork (`trusted_move`, `dependency_source`, `previous_repository_owner`):

- **Same account as before:** the previous release took this dependency (same name) from the
  same host and owner (GitHub/GitLab owner, a bucket, a URL's first path segment; `codeload`,
  `raw` and archive URLs are `github.com`). Tag bumps (`uNetworking/uWebSockets.js#v20.67.0` →
  `#v20.71.0`, `bitfinexcom/bfx-facs-base#v2.0.0`), the next release asset
  (`Signet-AI/signetai/releases/download/v1.0.0/...`), the next codeload tag
  (`method-ai-hq/method-spec/tar.gz/v0.20.6`), the same bucket (`agentmesh-releases`).
- **The previous release's repository:** the dependency is from the GitHub account the
  previous release's `repository` names (`@aimuzov/*` → `aimuzov/infra-mcp-kit#v3.4.1`). The
  new release's own `repository` never counts: the publisher writes it.
- **Not forkable:** a commit id (7-64 hex digits as a ref or path segment) or a `pull` /
  `merge-requests` ref keeps MEDIUM. GitHub serves a commit pushed to *any fork* through the
  parent repository's URLs (and every fork's pull request has `refs/pull/N/head` there), which
  is how the `vm-day1` git-dependency attacks worked: `@opensearch-project/opensearch` 3.5.3,
  3.7.0, 3.8.0 (`#d446803f…` in its own repository), `@antv/*`, `echarts-for-react`,
  `jest-canvas-mock`, `size-sensor` (`antvis/G2#1916faa3…`), 40 `@tanstack/*`
  (`tanstack/router#79ac49ee…`). A tag, branch or release asset takes write access to that
  account's repository. A release asset's tag is never read as a commit.
- **Still MEDIUM:** new packages (nothing earlier vouches; 12 of the rule's 16 positive or
  unverified versions), another account than before (`@chatbridgeworld/baileys`'s libsignal
  moving from `realvare` to `chatbridgegit`), a dependency that came from the registry before
  (`web_audit`, `better-sqlite3`), and a new dependency name on a known URL
  (`dependencykfeg@25.1.3`).

Live: 59 benign removed (40 packages). No positive's or unverified version's non-registry
finding changes. The DOWNGRADE_COSIGNALS use of this rule is unchanged (a LOW finding is
still a co-signal).

### F1. `npm.dependency.fresh-foreign` v4: established scopes (Stage 4)

LOW, weight 1, with a note, when the fresh dependency is in an npm scope that also holds a
package on the run's watchlist (`_WatchedScopes`). Only a scope's owner can publish into it
(a user scope's user, an organisation's members), so the "unrelated accounts" are an
established popular publisher, not an account registered for the attack; the dependent's
maintainers depend on a sibling of a package they could already depend on. Abusing it takes
the popular scope's own account, and its new package is then a new package in the feed, read
by Stages 1-3 itself.

Live: 11 benign removed: `@calmabacus/pi-web`, `@heyhuynhgiabuu/pi-task`, `pi-session-mcp`,
`pi-yun` (`@earendil-works/pi-schema`, 16 watched siblings), `@jayyuen66/dsh-plugin-shared`,
`dsh-claude-tui` (`@deepseek-ai`, 316), `@odatano/nightgate`, `nightgate-tx`
(`@midnightntwrk`, 15), `@desplega.ai/agent-swarm` (`@json-render`, 15), `@howells/lint`
(`@boundaries`, 2), `@vvedantb/ui` (`@web-kits`, 1). `tailwind-animora@2.0.1` (unverified,
`@asapsion/postcss-animate-pluginkit`, nothing watched in `@asapsion`) keeps MEDIUM, as do
`@kabema/konva`, `@w3c/webmcp-polyfill`, `@reylosql/*`, `@rh-core/core` (no watched sibling)
and the unscoped ones (`dsh-video-storyboard`, `mini-semantic-search`, `azmarqomni`).

### R1. `npm.combination.revived-with-new-dependency` v4: popular additions (Stage 4), rejected

**Rejected by the owner on 2026-11-10** after the `vm-day1` check (section 6): the real `vant`
takeover is exactly the shape it lowers. Not in the branch; the rule stays at v3. As built and
measured: round 3's owner question 3. LOW, weight 1, when no maintainer was added and every added
runtime dependency is a registry package on the run's watchlist (`popular_additions`; an
`npm:` alias by its target). The rule's premise is a payload pulled in through the new
dependency; a popular package can't carry one without a compromise of its own, which is its
own release in the feed. "No maintainer added" keeps `xrpl@2.14.2` (`vm-day1`: four
maintainers added, only popular dependencies, reported by this rule alone, score 5 → 3
without it). An own-scope dependency counts only if watched itself (round 2's stolen-scope
token objection), which is why the 12 `@teleporthq/*` reports stay (section 7).

Measured live: 9 benign removed (`@afosto/utils`, `@germainapm/nodejs-monitoring`,
`@graffiticode/tracing`, `@musedesignsystem/tokens`, `@saasquatch/vanilla-components`,
`@scioservices/upload-component`, `eslint-config-metarhia`, `productenv`, `vietqr`), no
positive; these 9 stay reported.

## 4. The non-registry positives, if the rule were LOW

The prompt's question: which precise signal would catch each of the rule's 13 positives if
`non-registry` were LOW? None exists, in this cluster or in agents A and B's install rules,
because none of these packages has an install hook or code of its own: the payload is entirely
in the dependency npm fetches (a git dependency's `prepare` runs at install; a tarball's own
hooks run).

| Version | Verdict | Dependency | What it does (verdict note) |
|---|---|---|---|
| `lane-m-snackager-clean2`, `lane-m2-probe-late`, `quiet-lantern-741e`, `quiet-lantern-e9db` @1.0.0 | malicious | `git+https://github.com/chimz-max/laneh-prepare-probe.git#<ref>` | the git dependency's `prepare.js` reads environments, GCP metadata token, AWS credentials |
| `lane-m-snackager-clean`, `lane-m-snackager-probe` 1.0.0/1.0.1, `lane-m2-snackager-probe` | unwanted | same repository | marker-only beacons |
| `@expo-probe-ff8e2b/snack-probe-c2a16@1.0.0` | malicious | `lordseidon/recon-vps#expo-probe-…` | `prepare.js` reads `/proc/*/environ`, GCP and AWS credentials |
| `claims-ac1@1.0.0`, `dependencykfeg` 25.0.3/25.1.3 | malicious | `github.com/GamerD11/ping_test/raw/...tgz` | the tarball's install-time recon |
| `garaya-jiklop@1.0.0` | malicious | `*.workers.dev/npm/...` | install-time beacon to the researcher's receiver |

A rescue would have to read the dependency itself (fetch the git ref or tarball as data and
run Stages 1-3 on it), which is a Stage 2/4 capability, not a metadata rule; or name the
shape "a package with no code whose only dependency is non-registry", which no rule does yet.
So the rule stays MEDIUM for new packages and new dependencies, and N1 lowers only what an
earlier release vouches for. **No dependency on agents A or B.**

## 5. Live result (real code)

| | Reported | Benign | Unwanted | Malicious | Unverified | Precision |
|---|---|---|---|---|---|---|
| `round4-base` (round 3's `fix.jsonl`) | 1,787 | 1,486 | 224 | 47 | 30 | 15.42% |
| **N1 + F1 (kept)** | **1,717** | **1,416** | 224 | 47 | 30 | **16.06%** |
| N1 + F1 + R1 (as measured; R1 rejected) | 1,708 | 1,407 | 224 | 47 | 30 | 16.15% |

The full replay was run with all three; the 79 versions it unreports split without overlap
(each changes in exactly one rule): N1 59, F1 11, R1 9, so N1 + F1 alone unreports 70 benign
versions (51 packages) and no version is newly reported. 80 versions differ at all: the 79,
and `@atharva-again/pi-tg@0.1.14` (benign, one of its two non-registry findings LOW, still
reported). No malicious, unwanted or unverified version changes in its decision or in any
finding of the five rules of this cluster. Replay fidelity: the fix run agrees with the
275-version subset runs used while building (0 differences); all 3,716 replayed without an
error.

**On `main` after agent D's Stage 2 commits (`ddb914c`), the branch rebased onto it.** The
275 versions where N1's, F1's or R1's rule fires at MEDIUM or above (the only ones Stage 1 or
4 code of this branch can change) were replayed with `main`'s code and with the rebased
branch: 275 → 205 reported, the same 70 benign versions (51 packages) unreported, the same
`@atharva-again/pi-tg` finding lowered, 0 malicious, unwanted or unverified versions changed
(71 versions differ in all). D's changes and these don't interact: the delta on `main` is the
delta on `round4-base`.

## 6. DataDog check (`vm-day1`)

- **At risk: 222 samples**: N1's rule at MEDIUM on 87, F1's on 131, R1's on 31 (round 3's
  baseline dump, today's code for these rules). All 222 are reported in the baseline.
- **With N1, F1 and R1 (`pipeline+4`, one process per sample, the fix tree): 222 reported, 0
  lost, 0 gained, 0 errors.**
- **N1 changes no sample's finding.** Every `vm-day1` non-registry sample is a new package or
  a source no earlier release used (the `storeartifact`/`jpartifacts` `ui-styles-pkg` probes,
  `@lensapp/eslint-config`, `base_parts_ai`), or pins a commit (`@opensearch-project/opensearch` ×3, `@antv/*` and the
  `atool` packages, 40 `@tanstack/*`), including `@opensearch-project/opensearch@3.8.0`, whose
  previous release 3.7.0 already pinned the same commit (in a misspelt repository).
- **F1 changes none:** every fresh dependency the rule fires on is unscoped.
- **R1 (rejected) lowers the finding on 2 samples, both still reported:** `vant@2.13.3` and
  `vant@3.6.13` (the 2024 `vant` takeover, published with the maintainer's own account, no
  maintainer added, adding `@vant/use` and `@vue/shared`, both watched). They stay reported
  through a HIGH `npm.install-hook` (the payload is a new `postinstall`), and 3.6.13 through
  six more rules. **This is R1's recall cost in plain terms:** a takeover that ships its payload
  in the package's own code and adds only popular dependencies no longer gets the revived
  MEDIUM; its code must be caught by Stages 1-3, as `vant`'s is. `xrpl@2.14.2`, the one sample
  this rule alone reports, keeps MEDIUM (maintainers added). The owner rejected R1 for this
  reason (2026-11-10). Without R1, 218 samples are at risk (N1's and F1's rules), and none
  changes at all.

## 7. Rejected or not proposed

- **`npm.version.suspicious` LOW on a prerelease** (as downgrade v3 and fresh-foreign v3): 3
  benign (`@ohos-ports/pnpm-fs.indexed-pkg-importer@1100.0.37-beta.0`,
  `@ohos-ports/style@1024.22.5-beta.1`, `@spear-ai/trino-pulumi-aws@484.0.0-0.…`), none of the
  131 `vm-day1` samples is a prerelease, but 44 of the 5,921 high-major (≥ 90) versions the
  OSV set lists as malware are (`exodus-checkout@99.0.0-canary.1` and 9 siblings,
  `@webquote-ui/iceberg@395.0.0-beta.1`, `nx-app@9999.0.0-security-test`). Not built.
- **Commit-to-commit bumps in the same repository** (N1 without the fork test for a previous
  commit pin): about 26 more benign (`@diffci.com/diffci` ×21, `trac-peer` ×2,
  `@coda-console/plugin-check`, `@blockrun/*`), but it loses `lane-m-snackager-probe@1.0.1`
  (unwanted: `#a879d11c…` → `#594fbaa1…` in the same repository), and swapping in a fork's
  commit is exactly what a token thief does; `@opensearch-project/opensearch@3.8.0` followed
  3.7.0's commit pin the same way (kept MEDIUM only because 3.7.0's repository name was a
  typo).
- **Trusting any origin the previous release used** (not the same dependency name): loses
  `dependencykfeg@25.1.3` (malicious), which adds `node-acct-utilssss21` from the exact URL
  25.0.3 used for `node-acct-utils`.
- **Own-owner dependencies on new packages, or at any ref (F6a):** the new package's
  `repository` is the attacker's to write; at a commit it is the opensearch attack.
- **Downgrade: `dependency.added` as a co-signal only for a dependency outside the package's
  own scope:** 10 benign (`@leofcoin/*`, `@volter/editor-blender`, `@runko/conformance`, ...),
  keeps `axios@1.14.1` and `@hithink-tech/hithink-finance-cli@0.2.0`, but a stolen token
  publishing a new own-scope payload and adding it is the downgrade's own scenario (round 2's
  ruling on own scopes). **Same publisher as the provenance releases:** 14 benign
  (`@wenathlan/*`, `@volter/*`, `moshcode`), but a CI token stolen and used by hand is the
  rule's case. Downgrade unchanged this round.
- **Revived: own-scope additions** (12 `@teleporthq/*`): rejected in round 2. Observation for
  the owner: their "dormancy" is measured from a 2023 alpha of the same version
  (`0.45.1-alpha.0` → `0.45.1`) while the package published 0.45.0 on 2026-10-29; the diff base
  is Stage 0's and `npm.dormant-revived` is not this cluster's.
- **uWebSockets.js as a vendor origin** (like SheetJS, F6b): 3 benign new packages
  (`@chubbyts/chubbyts-http-uwebsockets`, `@moussejs/core`, `copious-transitions`); an owner
  decision per vendor, not built.
- **`@scope/name@1.0.0` with no `npm:` (fetches nothing):** 1 benign
  (`@ohos-ports/modern-js-node-bundle-require`); the existing test deliberately keeps it firing.

## 8. Owner questions

1. ~~Keep N1, F1 and R1 for the freeze?~~ Decided 2026-11-10: N1 and F1 kept (70 benign, 0
   positives, 0 of 218 `vm-day1` samples changed), R1 rejected (`vant`).
2. N1 trusts a tag or release asset under the previous release's account: an attacker with
   the npm token *and* write access to that repository can push a tag. Acceptable, given that
   its code is then in the repository?
3. After the freeze: uWebSockets.js as a vendor origin (3)? The `@teleporthq/*` diff base?

## 9. How to reproduce

Scripts in `~/kitsunox-scratch/r4/C/scripts/` (round 3's harness plus `replay.py`'s watchlist
change; Python with `-I` under `systemd-run --user --scope`, outputs in `out/`):

- `replay.py SRC CANDS OUT 3 [@KEYS]`: Stages 1-4 per version; `same.py`: the harness check;
  `compare.py BASE FIX`: section 5.
- `joined.py`, `nragg.py`, `revfeat.py`, `dgfeat.py`, `fffeat.py`: section 2 and the
  rejections; `nrsim.py`: iteration only.
- `ddrules.py`: the `vm-day1` samples at risk; `ddmani.py`: their manifests; `dd.py SRC OUT 3
  KEYS`: `pipeline+4` per sample.
