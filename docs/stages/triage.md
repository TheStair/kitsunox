# Stage 1: Metadata triage

> **Status:** implemented 2026-10-27 (`stages/triage.py`, `ecosystems/npm/rules/metadata.py`).
> Evaluated on real benign traffic and DataDog malware samples; numbers below.

## Purpose

Look at every change from Stage 0 using only metadata (the manifests and publish info of the new
and previous versions) and decide which changes go on to the tarball stages. It costs nothing
beyond Stage 0's fetches: a full day (109,497 changes) triages in 44 s.

## Usage

```sh
uv run kitsunox triage <run_id>                          # writes runs/<run_id>/triage.jsonl
uv run kitsunox eval run <dataset> --predictor stage1-rules   # rules only
uv run kitsunox eval run <dataset> --predictor stage1         # full forward policy (what reaches Stage 2)
```

## Contract

- **Input:** `Change`. **Output:** `Candidate` (findings + a `StageDecision`).
- **Rules** implement `core.rules.Rule`: `evaluate(change, ctx) -> findings`. `RuleContext`
  carries `as_of` and nothing else; rules never read the clock, network or environment. Each
  finding records the rule id and version.
- **Forward policy** (the reason is recorded, first match wins):
  1. `rules: ...`: any finding is MEDIUM or above. The change is *flagged*: Stage 1 alone would
     report it.
  2. `watched package`.
  3. `new package`: no previous version.
  4. `install hook` (2026-10-30): the release has a `preinstall`, `install` or `postinstall`,
     so Stage 3 can compare the files the hook runs with the previous version's
     (`npm.install-script-changed`). A hook's command can stay word for word the same while the
     file it runs changes. First VM day: 2,251 of 101,232 updates (2.2%) had a hook, 1,440 of
     them not forwarded before.
  5. `unpacked size grew by N bytes`: declared `dist.unpackedSize` grew by at least 64 KiB
     (`MIN_GROWTH_BYTES`), or `unpacked size unknown` (6 of 110k updates).

  Reasons 3 and 5 were added on 2026-10-27 (the "hybrid" policy): they don't flag anything,
  they send code that has no metadata signal to Stage 2. LOW findings are kept for scoring
  (Stage 4) but don't forward on their own. See [static.md](static.md#routing-what-stage-2-reads)
  for the numbers behind the routing.
- **Handoff to Stage 2: `PackageBatch`** (`runs/<id>/batches.jsonl`). There is one batch per
  package per run. It holds every version of that package in the run, oldest first, plus the
  base (the earliest version's previous version). Unflagged sibling versions are included too.

## Bursty packages and the Stage 2 contract

Some packages publish dozens of versions a day (`@bike4mind/cli`: 233 on 2026-10-27).
Analysing only the newest version would let an attacker publish a malicious version and revert
it within the burst: a newest-vs-base diff shows nothing, but anyone who installed in between
got the payload. So the contract for Stage 2 is:

1. Analyse every **distinct file content** that appears in any version of the batch but not in
   the base, **once**, and attribute each finding to the first version that contained it.
2. Cache analysis results by **(content SHA-256, rule versions)** across runs. Analysis is a
   pure function of the content, so the cache is deterministic, and a file seen in any earlier
   version costs nothing.

Measured on the first 24h run:

| Unit of Stage 2 work | Count/day |
|---|---|
| Forwarded versions | 15,043 |
| Package batches if batched daily | 5,634 |
| Package batches at the hourly collection cadence (simulated by publish hour) | ~11,800 (median 1 version, p99 5, max 23) |

Hourly batching alone saves only about 20%, because bursts spread across hours. The real saving
is expected from the content cache (2.), which makes cost track the new code being published
rather than the number of versions. It can only be measured once Stage 2 downloads tarballs.

## Rules

Rates are from 2026-10-27. Benign is all 109,873 non-placeholder changes from the first runs.
Malicious is the 1,870 DataDog *first* malicious releases (see below).

| Rule | Sev. | Fires on benign | Recall, shape A | Recall, shape B | Caught by this rule only (A / B) |
|---|---|---|---|---|---|
| `npm.install-hook` (v2): `preinstall`/`install`/`postinstall` added or changed (new package: present). A command that changed only its own version string (`@pulumi/*`: `... resource command 1.3.0`; 39 of 52 changed commands on the first VM day) isn't changed: Stage 3 diffs what it runs | HIGH (new pkg: MEDIUM) | 0.04% A, 1.03% B | 64.2% | 56.0% | 494 / 404 |
| `npm.publish-method.downgrade` (v4): previous release had trusted publishing or provenance, this one has neither. With a co-signal (another Stage 1 rule below fires: install hook, non-registry or added dependency, maintainer added, unfamiliar publisher, suspicious version), or a watched package that also dropped `gitHead`: HIGH when watched, MEDIUM weight 3 otherwise. Without: one step lower, MEDIUM weight 3 when watched, LOW weight 1 otherwise. A MEDIUM downgrade reports only beside other signals (`correlate.WEAK_ALONE`). LOW, weight 1, on a prerelease, which npm installs only when asked for (v3) | HIGH / MEDIUM / LOW | 0.18% | 15.4% | n/a | 107 / n/a |
| `npm.dependency.non-registry` (v4): new dependency from git/URL/GitHub shorthand/`file:`; not for a protocol npm can't fetch (v3); LOW, weight 1, for a local path and for SheetJS's own CDN, `https://cdn.sheetjs.com/` (v4) | MEDIUM | 0.05% A, 0.30% B | 7.3% | 1.8% | 44 / 12 |
| `npm.version.suspicious` (v4): major ≥ 90, CalVer exempt (v2), a major that is a date (`YYYYMM`, `YYYYMMDD`) exempt (v3), a year major with a 0 or month-day minor and a `YYMM` major exempt (v4) | MEDIUM | 0.01% A, 0.21% B | 0% | 12.2% | 0 / 6 |
| `npm.publisher.unfamiliar`: publisher not a previous maintainer (v2: LOW) | LOW | 2.57% | 7.5% | n/a | 10 / n/a |
| `npm.dependency.added` | LOW | | | | |
| `npm.maintainer.added` | LOW | | | | |
| `npm.dormant-revived`: more than 365 days since the previous release | LOW | | | | |

`npm.dependency.non-registry` v2 (2026-10-30): the registry's own tarball URL for the same
package (`https://registry.npmjs.org/<name>/-/<file>.tgz`) is the registry, and a local path
(`file:`, `link:`) is LOW, weight 1, since it fetches nothing. Its `vm-day1` malicious samples
all used `github:` (71) or `http(s):` (17) URLs; on the live queue the two cases were 22
reports (`@feedmepos/mf-connect` pins registry tarballs; `@atairo/qixi` shipped
`file:../../frontend/...`). pnpm's `catalog:` left unrewritten is a registry spec, like
`workspace:`: it fails to install and fetches nothing (`postflareai`).

`npm.publish-method.downgrade` v4 and `npm.dependency.non-registry` v3 (2026-11-08,
[proposal](../proposals/stage1-precision.md)). Measured on the 87 live runs with Stage 4
output (2026-10-28T22:18Z to 2026-11-03T04:57Z, 473,108 distinct versions; every reported
version has a verdict) and on `vm-day1`:

- **Downgrade.** It fired on 787 live versions and was the only reason for reporting 89 (88
  benign, 1 inconclusive; 27 were one `@knapsack/*` release, a maintainer publishing by hand).
  All 149 malicious `vm-day1` samples it fires on have a co-signal (42 an install hook added or
  changed, 107 a new dependency) and none has `gitHead`. Requiring a co-signal leaves 15 of the
  89; no malicious sample, live or `vm-day1`, is lost. The rule's only unique catch in the eval,
  `axios@1.14.1`, keeps MEDIUM through its new dependency. The rule now evaluates its co-signal
  rules itself (`DOWNGRADE_COSIGNALS`) and names them in the explanation. **Known gap:** a
  stolen token used for a code-only release that keeps `gitHead` is no longer reported by the
  downgrade alone; Stages 2-3 must see its code.
- **Non-registry.** A protocol npm can't fetch (anything but `git`, `git+ssh`, `git+http(s)`,
  `git+file`, `ssh`, `http(s)`, `github`, `gitlab`, `bitbucket`, `gist`, `file`, `link`) fails
  the install and downloads nothing, like `workspace:`: Backstage's `backstage:^` was 6 benign
  reports (`@ai-crew-suite/*`). The rule still carries 4 live malicious versions alone
  (`dependencykfeg`, `claims-acct-unlock`, `claims-ac1`), so it stays MEDIUM. A dependency on the
  package's own repository still fires: the `@opensearch-project/opensearch` and `@antv/*`
  attacks pulled their payload from a commit there.

`npm.version.suspicious` v3 (2026-11-08): a major that is itself a date, `YYYYMM` or
`YYYYMMDD` with a real month and day and a year from 1990 to the year after `as_of`
(`202610.31.30847`, `20261028.0.0`), is not a dependency-confusion number. In the 4-day run
`20261107T163310Z-npm`, 314 of 1,438 reported versions were `@haybarn/*` new packages
(`query-farm`) with such versions, reported by this rule alone; with v3 that run reports 316
fewer (2 more: `@tmlmobilidade/go-utils-offer`, an `@ohos-ports` prerelease), and the 87 runs
above 4 fewer (all benign verdicts: `@nstarkman/figpress*`, `@leadfund/lead-mcp`, `coolbot`).
No DataDog sample and none of the 53,389 versions the OSV set (`20261108T151126Z`) lists
explicitly as malware has a calendar-shaped major; its 6- and 8-digit majors are `999999`,
`99999999`, `200000`, `100000` and `999991`, none a date.

`npm.version.suspicious` v4 and `npm.dependency.non-registry` v4 (2026-11-08,
[proposal round 2](../proposals/precision-round2.md), F5 and F6b), measured with the
implemented rules on the reviewed live reports (every latest verdict with rank > 0, re-decided
with the other stored findings, as in round 1):

- **Calendar versions** (`calendar_version`): a year-like major (1990 to the year after
  `as_of`) whose minor is a real month-day `MDD`/`MMDD` (`2026.706.0`, `2026.1107.0`) or is 0
  in `as_of`'s own year (`2026.0.1` in 2026), and a `YYMM` major (`2611.5.1`: 20 ≤ YY ≤ the
  next year's, a real month). **Narrower than the proposal**, which exempted a minor of 0 in
  any year: checked against the OSV set (`20261108T151126Z`, 53,389 malware versions), that
  shape exempts 15 of them, dependency-confusion probes such as `2000.0.0`, `2000.0.1`,
  `1999.0.1`, `2001.0.0` and `amazonui@2026.0.1` (published 2025). As implemented, with each
  record's publication year as `as_of`, it exempts none; the month-day and `YYMM` shapes
  exempt none either. The narrowing keeps 3 of the 4 live benign `YYYY.0` reports exempt
  (`spain-holidays@2027.0.0`, published in 2026, stays reported). The remaining reports are
  researchers' `99.x` placeholders. A `YYMM` major is at most 2712 today, far below the `9999`
  and up that confusion attacks use. Live: 46 fewer reports among the proposal's 3,032
  reported versions (47 simulated, less `spain-holidays`), all benign, one package each
  (`@4fu/arbor-*`, `@burdenoff/*`, `@runstructure/*`, `@beehexa/*`); 68 among all 3,211 with a
  verdict on 2026-11-08, all benign. `vm-day1`: the 6 malicious samples at risk (reported
  only if this rule is MEDIUM) are all still reported by `pipeline+4`.
- **SheetJS's CDN.** SheetJS left the npm registry and publishes `xlsx` only on
  `https://cdn.sheetjs.com/` (`xlsx-0.20.3/xlsx-0.20.3.tgz`). A spec under that exact origin is
  LOW, weight 1 (`VENDOR_REGISTRIES`, one literal; `https://cdn.sheetjs.com.evil.example/` is
  not it). 50 fewer reports on the 3,032 (11 packages), 53 on the 3,211 (13), all benign; the
  15 `vm-day1` malicious samples at risk through this rule are all still reported. Other hosts
  (`pkg.pr.new` previews, vendors' own CDNs) are each an owner decision; a dependency on the
  package's own GitHub repository still fires (F6a, rejected again: it loses
  `@opensearch-project/opensearch` 3.7.0 and 3.8.0).

`npm.publisher.unfamiliar` started at MEDIUM. It caused about 90% of Stage 1's benign
forwarding (team members often publish without being listed as maintainers) but caught only 10
samples on its own, so v2 makes it LOW.

## Evaluation

Dataset `day1`: 1,500 benign samples, re-weighted to the population, plus 3,444 DataDog samples.

| Predictor | Recall A (first release) | Recall B (first release) | Benign pass-through (weighted) |
|---|---|---|---|
| `popularity-only` | 21.8% | 0.0% | 13.9% |
| `stage1-rules` | **80.1%** | **58.2%** | **0.6%** |
| `stage1` (rules + watched) | 85.6% | 58.2% | 14.5% |

**Follow-on releases** are reported separately: a release whose previous version is *also*
malicious (worms such as Shai-Hulud publish several in a row; any later version of a malicious
package). Change-based rules can't see these, because the diff base already contains the attack.
`stage1-rules` catches 2.7% (A) and 21.7% (B) of them. In live operation the first malicious
release is the one that matters. Per compromised package, 767 of 1,002 had at least one flagged
version.

## Known limits

- **Payloads in normal code are invisible here.** 42% of first-release shape-B samples have no
  install hook and no other metadata signal: the malware runs when the package is imported.
  Stage 2 (static analysis of changed files) has to catch these.
- **Benign labels are provisional** until 30 days after the runs (the first runs are from
  2026-10-27).
- **DataDog bias:** samples come mostly from GuardDog detections, which look for exactly the
  kinds of signal these rules use (install hooks especially). Recall on attacks GuardDog misses
  may be lower. Prospective samples from our own collection will show this.
- **Popularity of DataDog samples** is taken from the watchlist at import time, not at attack
  time.
- Runs recorded with tool 0.1.0 may use a staged-publishing stub as the previous version.
  Evaluation corrects this (`rebase_stub_previous`); `kitsunox triage` on such a run does not.

## Tests

`tests/ecosystems/npm/test_rules_metadata.py` (every rule, hostile manifest types, forward
policy), `tests/test_cli.py::test_triage_writes_candidates`.
