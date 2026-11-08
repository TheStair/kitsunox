# Proposal: precision of the publish-method, revived and non-registry rules

> **Status:** proposal, measured 2026-11-08, nothing built. The owner approved Stage 1
> precision changes when the numbers support them, so changes 1 and 3 are written to be built
> as they stand. Change 2 is a **Stage 4** rule (`npm.combination.revived-with-new-dependency`)
> and needs its own go-ahead ("one stage at a time").
> **Builds on:** the queue review of 2026-11-08 ([devlog](../devlog.md)), decision
> [0007](../decisions/0007-datadog-samples-and-follow-on-releases.md) (eval set),
> [stages/triage.md](../stages/triage.md), [stages/correlate.md](../stages/correlate.md).

## Summary

The queue review found three rules that reported only benign versions when nothing else
fired. Measured on every reported version of the live runs with Stage 4 output (all of them
have a reviewer verdict) and on the `vm-day1` DataDog malicious samples:

| Change | Live reports it carries alone today | After | Malicious lost (eval / live) |
|---|---|---|---|
| 1. `npm.publish-method.downgrade` v4: full weight only with a co-signal | 89 versions (88 benign, 1 inconclusive) | 15 | **0 / 0** |
| 2. `revived-with-new-dependency` v2 (Stage 4): LOW when the same account comes back | 140 versions, all benign | 66 | **0 / 0** |
| 3. `npm.dependency.non-registry` v3: protocols npm can't fetch don't count | 71 versions (67 benign, **4 malicious**) | 65 | **0 / 0** |
| All three | 1,372 reported versions (1,011 packages) | **1,218 (872 packages)** | **0 of 254 / 0 of 41** |

- **Benign reports drop 11.9%** (1,287 → 1,134 benign versions, plus 1 inconclusive), and
  the review queue loses 139 package entries in 5.3 days of collection. Precision of a
  report goes from 3.0% to 3.4%. That is modest: the three rules are a small share of the
  noise. The large sources (Stage 2 regex LOWs, install-hook changes) are out of scope here.
- **No recall cost on what we can measure.** Every change was checked against all 254
  `vm-day1` malicious samples on which one of the three rules fires, with Stages 2 to 4 run on
  them, and against the 41 live versions with a malicious verdict. None is lost.
- **Recall risk we can't measure**, stated per change below. The worst one: a stolen-token
  release of a popular package that changes only code, adds no dependency or hook, and keeps
  `gitHead`, is no longer reported by the downgrade alone (change 1). Such a release must then
  be caught by its content (Stages 2 and 3), as the 2025 `chalk`/`debug` compromises were.
- **Measured and rejected:** collapsing monorepo bursts (bursts are *more* typical of attacks:
  93% of malicious downgrades vs 55% of benign), "provenance comes back later", "the account
  published by hand before", making the revived combination weak-alone, and treating a
  dependency from the package's own GitHub owner as benign (that is exactly how the
  `@opensearch-project/opensearch` and `@antv/*` attacks were built).

## 1. What the rules detect

| Rule | Stage | Today | Fires when |
|---|---|---|---|
| `npm.publish-method.downgrade` v3 | 1 | HIGH/5 watched; MEDIUM/3 unwatched (`WEAK_ALONE`); LOW/1 prerelease | the previous version had trusted publishing or a provenance attestation, this one has neither |
| `npm.combination.revived-with-new-dependency` v1 | 4 | MEDIUM/2, reports alone | `npm.dormant-revived` (≥ 365 days) and `npm.dependency.added` on a release |
| `npm.dependency.non-registry` v2 | 1 | MEDIUM/3, reports alone; LOW/1 for `file:`/`link:` | a new or changed runtime dependency spec that isn't a registry range, tag or alias |

**Why the downgrade matters** ([threat model](../threat-model.md) row 7). A maintainer's
stolen token publishes from the attacker's machine, not from the project's CI, so the release
loses its provenance. In the eval set this covers `axios@1.14.1`, the `@nx/*` and
`@mastra/*` waves and Shai-Hulud-style republishing (`@ctrl/*`, `@squawk/*`). But a
maintainer publishing by hand looks the same, and that is most of what it finds live.

## 2. Data and method

- **Live, Stages 1-4:** the 88 runs with `correlate.jsonl`, 2026-10-28T22:18Z to
  2026-11-03T04:57Z: **495,833 versions**. Each version's report decision was recomputed with
  today's `correlate.decide` from its stored findings, with the downgrade finding recomputed
  from the change (older runs stored v2). Today's rules report **1,372 versions (1,011
  packages)**, and **every one has a verdict** in `data/verdicts/npm.jsonl`: 1,287 benign, 41
  malicious, 44 inconclusive. (The stored decisions report 135 more; those came from older
  rule versions.)
- **Live, Stage 1 only:** the 4-day catch-up and the next run (2026-11-03T05:00Z to
  2026-11-07T22:27Z, 481,045 versions, `triage.jsonl`). Stage 4 was still running on them, so
  they give firing rates only.
- **Malicious:** `vm-day1`'s 3,444 DataDog samples. Stage 1 was run on all of them. For the
  254 where one of the three rules fires, Stages 2 to 4 were also run, with the `pipeline+4`
  predictor's own code (`Correlated`), and Stages 2-3 were forced on so a variant that changes
  Stage 1's routing could be simulated: a version a variant no longer routes loses its Stage
  2-3 findings and its repository comparison. Today's code reports all 254, as the stored
  `vm-day1--pipeline+4` report does.
- **Watched in the eval.** The DataDog set was imported without a watchlist, so **no
  malicious sample is "watched"** in `vm-day1`, and the downgrade is never HIGH there. Every
  variant was therefore checked twice: as evaluated, and with `watched` taken from the
  2026-10-29 watchlist (60 of the 149 malicious downgrades are on it: `axios`, `@nx/*`,
  `@mastra/*`, `@ctrl/*`, ...).
- **Limit of the live simulation:** variants keep Stage 2-3 findings even for a version they
  would no longer route, so live "after" numbers are upper bounds. This cannot hide a live
  malicious loss: none of the 41 has a downgrade or a revived finding, and change 3 doesn't
  touch theirs.

## 3. Change 1: the downgrade needs a co-signal (Stage 1, v4)

### Measurements

| | Benign (live) | Malicious (`vm-day1`) |
|---|---|---|
| Versions it fires on | 787 of 495,833 (0.16%); 646 more in the Stage-1-only runs | 149 of 3,444, all updates (shape A) |
| Severity today | 40 HIGH, 446 MEDIUM, 301 LOW | 149 MEDIUM (nothing watched) |
| Reported | 93 versions; **89 only because of this rule** (40 watched HIGH alone, 27 of them one `@knapsack` 4.110.0 release; 49 unwatched MEDIUM 3 + LOWs reaching 6) | 149 |
| Verdicts of those reported | 92 benign, 1 inconclusive (`@fabricorg/cli@0.7.6`, unpublished by its owner before capture) | — |
| Reported only because of this rule | 89 | **1: `axios@1.14.1`** (MEDIUM 3 + `dependency.added`, `githead-dropped`, `name-embeds-popular` = score 6, exactly the bar) |
| New version has `gitHead` | 295 of 787 (37%) | 0 of 149 |
| In a burst (same publisher, ≥ 5 downgraded versions within 10 min) | 435 of 787 (55%) | 139 of 149 (93%) |
| Has a Stage 1 co-signal (below) | a minority (see the result) | **149 of 149**: 42 add or change an install hook, 107 add a dependency |

All malicious downgrades come with another change to *what gets installed*: a new install
hook (`@nx/*`, `@ctrl/*`, `@squawk/*`, `cline`) or a new dependency (`axios`, `@mastra/*`).
The benign ones mostly don't: a maintainer publishing the same kind of release by hand.

### Proposed rule

`npm.publish-method.downgrade` v4. The condition (previous had trusted publishing or
provenance, new has neither) is unchanged. Severity:

| Case | Watched | Unwatched |
|---|---|---|
| Prerelease (unchanged) | LOW / 1 | LOW / 1 |
| With a co-signal | HIGH / 5 (unchanged) | MEDIUM / 3, `WEAK_ALONE` (unchanged) |
| Watched and `gitHead` dropped (previous had one, this has none) | HIGH / 5 | — |
| Otherwise | **MEDIUM / 3**, `WEAK_ALONE` (was HIGH) | **LOW / 1** (was MEDIUM) |

A **co-signal** is any of these Stage 1 rules firing on the same change: `npm.install-hook`,
`npm.dependency.added`, `npm.dependency.non-registry`, `npm.maintainer.added`,
`npm.publisher.unfamiliar`, `npm.version.suspicious`. The rule evaluates them itself (they
read only the `Change`, so it stays one stage, deterministic, with no new data), and names
them in the explanation. A watched downgrade without a co-signal still scores 3 and is
reported with any LOWs summing to 3 (e.g. `githead-dropped` 2 + one Stage 2 LOW) or any other
MEDIUM. No Stage 4 change is needed: `WEAK_ALONE` already applies to any MEDIUM downgrade.

```python
# ecosystems/npm/rules/metadata.py, after the rule classes, before RULES:
_DOWNGRADE_COSIGNALS: Final = (InstallHook(), NonRegistryDependency(), DependencyAdded(),
                               MaintainerAdded(), UnfamiliarPublisher(), SuspiciousVersion())

# PublishMethodDowngrade (version = 4), after the had/has check:
with_ = [r.id for r in _DOWNGRADE_COSIGNALS if r.evaluate(change, ctx)]
dropped = old.git_head is not None and new.git_head is None
if parsed is not None and parsed.is_prerelease:
    severity, weight = Severity.LOW, 1.0
elif with_ or (_watched(change) and dropped):
    severity, weight = (None, None) if _watched(change) else (Severity.MEDIUM, 3.0)
elif _watched(change):
    severity, weight = Severity.MEDIUM, 3.0
else:
    severity, weight = Severity.LOW, 1.0
# explanation: append f" With: {', '.join(with_)}." or " Nothing else about what gets
# installed changed." so the report shows why the weight was kept or lowered.
```

### Result

| Variant (non-prerelease releases) | Live reported (dg rows) | Benign removed | Eval lost (as evaluated / watched) |
|---|---|---|---|
| V0 today | 93 versions, 90 packages | — | 0 / 0 |
| **V11 proposed** (co-signal; `gitHead` drop also counts when watched) | **19 versions, 18 packages** | 73 benign + 1 inconclusive | **0 / 0** |
| V6 co-signal only | 17 | 75 + 1 | 0 / 0 |
| V8 co-signal for unwatched only (watched stays HIGH) | 57 | 35 + 1 | 0 / 0 |

V11 keeps two more watched versions than V6 (`claude-mem@15.8.2`, `@adea-ai/themes@0.11.6`)
as a hedge: a stolen-token publish of a popular package without its usual `gitHead` is the
one shape the eval says is always present (149/149) and cheap to keep. Stage 1 severity mix
moves from 40/446/301 (HIGH/MEDIUM/LOW) to 2/63/722 in the Stage 4 runs, and from 37/424/185
to 9/83/554 in the Stage-1-only runs, so fewer unwatched versions are routed to Stage 2 by
this rule (routing was simulated for the eval; nothing lost).

**Recall risk (not measurable here):** a stolen-token release with no new dependency, hook,
maintainer or publisher, that keeps `gitHead` (published from a git checkout), is no longer
reported by metadata alone; Stages 2-4 must see its code. In the eval no attack has this
shape, and the code-only compromises in it (`chalk`/`debug`-family, `@duckdb/node-api`) had
no provenance to lose, so this rule never covered them.

### Tests that pin it

In `tests/ecosystems/npm/test_rules_metadata.py`:

- `test_a_downgrade_without_a_cosignal_is_one_step_lower`: CI → manual, nothing else changed:
  watched → MEDIUM 3, unwatched → LOW 1 (the `@knapsack/*` 4.110.0 shape).
- `test_a_downgrade_with_a_cosignal_keeps_its_weight`, parametrized over a dependency added
  (`axios@1.14.1`: `plain-crypto-js`), an install hook added (`@nx/*`), a non-registry
  dependency, a maintainer added, an unfamiliar publisher, a suspicious version: watched HIGH
  5, unwatched MEDIUM 3, and the explanation names the co-signal.
- `test_a_watched_downgrade_that_drops_git_head_stays_high` (and the same change unwatched is
  LOW 1).
- Update `test_a_downgrade_is_high_only_for_a_watched_package` to include a co-signal; keep
  `test_a_downgrade_on_a_prerelease_is_low`.

In `tests/stages/test_correlate.py`: `test_a_watched_downgrade_without_a_cosignal_alone_is_not_reported`
(MEDIUM downgrade alone is weak), and `test_the_axios_shape_is_still_reported`: MEDIUM 3
downgrade + `dependency.added` 1 + `githead-dropped` 2 + `name-embeds-popular` 1 → reported.

## 4. Change 2: revived with the same account is LOW (Stage 4, v2)

**Measured.** Live: fires on 143 versions (124 packages), all reported, 140 only because of
it, **all benign** (`@genpact/*` 14, `@teleporthq/*` 9, ...). Eval: fires on 36 malicious
samples; only **`xrpl@2.14.2`** depends on it (its other signals are LOW). The rest have
install hooks or `npm.dependency.fresh-foreign` (`@mastra/*` adding `easy-day-js`).

**Proposed.** If the release's publisher is the previous release's publisher and no
maintainer was added, the finding is LOW / 1 (still adds to the score); otherwise MEDIUM / 2
as today. Takeovers of dormant packages in the eval come from a different account
(`xrpl`: `mukulljangid` after `ckniffen`; `@mastra/*`: `ehindero` after the original authors).

| Variant | Live reported | Eval lost |
|---|---|---|
| R0 today | 143 versions (124 packages) | 0 |
| **R2 proposed** | **69 (62 packages)** | **0** |
| R1 weak-alone | 6 | 1: `xrpl@2.14.2` |
| R3 only gaps ≥ 2 years | 75 | 1: `xrpl@2.14.2` |
| R4 LOW when every added dependency is own-scope or watched | 24 | 1: `xrpl@2.14.2` (adds `@scure/*`, `@xrplf/*`) |

**Recall risk:** a dormant account taken over *as itself* (an expired e-mail domain, a reused
password) keeps its name. `leo-logger@1.0.8` in the eval is that shape and is still reported
by its install-script findings, not by this rule.

**Tests** (`tests/ecosystems/npm/test_rules_correlate.py`): same publisher and maintainers →
LOW 1; different publisher (the `xrpl` shape) → MEDIUM 2; same publisher with a maintainer
added → MEDIUM 2; the canary and `@types/*` exemptions unchanged.

## 5. Change 3: only protocols npm fetches count (Stage 1, v3)

**Measured.** Live: fires on 128 versions; 77 reported, 71 only because of it, **including 4
malicious** (`dependencykfeg@25.0.3`, `@25.1.3`, `claims-acct-unlock@25.2.1`, `claims-ac1@1.0.0`:
tarballs on `github.com/GamerD11/ping_test`). So this rule earns its MEDIUM and must stay.
Six benign reports are `@ai-crew-suite/*` 0.0.1 with Backstage's `backstage:^` protocol, which
npm can't resolve ("Unsupported URL Type"): it fetches nothing, like the `workspace:` and
`catalog:` specs v1 already exempts.

**Proposed.** A spec with an explicit protocol that npm doesn't fetch from (anything but
`git:`, `git+ssh:`, `git+http(s):`, `git+file:`, `http(s):`, `github:`, `gitlab:`,
`bitbucket:`, `gist:`, `file:`, `link:`) is not a finding. Specs without a protocol keep
today's treatment (`user/repo` shorthand still fires).

| Variant | Live reported | Eval lost |
|---|---|---|
| N0 today | 77 (70 benign, 7 malicious) | 0 |
| **N1 proposed** | **71 (64 benign, 7 malicious)** | **0** |
| N2 = N1 + LOW for a dependency on the package's own GitHub owner | 45 | **2: `@opensearch-project/opensearch@3.7.0`, `@3.8.0`** |

N2 is rejected: those attacks pointed a dependency at a commit in the project's *own*
repository (`github:opensearch-project/opensearch-js#<sha>`; `@antv/*` did the same with
`github:antvis/G2#<sha>`, caught there by install hooks). "Own owner" is the attack, not a
sign of innocence. Allow-listing `cdn.sheetjs.com` or `pkg.pr.new` was not tried: host
allow-lists age badly and `pkg.pr.new` builds from any repository.

**Tests** (`test_non_registry_dependency`): add `("backstage:^", False)`,
`("portal:../x", False)`, `("gist:abc", True)`, `("bitbucket:x/y", True)`,
`("git+ssh://git@github.com/x/y.git", True)`; and
`test_a_dependency_on_the_packages_own_repository_commit_still_fires` pinning N2's rejection.

## 6. Combined effect

| | Today | All three |
|---|---|---|
| Live reported versions (Oct 28 22:18Z – Nov 3 04:57Z) | 1,372 | 1,218 |
| ...packages (queue entries) | 1,011 | 872 |
| ...benign / malicious / inconclusive | 1,287 / 41 / 44 | 1,134 / 41 / 43 |
| `vm-day1` malicious recall (all cells) | 2,505 / 3,444 | 2,505 / 3,444 (the 3,190 untouched samples don't fire any of the three rules) |
| `vm-day1` benign reported (recomputed) | 14 / 1,500 | 14 / 1,500 |

After building: re-run `kitsunox eval run vm-day1 --predictor pipeline+4` on a copy of
`data/` (it writes under `data/eval/`) and expect identical malicious cells.

## 7. Measured and rejected

- **Bursts as one signal / lower weight** (V5): live 93 → 57, no eval loss today, but 139 of
  149 malicious downgrades are bursts (worms and stolen tokens republish whole scopes) against
  55% of benign. A burst should become **one review item**, not a weaker one: a queue
  grouping change (report stage), suggested in open questions.
- **`gitHead` present → LOW** (V1): 93 → 76, no eval loss; superseded by V11, and anyone
  publishing from a clone keeps `gitHead`.
- **Unwatched downgrade → LOW unconditionally** (V3): loses `axios@1.14.1` as evaluated.
- **Watched → MEDIUM unconditionally** (V4): 93 → 53; V11 removes more and keeps a hedge.
- **The account published by hand before**: measured 2026-10-30 (devlog), loses 7 of 149
  (`axios@1.14.1` and five `@nx/*`). Not re-run: Stage 1 sees only the previous version.
- **Provenance returns on a later release**: not measurable (one packument per run), and wrong
  in principle: after a stolen-token release the project's CI publishes the next one with
  provenance, which says nothing about the bad one.
- **No downgrade rule at all** (V9): live 93 → 4, loses `axios@1.14.1`. The rule's unique
  eval recall is that one sample, at exactly the score bar.

## 8. Open questions for the owner

1. **Change 1 hedge:** V11 (19 reports, keeps watched `gitHead` drops) or V6 (17)? I'd take
   V11.
2. **Change 2 is Stage 4.** Approve it separately? Its unmeasured risk is a dormant account
   hijacked as itself.
3. **Queue grouping:** collapse versions with the same publisher and rule set within an hour
   into one queue entry (27 `@knapsack/*` → 1), instead of any weight change? Report stage;
   no recall cost.
4. **Eval popularity:** re-import the DataDog set with a watchlist so the watched branch is
   tested by the eval itself (today nothing malicious is watched there).
5. `axios@1.14.1` is reported at score exactly 6. Any later change to LOW weights or
   `LOW_CAP` should be checked against it.

## Reproducing

Scripts are outside the repository, in `~/kitsunox-scratch/agent-stage1/scripts/`, run from a
worktree with `PYTHONPATH=src .venv/bin/python -P -s <script>`, under a 4 GB memory cap.
They read `data/` only; the eval run used a hard-linked copy of `data/eval`, `data/labels`
and `data/watchlists` (every store writes by atomic rename, so the originals can't change).

- `extract_live.py`: one compact row per version of interest from each run's
  `correlate.jsonl` (else `triage.jsonl`).
- `mal_stage1.py`: Stage 1 on all 3,444 malicious samples. `mal_full.py`: Stages 1-4 on the
  254 where a studied rule fires (`Correlated` with Stages 2-3 forced on; ~30 min).
- `dg_variants.py`, `rv_nr_variants.py`: the variant tables. `combined.py`: section 6.
  `sim.py`: shared helpers (recomputes the decision with `correlate.decide`).
