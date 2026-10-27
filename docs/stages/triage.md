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
uv run kitsunox eval run <dataset> --predictor stage1         # rules + watched packages
```

## Contract

- **Input:** `Change`. **Output:** `Candidate` (findings + a `StageDecision`).
- **Rules** implement `core.rules.Rule`: `evaluate(change, ctx) -> findings`. `RuleContext`
  carries `as_of` and nothing else; rules never read the clock, network or environment. Each
  finding records the rule id and version.
- **Forward policy:** forward if any finding is MEDIUM or above, or the package is watched.
  LOW findings are kept for scoring (Stage 4) but don't forward on their own.
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
| `npm.install-hook`: `preinstall`/`install`/`postinstall` added or changed (new package: present) | HIGH (new pkg: MEDIUM) | 0.04% A, 1.03% B | 64.2% | 56.0% | 494 / 404 |
| `npm.publish-method.downgrade`: previous release had trusted publishing or provenance, this one has neither | HIGH | 0.18% | 15.4% | n/a | 107 / n/a |
| `npm.dependency.non-registry`: new dependency from git/URL/GitHub shorthand/`file:` | MEDIUM | 0.05% A, 0.30% B | 7.3% | 1.8% | 44 / 12 |
| `npm.version.suspicious`: major ≥ 90, CalVer exempt (v2) | MEDIUM | 0.01% A, 0.21% B | 0% | 12.2% | 0 / 6 |
| `npm.publisher.unfamiliar`: publisher not a previous maintainer (v2: LOW) | LOW | 2.57% | 7.5% | n/a | 10 / n/a |
| `npm.dependency.added` | LOW | | | | |
| `npm.maintainer.added` | LOW | | | | |
| `npm.dormant-revived`: more than 365 days since the previous release | LOW | | | | |

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
