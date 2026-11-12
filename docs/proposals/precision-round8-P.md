# Precision round 8, agent P

Base: main `d3ce1f1`. Replay set: the 3,716 verdicted live versions
(`~/kitsunox-scratch/r7/shared/integ.jsonl` = main), Stages 1-4 replayed per version with the
real code (`replay.py`), counted with today's verdicts (`relabel.py`). `vm-day1`: `pipeline+4`
per malicious sample (`dd.py`, repository comparison off), main and fix.

| # | Target | Commit | Benign removed | Positives lost | Unverified lost | `vm-day1` lost |
|---|---|---|---|---|---|---|
| P3 | `npm.version.suspicious` v5: another declared package at the same major | (see git log) | 1 (replay set); 12 on live runs | 0 | 0 | 0 of 131 the rule fires on |

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
