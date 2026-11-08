# 0008: What Stage 2 reads (hybrid routing) and tarball capture

**Date:** 2026-10-27
**Status:** Accepted (the user chose the hybrid option; the routing details below come from
measurement)
**Revises:** Stage 1's forward policy (roadmap decision 3) and the tarball consequence of
[0006](0006-scheduled-collection-and-retention.md).

## Context

On `day1`, Stage 2's rules alone catch 71.5% of malicious updates (shape A) and 49.9% of
malicious first releases (shape B), at 1.0% benign pass-through. Combined with Stage 1 they
would reach 91.4% / 66.1%, **but only if Stage 2 reads every release**. Behind the old Stage 1
gate (rules or watched), almost all of what only Stage 2 catches is dropped first: it is
unwatched and has no metadata signal. Reading every release costs about 114k tarballs a day,
with a heavy tail (median 62 KB, mean 2.1 MB).

The user was offered three options: keep the gate; read everything; or a hybrid (all new
packages, plus updates by some cheap criterion). They chose the hybrid.

## Measurements behind the details

Simulated from the saved per-sample results of `stage1`, `stage1-rules` and `stage2-rules`,
plus the declared `dist.unpackedSize` of each release (volume from `day1`'s three live runs):

- **"Small updates" was the wrong criterion.** Routing updates under a size limit added nothing
  below 5 MB. Malicious updates are large, because the payload is added to the package.
- **Size growth is a strong routing signal.** Updates whose declared unpacked size grew by at
  least 64 KiB: 71% of malicious first-release updates vs 8.3% of benign ones.
- **A 16 MB per-version download cap** (declared size) cuts volume about 10x for 0.3 points of
  update recall. Versions over 16 MB are 9% of releases and 86% of unpacked bytes, mostly
  platform binaries that the rules skip anyway.
- **Watched packages add little measured recall** (DataDog is mostly unpopular packages), but
  popular-package takeovers are the highest-impact attacks, so they stay routed.

| Routing (with 16 MB cap) | Recall A | Recall B | Benign flagged | Versions/day | Unpacked GB/day |
|---|---|---|---|---|---|
| Old gate (rules or watched) | 83.5% | 58.2% | 1.0% | ~15k | ~500 (no cap) |
| **Hybrid: + new packages + grew ≥ 64 KiB** | **86.0%** | **66.0%** | **0.9%** | ~24k | ~82 |
| Everything (no cap) | 91.4% | 66.1% | 1.5% | ~114k | ~2,100 |

## Decision

- **Stage 1 forwards** for one of four recorded reasons: `rules: ...` (flagged), `watched
  package`, `new package`, `unpacked size grew by N bytes` (or `unpacked size unknown`).
- **Stage 2 skips versions that declare more than 16 MB unpacked** and records why
  (`files unavailable: declared unpacked size ...`).
- **`collect` runs Stage 1 and Stage 2 every tick**, so tarballs are fetched within about an
  hour of publication, before npm deletes malicious ones.
- **Tarballs follow 0006's retention**: 7 days, then kept only for packages named in an OSV
  record. The immutable index (cross-run fetch cache) no longer keeps blobs alive on its own.

## Consequences

- About 14 GB of tarballs a day (one hourly run measured: 794 MB in 2 min 20 s), so about
  100 GB at steady state with 7-day retention.
- **`dist.unpackedSize` is publisher-declared.** An attacker can understate growth to avoid the
  growth route, or overstate size to dodge the cap. Understating to under 16 MB just means we
  download it (extraction limits still apply). Comparing the declared size with the real one
  after download is a candidate Stage 1/2 rule.
- Large malicious updates (over 16 MB) are only seen by Stage 1.
- Stage 1's `stage1` pass-through now measures what Stage 2 fetches (25.8% weighted), not what
  is flagged. What is flagged is `stage1-rules`, and end to end, `pipeline`.

## Addendum (2026-11-08): a 32 MB cap for versions with an install hook

Live recall against OSV records was 25.4%, and 48 of the 100 misses were updates Stage 2 had
no files for (35 not routed, 12 over the cap, 1 fetch error). Replaying the 24 still on the
registry through Stages 2–3 with no cap reported **none**: routing was not the binding
constraint, the rules were. So the routing criteria stay as decided above; no routing rule
measured (small updates, any growth, fast re-publish, file-count change, publisher change)
catches anything today's rules flag on DataDog first releases or live.

The cap changes for one class: a version that **declares an install hook** is read up to
**32 MB** declared (`MAX_HOOK_ARTIFACT_BYTES`, `fetch_limit` in `stages/static.py`; the
evaluation's routing uses the same function). Code that runs on `npm install` is where
compromises put their payload, and on `vm-day1` 97 of 481 malicious shape-A follow-ons were
over 16 MB, all hooked: 44 are at most 32 MB and Stage 2 flags them when read (+9.1 points of
follow-on recall; +1 first release, +2 B follow-ons). Cost on 2026-11-02: 339 versions a day,
2.5–4.8 GB of tarballs (+14–27% of 17.7 GB), and about 6 benign reports a day (2 of 111
sampled). A flat 32 MB cap would cost ~14 GB a day more for the same follow-ons.

Measurements, options and the owner's open questions:
[stage2-routing-recall](../proposals/stage2-routing-recall.md).
