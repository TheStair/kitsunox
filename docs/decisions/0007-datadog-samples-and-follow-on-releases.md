# 0007: DataDog malware samples for recall, with follow-on releases split out

**Date:** 2026-10-27
**Status:** Accepted
**Revises:** the Phase 3 "light" scope (no malware downloads). The user approved downloads
provided samples are only ever executed in the sandbox.

## Context

Prospective labeling gave 0 malicious samples on day one, and Stage 1 needed recall numbers. The
DataDog malicious-software-packages dataset (Apache-2.0) holds 1,448 npm `compromised_lib`
samples (shape A) and 25,267 `malicious_intent` samples (shape B), each a ZipCrypto zip. The zip
contains the package files and `package_info-*.json`: the registry packument as captured, which
includes `_npmUser`, maintainers, `dist`, the `time` map and earlier versions.

## Decision

- Import **all shape-A samples, plus a deterministic 2,000 shape-B samples** (ordered by a hash
  of the path), pinned to one dataset commit (`e51c2b57744d`).
- Keep the zips encrypted, as distributed, in a separate blob store (`data/eval/malware/`).
  Decrypt only the `package_info` member, in memory, through `extract_zip` (which gained
  `password` and `include`). Package code is never extracted or executed.
- Build each sample's `Change` with the same `Packument` parser Stage 0 uses, so Stage 1 rules
  see exactly what they would see live.
- **Follow-on releases are reported separately.** DataDog's `manifest.json` lists malicious
  versions per package. When a sample's previous version is also listed (481 of 1,446 shape-A
  samples, 1,093 of 1,998 shape-B), it is tagged `follow-on`. Diffing against a malicious base
  hides the attack, and live operation would already have flagged the first release.
- DataDog numbers are always reported in their own cells (`malicious/<shape>/datadog`) and never
  pooled with prospective samples.

## Consequences

- Stage 1 gets real recall numbers: on first releases, 80.1% for A and 58.2% for B, at 0.6%
  benign pass-through.
- **Selection bias:** most samples come from GuardDog, whose heuristics overlap with Stage 1's
  rules. Prospective samples will be the check against this.
- 5.1 GB of encrypted samples on disk. They are outside the retention GC (separate store), and
  reproducible from the recorded snapshot.
- Not imported yet: the other ~23k shape-B samples. Code-level stages will also want the package
  files, which are already on disk, still encrypted.

## Addendum 2026-11-11: follow-ons are reported in operation (round 6 U)

Stage 4 now has a follow-on pass (`correlate.follow-on`, MEDIUM, weight 3; `STAGE_VERSION`
18; [round 6 U](../proposals/precision-round6-U.md)). A release whose previous release was
reported with payload evidence, and which still holds the same bytes at the same path (or the
same manifest fields), gets the finding, naming the earlier release; chains carry it on. The
previous release is looked up in the same run and, within 7 days, in earlier runs'
`follow-on.jsonl` (each run pins the entries it used in its `follow-on-history.jsonl`, so a
re-score reads exactly those; an unreadable earlier index is skipped). Deterministic from the
run's inputs: never the clock or a verdict. Payload evidence: always-new rules (known
signatures, channel follow/tagging; part A, zero-cost), a hard-coded destination in a file that
also reads secrets or runs at install (B1), install persistence (B2). The owner took A, B1, B2
and C (2026-11-11) and kept the finding on already-reported follow-ons. Measured live: +3
malicious (`pdf-html5-page-flip@2.0.2`, `template-cards@16.1.2`, `template-pictogram@9.1.3`),
+59 unwanted, +7 benign, +2 unverified over the follow-ons of reported releases (most never
reviewed, labels inherited through the byte-identical evidence); `vm-day1`: +12 malicious
follow-ons with B1; nothing lost. Not carried (measured, about one benign per positive or
worse): install hooks, non-registry dependencies, generic content rules. `esoftplay@0.0.269-
beta96052d3` is not rescued: its earlier betas were reported for another file. The
`vm-day1` follow-on cells still use `pipeline+4` per sample; a follow-on-aware predictor is a
post-freeze question.

