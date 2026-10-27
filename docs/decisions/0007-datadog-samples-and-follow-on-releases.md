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
