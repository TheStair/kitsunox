# 0021: Partial reads of large packages with an install hook

**Date:** 2026-11-13
**Status:** Proposed (round 11, agent O). Built on a branch and measured in
[the proposal](../proposals/partial-reads-round11-O.md). It merges only once the owner
approves.
**Builds on:** [0008](0008-stage2-routing-and-tarball-capture.md) (Stage 2's download caps:
16 MB declared unpacked, 32 MB with an install hook), [0006](0006-scheduled-collection-and-retention.md)
(snapshots, blob retention, the hold), [0009](0009-network-failure-handling.md) (network
failures are retried, never taken for "missing").
**Stage:** 2 ([stages/static.md](../stages/static.md), "Partial reads"); Stages 3 and 4 read
the result through the same `ArtifactFiles`.

## Context

`ArtifactFiles` does not download a version whose declared unpacked size is over
`fetch_limit` (16 MB, 32 MB with an install hook). Stages 2-4 then have no files for it, and
only Stage 1's metadata findings are left. That is a known recall gap:

- Three of the label-blind sample's misses that main still misses are hooked versions over
  32 MB: `@plannotator/opencode@0.28.45` (63.9 MB), `@cgh567/agent@2.6.60` (44.7 MB; its hook
  downloads Homebrew openssl bottles) and `local-operator-ui@0.52.8` (38.9 MB), all unwanted.
- On the two days of runs on disk (2026-11-11..13, 47 runs) Stage 2 skipped **1,437
  hook-bearing versions** for size (311 packages, 183 GB declared unpacked); 3 of them were
  over 512 MB. `@dcl-regenesislabs/bevy-explorer-web` alone was 248 of them (67 GB).

The size is almost always platform binaries, WebAssembly, media or bundled assets. The code
that runs at install (`package.json`, the hook's script, `binding.gyp`) is small. Reading the
whole tarball into memory and into the blob store, as for a normal read, would cost ~90 GB a
day of downloads and, worse, the same in tarball blobs (two days of retention: ~180 GB on a
393 GB disk that crashes when full).

## Options

1. **Raise the cap again.** Every byte is downloaded *and stored*; the 32 MB addendum already
   cost 2.5-4.8 GB a day for 339 versions. Over 32 MB it is ~45 GB of blobs a day.
2. **Range requests for the files we want.** A gzip stream has no index: reaching a file means
   decompressing everything before it. Not possible.
3. **Stream the tarball once, keep only what the rules read** (chosen). Download in a single
   streaming pass, decompress and walk the tar as it arrives, verify `dist.integrity` over the
   whole stream, keep text and code up to a budget, and for every other file only its name,
   size, hash and first 512 bytes. Store the kept subset as a small, deterministic re-pack.
   Bandwidth is spent, disk is not.

## Decision

### What is read partially

`ArtifactFiles` reads a version partially when it **declares an install hook**
(`has_hook`), its declared unpacked size is **over `fetch_limit`** (32 MB), and it is **at most
`MAX_PARTIAL_ARTIFACT_BYTES` (1 GiB)**. This applies to whichever snapshot asks, so a hooked
base or previous release over the cap is read partially too. Everything else is as before:
under the cap, a normal read; without a hook or over 1 GiB, `files unavailable: declared
unpacked size ...`. The choice depends only on the version's metadata, never on what happens
to be cached, so a re-score reads the same way.

The ceiling: 1,434 of the 1,437 skipped hooked versions were at most 512 MB; the other 3 were
659 MB (`@dialetica/server`). Streaming needs no memory or disk in proportion to the size, so
the ceiling only bounds the time and bandwidth one version can take (about 10-20 s at the
measured rates). 1 GiB covers every version seen and is a round bound on a publisher-declared
number. The decompressed stream is capped separately (below), whatever is declared.

### The streaming read (`util/archive.stream_tar_gz`, `HttpFetcher.get_derived`)

- One `GET`, through `HttpFetcher` (pacing, retries, HTTPS-only, User-Agent). The body is
  handed to the reader chunk by chunk and never held whole, in memory or on disk.
  `get_derived` stores only what the reader returns. A transport error mid-stream restarts
  the download from the start, like any other retry; when retries run out it is a
  `TransientFetchError` (decision 0009: retried by the next tick, never "missing"). An error
  the reader raises (integrity, archive limits, malformed tar) is not retried and is the same
  failure a normal read gives (`files unavailable: IntegrityError: ...`). `DiskSpaceError`
  from the blob store is never caught.
- **Integrity:** the SRI digest (or legacy SHA-1) is computed incrementally over every
  compressed byte (`util/hashing.IntegrityCheck`) and checked when the stream ends, before
  anything is stored. A mismatch raises the same `IntegrityError` as `verify_integrity`.
- **Archive guards**, as `extract_tar_gz`'s: safe relative paths (`safe_relative_path`),
  non-regular entries reported in `skipped`, at most 50,000 entries, a compression ratio of
  at most 1000 (checked as the stream goes), at most 1 GiB compressed and **at most 1.25 GiB
  decompressed** (`PARTIAL_LIMITS`: a 1 GiB package plus tar headers), a single gzip member
  with nothing after it, and no truncated stream. The tar is walked in stream mode with the
  same lenient reading (zero and invalid blocks skipped), and entries a strict reader would
  not see are found by their offsets (an entry that does not start where the previous one
  ended) and recorded as the same anomaly; non-zero bytes after the last entry too.
- **What is kept** (`KeepPolicy`, Stage 2's `PARTIAL_POLICY`):
  - A file is **binary** when its first 8 KiB hold a NUL byte (what `static.analyse` already
    treats as binary and skips), unless its extension is a source or script one (`.js`,
    `.cjs`, `.mjs`, `.ts`, `.json`, `.sh`, `.ps1`, `.bat`, `.cmd`, `.py`, `.gyp`, ...), which is
    always kept as text. Binaries are never kept: their path, size, SHA-256, mode and first
    512 bytes (the head: enough for `static.disguised-file` to recognise an ELF or an archive
    under a font's name) go into the manifest.
  - Text files are kept up to **16 MB each** (`MAX_FILE_BYTES`, the file rules' own limit) and
    **64 MB in all**. When the budget is full, a more important file evicts less important
    kept ones, largest first: (0) `package.json`, `binding.gyp`, every path the version's
    install hooks name in its registry metadata (`partial_policy`: so a hook's script late in
    the tar is never left out), and text under a binary format's name (a disguise candidate);
    (1) the package's own code; (2) bundled code and JSON under `node_modules/`, and the
    package's own JSON; (3) everything else (documentation, type declarations, source maps,
    tests, data). Within a class the first file in tar order wins. Every file not kept is
    listed with its reason (`binary`, `file` over the per-file limit, `budget`).
- The policy has a version (`PARTIAL_POLICY.version`) that is part of the request key, so
  changing what is kept never serves an old subset as a new one.

### What is stored (the replay contract)

The kept subset is stored as a blob: a **deterministic tar.gz** (entries sorted by path,
mtime 0, owner 0, no names, gzip mtime 0) holding the kept files under `package/` with their
modes, and a manifest `kitsunox-partial.json` at the root (`PartialManifest`: the tarball URL,
its integrity string, the compressed size and SHA-256 of the original stream, the number of
entries, the policy, and every omitted file, skipped entry, duplicate and anomaly). It is read
back with `extract_tar_gz`, the same safe extractor as every tarball, and a reviewer can open
it with any `tar`.

It is recorded in the run's `static-snapshot.json` (and the immutable index, as the tarballs
are) under the request key **`GET <tarball url> partial=<policy version>`**, with the
tarball's own URL as `url`, the re-pack's SHA-256 and size, and the content type
`application/vnd.kitsunox.partial+gzip` (the marker). Consequences:

- **Replay.** A re-score (`collect`'s seeded Stage 2) serves the partial entry from the run's
  snapshot, so the same subset is analysed byte for byte offline. Stages 3 and 4 read it from
  the immutable index through `ArtifactFiles`, as they read Stage 2's tarballs. A replay never
  needs the original tarball, which is never stored.
- **Retention and the hold** work by URL and digest, so the re-pack is pruned, pinned for a
  labeled package, held as `small` (it almost always is under `HOLD_SMALL_BYTES`), held for a
  reported version through the ledger's `tarball` (the ledger records it as the captured
  artifact), and held for good when malicious, all with no change.
- **Stage 5** looks tarballs up under the plain `GET <url>` key (`TarballIndex`), so it never
  takes a re-pack for the tarball: such a version is "not captured" there, as before.

### What the stages see

- The tree is an `ArtifactTree` with the kept files, and `omitted` lists the rest
  (`OmittedFile`: path, size, SHA-256, mode, reason, head).
- Stage 2 adds **`static.partial-read`** (INFO, weight 0): "Partial read: N files (X MB) not
  read: ..." with the largest omitted files as evidence, so a report says what was not read,
  and appends `; partial read: N files (X MB) not read` to its decision reason. File rules
  see the kept files only; binaries were skipped by them anyway.
- `npm.artifact.size-mismatch` adds the omitted files' sizes to the measured total.
  `npm.artifact.install-target-missing` and `npm.artifact.install-stub` need the whole
  package (`_whole`) and so never hold on a partial tree. `static.disguised-file` also checks
  the heads of omitted binaries for an executable or an archive under another format's name.
- Stage 3 parses the kept code; Stage 4 compares the kept files with the repository. A binary
  is absent from both, as its content was unread by their rules before.

## Consequences

- Hooked versions from 32 MB to 1 GiB are read: about 700 a day (measured in the proposal:
  bandwidth, tick time, blobs, reports and their verdicts).
- A payload that is binary, or text past the budget in a package with more than 64 MB of more
  important text, is still not read; the report says how much was not read.
- An attacker can still overstate `dist.unpackedSize` past 1 GiB to avoid any read, as they
  could overstate it past 32 MB before; that is a metadata lie `npm.artifact.size-mismatch`
  cannot see without the files. Hookless versions over 16 MB are unchanged (see the
  proposal's owner questions).
- CLAUDE.md's invariant "tarballs are only ever extracted with `extract_tar_gz`" gains one
  exception, `stream_tar_gz` beside it in `util/archive.py`, which applies the same guards
  (the owner edits CLAUDE.md).
