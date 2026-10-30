# 0014: Stage 5 uses OpenSSF package-analysis instead of our own runner

**Date:** 2026-10-30
**Status:** Accepted (the project owner, 2026-10-30). Amended 2026-10-30: package-analysis
runs airgapped, with no online mode ([Network decision](#network-decision)).
**Supersedes in part:** [0012](0012-sandbox-design.md): its runner, capture network, canary
profile, self-test and build plan. Its threat analysis and the facts about the VM still apply.
**Stage design:** [stages/sandbox.md](../stages/sandbox.md)

## Context

0012 chose gVisor under rootless Docker and designed a Kitsunox-owned sandbox: a detonation
image and entrypoint, a trace-point monitor outside the sandbox, a per-job capture container
(DNS sinkhole and HTTP sink), a "developer laptop" canary profile, a fail-closed self-test,
and a host-setup script for a dedicated account. Two build rounds produced the pipeline side
and the parsers that face the sample: the gVisor wire decoder, the monitor, the capture sink
and its log parser, the trace-session config, with tests.

The rest could not be produced in this development environment. The isolation and host layer
(runner, `docker run` builder, entrypoint, Dockerfiles, host setup, systemd units, self-test
probe) and the behaviour fixtures were never written: the automated build was stopped by the
development tooling's safety checks in round 1 and again in round 2 (the round-2 runner agent:
"I didn't build any of the runner part"). The round-2 review then found the existing parsers
waiting on that missing layer ("Not ready for Phase 1/4"), with open findings on the monitor's
drain, its byte budget and the gate's freshness. So about 2,300 lines of sample-facing code
existed with nothing to drive them, and the part that actually isolates a sample, the part
that most needs review, was the part we could not build.

[OpenSSF package-analysis](https://github.com/ossf/package-analysis) does the same job: it
installs npm and PyPI packages in a gVisor sandbox, records commands, files, sockets and DNS,
and publishes the results. OpenSSF runs it continuously on new registry packages. It was
already listed as prior art in 0012.

## Options

| | A. Finish our own runner | B. OpenSSF package-analysis, run by the owner | C. No dynamic analysis |
|---|---|---|---|
| Who builds and runs the isolation | Kitsunox (the part that couldn't be produced here) | package-analysis, installed by the owner from its own docs | nobody |
| Observes | Our design: per-process trace with time, HTTP and SNI, our canaries | Commands, files, sockets, DNS questions, 4 KiB of output, per phase; no time, process tree or payloads | nothing new |
| Maintenance | Ours: gVisor wire format, Docker, images | Upstream's: tagged releases (rel-38, 2026-05-20), published images | none |
| Kitsunox code | Pipeline side plus about 2,300 lines of parsers, and the unbuilt runner | Pipeline side plus an importer for a documented JSON format | Stages 1-4 only |
| Determinism | Analysis of a stored log only | The same: analysis of a stored result only | n/a |
| Matches CLAUDE.md's sandbox guardrail | By design (no network or capture proxy, read-only input) | Only partly (see Consequences); the airgapped VM and the exported `-fully-offline -nopull -offline` meet the network part | trivially |

## Decision

**Option B.** Stage 5's dynamic analysis is OpenSSF package-analysis, pinned at **rel-38**
(commit `98cd1130815a3b5fb1cac44661ef93fa16da6962`; image digests in the stage doc). The owner
installs and runs it on their airgapped analysis VM, following package-analysis's
documentation.
Kitsunox's part is pipeline-side only:

1. select versions (reported by Stage 4, with an install hook in the tarball's own
   `package.json`, score order, a cap);
2. export their tarballs with a manifest and the `run_analysis.sh` arguments, one results
   directory per job, **for an airgapped VM** (`-fully-offline -nopull -offline`; see
   [Network decision](#network-decision)), with every path relative to the export directory so
   it can be carried to that VM ([Where package-analysis runs](#where-package-analysis-runs));
3. import package-analysis's dynamic-analysis JSON as hostile data, validated strictly
   against the rel-38 schema, cached byte for byte, and turned into findings by named rules.

Kitsunox ships no install scripts, container runners, Docker or gVisor setup; the stage doc
links to package-analysis's docs instead. Kitsunox never runs package-analysis, Docker,
`npm`, `node` or package code.

## Network decision

**Airgapped, with no online mode** (the owner, 2026-10-30: "Package analysis needs to be
airgapped"). The analysis VM has no network at all; package-analysis's images, the export
directory and the results cross the airgap only as files the owner carries. Every exported job
says so in its arguments, checked against the pinned `scripts/run_analysis.sh` and
`cmd/analyze`:

- `-fully-offline`, `run_analysis.sh`'s own flag (stripped before the analysis image starts):
  the outer analysis container gets `docker run --network none`;
- `-nopull`: package-analysis uses the rel-38 sandbox image already in the podman store and
  never pulls (the owner loads it from a `docker save` file, as package-analysis's `sync`
  targets do);
- `-offline`: the sandbox container gets `--network=none`, and package-analysis skips its
  network setup.

This supersedes the round-3 design (offline by default, online as an owner's opt-in): the
`NetworkMode` type, `run_sandbox_stage(network=...)` and the `offline`/`online` analyser
strings are gone. The network is still recorded, as the constant `"airgapped"`, in every job
(`SandboxJob` schema 4, `jobs.json` schema 3), in each run's `sandbox.json` (stage version 5)
and in each imported `SandboxRun`, and it is in the analyser string
(`ossf/package-analysis rel-38 dynamic airgapped`) and so in every key: results of the round-3
`offline` jobs never answer airgapped ones. Kitsunox can't verify how a job was run (the result
records no network mode); it trusts that the owner ran each job's exact args.

**Why airgapped and not online:** online analysis would give a malicious package real internet
from the analysis VM (NAT, DNS through 8.8.8.8; package-analysis blocks only private ranges,
the host and the metadata address): real exfiltration, C2, second stages and attacks on other
hosts, from the VM's public address. CLAUDE.md's guardrail asks for the network disabled or
routed to a capture proxy; package-analysis has no capture proxy, so disabled it is, at every
layer. An airgapped VM also removes the network from a gVisor escape into the privileged outer
container.

**Cost:** npm can't fetch registry dependencies, so a tarball that needs any it doesn't ship
fails to install, most likely before any hook runs (npm resolves the whole tree before it runs
lifecycle scripts; to confirm on the first results), and the import phase never runs. Kitsunox
records such a run as analysed with install status `error_analysis` (run status `failed`), adds
`sandbox.install-failed` (INFO, version 2, naming the airgap as the likely cause) and counts it
in `sandbox.json`; it is never `quiet`. Measured on the registry manifests of one run, 19% of
the hooked versions have no dependencies. The owner's direction for the rest: ship every
dependency tarball the package needs inside the exported package, so `npm install` works
offline. That is built (2026-10-30, [design note](../proposals/offline-dependency-bundle.md),
`sandbox/bundle.py`): a selected version with dependencies is exported as a Kitsunox-built
bundle (the package plus its resolved closure under `package/node_modules/`, an explicit
`bundleDependencies`), keyed by the bundle's uncompressed tar and dependency set, and reported
with `sandbox.bundled` (INFO). A version that can't be bundled completely is exported as the
registry tarball with `unbundled_reason` and `sandbox.bundle-incomplete` (INFO); a network
failure while bundling leaves it pending (decision 0009), never silently unbundled. The airgap
itself is unchanged: Kitsunox fetches the dependencies on the collection VM, through its
`HttpFetcher` (`sandbox-snapshot.json`), never on the analysis VM.

## Where package-analysis runs

**A separate, airgapped analysis VM** (the owner's decision), with no network, no `data/`, no
`.env`, no credentials and no shared folders, clipboard or drag-and-drop with its host,
snapshotted before the first real sample. The export is built for it: every path in `jobs.json`
is relative to the export directory, so the owner carries the directory in, runs each job from
inside it, and carries `results/` out into the results root Kitsunox reads. The facts that make this the
recommendation, from `scripts/run_analysis.sh` at rel-38:

- the outer analysis container is started with `docker run --cgroupns=host --privileged --rm`:
  privileged, so a process that escapes gVisor into it is effectively root on the VM;
- it bind-mounts the host's `/var/lib/containers` (the container store, writable) and six
  writable result and log directories (`RESULTS_DIR`, static results, file writes, analysed
  packages, logs at `/tmp`, strace logs), plus the tarball;
- it sets no CPU, memory, pid or time limit, and has the VM's network unless
  `-fully-offline` is given (every exported job gives it);
- the outer image is started at `:latest` (only the sandbox images follow `-image-tag`); on
  the airgapped VM that is the image the owner loaded under that name.

Isolation therefore rests on gVisor alone, inside a privileged container. On the collection
VM, a gVisor escape could read `data/` and `.env` (the Discord webhook, any future keys) and
tamper with collected data; on the airgapped VM it reaches nothing of Kitsunox's, and no
network.

## Owner steps

No install scripts: the stage doc's
["How the owner runs package-analysis"](../stages/sandbox.md#how-the-owner-runs-package-analysis)
lists the steps, each linking package-analysis's own documentation at the pinned commit:
prepare the airgapped VM and install package-analysis
([README "Local Analysis"](https://github.com/ossf/package-analysis/blob/98cd1130815a3b5fb1cac44661ef93fa16da6962/README.md#local-analysis),
[test/e2e/README.md](https://github.com/ossf/package-analysis/blob/98cd1130815a3b5fb1cac44661ef93fa16da6962/test/e2e/README.md)
for cgroups v2); bring the rel-38 images in as `docker save` files and load them
([sandboxes/README.md](https://github.com/ossf/package-analysis/blob/98cd1130815a3b5fb1cac44661ef93fa16da6962/sandboxes/README.md)
for local images and `-nopull`, the
[Makefile](https://github.com/ossf/package-analysis/blob/98cd1130815a3b5fb1cac44661ef93fa16da6962/Makefile)'s
`sync` targets); carry the export directory in; run each job's `command` from inside it; carry
`results/` out into the results root. Each export's `README.txt` repeats these steps and the
per-job command.

## Consequences

### Removed (CLAUDE.md "quality over volume")

Code that only made sense with our own runner, deleted on 2026-10-30 (lines as of deletion):

| Path | Lines | What it was |
|---|---|---|
| `sandbox/runner/monitor.py` | 776 | gVisor runtime-monitoring server: events to observations, exec confirmation, byte budget |
| `sandbox/runner/gvisor_wire.py` | 616 | Decoder for gVisor's seccheck protobuf wire format, trace-session checks |
| `sandbox/runner/capture_log.py` | 258 | Parser for the capture container's log |
| `sandbox/capture/capture.py` | 623 | DNS sinkhole and HTTP/TLS sink for the capture container |
| `sandbox/config/session.json` | 62 | The gVisor trace session (`--pod-init-config`) |
| `sandbox/runner/__init__.py`, `sandbox/capture/__init__.py` | 2 | |
| `tests/sandbox/test_monitor.py`, `test_gvisor_wire.py`, `test_capture.py` | 1,626 | Their tests |
| **Total** | **3,963** | 2,337 of code and config, 1,626 of tests |

The `sandbox` pytest marker and the `sandbox/` entries in ruff's and mypy's paths went with
them. With option B nothing would ever call this code: package-analysis does its own tracing
(gVisor's built-in `--strace`) and has no capture container. Keeping it would mean
maintaining parsers of attacker-facing input for a sandbox that doesn't exist, and the open
round-2 findings against it would stay open forever. The code is not in git history (it was
never committed); the design it implemented stays in 0012. The pipeline side was rewritten
for package-analysis in the same change: job schema version 2 (no image digest, profile,
network, limits or config hash; the key is the tarball and the analyser), the importer
`sandbox/ossf.py`, and the rules re-based on what package-analysis records. After the round-3
review the job is schema version 3: it adds the network mode (in the analyser string and the
key) and the tarball's own package name (`install_name`, the `-package` given). With the
airgap decision it is schema version 4: the network is the constant `airgapped`, and an
optional `bundle` description is recorded for the offline dependency bundle. With the bundle
built it is schema version 5: `bundle` is a typed `JobBundle` (in the key: the tar's sha256,
the format, the dependency set), and `unbundled_reason` records why a version that needs
dependencies is exported as the registry tarball (`jobs.json` schema 4, Stage 5 version 6).

### What we lose

- **Our canaries.** 0012's profile planted an npm token in `~/.npmrc`, an SSH key, AWS and
  GitHub credentials, `gh` hosts and a project `.env`, each value derived per job, and matched
  them in DNS names, HTTP requests and payloads (`sandbox.canary-exfil`). package-analysis has
  no user-facing way to plant files or variables. It plants its own AWS variables and an SSH
  key, with random values not written to the results; the importer recovers the AWS values
  from the recorded environment of package-analysis's own driver command (never from other
  commands, which the package controls) and masks them, and `sandbox.bait-exfil` looks for
  them. There is no npm-token bait.
- **Our capture container.** No HTTP request lines or bodies, no TLS SNI: only DNS questions
  and socket addresses. Exfiltration over HTTPS is not seen.
- **Time, processes and lifetimes.** No timestamps, no pids or process tree, no detection of a
  process outliving npm or of a time budget being hit (`sandbox.detached`,
  `sandbox.budget-exceeded` are gone).
- **Full coverage without a network.** package-analysis is online by default; Kitsunox's
  exported jobs run airgapped, which breaks installs that need registry dependencies the
  tarball doesn't ship. The offline dependency bundle covers the versions it can bundle
  completely; the rest (git or URL dependencies, caps, packages missing by `as_of`), and
  native addons or install-time downloaders inside a bundle, still fail offline
  ([Network decision](#network-decision)). A bundle is also not the registry tarball: its
  layout and rewritten `package.json` differ from a real install (the design note's
  "How A differs").
- **The guardrail's container shape.** package-analysis runs a `--privileged` outer container
  (podman inside, then gVisor), mounts `/var/lib/containers`, several writable result
  directories and the tarball, and sets no resource or time limits for npm. CLAUDE.md asks
  for no host mounts beyond a read-only input and a write-only output, resource limits, and no
  network or a capture proxy. Isolation now rests on gVisor inside a privileged container, on
  the owner's VM.
- **Our self-test** before every batch.

### What we gain

- A sandbox that is maintained upstream (tagged releases, published images), used by OpenSSF
  to analyse registry packages at scale, and documented, instead of one built and reviewed by
  us alone.
- A documented result schema (`docs/data_schema.md`, the BigQuery loader schema) to validate
  against, and upstream's own npm noise baseline (`docs/queries.md`) to shape rules.
- Much less sample-facing Kitsunox code: one strict importer instead of a wire decoder,
  monitor and capture parsers.
- A clean split of responsibility. The privileged, sample-running part is the owner's,
  installed from upstream's docs; Kitsunox stays a static pipeline that reads files.

### Licence

package-analysis is Apache-2.0 (no NOTICE file). Kitsunox vendors none of its code or data:
the importer is written from the struct definitions, the test fixtures are hand-written,
small and inert, and the docs link to the pinned source. Results the owner produces describe
third-party packages; they stay under `data/` (gitignored), never in `tests/fixtures/`.

### Evaluation

Phase 5 of 0012 is unchanged in spirit. After the owner has reviewed package-analysis's results
on benign reported versions with hooks, analyse the DataDog samples with install hooks (0012 D7;
exporting decrypted samples for package-analysis is a separate task) and a benign sample of
reported versions with hooks. Record per rule the share of malicious samples with a non-INFO
finding and of benign ones with any, in `docs/evaluation.md`; set weights from that; remove
rules that only add noise. Stage 5 still can't raise recall; it adds precision, evidence and
queue order.

### 0012 still applies to the owner's VM

- **Threats 1-10** stand, some sharper and one removed: the outer container is privileged, so
  a gVisor escape (threat 1) lands with root-equivalent access to that VM's Docker host; the
  airgap removes real exfiltration (threat 5) and gives such an escape no network; no limits
  are set upstream (threat 2); and the results are poisoned output (threat 7), which the
  importer treats as hostile.
- **The runtime facts:** the VM has no `/dev/kvm` (Hyper-V on the Windows host), so gVisor runs
  on a platform that needs no KVM; package-analysis's gVisor setup uses runsc's default
  platform, which is systrap in current gVisor. To confirm on the owner's VM.
- **D2, host.** The privileged container makes 0012 option 4 (a VM without `data/` and `.env`)
  the choice, airgapped ([Where package-analysis runs](#where-package-analysis-runs)), and the
  export is portable to it. If package-analysis runs on the collection VM instead, a gVisor
  escape can read `data/` and `.env`. Either way: VMware shared folders, clipboard and
  drag-and-drop off, and a snapshot before the first real sample.
- **D3, network:** none, at every layer: an airgapped VM, `-fully-offline`, `-nopull`,
  `-offline` (within CLAUDE.md's guardrail; installs with dependencies the tarball doesn't ship
  fail before their hooks run, and are reported as such). There is no online mode
  ([Network decision](#network-decision)).
- **D4, D6, D7** stand: entry is reported versions with an install hook (now read from the
  tarball), Stage 5 only adds findings, and real malware runs only after the owner's review.
- **D5 and D8** are package-analysis's: its own sandbox profile (root in `/app`) and its
  Node.js 24 image.
- **The review gate stands:** no real malicious sample is analysed before the owner has
  reviewed package-analysis's results on benign packages.
