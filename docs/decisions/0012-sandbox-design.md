# 0012: Stage 5 sandbox: isolation runtime, host and network

> **Superseded in part by [0014](0014-stage5-uses-ossf-package-analysis.md)** (2026-10-30): Stage 5 uses OpenSSF package-analysis; the threats and VM facts here still apply.

**Date:** 2026-10-29
**Status:** Accepted 2026-10-30 ("Build it"; see *Decided so far*). Phase 4's review gate still
stands: no real package runs before the user has reviewed the self-test and fixture results.
**Builds on:** roadmap Phase 10 (sandbox is optional; "design doc and review first"),
[0009](0009-network-failure-handling.md) (why the pipeline lives on a VM, not in the cloud),
[0010](0010-stage4-correlation-and-repo-comparison.md) (what Stage 4 reports)
**Stage design:** [stages/sandbox.md](../stages/sandbox.md)

## Context

Stages 1-4 read packages as data. They can't tell whether an obfuscated `postinstall` really
reads `~/.npmrc` and sends it somewhere, or what host a second-stage downloader contacts.
Running the install hooks and watching what they do answers both questions, and gives the
reviewer evidence that's hard to argue with ("the hook opened `~/.ssh/id_rsa` and POSTed the
canary token to `x.example`").

Running malware means accepting new risk, so CLAUDE.md sets non-negotiable rules: Docker
only, no host mounts beyond a read-only input dir and a write-only output dir, network
disabled or routed to a capture proxy, resource limits, disposable containers, and a
reviewed design before anything runs.

**The host, measured on 2026-10-29:**

| Fact | Value | Why it matters |
|---|---|---|
| OS / kernel | Ubuntu 26.10, Linux 7.3.0-10-generic, VMware guest | Recent kernel; the hypervisor is VMware |
| CPU / RAM / disk | 4 vCPU, 30 GB, 333 GB free of 393 GB | The sandbox shares this with hourly collection |
| Hardware virtualization in the guest | no `vmx`/`svm` CPU flag, no `/dev/kvm` | Firecracker, Kata and nested VMs can't run as configured |
| Host hypervisor | VMware Workstation on a Windows host with Hyper-V on (user, 2026-10-29) | VMware then runs on top of Hyper-V, which hides AMD-V from the guest. Nested virtualization would mean turning Hyper-V off on the host; the user chose not to. This VM never gets `/dev/kvm` |
| `kernel.apparmor_restrict_unprivileged_userns` | `1` | Rootless containers need an AppArmor profile for `rootlesskit` ([Docker docs](https://docs.docker.com/engine/security/rootless/troubleshoot/)) |
| cgroup v2 controllers | `cpuset cpu io memory hugetlb pids ...` | CPU, memory, pids and io limits are available |
| LSMs | `lockdown,capability,landlock,yama,apparmor,bpf,...` | AppArmor and Landlock are available as extra layers |
| Docker | not installed | Every option below starts from nothing |

The VM also holds everything worth stealing: `data/` (runs, tarballs, encrypted DataDog
samples, labels) and `.env` (the Discord webhook today; maybe a GitHub token later).
Collection runs hourly as the user `thestair`.

**Volume.** On the first live day Stage 4 reported 1,759 of 109,497 versions (1.6%, about 73
an hour; [validation.md](../validation.md)). In the VM's first 24-hour run
(`20261029T221803Z-npm`, 110,084 versions), 2,317 versions (2.1%) declare an install hook
(`preinstall`/`install`/`postinstall` or `hasInstallScript`), and `npm.install-hook` fired on
135. So Stage 5 would see on the order of 150-350 detonations a day (6-15 an hour). This is an
estimate to measure once the VM chain has a full reported day (see the stage doc).

## Threats to the host

Each option below is judged against these.

1. **Container escape.** A sample breaks out of the container and runs code on the VM.
   With plain `runc`, the container shares the host kernel, so any kernel bug reachable from
   the default seccomp profile is an escape, and `runc` itself has had escapes: CVE-2019-5736
   (overwrite the host `runc` binary, [NVD](https://nvd.nist.gov/vuln/detail/CVE-2019-5736)),
   CVE-2024-21626 (leaked file descriptor to the host filesystem,
   [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-21626)), and three in November 2025
   (CVE-2025-31133, -52565, -52881): mount races that let a container write
   `/proc/sys/kernel/core_pattern` or `/proc/sysrq-trigger`
   ([oss-security](https://www.openwall.com/lists/oss-security/2025/11/05/3),
   [Sysdig](https://sysdig.com/blog/runc-container-escape-vulnerabilities)). All of these
   assume a malicious *image* or a process inside the container, which is exactly our case.
2. **Resource exhaustion.** Fork bombs, memory balloons, disk fills, or a hook that never
   ends. On this VM that would starve the hourly collection, and Stage 2 must capture
   tarballs before npm deletes them (decision 0008). A crashed collection tick is a real loss
   of data.
3. **Sandbox detection and staying quiet.** Malware checks for CI, sandboxes, honeypot
   tokens, odd hostnames and usernames, waits a random time, and exits quietly
   (2025 reports on `@digitalcnzz/commonmodule` and `@sailing-package/core`:
   [1](https://radar.offseq.com/threat/malicious-code-in-digitalcnzzcommonmodule-npm-c4daa24369f2f6b6),
   [2](https://radar.offseq.com/threat/malicious-code-in-sailing-packagecore-npm-b0ee693f9628dd9d);
   secondary sources). gVisor in particular is recognisable from inside (its own kernel
   messages and `/proc` contents). The danger is not to the host but to the result: a
   quiet run must never be read as "benign".
4. **Timing evasion.** Payloads that sleep past any reasonable budget, start a detached
   process that outlives `npm`, or activate on a date. A time budget can't fix this; it can
   only record that a process was still running when the budget ran out.
5. **Exfiltration through DNS.** Even with "no internet", a resolver that forwards queries
   leaks data in query names (Shai-Hulud-style token theft would need only one lookup).
   The sandbox must have no upstream resolver at all.
6. **The capture proxy is attacked.** The DNS sinkhole and HTTP recorder parse attacker
   bytes. A bug there could forge the observations of the same sample (or, if shared, of
   other samples), or become a pivot to the host if the proxy has more reach than the sample.
7. **Poisoned output.** Anything the sandbox produces (logs, file lists, exit messages) is
   attacker-controlled: oversized, path-traversing, terminal escapes, Markdown injection,
   prompt injection for a future LLM stage. The existing rule applies: untrusted data, parsed
   strictly, size-capped, escaped on render.
8. **Secrets and data on the host.** A sample that escapes as `thestair` reads `.env` and
   `data/`. One that escapes as an unrelated, unprivileged user reads nothing of ours unless it
   also escalates.
9. **The sandbox image and tooling.** Node, npm, gVisor and Docker are fetched code we trust.
   Pin them (image by digest, packages by version) and update deliberately.
10. **Out of scope.** Hypervisor (VMware) escapes, CPU side channels (Spectre-class), and
    attacks on the user's desktop through VMware shared folders or the clipboard. The last
    one is cheap to close: turn those VMware features off for this VM (decision D2).

## Options

| | 1. Rootless Docker + `runc`, seccomp/AppArmor | 2. Docker + gVisor (`runsc`) | 3. Firecracker / Kata microVM | 4. Separate detonation VM | 5. Static only |
|---|---|---|---|---|---|
| Boundary a sample must break | Host kernel (shared) + user namespace | gVisor's Sentry (user-space kernel) **and** the host seccomp/namespace jail around it | Hardware virtualization (KVM) | Hypervisor (VMware) | none needed |
| Runs on this VM today | Yes, after AppArmor profile for `rootlesskit` | Yes: the default `systrap` platform needs no KVM ([Arm install guide](https://learn.arm.com/install-guides/gvisor/), [Northflank](https://northflank.com/blog/what-is-gvisor)) | **No**: needs `/dev/kvm`; nested VT-x must be enabled in VMware, which fails if the Windows host runs Hyper-V/VBS ([Broadcom KB 389469](https://knowledge.broadcom.com/external/article/389469)) | Yes, with a second VM on the desktop (RAM, disk, manual setup) | Yes |
| How we'd observe | `strace` in the container (needs `SYS_PTRACE`, visible to the sample via `TracerPid`), or host eBPF (Tetragon/Tracee, root on the host) | **Runtime monitoring**: trace points for every syscall, streamed as protobuf over a Unix socket to a monitor *outside* the sandbox ([gVisor](https://gvisor.dev/docs/user_guide/runtimemonitor/), [seccheck README](https://github.com/google/gvisor/blob/master/pkg/sentry/seccheck/README.md)); also `--strace` and `--log-packets` debug logs ([debugging](https://gvisor.dev/docs/user_guide/debugging)) | An agent inside the guest (tamperable) or eBPF in the guest | An agent inside the guest (tamperable); revert the snapshot after | n/a |
| Known weak points | Every kernel bug in the allowed syscall surface; `runc` escapes above | Sentry bugs alone are "insufficient to escape by design" ([security model](https://gvisor.dev/docs/architecture_guide/security/)); the Gofer runs outside and is the high-value target (one 2026 aggregator report of a Gofer escape when CUSE is enabled, [stack.watch](https://stack.watch/vuln/CVE-2026-96812/), unverified); detectable from inside; syscall-heavy work 50-100%+ slower ([Jacar](https://jacar.es/en/gvisor-sandboxing-for-multi-tenant-containers/)); Docker's embedded DNS (127.0.0.11) unreachable, so DNS must be set explicitly ([FAQ](https://gvisor.dev/docs/user_guide/faq)) | Large build: guest kernel, rootfs, jailer, tap networking | Hard to automate from inside the pipeline VM (revert needs `vmrun` on the Windows host); copies files over a network link | Misses runtime-only evidence |
| Prior art | common | OpenSSF Package Analysis detonates npm/PyPI packages in gVisor ([repo](https://github.com/ossf/package-analysis)); a 2025 paper extends it ([arXiv 2511.09957](https://arxiv.org/abs/2511.09957)) | Fly.io, AWS Lambda ([Fly.io comparison](https://fly.io/learn/firecracker-vs-gvisor/)) | classic malware labs | the current pipeline |
| Engineering cost | Low | Low to medium (runtime registration, monitor) | High | Medium, plus manual operations | None |

Notes on the rows:

- **Option 1** is what most people mean by "a hardened container". Its weakness is that the
  kernel surface is the whole Linux syscall interface minus seccomp's list, and this host's
  kernel is the same one that holds `data/`. Observing well also needs either a ptrace-based
  tracer the sample can detect, or a root eBPF agent on the host, which is one more privileged
  component.
- **Option 2's rootless story.** gVisor's docs describe Docker and Podman rootless mode, where
  `rootlesskit` makes the user namespace and `runsc` runs as root inside it, and `runsc`'s
  own `--rootless` flag (which has no `create`, no netstack, so it isn't for us)
  ([gVisor rootless](https://gvisor.dev/docs/user_guide/rootless/)). We found no project
  documentation that rootless Docker + `runsc` + runtime monitoring works together, so the
  first build phase is a spike that proves it, with a documented fallback.
- **Option 3** has the strongest per-sample boundary, but it doesn't run here without
  changing the VMware configuration, and even then the observer lives inside the guest.
- **Option 4** gives the cleanest separation from `data/` and `.env`. It can also be added
  *later* around option 2: the runner contract in the stage doc is a job directory in and a
  result directory out, so moving the runner to a second VM changes the transport, not the
  stage.
- **Option 5** is honest to keep on the table. Phase 10 is optional. End to end the pipeline
  already reports 91.1% of malicious updates and 66.5% of malicious new packages at 0.9% of
  benign updates ([correlate.md](../stages/correlate.md)). Because Stage 5 runs only on
  versions Stage 4 already reports, it can't raise that recall. What it adds is
  *precision and evidence*: confirming which reported install hooks really steal or download,
  ordering the queue by observed behavior, and C2 hosts for the reviewer.

## Recommendation (proposed)

**Option 2, hardened: Docker Engine in rootless mode under a dedicated unprivileged account,
with gVisor `runsc` (systrap platform) as the only runtime for detonation containers.** On the
existing VM, with these layers. Each layer stops something the others don't:

| Layer | Stops |
|---|---|
| gVisor Sentry + its host seccomp filter | Kernel and `runc` escape classes (threat 1). `runsc` doesn't use `runc` |
| Rootless Docker under a separate user (`kxsandbox`, no login, no sudo, no read access to `/home/thestair`) | An escape lands as a user who can read neither `data/` nor `.env` (threat 8); the daemon socket isn't root-equivalent |
| Container flags: `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`, non-root user in the image, tmpfs work dirs, no Docker socket, only the job's input mounted | Privilege inside the sandbox, persistence between jobs |
| `--network none` first; later an `--internal` per-job network whose only peer is a capture container with no upstream (no resolver forwarding, no route out, IPv6 off) | Real exfiltration, including over DNS (threat 5) |
| One capture container per job, itself gVisor-run, read-only, non-root, size limits | A compromised proxy forging other samples' results or pivoting (threat 6) |
| Per-container cgroup limits, plus a systemd slice capping the whole sandbox account (CPU, memory, tasks), plus a per-tick cap | Starving collection (threat 2) |
| Monitor outside the sandbox writes the observations; anything from inside is secondary and untrusted | Poisoned evidence (threats 6, 7) |
| "No behavior observed" is INFO, never negative weight; realistic developer profile with canary secrets | Evasion turning into a false all-clear (threats 3, 4) |
| VM snapshot before the first real sample; VMware shared folders, clipboard and drag-and-drop off | Recovery from the unknown, and threat 10 |
| A self-test (`kitsunox sandbox selftest`, design in the stage doc) before every batch, fail closed | Silent drift: a Docker upgrade that changes the runtime, a lost limit |

**Fallback if the Phase 1 spike shows rootless + `runsc` + monitoring doesn't work:**
rootful Docker with `runsc`, where only the `kxsandbox` account is in the `docker` group
(root-equivalent, so that account becomes as sensitive as root) and `thestair` hands jobs
over through the spool directory, never the socket. Podman rootless with `runsc` is the
second fallback; it's Docker-compatible but not what CLAUDE.md names, so it needs your OK.

### Consequences

- New software on the VM: Docker Engine (rootless extras, from Docker's apt repository, which
  ships the `rootlesskit` AppArmor profile; the convenience script doesn't), gVisor `runsc`,
  a pinned Node/npm image. All pinned and listed in the stage doc.
- A second Unix account and a spool directory outside the home directory. The pipeline user
  writes jobs; the sandbox user writes results; neither can read the other's home.
- Stage 5 runs on its own timer, not inside `collect`, so a slow batch never delays tarball
  capture. It takes the data-dir lock only for the short step that merges results into a run.
- Some samples will detect gVisor and stay quiet. We accept that and say so in every report
  ("no behavior observed; this is not evidence of safety").
- Results are not reproducible the way Stages 0-4 are. The *analysis* of a recorded
  observation log is; the detonation is cached by tarball hash, image digest and config, and
  replays never re-detonate. Details in the stage doc.
- Reporting must learn to read Stage 5's output. That's a contract change in the Report
  stage, flagged here and not designed beyond a sketch.
- Expected cost: 2 of 4 vCPUs and up to 6 GB RAM while a batch runs; the image and caches
  under 2 GB of disk; observation logs a few MB a day.

## Decided so far

- **2026-10-29, nested virtualization: no.** The host runs Hyper-V, and the user doesn't want
  it turned off. Options 3 (Firecracker / Kata) and gVisor's KVM platform are out. gVisor runs
  on its **systrap** platform, which needs no KVM. This is the recommended runtime anyway: it
  puts a user-space kernel between the sample and the host kernel, and the VM is a second
  boundary. The user asked for the safest execution possible without nested virtualization,
  which is this recommendation: gVisor (systrap) under rootless Docker in a dedicated account.
  Rootful Docker + gVisor stays only as the Phase 1 fallback if the rootless spike fails.

- **2026-10-30, the user: "Build it, go ahead and keep working."** That answers D0 (build).
  The user didn't answer the other questions one by one, so each takes the recommended or
  most conservative option. Any of them can be revisited:
  - **D2:** same VM as collection, with slice limits. Before Phase 4, the user turns off
    VMware shared folders, clipboard and drag-and-drop for this VM and takes a snapshot.
  - **D3:** no HTTPS interception at first. The capture records DNS names, connection
    attempts, TLS SNI and plain HTTP. Real internet access is never offered.
  - **D4:** only versions Stage 4 reports that declare an install hook, highest score first,
    at most 30 per tick.
  - **D5:** the developer profile only.
  - **D6:** Stage 5 only adds findings and weight. It never clears or lowers a version.
  - **D7:** deferred to the Phase 4 gate. DataDog samples are detonated only after the user
    has reviewed the self-test and fixture results.
  - **D8:** Node's bundled npm 11, pinned. The entrypoint runs hooks explicitly in any case,
    and the positive control proves that they ran.

## What you need to decide

1. **D1: Runtime.** *Decided 2026-10-29 (above):* gVisor, systrap platform, under rootless
   Docker in a dedicated account; rootful Docker + gVisor only if the Phase 1 spike fails.
   `runc` alone is not an option.
2. **D2: Host.** Same VM as collection, with the slice limits and snapshots (recommended),
   or a second VM now (option 4 around option 2)? Either way: may I ask you to turn off
   VMware shared folders, clipboard and drag-and-drop for the pipeline VM and take a snapshot
   before Phase 4?
3. **D3: Network.** Phase 2 runs with no network at all. Phase 3 adds the capture network.
   Do you want HTTPS bodies recorded (a CA certificate injected into the sandbox's trust
   store; pinned or custom TLS still shows only the SNI host), or DNS names, connection
   attempts and plain HTTP only? Real internet access is never offered (recommended: keep
   it that way).
4. **D4: What enters.** Versions Stage 4 reports that declare an install hook, highest score
   first, at most 30 per tick, the rest deferred (recommended). A changed hook on an update
   is already HIGH, so those are reported. Should *unreported* updates that keep their hook
   but ship a changed file the hook runs also enter, when the tick has room? This is the only
   way the sandbox could add recall. Of the latest run's 2,317 versions with a hook, most
   are unreported; how many changed the hook's file is unmeasured.
5. **D5: Profiles.** One "developer laptop" profile (recommended), or also a "CI runner"
   profile (`CI=true`, `GITHUB_ACTIONS=true`), which catches CI-only payloads and doubles
   the cost?
6. **D6: Effect on the decision.** Stage 5 findings only add weight and evidence; they never
   clear or lower a version Stage 4 reported (recommended). OK?
7. **D7: Real malware.** After the review gate, may DataDog samples (decrypted only into the
   sandbox job spool, deleted after the job) be detonated to measure what the sandbox sees?
   This is the only way to get Stage 5 recall numbers.
8. **D8: npm version.** npm 12 turns dependency install scripts off by default
   ([The Hacker News](https://thehackernews.com/2026/07/npm-12-disables-install-scripts-by.html),
   [Semgrep](https://semgrep.dev/blog/2026/rip-npm-postinstall-scripts-npm-v12-default-change)).
   Malware still targets the many users on older npm, pnpm with approvals, yarn and bun. Pin
   npm 11 in the image (hooks run as most victims ran them until now), or npm 12 with an
   explicit allow? Either way a positive-control fixture proves hooks actually ran.
9. **Or D0: don't build it.** Stay static-only (option 5) and spend Phase 10's time on the
   git path or reviewer verdicts. A defensible choice; this note would then be recorded as
   *Rejected* with the reason.
