# Proposal: a sinkhole network for Stage 5 (airgapped, but answering)

> **Status:** proposal, 2026-11-02, for the owner's review. Nothing here is built. It changes
> [decision 0014](../decisions/0014-stage5-uses-ossf-package-analysis.md)'s "airgapped (the only
> mode)" into "airgapped, with a sinkhole inside the airgap"; if accepted, 0014 gets an addendum
> and Stage 5's jobs get a new network value. Stage design: [stages/sandbox.md](../stages/sandbox.md).

## The problem

The first day of local sandbox results ([stages/sandbox.md, First results](../stages/sandbox.md#first-results-2026-11-02))
showed that the airgap hides the behaviour Stage 5 exists to see:

- **The three versions recorded malicious that ran all scored +0.** `sol-wallet-adapter`,
  `wallet-adapter-base` and `contracts-upgradeable` run a `preinstall` that posts the hostname
  and user name to a Discord webhook. Offline, `getaddrinfo("discord.com")` fails, the script
  throws, npm reports the install failed, and the record holds one socket to `127.0.0.1:53`,
  which every run has (npm opens it too). No name, no address, no finding.
- **37 of the 45 failed installs failed for want of the network**: the hook's own request
  threw. Whatever it would have done next is unseen.
- **DNS is blind.** package-analysis takes DNS questions from its packet capture on the
  sandbox bridge. With `-offline` there is no bridge (the runner adds an empty dummy interface
  just so the capture starts), so `DNS` is always empty and `Sockets` never carries names.

Going online is not an option (decision 0014: nothing a sample does may reach anything).
The middle ground: keep the airgap and put a **sinkhole** inside it. It answers every DNS
question with a local address, accepts every connection, records what was asked for and what
was sent, and returns nothing useful.

## What changes for a sample

| Today (offline) | With the sinkhole |
|---|---|
| `getaddrinfo` fails (no resolver) | every A question gets a synthetic address; AAAA gets an empty answer (so clients fall back to IPv4) |
| no DNS questions recorded | package-analysis's own capture records each question, and `Sockets` names the host (both are in the result we already import) |
| `connect` to anything fails at once | TCP connects to the sinkhole; it records the destination, then: for TLS, the ClientHello's server name (SNI), then closes; for plaintext HTTP, the request line, `Host`, header names and the first 16 KiB of the body, and answers `200` with an empty body |
| UDP has nowhere to go | the first datagram per destination is recorded (size and first 512 bytes), and nothing is answered |
| a hook that needs the network throws early | it gets further: its own request "succeeds" (plaintext) or fails at TLS, as it would behind a captive portal |

For the three Discord samples, that means: a DNS question for `discord.com`, a socket named
`discord.com`, and a TLS ClientHello with SNI `discord.com`. Over HTTPS the body (the hostname
and user name) is still unseen. Over plaintext HTTP, which many quick exfil scripts use
(`http://<ip>:<port>/`, interactsh and Burp collaborator often), the body is recorded, so the
masked bait values package-analysis plants become visible to `sandbox.bait-exfil`.

## How it runs

Everything stays on this VM, in containers with **no network interface to the host**:

```
docker run --network none   kitsunox-sink    (owns the network namespace; unprivileged)
   └─ docker run --network container:<sink>  analysis (privileged, as today)
        └─ podman: sandbox on analysis-net (CNI bridge cni-analysis, 172.16.16.0/24)
             └─ gVisor: npm install / require
```

1. **The sink container starts first**, from a small pinned image (a Python slim image by
   digest, pulled once by `setup.sh` like the others), with `--network none`, `--read-only`,
   `--cap-drop ALL`, `--user 65534`, a memory and pid limit, and one writable mount: the job's
   `sink/` output directory. It runs `tools/sandbox/kitsunox_sink.py` (stdlib only, read-only
   mount) listening on high ports on `0.0.0.0`: DNS on UDP 5353, TCP on 8443, UDP on 5354.
2. **The analysis container joins that namespace** (`--network container:<sink>` instead of
   `--network none`). Its fixed shim (as `PCAP_SHIM` today: constants only, the job's values
   never in shell words) loads Kitsunox's own iptables rules into the shared namespace before
   `analyze` starts:
   - `nat PREROUTING -i cni-analysis -p udp --dport 53 -j REDIRECT --to-ports 5353`
   - `nat PREROUTING -i cni-analysis -p tcp -j REDIRECT --to-ports 8443`
   - `nat PREROUTING -i cni-analysis -p udp -j REDIRECT --to-ports 5354`
   - `filter INPUT -i cni-analysis` accepts only those three ports and drops the rest;
     `FORWARD` drops everything (there is nowhere to forward to anyway).

   REDIRECT happens before routing, so no address needs to exist for 8.8.8.8 or for the
   synthetic answers: the packet is delivered to the sink on the bridge's own address.
   The sink reads where a connection was going with `SO_ORIGINAL_DST`.
3. **`analyze` runs without `-offline`.** package-analysis then gives the sandbox
   `--network=analysis-net --dns=8.8.8.8 --dns=8.8.4.4`, creates the `cni-analysis` bridge
   through CNI, and captures on it (so the dummy interface shim goes; see open question 1).
   `-nopull` stays.
4. **Synthetic addresses:** each distinct name gets its own address from `198.18.0.0/15` (the
   benchmarking range, never routed), handed out in order of first question, so a connection
   to an address maps back to its name even without SNI. Names that are IP literals are not
   resolved.
5. **After the run**, the runner moves `sink/` into the results as `<key>/sink.json` (one
   JSON document, capped: 2,000 records, 16 KiB of body per request, 4 MiB in all; overflow
   counted, never silently dropped).

**Why the sink isn't in the analysis container:** that container is privileged, so a bug in
code parsing a sample's bytes there is close to root on the VM. The sink parses
attacker-controlled bytes (DNS queries, ClientHellos, HTTP heads), so it runs unprivileged,
read-only, without capabilities, in its own container, and parses only with fixed caps
(no TLS termination, no HTTP body decoding, no decompression). The analysis container gains
only fixed iptables commands. package-analysis's own packet parser already reads sample
packets in the privileged container today; that does not change.

**Why nothing can leave:** the namespace all of this shares belongs to a container started with
`--network none`: it has a loopback interface and whatever is created inside it (the CNI
bridge and the sandbox's veth). There is no interface with a route off the VM, so a mistake in
the rules fails closed: packets are dropped, not sent. The bridge's masquerade and default
route (from upstream's conflist) have no uplink to use. The verification below checks this
from the host side, not just by reasoning.

## Kitsunox changes

- **Jobs:** `SandboxJob.network` gains `"sinkhole"`; the analyser string becomes
  `ossf/package-analysis rel-38 dynamic sinkhole`, so keys change. Exports drop `-offline`
  from `args` and keep `-nopull` (the runner's job check accepts exactly the new shape). Old
  airgapped results stay valid for their keys; a version is analysed again only if it is still
  in an unpruned run and selected (see open question 3).
- **Import:** `sink.json` is validated like the result (strict schema, caps, the same bait
  masking over every string, the same visible-text clipping) and becomes new observations:
  `http` (method, host, path, header names, body prefix), `tls` (SNI), and `connect`/`dns` for
  UDP and the sink's DNS log. The sink can't tell `install` from `import` (package-analysis
  records no times), so its records carry phase `run`; the capture's DNS and Sockets keep
  their phases.
- **Rules** (weights to be set from evaluation, as 0014 says):
  - `sandbox.network` sees names now. New HIGH case: a name or SNI on Stage 2's exfil
    endpoint list (`static.exfil-endpoint`: Discord and Telegram webhooks, webhook.site,
    pipedream, interactsh/oast, Burp collaborator, ngrok, …), or an HTTP request whose path
    matches one (`/api/webhooks/`).
  - `sandbox.bait-exfil` reads HTTP heads and bodies (masked bait values, and their shapes).
  - `sandbox.dns-tunnel-shape` gets real questions to work on.
  - npm's own traffic (`registry.npmjs.org`, its update check, audit) stays excluded in
    `install` by the existing rules.
- **Reports:** the sandbox section lists names asked for, SNIs and HTTP request lines.

## What it still can't see

- **HTTPS bodies.** Most exfil goes over HTTPS: we get the name and SNI, not the payload.
  Decrypting would need a CA the sample trusts (`NODE_EXTRA_CA_CERTS` in the sandbox's
  environment, which rel-38 has no flag for, or a modified sandbox image, which breaks the
  digest pin) and would make the sink a TLS server for hostile clients. Not proposed.
- **Second stages.** Downloads get an empty `200` (plaintext) or a TLS failure, so a payload
  fetched from the network never arrives; we see where it would have come from.
- **Sandbox detection.** A resolver that answers every name, including random ones, is a
  known tell; a careful sample can stay quiet. `sandbox.quiet` remains "not evidence of
  safety".
- **Phase of sink records** (above), and anything sent before the first byte reaches the sink
  over a protocol other than TCP or UDP.

## Cost and risk

- **Run time:** hooks get further, so runs take longer. npm's own registry attempts fail fast
  (TLS reset). The 20-minute timeout and 12 jobs an hour stay; measure the median before and
  after on the verification set.
- **Attack surface:** a new parser (the sink) for sample bytes, contained as above; the
  analysis container's rules are fixed text in the runner, tested like `PCAP_SHIM`.
- **Effort:** the sink (about 300 lines and tests, stdlib only), runner and setup changes,
  the importer and model changes, three rule changes, docs. Roughly two sessions.

## Verification (before any real sample runs in this mode)

1. **Egress, from the host.** While the smoke package below runs, capture on every host
   interface (`tcpdump -i any`) and on Docker's bridges, filtered to anything not from the
   host's own processes: expect nothing from the job. Also check `docker inspect` shows the
   sink with network mode `none` and the analysis container with `container:<sink>`.
2. **A smoke package for the network** (inert, written by us, published nowhere): its
   `postinstall` resolves a name, sends an HTTP POST with a fixed body, opens a TLS connection
   to a second name, sends one UDP datagram, and prints. Expected: three DNS questions in the
   result, sockets named, the POST's body in `sink.json`, the SNI, the datagram; install
   `completed`.
3. **Replay known cases** from captured tarballs: the three Discord squats (expect names and
   SNI `discord.com`, a HIGH `sandbox.network`), the `atlassian-wallboard-plugin` claims family,
   and ten benign versions reviewed this week (expect no new HIGH findings).
4. **Measure** install failures and run time against the airgapped results for the same
   versions; record both in `docs/evaluation.md`.
5. **Review gate,** as 0014: the owner reads the smoke result before the timer runs real
   samples in the new mode.

## Open questions for the owner

1. **Capture start:** with `-offline` the capture failed because `cni-analysis` didn't exist
   when `analyze` opened it. Online, upstream runs this way in production, so podman should
   create the bridge first; if not, the shim creates the bridge itself with the conflist's
   name and subnet. Settled by the smoke test.
2. **Plaintext answers:** answer HTTP with `200` and an empty body (proposed: it lets a
   script proceed to its next request), or with a connection reset (closer to offline)?
3. **Re-analysis:** after the switch, re-export reported versions from the last 7 days with
   install hooks (about 250 jobs, about a day of runner time), or only new runs?
4. **Separate VM:** the stronger isolation in stages/sandbox.md (an analysis VM with no
   network adapter) still works with this design, because the sink runs beside the analysis
   container and needs no network either.
