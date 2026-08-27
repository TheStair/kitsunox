# Kitsunox — Architecture

> AI-assisted detection of software supply chain attacks in open source package
> registries, starting with npm. Capstone project — academic, not production.

Related: [[Build Status]] · [[TODO]]

---

## 1. Problem & approach

npm supply chain attacks (compromised maintainer accounts, malicious `postinstall`
scripts, dependency confusion / typosquatting, dormant packages suddenly republishing)
are usually caught **reactively** — after damage, via advisory databases.

Kitsunox does **continuous, ecosystem-wide monitoring** of npm publishes, with a
**token-efficient tiered funnel** so that expensive LLM reasoning is spent only on
genuinely ambiguous cases. Cheap deterministic checks eliminate the overwhelming
majority of events first.

---

## 2. The tiered filtering funnel

```mermaid
flowchart TD
    FEED["npm _changes feed<br/>(poll loop, ~everything)"] --> PRE

    PRE{{"Pre-score router<br/>metadata only, no code fetch"}}
    PRE -->|"established pkg,<br/>stable maintainers,<br/>unremarkable"| IGNORE["IGNORE<br/>(record & drop)"]
    PRE -->|"worth a<br/>deterministic scan"| T01
    PRE -->|"ambiguous /<br/>high blast radius"| T2GATE

    subgraph TIER0 ["Tier 0 — deterministic, no LLM"]
        T01["scanner.run_tier0"]
        T01 --> IOC["iocs: known-malicious<br/>package / dependency"]
        T01 --> PAT["patterns: eval, base64→exec,<br/>child_process, net-in-install,<br/>obfuscation, secret exfil"]
        T01 --> HEU["heuristics: new blob,<br/>entropy spike, new install script,<br/>non-registry dep, pinning loss"]
    end

    IOC & PAT & HEU --> FINDINGS["Findings<br/>(rule_id, severity, evidence, rationale)"]

    FINDINGS --> T1["Tier 1 — structural scoring<br/>(risk score, not verdict) — STUB"]
    T1 --> T2GATE{{"score &gt; threshold<br/>or novel pattern?"}}
    T2GATE -->|no| DONE["persist & stop"]
    T2GATE -->|yes| T2

    subgraph TIER2 ["Tier 2 — gated LLM (STUB)"]
        T2["Haiku 4.5 triage"] -->|residual| T2B["Sonnet 5 deep reasoning"]
        T2B --> VERDICT["structured verdict<br/>+ confidence + rationale trace"]
    end

    VERDICT --> DONE
```

**Design rule:** never run an LLM on every event. Tier 0/1 are pure code. Tier 2 sees
only the specific diff hunks / script content that triggered escalation — never whole
files or repos.

| Stage | LLM? | Runs on | Output | Status |
|---|---|---|---|---|
| Pre-score | no | ~all events | route + reasons | 🟡 fallback only ([[TODO#1. prescore.route\|prescore]]) |
| **Tier 0** | no | routed events | findings | 🟢 iocs done; 🟡 patterns/heuristics ([[TODO#2. tier0/patterns.scan\|patterns]], [[TODO#3. tier0/heuristics.check\|heuristics]]) |
| Tier 1 | no | Tier 0 output | risk score | 🔴 stub |
| Tier 2 | yes | score > threshold | verdict | 🔴 stub |

---

## 3. Unit of analysis

**Per publish** (decided). npm publishes can diverge from git — what's in the registry is
not guaranteed to match the tagged commit — so the tarball is the source of truth:

```mermaid
flowchart LR
    EV["publish event<br/>pkg@X"] --> RESOLVE["resolve prev version<br/>from packument timeline"]
    RESOLVE --> DL1["download tarball pkg@X"]
    RESOLVE --> DL2["download tarball pkg@prev"]
    DL1 & DL2 --> UNPACK["unpack<br/>(strip 'package/' prefix)"]
    UNPACK --> DIFF["file-tree diff<br/>added / removed / modified + hunks"]
    DIFF --> T0["Tier 0 scanners"]

    DL1 -.->|"404 / unpublished<br/>(e.g. event-stream@3.3.6)"| UNAVAIL["TarballUnavailable<br/>→ IOC path still runs<br/>→ backfill marks 'uneval'"]
```

---

## 4. Live pipeline (the `listen` command)

```mermaid
sequenceDiagram
    autonumber
    participant Feed as ChangesFeedClient
    participant Pipe as pipeline.handle_change
    participant Pre as prescore.route
    participant Reg as RegistryClient
    participant Scan as scanner.run_tier0
    participant Repo as Repository (SQLite)

    loop poll every ~15s
        Feed->>Feed: GET /_changes?since=<cursor>&limit=1000
        Feed->>Repo: set_cursor(last_seq)
        loop each ChangeRow
            Feed->>Pipe: handle_change(row)
            Pipe->>Repo: get_baseline(name)  (pre-update state)
            Pipe->>Pre: route(row, ctx)
            Note over Pre: metadata only — 1 abbreviated packument at most
            Pre-->>Pipe: Route + reasons (+ maybe version/prev)
            Pipe->>Repo: record_publish_event + set_event_route
            Pipe->>Repo: observe_publish_for_baseline (fold in: maintainers, cadence, last version)
            alt route == IGNORE or delete
                Pipe->>Repo: set_event_tier0("clean")
            else routed
                Pipe->>Reg: packument / version_meta / tarballs
                Pipe->>Scan: run_tier0(event)
                Scan->>Reg: diff_versions(prev, cur)
                Scan->>Scan: iocs + patterns + heuristics → dedupe
                Scan-->>Pipe: Tier0Result (findings, status)
                Pipe->>Repo: add_findings + set_event_tier0(status)
            end
        end
    end
```

**Crash recovery:** the cursor is persisted after every page, so a restart resumes from
`feed_cursor.last_seq` with no reprocessing. Row handling is idempotent on
`(package, version, rev, source)`.

---

## 5. Historical backfill (the `backfill` command) — evaluation

This is how the project gets graded. It doesn't wait for live data.

```mermaid
flowchart TD
    INC["Incident (eval/incidents.py)<br/>event-stream, ua-parser-js, coa/rc,<br/>node-ipc, chalk/debug 2025, shai-hulud"] --> LABELS

    LABELS["load_incident_labels_into_db<br/>(OSV + OpenSSF → incident_label)"] --> RECON

    RECON["for each package:<br/>fetch full packument + deps.dev history"] --> TIMELINE
    TIMELINE["reconstruct version timeline<br/>(time{} / publishedAt)"] --> SYNTH
    SYNTH["synthesize PublishEvent per<br/>(prev, cur) pair in incident window<br/>+ maintainer set as of that version"] --> RUN

    RUN["prescore.route → scanner.run_tier0"] --> SCORE

    SCORE{{"compare vs incident_label"}}
    SCORE -->|flagged & malicious| DET["detected"]
    SCORE -->|clean & malicious| MISS["missed"]
    SCORE -->|clean & benign| TN["true negative"]
    SCORE -->|tarball unavailable| UNEVAL["uneval (excluded from rate)"]

    DET & MISS & TN & UNEVAL --> REPORT["IncidentReport.render()<br/>detection rate + per-version trace"]
```

Final deliverable numbers:
1. **Detection rate** on known incidents (backfill)
2. **False-positive rate** on a random control sample of benign live publishes *(Tier 1 / eval phase — not built)*
3. **Token/cost accounting**: how much volume was filtered before Tier 2

---

## 6. Persistent store

SQLite now (single file, hand it to a reviewer), all access behind
`db/repo.Repository` + SQLAlchemy 2.0 so a Postgres swap is one module. Alembic
migrations from day one.

```mermaid
erDiagram
    feed_cursor {
        int id PK "singleton (1)"
        int last_seq
        datetime updated_at
    }

    package_baseline {
        int id PK
        string ecosystem
        string name
        datetime first_seen_at
        datetime last_publish_at
        json known_maintainers
        int publish_count
        float publish_cadence_days_median
        string last_version
        string last_tarball_sha256
        int weekly_downloads
        int dependents_count
    }

    publish_event {
        int id PK
        int seq "changes-feed sequence; null for backfill"
        string package_name
        string version
        string prev_version
        string rev
        bool is_delete
        datetime published_at
        string route "ignore | tier01 | tier2"
        json route_reasons
        string tier0_status "pending | clean | flagged | error"
        string source "live | backfill"
        datetime processed_at
    }

    finding {
        int id PK
        int publish_event_id FK
        int tier
        string rule_id "e.g. tier0.ioc.malicious_dependency"
        string severity "info..critical"
        string file_path
        int line
        string evidence "bounded snippet, never a whole file"
        string rationale
    }

    incident_label {
        int id PK
        string package_name
        string version "null = whole package"
        string label "malicious | benign_control"
        string source "osv | openssf | manual"
        string ref "GHSA id / URL"
        datetime incident_date
    }

    publish_event ||--o{ finding : "has"
    package_baseline ||..o{ publish_event : "name (soft link)"
    incident_label ||..o{ publish_event : "ground truth for backfill scoring"
```

`package_baseline` **is** the "small threat-intel database the system builds over time" —
it's not a stateless scanner.

---

## 7. Module layout & dependencies

```mermaid
flowchart TD
    CLI["cli.py"] --> PIPE["pipeline.py"]
    CLI --> EVAL["eval/backfill.py"]

    PIPE --> FEED["ingest/changes_feed.py"]
    PIPE --> PRE["ingest/prescore.py 🟡"]
    PIPE --> SCAN["analysis/scanner.py 🟡"]
    PIPE --> REPO["db/repo.py"]

    EVAL --> INC["eval/incidents.py 🟡"]
    EVAL --> PRE
    EVAL --> SCAN

    SCAN --> TAR["analysis/tarball.py"]
    SCAN --> IOC["analysis/tier0/iocs.py"]
    SCAN --> PAT["analysis/tier0/patterns.py 🟡"]
    SCAN --> HEU["analysis/tier0/heuristics.py 🟡"]

    IOC --> TI["threatintel/sync.py"]
    PRE --> REG["ingest/registry_client.py"]
    SCAN --> REG
    FEED --> REG

    REPO --> MODELS["db/models.py"]
    REPO --> ENGINE["db/engine.py"]

    ALL["everything downstream of ingest/"] -. speaks .-> IR["ir.py<br/>(ecosystem-neutral IR)"]

    classDef stub fill:#3a2a1a,stroke:#c80,color:#fca
    class PRE,SCAN,INC,PAT,HEU stub
```

🟡 = author-owned stub (see [[TODO]]). Everything else is implemented.

**The Postgres seam:** only `db/*` imports SQLAlchemy. `Repository` returns plain
dataclasses (`BaselineView`, `EventView`, `LabelView`), never ORM objects.

**The multi-ecosystem seam:** `ir.py` is deliberately npm-agnostic. npm terms are mapped
*in* at `ingest/registry_client.py`; PyPI/crates would add a sibling client, nothing else.

---

## 8. External services

| Service | Endpoint | Used for | Notes |
|---|---|---|---|
| npm replication | `GET replicate.npmjs.com/registry/_changes?since=&limit=` | the firehose | **poll only** since May 2025 — no `feed=continuous`, no `include_docs`. Header `npm-replication-opt-in: true`. `limit` max 10000. |
| npm replication root | `GET replicate.npmjs.com/registry/` | `update_seq` to start "near now" | |
| npm registry | `GET registry.npmjs.org/<pkg>` | full packument: `versions`, `time`, `maintainers`, per-version `dist`/`scripts`/`_npmUser` | abbreviated variant (`Accept: application/vnd.npm.install-v1+json`) is smaller but has **no `time`** |
| npm downloads | `GET api.npmjs.org/downloads/point/last-week/<pkg>` | popularity signal | |
| deps.dev | `GET api.deps.dev/v3/systems/npm/packages/<pkg>` | dependents count, per-version `publishedAt` | |
| OSV.dev | `POST api.osv.dev/v1/query` `{package:{ecosystem:"npm",name}}` | live IOC fallback + malicious-version ground truth | malware advisories flagged via `MAL-*` id or CWE-506 family |
| OSV bulk export | `osv-vulnerabilities.storage.googleapis.com/npm/all.zip` | offline mirror (all npm advisories, malware filtered) | |
| OpenSSF Malicious Packages | `codeload.github.com/ossf/malicious-packages/tar.gz/refs/heads/main` | offline mirror of confirmed-malicious npm packages | pulled as **tarball, not git clone** — repo has Windows-invalid paths |

`intel-sync` streams the two bulk sources into a single `data/intel-mirror/index.json`
(~440k hits, ~2 s to load). `data/` is git-ignored.

---

## 9. Configuration

Env vars (prefix `KITSUNOX_`) or `.env` — see `.env.example`. Key ones:

| Var | Default | Meaning |
|---|---|---|
| `KITSUNOX_DB_URL` | `sqlite:///data/kitsunox.db` | |
| `KITSUNOX_FEED_START` | `now` | `now` \| `now-<N>` (N seq back) \| `0` (full history) — only used when the cursor is empty |
| `KITSUNOX_POLL_INTERVAL_SECONDS` | `15` | sleep when caught up |
| `KITSUNOX_CHANGES_PAGE_LIMIT` | `1000` | `_changes` page size |

---

## 10. CLI

```
kitsunox db-init                       # alembic upgrade head
kitsunox intel-sync                    # rebuild data/intel-mirror/index.json
kitsunox listen [--once] [--max-events N]
kitsunox scan <pkg>@<version>          # ad-hoc Tier 0, no feed
kitsunox backfill [--incident <key>]   # historical evaluation  [needs TODO #5, #6]
```
