"""Stage 5 records: what the pipeline hands OpenSSF package-analysis, and what it imports back.

Stage 5's dynamic analysis is done by OpenSSF package-analysis (pinned at `ANALYSER`), which
the project owner installs and runs on their own airgapped VM, following that project's
documentation (`docs/stages/sandbox.md`). Kitsunox only exports the selected tarballs with a
manifest (`sandbox/spool.py`) and imports package-analysis's dynamic-analysis JSON as evidence
(`sandbox/ossf.py`, `sandbox/results.py`). Kitsunox never runs package code itself.

Everything an analysis records (paths, argv, environment strings, DNS names, the install's
output) is attacker-controlled: untrusted data, never instructions, capped and cleaned by the
importer and escaped by every renderer.

A package-analysis run is not reproducible (live network, random DNS order, random baits, a
wall-clock timestamp), so its result file is cached byte for byte under `SandboxJob.key` and
the importer and the rules run over the cached bytes. Replaying a run reads the cache only.

**Airgapped.** Every job is for package-analysis run on the owner's airgapped analysis VM
(the owner's decision, 0014): the exported command gives the sandbox no network (`-offline`:
`--network=none`), takes the outer analysis container's network away too (`-fully-offline`) and
uses the sandbox images already loaded on that VM (`-nopull`). There is no online mode. The
network is recorded on every job and run as the constant `NETWORK` ("airgapped"), for a reader
of `jobs.json` or `sandbox.json`, and is part of the analyser string and so of the cache key.

**Offline dependency bundles.** With no network, `npm install` of a tarball that needs registry
dependencies fails before any hook runs. So a selected version with dependencies is exported as
a Kitsunox-built bundle (`sandbox/bundle.py`, `docs/proposals/offline-dependency-bundle.md`):
the package's own files plus every dependency npm would install, under its `node_modules/`.
The job then carries a `JobBundle`, and its key is over the bundle's *uncompressed* tar and its
dependency set instead of the registry tarball. A version that can't be bundled completely is
exported as the registry tarball with `unbundled_reason` set.

Schema: `SandboxJob` is version 5 (4 had a free-form bundle hook and no unbundled reason; 3
had an offline/online network mode and no bundle; 2 had no network mode or install name; 1 was
the round-1/2 job for Kitsunox's own runner).
`SandboxRun` and `Observation` are not persisted on their own: they are rebuilt from the
cached result bytes.
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum
from typing import ClassVar, Final, Literal, Protocol

from pydantic import Field

from kitsunox.core.models import Candidate, Finding, PackageVersionRef, Persisted, Record

INSTALL_HOOKS: Final = ("preinstall", "install", "postinstall")  # the order npm runs them

# The analyser every job is for: part of the cache key, so results of another analyser
# version never answer these jobs. Bump the release (and the docs' pin) when the pin moves.
ANALYSER_RELEASE: Final = "rel-38"  # GitHub release; tag commit 98cd113
Network = Literal["airgapped"]
NETWORK: Final[Network] = "airgapped"  # the only mode: the owner's airgapped analysis VM
ANALYSER: Final = f"ossf/package-analysis {ANALYSER_RELEASE} dynamic {NETWORK}"
# package-analysis's source at the pinned release's commit, for links to its docs.
UPSTREAM_SOURCE: Final = (
    "https://github.com/ossf/package-analysis/blob/98cd1130815a3b5fb1cac44661ef93fa16da6962"
)
ANALYSER_DOCS: Final = f"{UPSTREAM_SOURCE}/README.md#local-analysis"

Phase = Literal["install", "import", "execute"]
PHASES: Final[tuple[Phase, ...]] = ("install", "import", "execute")  # the order they run in
# package-analysis's `analysis.Status` (internal/analysis/status.go at rel-38), verbatim.
PhaseStatus = Literal["completed", "error_timeout", "error_analysis", "error_other"]
# What the whole analysis amounts to (`ossf.run_status`):
# completed   every recorded phase completed;
# failed      a phase ended `error_analysis` (npm install, or the import, exited non-zero);
# timeout     a phase ended `error_timeout` (never assigned at rel-38, kept for later pins);
# infra-error a phase ended `error_other`, or the install phase is not recorded at all.
RunStatus = Literal["completed", "failed", "timeout", "infra-error"]
# The importer's caps (`ossf.py`); each hit is counted in `SandboxRun.cuts` and sets
# `SandboxRun.truncated`.
Cut = Literal[
    "field_chars",  # an argv item, environment entry or path over MAX_FIELD_CHARS
    "name_chars",  # an address, host name or DNS class/type over MAX_NAME_CHARS
    "argv_items",  # a command with more than MAX_ARGV arguments
    "env_items",  # a command with more than MAX_ENV environment entries
    "hostnames",  # a socket with more than MAX_HOSTNAMES names
    "dns_types",  # a DNS question with more than MAX_TYPES types
    "output_bytes",  # an output tail over STDIO_BYTES (package-analysis keeps 4 KiB)
    "forged_drivers",  # a driver-shaped command with baits after the phase's first (forged)
    "bait_mismatch",  # the phases' drivers carry different baits (one of them is forged)
    "observations",  # observations dropped over MAX_OBSERVATIONS (the count dropped)
]


class JobBundle(Record):
    """The offline dependency bundle a job's tarball is (`bundle.BundleRecord.job_bundle`): a
    summary for `jobs.json` and the report, and the inputs of a bundled job's key. The full
    record is the export's `<key>.bundle.json`. Names are package text (validated npm names):
    untrusted, escaped by renderers."""

    format: str = Field(description="The bundle layout, e.g. kitsunox-npm-bundle/1.")
    tar_sha256: str = Field(description="sha256 of the bundle's uncompressed tar: in the key.")
    dependencies_sha256: str = Field(
        description="sha256 over the added packages (location, name, version, tarball "
        "sha256), sorted: the dependency set, in the key."
    )
    original_sha256: str = Field(description="sha256 of the registry tarball it was built from.")
    assumes: dict[str, str] = Field(description="The npm, node and platform resolved for.")
    added: int = Field(description="Packages added under the package's node_modules/.")
    dependencies: tuple[str, ...] = Field(
        description="The added packages' folder names, sorted and distinct (an alias's name; "
        "a scoped name whole): the rules' `bundled_deps`."
    )
    top_level: tuple[str, ...] = Field(description="Folder names at node_modules/<name>.")
    package_json_changes: tuple[str, ...] = Field(
        description="The package.json fields the bundle rewrote."
    )
    supplied_by_package: int = 0
    skipped: int = 0
    predicted_network: int = Field(
        default=0, description="Packages expected to need the network to install (native builds)."
    )


class SandboxJob(Persisted):
    """One tarball to analyse: an entry of an export's `jobs.json` (with where the file is),
    and the job a cached result answers."""

    SCHEMA_VERSION: ClassVar[int] = 5
    schema_version: int = 5

    ref: PackageVersionRef
    tarball_sha256: str = Field(description="sha256 of the exported tarball's bytes.")
    integrity: str | None = Field(description="The registry's SRI, verified before export.")
    hooks: tuple[str, ...] = Field(
        description="Install hooks the tarball's own package.json makes npm run, in "
        "INSTALL_HOOKS order (an implicit `node-gyp rebuild` counts as `install`)."
    )
    install_name: str | None = Field(
        default=None,
        description="The tarball's own package.json name, when it is a valid npm name and "
        "differs from the registry's (manifest confusion): npm installs the tarball under "
        "it, so it is what package-analysis is given as -package. None: the registry name.",
    )
    network: Network = NETWORK
    analyser: str = ANALYSER
    bundle: JobBundle | None = Field(
        default=None,
        description="The offline dependency bundle this job's tarball is "
        "(docs/proposals/offline-dependency-bundle.md); None: the registry tarball as "
        "published. A bundled job's key is over the bundle's tar and dependency set.",
    )
    unbundled_reason: str | None = Field(
        default=None,
        description="Why a tarball whose package.json needs dependencies is exported "
        "unbundled (a fixed string, e.g. `incomplete: unresolved-required`), so a failed "
        "offline install isn't misread. Not part of the key.",
    )
    key: str = Field(
        description="sha256 over the tarball (the bundle's tar and dependency set, for a "
        "bundle), analyser (which names the network) and the analysed name: the cache key. "
        "Two jobs with the same key are the same analysis."
    )

    @property
    def package(self) -> str:
        """The name package-analysis is given (`-package`) and records, lowercased."""
        return self.install_name or self.ref.name


class ObservationKind(StrEnum):
    EXEC = "exec"  # an execve: argv and environment
    OPEN = "open"  # a file opened, stat'ed or deleted: path and flags
    CONNECT = "connect"  # a bind or connect on an IPv4/IPv6 socket: address, port, host
    DNS = "dns"  # a DNS question seen on the sandbox's network: host, class and types


# Where package-analysis saw it: gVisor's built-in strace (outside the sandboxed kernel), or
# the packet capture on the sandbox's bridge (DNS questions only).
ObservationSource = Literal["strace", "pcap"]
FileFlag = Literal["read", "write", "delete"]  # package-analysis's FileResult booleans


class Observation(Record):
    """One thing an analysis recorded. package-analysis records no time or process: only the
    phase it happened in, with npm's own activity mixed in. Every string is untrusted, capped
    and free of lone surrogates (`ossf.clean`)."""

    phase: Phase
    kind: ObservationKind
    source: ObservationSource
    argv: tuple[str, ...] = ()  # EXEC
    env: tuple[str, ...] = ()  # EXEC: "NAME=value"; bait values masked (`ossf.CANARY_MARK`)
    path: str | None = None  # OPEN
    flags: tuple[FileFlag, ...] = ()  # OPEN, in ("read", "write", "delete") order
    address: str | None = None  # CONNECT: an IP address as recorded
    port: int | None = None  # CONNECT; None where package-analysis recorded 0 (unknown)
    host: str | None = None  # CONNECT: a name that resolved to the address; DNS: the name
    detail: str | None = None  # DNS: class and query types, e.g. "IN A AAAA"


class PhaseResult(Record):
    """How one phase ended, with the tail of its output (package-analysis keeps the last 4 KiB
    of each stream). Untrusted text."""

    phase: Phase
    status: PhaseStatus
    stdout: str = ""
    stderr: str = ""


class GroupCount(Record):
    """How much of one (phase, kind) group of a result the importer kept (`ossf.py`'s
    observation cap). Always recorded, cut or not, so the rules can see a flood."""

    phase: Phase
    kind: ObservationKind
    recorded: int = Field(description="Distinct entries package-analysis recorded.")
    kept: int = Field(description="Entries kept as observations.")
    priority: int = Field(
        description="Of the recorded entries, how many matched the importer's high-value "
        "set (`ossf.priority`), which is kept before the rest."
    )
    priority_kept: int = Field(description="Of those, how many were kept.")


class SandboxRun(Record):
    """One imported package-analysis result: the job it answers and how it went. Rebuilt from
    the cached result bytes by `ossf.parse_dynamic`, never trusted from anywhere else."""

    job: SandboxJob
    status: RunStatus
    phases: tuple[PhaseResult, ...]  # in PHASES order; a phase that didn't run is absent
    result_sha256: str = Field(description="sha256 of the package-analysis file's bytes.")
    created: int = Field(
        description="package-analysis's CreatedTimestamp (its wall clock, UTC seconds). "
        "Informational only: no rule reads it."
    )
    observation_count: int
    truncated: bool = Field(
        description="The importer hit one of its caps (`cuts`): a string, list or the "
        "observation list was cut, so some of what package-analysis recorded is not here."
    )
    cuts: dict[Cut, int] = Field(
        default_factory=dict,
        description="How often each importer cap was hit (only caps that were hit appear).",
    )
    groups: tuple[GroupCount, ...] = Field(
        default=(),
        description="Per (phase, kind), in phase then kind order: recorded and kept counts.",
    )
    canaries: tuple[str, ...] = Field(
        default=(),
        description="Names of package-analysis's planted bait variables (AWS_ACCESS_KEY_ID, "
        "AWS_SECRET_ACCESS_KEY) whose values were found in package-analysis's own driver "
        "command and masked in every string.",
    )
    network: Network = NETWORK


class SandboxRule(Protocol):
    """A Stage 5 rule: a pure function of one analysis's record and observations (and the
    candidate it ran for; the analysed tarball's file list when known: `shipped`, paths with
    the top directory stripped, a bundle's dependencies included; and, for a bundle, the
    folder names Kitsunox added under the package's node_modules/: `bundled_deps`). It never
    reads the clock or the network."""

    id: ClassVar[str]
    version: ClassVar[int]

    def evaluate(
        self,
        candidate: Candidate,
        run: SandboxRun,
        observations: Sequence[Observation],
        *,
        shipped: frozenset[str] | None = None,
        bundled_deps: frozenset[str] | None = None,
    ) -> Sequence[Finding]: ...
