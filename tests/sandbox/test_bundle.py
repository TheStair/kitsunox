"""Offline dependency bundles (`sandbox/bundle.py`). Every package here is hand-made and inert:
a package.json and a one-line JavaScript string, served from a mock registry."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import math
import tarfile
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from conftest import Router, TarEntry, make_tar_gz, sri_sha512
from kitsunox.ecosystems.npm.registry import packument_url
from kitsunox.sandbox import bundle as B
from kitsunox.util.archive import ExtractLimits, extract_tar_gz
from kitsunox.util.hashing import sha256_hex
from kitsunox.util.http import (
    BlobStore,
    FetchError,
    FetchMode,
    HttpFetcher,
    Snapshot,
    TransientFetchError,
)

AS_OF = datetime(2026, 10, 20, tzinfo=UTC)
OLD = "2026-10-01T00:00:00Z"
NEW = "2026-10-25T00:00:00Z"  # after AS_OF


def tgz(files: Mapping[str, bytes | str], prefix: str = "package") -> bytes:
    return make_tar_gz(
        TarEntry(f"{prefix}/{path}", data.encode() if isinstance(data, str) else data)
        for path, data in files.items()
    )


def manifest_bytes(manifest: Mapping[str, Any]) -> bytes:
    return (json.dumps(manifest, indent=2) + "\n").encode()


class Registry:
    """A mock npm registry: packuments and tarballs behind a Router."""

    def __init__(self, router: Router) -> None:
        self.router = router
        self.docs: dict[str, dict[str, Any]] = {}

    def publish(
        self,
        name: str,
        version: str,
        *,
        when: str = OLD,
        latest: bool = True,
        dist: Mapping[str, Any] | None = None,
        extra_files: Mapping[str, str] | None = None,
        **fields: Any,
    ) -> bytes:
        manifest = {"name": name, "version": version, **fields}
        files = {
            "package.json": manifest_bytes(manifest),
            "index.js": f"module.exports = {json.dumps(name)};\n".encode(),
            **{k: v.encode() for k, v in (extra_files or {}).items()},
        }
        tarball = tgz(files)
        base = name.rsplit("/", 1)[-1]
        url = f"https://registry.npmjs.org/{name}/-/{base}-{version}.tgz"
        doc = self.docs.setdefault(name, {"name": name, "versions": {}, "time": {}})
        doc["versions"][version] = {
            **manifest,
            "dist": dict(dist)
            if dist is not None
            else {"tarball": url, "integrity": sri_sha512(tarball)},
        }
        doc["time"][version] = when
        if latest:
            doc.setdefault("dist-tags", {})["latest"] = version
        self.router.add_bytes(url, tarball)
        return tarball

    def sync(self) -> None:
        for name, doc in self.docs.items():
            self.router.add_json(packument_url(name), doc)


@pytest.fixture
def registry(router: Router) -> Registry:
    return Registry(router)


def make_fetcher(tmp_path: Path, router: Router) -> HttpFetcher:
    return HttpFetcher(
        store=BlobStore(tmp_path / "blobs"),
        snapshot=Snapshot(),
        mode=FetchMode.RECORD,
        client=router.client(),
    )


def original(manifest: Mapping[str, Any], **files: str) -> bytes:
    return tgz(
        {"package.json": manifest_bytes(manifest), "index.js": "module.exports = 1;\n", **files}
    )


Built = tuple[bytes, B.BundleRecord, B.Resolution]


def build(
    tmp_path: Path,
    router: Router,
    registry: Registry,
    manifest: Mapping[str, Any],
    *,
    caps: B.BundleCaps = B.DEFAULT_CAPS,
    files: Mapping[str, str] | None = None,
) -> Built:
    registry.sync()
    fetcher = make_fetcher(tmp_path, router)
    data = original(manifest, **(files or {}))
    package = B.read_original(data)
    resolution = B.resolve(
        package.manifest,
        packuments=B.registry_packuments(fetcher),
        as_of=AS_OF,
        caps=caps,
        supplied=package.supplied,
    )
    fetched = B.fetch_dependencies(resolution, fetcher, caps=caps)
    out, record = B.build_bundle(data, resolution, fetched, caps=caps)
    return out, record, resolution


def files_of(bundle: bytes) -> dict[str, bytes]:
    tree = extract_tar_gz(bundle, strip_components=1)
    assert not tree.skipped and not tree.duplicates and not tree.anomalies
    return dict(tree.files)


def locations(resolution: B.Resolution) -> dict[str, str]:
    return {p.location: p.version for p in resolution.packages}


ROOT = {"name": "kx-root", "version": "1.0.0"}


# --- the basic tree ---------------------------------------------------------------------------


def test_simple_tree_bundles_the_closure(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("a", "1.0.0", dependencies={"b": "~2.0.0"})
    registry.publish("a", "1.4.0", dependencies={"b": "~2.0.0"})
    registry.publish("b", "2.0.3")
    registry.publish("b", "2.1.0")
    root = {**ROOT, "scripts": {"postinstall": "node index.js"}, "dependencies": {"a": "^1.0.0"}}
    data, record, resolution = build(tmp_path, router, registry, root)

    assert locations(resolution) == {"node_modules/a": "1.4.0", "node_modules/b": "2.0.3"}
    assert resolution.complete and record.status == "complete"
    files = files_of(data)
    assert json.loads(files["node_modules/a/package.json"])["version"] == "1.4.0"
    assert files["node_modules/b/index.js"] == b'module.exports = "b";\n'
    rewritten = json.loads(files["package.json"])
    assert rewritten["bundleDependencies"] == ["a"]
    assert list(rewritten) == ["name", "version", "scripts", "dependencies", "bundleDependencies"]
    assert files["index.js"] == b"module.exports = 1;\n"  # original files byte for byte
    assert [(c.field, c.after) for c in record.package_json.changes] == [
        ("bundleDependencies", ["a"])
    ]
    assert [(a.location, a.package_name, a.version) for a in record.added] == [
        ("node_modules/a", "a", "1.4.0"),
        ("node_modules/b", "b", "2.0.3"),
    ]
    assert record.added[1].required_by == (
        B.RequiredBy(requirer="node_modules/a", spec="~2.0.0", type="prod"),
    )
    assert record.files["node_modules/a/index.js"] == "node_modules/a"
    assert record.files["index.js"] == "package"
    assert record.added[0].integrity == registry.docs["a"]["versions"]["1.4.0"]["dist"]["integrity"]
    assert record.original_sha256 != record.bundle_sha256
    summary = record.summary()
    json.dumps(summary)  # JsonValue: fits SandboxJob.bundle
    assert summary["top_level"] == ["a", "b"] and summary["status"] == "complete"
    assert B.BundleRecord.model_validate_json(record.model_dump_json()) == record


def test_dev_dependencies_are_never_resolved(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("a", "1.0.0", devDependencies={"jest": "^30"})
    root = {**ROOT, "dependencies": {"a": "1"}, "devDependencies": {"eslint": "^10"}}
    _, record, resolution = build(tmp_path, router, registry, root)
    assert locations(resolution) == {"node_modules/a": "1.0.0"}
    assert record.status == "complete"
    assert not any("eslint" in url or "jest" in url for url in router.requests)


def test_conflicting_versions_nest_under_the_requirer(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("a", "1.0.0", dependencies={"c": "^1.0.0"})
    registry.publish("b", "1.0.0", dependencies={"c": "^2.0.0"})
    registry.publish("c", "1.5.0", latest=False)
    registry.publish("c", "2.2.0")
    root = {**ROOT, "dependencies": {"b": "^1", "a": "^1"}}
    data, record, resolution = build(tmp_path, router, registry, root)
    assert locations(resolution) == {
        "node_modules/a": "1.0.0",
        "node_modules/b": "1.0.0",
        "node_modules/c": "1.5.0",  # a comes first in sorted order and takes the top slot
        "node_modules/b/node_modules/c": "2.2.0",
    }
    assert resolution.post_check == () and record.status == "complete"
    files = files_of(data)
    assert json.loads(files["node_modules/b/node_modules/c/package.json"])["version"] == "2.2.0"


def test_reuses_a_visible_copy_and_nests_under_a_shadowing_one(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("a", "1.0.0", dependencies={"b": "^1", "c": "^1"})
    registry.publish("b", "1.0.0", dependencies={"c": "^2"})
    registry.publish("c", "1.0.0", latest=False)
    registry.publish("c", "2.0.0")
    root = {**ROOT, "dependencies": {"a": "^1", "c": "^2"}}
    _, _, resolution = build(tmp_path, router, registry, root)
    assert locations(resolution) == {
        "node_modules/a": "1.0.0",
        "node_modules/a/node_modules/c": "1.0.0",
        "node_modules/b": "1.0.0",
        "node_modules/c": "2.0.0",
    }
    # b, at the top, reuses the top c@2; the post-check finds every edge satisfied
    assert resolution.post_check == ()


def test_a_dependency_that_requires_the_package_finds_the_package(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish(
        "a", "1.0.0", peerDependencies={"kx-root": "^1"}, dependencies={"kx-root": "^1"}
    )
    _, record, resolution = build(tmp_path, router, registry, {**ROOT, "dependencies": {"a": "1"}})
    assert locations(resolution) == {"node_modules/a": "1.0.0"}
    assert record.status == "complete"


# --- peers ------------------------------------------------------------------------------------


def test_required_peers_are_copied_into_dependencies(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("react", "18.3.1")
    registry.publish("types", "1.0.0")
    root = {
        **ROOT,
        "peerDependencies": {"react": "^18", "types": "^1"},
        "peerDependenciesMeta": {"types": {"optional": True}},
    }
    data, record, resolution = build(tmp_path, router, registry, root)
    assert locations(resolution) == {"node_modules/react": "18.3.1"}
    assert resolution.peers_copied == (("react", "^18"),)
    rewritten = json.loads(files_of(data)["package.json"])
    assert rewritten["dependencies"] == {"react": "^18"}
    assert rewritten["bundleDependencies"] == ["react"]
    assert rewritten["peerDependencies"] == root["peerDependencies"]  # untouched
    assert [c.field for c in record.package_json.changes] == [
        "dependencies.react",
        "bundleDependencies",
    ]
    assert [(s.name, s.reason) for s in record.skipped] == [("types", "optional-peer")]
    assert record.status == "complete"


def test_dependency_peers_are_placed_beside_it_and_conflicts_kept(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("plugin", "1.0.0", peerDependencies={"host": "^1"})
    registry.publish("other", "1.0.0", peerDependencies={"lib": "^1"})
    registry.publish("host", "1.2.0", latest=False)
    registry.publish("host", "2.0.0")
    registry.publish("lib", "1.0.0")
    root = {**ROOT, "dependencies": {"plugin": "1", "other": "1", "host": "^2"}}
    _, record, resolution = build(tmp_path, router, registry, root)
    assert locations(resolution) == {
        "node_modules/host": "2.0.0",
        "node_modules/lib": "1.0.0",  # other's peer: a sibling of other
        "node_modules/other": "1.0.0",
        "node_modules/plugin": "1.0.0",
    }
    # npm keeps the copy it found and warns (ERESOLVE overriding peer dependency): no second
    # host, nested where plugin's peer lookup would never look
    assert [(c.name, c.found, c.placed) for c in record.peer_conflicts] == [
        ("host", "node_modules/host", "node_modules/host")
    ]
    assert record.status == "complete" and resolution.post_check == ()


# --- platforms and engines ----------------------------------------------------------------------


def test_only_matching_platform_packages_are_shipped(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    variants: dict[str, dict[str, Any]] = {
        "@esbuild/linux-x64": {"os": ["linux"], "cpu": ["x64"]},
        "@esbuild/linux-arm64": {"os": ["linux"], "cpu": ["arm64"]},
        "@esbuild/darwin-x64": {"os": ["darwin"], "cpu": ["x64"]},
        "@esbuild/linux-x64-musl": {"os": ["linux"], "cpu": ["x64"], "libc": ["musl"]},
        "@esbuild/not-windows": {"os": ["!win32"]},
        "@esbuild/old-node": {"engines": {"node": "<20"}},
    }
    for name, fields in variants.items():
        registry.publish(name, "0.25.0", **fields)
    root = {
        **ROOT,
        "scripts": {"postinstall": "node install.js"},
        "optionalDependencies": dict.fromkeys(variants, "0.25.0"),
    }
    data, record, resolution = build(tmp_path, router, registry, root)
    assert locations(resolution) == {
        "node_modules/@esbuild/linux-x64": "0.25.0",
        "node_modules/@esbuild/not-windows": "0.25.0",
    }
    assert sorted((s.name, s.reason) for s in record.skipped) == [
        ("@esbuild/darwin-x64", "platform"),
        ("@esbuild/linux-arm64", "platform"),
        ("@esbuild/linux-x64-musl", "platform"),
        ("@esbuild/old-node", "engines"),
    ]
    # every optional name stays listed, so npm skips the ones not shipped without a fetch
    assert json.loads(files_of(data)["package.json"])["bundleDependencies"] == sorted(variants)
    assert record.status == "complete"
    assert all(p.optional for p in resolution.packages)
    assert not any("darwin" in url and url.endswith(".tgz") for url in router.requests)


def test_a_required_dependency_for_another_platform_is_incomplete(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("fsevents-ish", "2.0.0", os=["darwin"])
    registry.publish("old", "1.0.0", engines={"node": "<18"})
    root = {**ROOT, "dependencies": {"fsevents-ish": "^2", "old": "1"}}
    _, record, resolution = build(tmp_path, router, registry, root)
    # engines only warn for a required package (engine-strict is off); the platform refuses
    assert locations(resolution) == {"node_modules/old": "1.0.0"}
    assert resolution.packages[0].engines_ok is False
    assert [(u.name, u.reason) for u in record.unresolved] == [
        ("fsevents-ish", "platform-mismatch")
    ]
    assert record.status == "incomplete"
    assert set(record.incomplete_reasons) >= {"platform-mismatch", "unresolved-required"}


def test_a_failing_optional_subtree_is_pruned_whole(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("opt", "1.0.0", dependencies={"native": "^1", "shared": "^1"})
    registry.publish("native", "1.0.0", os=["darwin"])
    registry.publish("shared", "1.0.0")
    root = {**ROOT, "dependencies": {"keep": "1"}, "optionalDependencies": {"opt": "1"}}
    registry.publish("keep", "1.0.0")
    _, record, resolution = build(tmp_path, router, registry, root)
    # npm marks opt and everything only it needs inert: none of it ships
    assert locations(resolution) == {"node_modules/keep": "1.0.0"}
    assert [(s.name, s.reason) for s in record.skipped] == [("opt", "optional-dependency-failed")]
    assert resolution.passes == 2
    assert record.status == "complete"


def test_platform_checks_follow_npm_install_checks() -> None:
    assert B.platform_ok({"os": "linux", "cpu": "any"})
    assert B.platform_ok({"os": ["!darwin", "!win32"], "cpu": []})
    assert not B.platform_ok({"os": ["!linux"]})
    assert not B.platform_ok({"libc": "musl"})
    assert B.platform_ok({"libc": ["glibc"]})
    assert not B.platform_ok({"os": 7})  # npm would throw on it
    assert not B.platform_ok({"libc": "glibc"}, B.Platform(libc=""))


# --- version picks ------------------------------------------------------------------------------


def test_picks_skip_deprecated_and_ignore_latest_published_after_as_of(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("d", "1.0.0")
    registry.publish("d", "1.1.0", deprecated="use 1.0")
    registry.publish("d", "1.2.0", when=NEW)  # `latest`, but after the run's moment
    registry.publish("e", "2.0.0")
    registry.docs["e"]["dist-tags"]["next"] = "3.0.0-rc.1"
    registry.publish("e", "3.0.0-rc.1", when=NEW, latest=False)
    registry.docs["e"]["dist-tags"]["latest"] = "2.0.0"
    root = {**ROOT, "dependencies": {"d": "^1", "e": "next"}}
    _, record, resolution = build(tmp_path, router, registry, root)
    assert locations(resolution) == {"node_modules/d": "1.0.0"}
    assert resolution.packages[0].latest_after_as_of is True
    assert [(u.name, u.reason) for u in record.unresolved] == [("e", "tag-after-as-of")]
    assert record.status == "incomplete"


def test_versions_without_a_publish_time_are_not_candidates(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("t", "1.0.0")
    registry.publish("t", "1.9.0")
    del registry.docs["t"]["time"]["1.9.0"]
    _, _, resolution = build(tmp_path, router, registry, {**ROOT, "dependencies": {"t": "^1"}})
    assert locations(resolution) == {"node_modules/t": "1.0.0"}
    assert resolution.untimed_versions >= 1


# --- specs npm can't resolve from a packument ---------------------------------------------------


@pytest.mark.parametrize(
    ("spec", "reason"),
    [
        ("github:user/repo", "git"),
        ("user/repo#main", "git"),
        ("git+https://github.com/u/r.git", "git"),
        ("git@github.com:u/r.git", "git"),
        ("https://example.com/x.tgz", "remote"),
        ("file:../x", "file"),
        ("../x", "file"),
        ("./x.tgz", "file"),
        ("workspace:*", "protocol"),
        ("link:../x", "protocol"),
        ("npm:github:u/r", "invalid"),
        ("npm:../evil@1", "invalid"),
    ],
)
def test_classify_spec_refuses_non_registry_specs(spec: str, reason: str) -> None:
    assert B.classify_spec("x", spec).kind == reason


def test_classify_spec_accepts_registry_specs_and_aliases() -> None:
    assert B.classify_spec("x", "^1.2.3") == B.SpecKind("registry", "x", "^1.2.3")
    assert B.classify_spec("x", "latest").kind == "registry"
    assert B.classify_spec("x", "").kind == "registry"
    assert B.classify_spec("x", "npm:@s/real@^2") == B.SpecKind("alias", "@s/real", "^2")
    assert B.classify_spec("x", "npm:real") == B.SpecKind("alias", "real", "")


def test_unresolvable_specs_are_recorded_and_never_guessed(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("real", "2.1.0")
    root = {
        **ROOT,
        "dependencies": {
            "from-git": "github:user/repo",
            "from-url": "https://example.com/x.tgz",
            "local": "file:../local",
            "mono": "workspace:^1",
            "missing": "^1",
            "nothing-yet": "^9",
            "renamed": "npm:real@^2",
        },
        "optionalDependencies": {"opt-git": "git+ssh://git@github.com/u/r.git"},
    }
    registry.publish("nothing-yet", "1.0.0")
    data, record, resolution = build(tmp_path, router, registry, root)
    assert {(u.name, u.reason, u.optional) for u in record.unresolved} == {
        ("from-git", "git", False),
        ("from-url", "remote", False),
        ("local", "file", False),
        ("mono", "protocol", False),
        ("missing", "not-on-registry", False),
        ("nothing-yet", "no-match", False),
        ("opt-git", "git", True),
    }
    assert record.status == "incomplete"
    assert "unresolved-required" in record.incomplete_reasons
    # the alias is resolved against its target and lives under the alias's folder
    assert [(p.location, p.package_name) for p in resolution.packages] == [
        ("node_modules/renamed", "real")
    ]
    files = files_of(data)
    assert json.loads(files["node_modules/renamed/package.json"])["name"] == "real"
    assert "example.com" not in " ".join(router.requests)
    # every name stays listed, so npm fetches none of them
    assert json.loads(files["package.json"])["bundleDependencies"] == sorted(
        [*root["dependencies"], "opt-git"]
    )


def test_an_optional_dependency_that_is_missing_does_not_make_it_incomplete(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("a", "1.0.0")
    root = {**ROOT, "dependencies": {"a": "1"}, "optionalDependencies": {"gone": "^1"}}
    _, record, _ = build(tmp_path, router, registry, root)
    assert [(u.name, u.reason, u.optional) for u in record.unresolved] == [
        ("gone", "not-on-registry", True)
    ]
    assert record.status == "complete"


# --- path safety ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["../evil", "..", ".", "a/b", "@s/..", "@s/../../x", "node_modules", ".bin", "a\\b", "", "@s"],
)
def test_unsafe_dependency_names_are_never_paths(
    tmp_path: Path, router: Router, registry: Registry, name: str
) -> None:
    root = {**ROOT, "dependencies": {name: "^1", "ok": "1"}}
    registry.publish("ok", "1.0.0")
    data, record, resolution = build(tmp_path, router, registry, root)
    assert [(u.name, u.reason) for u in record.unresolved] == [(name, "invalid-name")]
    assert locations(resolution) == {"node_modules/ok": "1.0.0"}
    assert all(
        p == "package.json" or p == "index.js" or p.startswith("node_modules/ok/")
        for p in files_of(data)
    )


def test_scoped_dependencies_live_under_their_scope(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("@scope/pkg", "1.0.0", dependencies={"@scope/util": "^1"})
    registry.publish("@scope/util", "1.0.1")
    data, _, resolution = build(
        tmp_path, router, registry, {**ROOT, "dependencies": {"@scope/pkg": "1"}}
    )
    assert locations(resolution) == {
        "node_modules/@scope/pkg": "1.0.0",
        "node_modules/@scope/util": "1.0.1",
    }
    assert "node_modules/@scope/util/package.json" in files_of(data)


def test_valid_name_and_registry_url_checks() -> None:
    assert B.valid_name("@types/node") and B.valid_name("Legacy_Mixed-Case")
    assert not B.valid_name("@s/node_modules")
    assert B.registry_tarball_url("https://registry.npmjs.org/a/-/a-1.0.0.tgz")
    for url in (
        "https://registry.npmjs.org@evil.example/a.tgz",
        "https://registry.npmjs.org.evil.example/a.tgz",
        "http://registry.npmjs.org/a/-/a-1.0.0.tgz",
        "https://registry.npmjs.org:8443/a.tgz",
        "https://registry.npmjs.org/../a.tgz",
        "https://registry.npmjs.org/a.tgz?x=1",
        "https://registry.npmjs.org/a%2F..%2Fb.tgz",
        "https://evil.example/a.tgz",
        7,
    ):
        assert not B.registry_tarball_url(url), url


def test_a_non_registry_tarball_url_is_refused(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    payload = tgz({"package.json": manifest_bytes({"name": "x", "version": "1.0.0"})})
    router.add_bytes("https://evil.example/x.tgz", payload)
    registry.publish(
        "x",
        "1.0.0",
        dist={"tarball": "https://evil.example/x.tgz", "integrity": sri_sha512(payload)},
    )
    registry.publish("nodigest", "1.0.0", dist={"tarball": "https://registry.npmjs.org/n.tgz"})
    root = {**ROOT, "dependencies": {"x": "1", "nodigest": "1"}}
    _, record, resolution = build(tmp_path, router, registry, root)
    assert resolution.packages == ()
    assert {(u.name, u.reason) for u in record.unresolved} == {
        ("x", "non-registry-tarball"),
        ("nodigest", "no-digest"),
    }
    assert "https://evil.example/x.tgz" not in router.requests


# --- fetching -----------------------------------------------------------------------------------


def test_integrity_mismatch_is_unresolved_and_not_shipped(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("a", "1.0.0", dependencies={"b": "1"})
    registry.publish("b", "1.0.0")
    url = registry.docs["a"]["versions"]["1.0.0"]["dist"]["tarball"]
    router.add_bytes(url, tgz({"package.json": b'{"name":"a","version":"1.0.0"}', "evil.js": "1"}))
    data, record, _ = build(tmp_path, router, registry, {**ROOT, "dependencies": {"a": "1"}})
    assert [(u.name, u.reason) for u in record.unresolved] == [("a", "integrity-mismatch")]
    assert record.status == "incomplete" and "fetch-failed" in record.incomplete_reasons
    assert [a.location for a in record.added] == ["node_modules/b"]
    assert not any(p.startswith("node_modules/a/") for p in files_of(data))


def test_transient_failures_propagate(tmp_path: Path, router: Router, registry: Registry) -> None:
    registry.publish("a", "1.0.0")
    registry.sync()
    router.offline.add(packument_url("a"))
    fetcher = make_fetcher(tmp_path, router)
    with pytest.raises(TransientFetchError):
        B.resolve(
            {**ROOT, "dependencies": {"a": "1"}},
            packuments=B.registry_packuments(fetcher),
            as_of=AS_OF,
        )


def test_dependency_tarball_anomalies_are_recorded(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("a", "1.0.0", scripts={"postinstall": "node x.js"})
    url = registry.docs["a"]["versions"]["1.0.0"]["dist"]["tarball"]
    # the tarball's package.json says something the registry's manifest doesn't
    tampered = tgz(
        {
            "package.json": manifest_bytes(
                {"name": "a", "version": "1.0.0", "scripts": {"preinstall": "node evil.js"}}
            ),
            "node_modules/.bin/a": "#!/bin/sh\n",
        }
    )
    router.add_bytes(url, tampered)
    registry.docs["a"]["versions"]["1.0.0"]["dist"]["integrity"] = sri_sha512(tampered)
    data, record, _ = build(tmp_path, router, registry, {**ROOT, "dependencies": {"a": "1"}})
    (added,) = record.added
    assert set(added.anomalies) == {"bin-dir-dropped", "manifest-differs:scripts"}
    assert added.hooks == ("preinstall",)  # what the tarball runs
    assert "node_modules/a/node_modules/.bin/a" not in files_of(data)


# --- caps -----------------------------------------------------------------------------------------


def test_caps_stop_resolution_and_refuse_the_bundle(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("a", "1.0.0", dependencies={"b": "1"})
    registry.publish("b", "1.0.0", dependencies={"c": "1"})
    registry.publish("c", "1.0.0")
    registry.sync()
    fetcher = make_fetcher(tmp_path, router)
    root = {**ROOT, "dependencies": {"a": "1"}}
    source = B.registry_packuments(fetcher)
    for caps, cap in (
        (B.BundleCaps(max_packages=2), "packages"),
        (B.BundleCaps(max_depth=2), "depth"),
    ):
        resolution = B.resolve(root, packuments=source, as_of=AS_OF, caps=caps)
        assert resolution.cap_exceeded == cap and not resolution.complete
        assert resolution.incomplete_reasons == (f"cap:{cap}",)
        with pytest.raises(B.BundleError) as caught:
            B.fetch_dependencies(resolution, fetcher)
        assert caught.value.reason == "over-cap"
        with pytest.raises(B.BundleError):
            B.build_bundle(original(root), resolution, B.DependencyFetch(trees={}))


def test_nesting_and_size_caps(tmp_path: Path, router: Router, registry: Registry) -> None:
    registry.publish("a", "1.0.0", dependencies={"c": "^1"})
    registry.publish("c", "1.0.0", latest=False)
    registry.publish("c", "2.0.0")
    root = {**ROOT, "dependencies": {"a": "1", "c": "^2"}}
    with pytest.raises(B.BundleError, match="nesting"):
        build(tmp_path, router, registry, root, caps=B.BundleCaps(max_nesting=1))
    with pytest.raises(B.BundleError, match="files"):
        build(tmp_path, router, registry, root, caps=B.BundleCaps(max_files=4))
    with pytest.raises(B.BundleError, match="compressed-bytes"):
        build(tmp_path, router, registry, root, caps=B.BundleCaps(max_compressed_bytes=200))


# --- the original tarball -------------------------------------------------------------------------


def test_originals_that_cannot_be_repacked_are_refused() -> None:
    good = manifest_bytes({**ROOT, "dependencies": {"a": "1"}})
    device = make_tar_gz(
        [TarEntry("package/package.json", good), TarEntry("package/dev", type=tarfile.CHRTYPE)]
    )
    cases = {
        "skipped-entries": device,
        "duplicates": make_tar_gz(
            [TarEntry("package/package.json", good), TarEntry("package/package.json", good)]
        ),
        "top-level-prefix": make_tar_gz(
            [TarEntry("package/package.json", good), TarEntry("other/x.js", b"1")]
        ),
        "no-package-json": tgz({"index.js": "1"}),
        "package-json-invalid": tgz({"package.json": b'["not", "an", "object"]'}),
        "unreadable": b"not a tarball",
    }
    for detail, data in cases.items():
        with pytest.raises(B.BundleError) as caught:
            B.read_original(data)
        assert (caught.value.reason, caught.value.detail) == ("original-not-repackable", detail)
    for raw in (b"[]", b'{"a": NaN}', b'{"a": Infinity}', b"\xff", b"\xef\xbb\xbf[]"):
        assert B.parse_manifest(raw) is None


def test_the_originals_own_node_modules_is_kept_and_not_replaced(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("shipped", "9.9.9")
    registry.publish("needed", "1.0.0")
    shipped = manifest_bytes(
        {"name": "shipped", "version": "1.0.0", "dependencies": {"needed": "1"}}
    )
    root = {**ROOT, "dependencies": {"shipped": "^1"}, "bundleDependencies": ["shipped"]}
    data, record, resolution = build(
        tmp_path,
        router,
        registry,
        root,
        files={
            "node_modules/shipped/package.json": shipped.decode(),
            "node_modules/shipped/index.js": "module.exports = 'mine';\n",
            "node_modules/loose/readme.md": "no manifest here\n",
        },
    )
    assert [(s.location, s.version) for s in record.supplied_by_package] == [
        ("node_modules/loose", None),
        ("node_modules/shipped", "1.0.0"),
    ]
    # npm takes a bundled folder as it is and never resolves its own dependencies
    assert locations(resolution) == {}
    files = files_of(data)
    assert files["node_modules/shipped/index.js"] == b"module.exports = 'mine';\n"
    assert files["node_modules/shipped/package.json"] == shipped
    assert record.package_json.changes == ()  # the bundle list was already right
    assert not any("shipped/-/" in url for url in router.requests)


def test_a_dependency_free_package_needs_no_bundle(tmp_path: Path, router: Router) -> None:
    fetcher = make_fetcher(tmp_path, router)
    data = original({**ROOT, "devDependencies": {"x": "1"}})
    with pytest.raises(B.BundleError) as caught:
        B.make_bundle(data, packuments=B.registry_packuments(fetcher), fetcher=fetcher, as_of=AS_OF)
    assert caught.value.reason == "nothing-to-bundle"
    assert router.requests == []


def test_a_resolution_for_another_package_json_is_refused(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("a", "1.0.0")
    _, _, resolution = build(tmp_path, router, registry, {**ROOT, "dependencies": {"a": "1"}})
    other = original({**ROOT, "dependencies": {"a": "1"}, "scripts": {"install": "x"}})
    with pytest.raises(B.BundleError) as caught:
        B.build_bundle(other, resolution, B.DependencyFetch(trees={}))
    assert caught.value.reason == "resolution-mismatch"


def test_rewrite_keeps_the_originals_indentation() -> None:
    raw = b'{\n\t"name": "kx-root",\n\t"version": "1.0.0",\n\t"dependencies": {"a": "1"}\n}'
    manifest = json.loads(raw)
    resolution = B.Resolution(
        package="kx-root",
        version="1.0.0",
        manifest_digest="",
        as_of=AS_OF,
        assumes={},
        bundle_names=("a",),
    )
    rewritten, _ = B.rewrite_manifest(raw, manifest, resolution)
    assert rewritten.startswith(b'{\n\t"name": "kx-root",') and not rewritten.endswith(b"\n")
    assert json.loads(rewritten)["bundleDependencies"] == ["a"]


# --- determinism and the written tarball ------------------------------------------------------


def _publish_all(registry: Registry, order: Callable[[list[str]], list[str]]) -> None:
    versions = order(["1.0.0", "1.1.0", "1.2.0"])
    for version in versions:
        registry.publish("a", version, dependencies={"b": "^1"}, latest=version == "1.2.0")
    for version in order(["1.0.0", "1.3.0"]):
        registry.publish("b", version, latest=version == "1.3.0")
    registry.docs["a"]["dist-tags"]["latest"] = "1.2.0"
    registry.docs["b"]["dist-tags"]["latest"] = "1.3.0"


def test_bundles_are_byte_identical_across_runs_and_packument_order(
    tmp_path: Path, registry: Registry
) -> None:
    root = {**ROOT, "dependencies": {"a": "^1"}, "scripts": {"preinstall": "echo hi"}}
    builds = []
    for i, order in enumerate((list, lambda xs: list(reversed(xs)), list)):
        router = Router()
        reg = Registry(router)
        _publish_all(reg, order)
        if i == 1:  # shuffle the packuments' own key order too
            for doc in reg.docs.values():
                doc["versions"] = dict(reversed(list(doc["versions"].items())))
                doc["time"] = dict(reversed(list(doc["time"].items())))
        builds.append(build(tmp_path / str(i), router, reg, root))
    assert builds[0][0] == builds[1][0] == builds[2][0]
    assert builds[0][1] == builds[1][1] == builds[2][1]
    assert builds[0][1].tar_sha256 == builds[1][1].tar_sha256


def test_the_written_tarball_is_npm_pack_shaped(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("a", "1.0.0")
    data, record, _ = build(tmp_path, router, registry, {**ROOT, "dependencies": {"a": "1"}})
    # gzip header: no FNAME flag, mtime 0
    assert data[:3] == b"\x1f\x8b\x08" and data[3] & 0x08 == 0 and data[4:8] == b"\0\0\0\0"
    raw = gzip.decompress(data)
    assert sha256_hex(raw) == record.tar_sha256 and sha256_hex(data) == record.bundle_sha256
    # the first ustar header (our own bytes): sorted first path, fixed metadata
    header = raw[:512]
    assert header[:100].rstrip(b"\0") == b"package/index.js"
    assert int(header[100:107], 8) == 0o644
    assert int(header[108:115], 8) == 0 and int(header[116:123], 8) == 0
    assert int(header[136:147], 8) == B.NPM_PACK_MTIME
    assert header[156:157] == b"0"
    assert header[265:297].strip(b"\0") == b"" and header[297:329].strip(b"\0") == b""
    paths = list(files_of(data))
    assert paths == sorted(paths, key=lambda p: p.encode())
    assert record.bundle_bytes == len(data)


def test_write_tar_gz_round_trips_long_and_unicode_paths() -> None:
    long = "package/" + "/".join(["node_modules/" + "d" * 60] * 4) + "/ü.js"
    entries = {long: (b"x", True), "package/package.json": (b"{}", False)}
    _, data = B.write_tar_gz(entries)
    tree = extract_tar_gz(data, strip_components=1)
    assert not tree.anomalies and not tree.skipped
    assert dict(tree.files) == {long.removeprefix("package/"): b"x", "package.json": b"{}"}
    assert B.write_tar_gz(entries) == B.write_tar_gz(dict(reversed(list(entries.items()))))


def test_predicted_network_for_native_addons(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("native", "1.0.0", extra_files={"binding.gyp": "{}"})
    registry.publish(
        "prebuilt", "1.0.0", scripts={"install": "prebuild-install || node-gyp rebuild"}
    )
    registry.publish("fine", "1.0.0", scripts={"install": "node-gyp-build"})
    root = {**ROOT, "dependencies": {"native": "1", "prebuilt": "1", "fine": "1"}}
    _, record, _ = build(tmp_path, router, registry, root)
    assert [(p.location, p.reason) for p in record.predicted_network] == [
        ("node_modules/native", "node-gyp"),
        ("node_modules/prebuilt", "install-tool"),
    ]
    native = next(a for a in record.added if a.name == "native")
    assert native.binding_gyp and native.hooks == ("install",)


def test_make_bundle_runs_every_step(tmp_path: Path, router: Router, registry: Registry) -> None:
    registry.publish("a", "1.0.0")
    registry.sync()
    fetcher = make_fetcher(tmp_path, router)
    data = original({**ROOT, "dependencies": {"a": "1"}})
    built = B.make_bundle(
        data, packuments=B.registry_packuments(fetcher), fetcher=fetcher, as_of=AS_OF
    )
    assert built.record.status == "complete"
    assert "node_modules/a/package.json" in files_of(built.data)
    with pytest.raises(ValueError, match="timezone"):
        B.resolve(ROOT, packuments=lambda name: None, as_of=datetime(2026, 1, 1))


# --- edge cases of dependencies' own tarballs -----------------------------------------------------


def test_a_dependencys_own_bundle_is_kept_and_checked(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    inner = json.dumps({"name": "inner", "version": "1.0.0"})
    registry.publish(
        "bundler",
        "1.0.0",
        dependencies={"inner": "^1"},
        bundleDependencies=["inner"],
        extra_files={"node_modules/inner/package.json": inner},
    )
    registry.publish("liar", "1.0.0", dependencies={"ghost": "^1"}, bundleDependencies=True)
    root = {**ROOT, "dependencies": {"bundler": "1", "liar": "1"}}
    data, record, resolution = build(tmp_path, router, registry, root)
    # neither bundled name is resolved: npm takes whatever the tarball ships
    assert locations(resolution) == {"node_modules/bundler": "1.0.0", "node_modules/liar": "1.0.0"}
    assert "node_modules/bundler/node_modules/inner/package.json" in files_of(data)
    liar = next(a for a in record.added if a.name == "liar")
    assert "bundled-dependency-missing" in liar.anomalies
    assert record.status == "complete"  # npm records the missing folder and carries on


def test_a_path_collision_keeps_the_first_file(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish(
        "a",
        "1.0.0",
        dependencies={"c": "^1"},
        extra_files={"node_modules/c/index.js": "module.exports = 'unlisted';\n"},
    )
    registry.publish("c", "1.0.0", latest=False)
    registry.publish("c", "2.0.0")
    root = {**ROOT, "dependencies": {"a": "1", "c": "^2"}}
    data, record, _ = build(tmp_path, router, registry, root)
    assert files_of(data)["node_modules/a/node_modules/c/index.js"] == (
        b"module.exports = 'unlisted';\n"
    )
    nested = next(a for a in record.added if a.location == "node_modules/a/node_modules/c")
    assert "path-collision" in nested.anomalies
    assert "path-collision" in record.incomplete_reasons


def test_a_dependency_without_a_usable_package_json(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("a", "1.0.0")
    url = registry.docs["a"]["versions"]["1.0.0"]["dist"]["tarball"]
    broken = tgz({"package.json": b"{not json", "index.js": "1"})
    router.add_bytes(url, broken)
    registry.docs["a"]["versions"]["1.0.0"]["dist"]["integrity"] = sri_sha512(broken)
    _, record, _ = build(tmp_path, router, registry, {**ROOT, "dependencies": {"a": "1"}})
    assert record.added[0].anomalies == ("package-json-unreadable",)
    assert record.incomplete_reasons == ("dependency-package-json",)


def test_missing_tarballs_and_missing_trees_are_fetch_failures(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("a", "1.0.0", dependencies={"b": "1"})
    registry.publish("b", "1.0.0")
    url = registry.docs["b"]["versions"]["1.0.0"]["dist"]["tarball"]
    del router.routes[url]
    _, record, resolution = build(tmp_path, router, registry, {**ROOT, "dependencies": {"a": "1"}})
    assert [(u.name, u.reason) for u in record.unresolved] == [("b", "tarball-not-found")]
    assert [a.name for a in record.added] == ["a"]
    # a fetch that left a package out entirely counts the same
    _, again = B.build_bundle(
        original({**ROOT, "dependencies": {"a": "1"}}), resolution, B.DependencyFetch(trees={})
    )
    assert again.added == () and again.incomplete_reasons == ("fetch-failed",)


def test_invalid_manifest_fields_are_recorded(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("p", "1.0.0")
    root = {
        **ROOT,
        "dependencies": ["a"],
        "optionalDependencies": {},
        "peerDependencies": {"p": "1"},
    }
    with pytest.raises(B.BundleError) as caught:
        build(tmp_path, router, registry, root)
    assert (caught.value.reason, caught.value.detail) == (
        "original-not-repackable",
        "dependencies-not-object",
    )
    registry.sync()
    fetcher = make_fetcher(tmp_path / "again", router)
    resolution = B.resolve(root, packuments=B.registry_packuments(fetcher), as_of=AS_OF)
    assert "invalid-manifest-field" in resolution.incomplete_reasons


def test_tags_and_non_string_specs(tmp_path: Path, router: Router, registry: Registry) -> None:
    registry.publish("a", "1.0.0", dependencies={"b": "latest"})
    registry.publish("b", "1.0.0")
    registry.publish("b", "2.0.0-beta.1", latest=False)
    root = {**ROOT, "dependencies": {"a": "1", "b": "latest", "weird": 7}}
    _, record, resolution = build(tmp_path, router, registry, root)
    assert locations(resolution) == {"node_modules/a": "1.0.0", "node_modules/b": "1.0.0"}
    b = next(p for p in resolution.packages if p.name == "b")
    assert {r.requirer for r in b.required_by} == {"", "node_modules/a"}
    assert [(u.name, u.reason, u.spec) for u in record.unresolved] == [
        ("weird", "invalid-spec", "7")
    ]
    assert resolution.post_check == ()


def test_the_self_check_compares_every_byte() -> None:
    _, data = B.write_tar_gz({"package/a.js": (b"1", False)})
    B._self_check(data, {"a.js": (b"1", False)}, B.DEFAULT_CAPS)
    with pytest.raises(B.BundleError, match="contents"):
        B._self_check(data, {"a.js": (b"2", False)}, B.DEFAULT_CAPS)
    with pytest.raises(B.BundleError, match="unreadable"):
        B._self_check(b"junk", {}, B.DEFAULT_CAPS)


def test_bundle_lists_normalize_like_npm() -> None:
    assert B.bundle_list({"bundleDependencies": True, "dependencies": {"a": "1", "b": "2"}}) == [
        "a",
        "b",
    ]
    assert B.bundle_list({"bundledDependencies": ["x", 3]}) == ["x"]
    assert B.bundle_list({"bundleDependencies": None, "bundledDependencies": ["x"]}) == []
    assert B.bundle_list({"bundleDependencies": {"y": "1"}}) == ["y"]
    assert B.bundle_list({"bundleDependencies": "no"}) == []


def test_an_optional_package_that_is_also_required_is_not_pruned(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("opt", "1.0.0", dependencies={"native": "^1", "old": "^1"})
    registry.publish("native", "1.0.0", os=["darwin"])
    registry.publish("old", "1.0.0", engines={"node": "<10"})
    registry.publish("needs-opt", "1.0.0", dependencies={"opt": "^1"})
    root = {**ROOT, "dependencies": {"needs-opt": "1"}, "optionalDependencies": {"opt": "1"}}
    _, record, resolution = build(tmp_path, router, registry, root)
    # opt is required through needs-opt: its platform failure is a real one, and its
    # engines failure only a warning
    assert locations(resolution) == {
        "node_modules/needs-opt": "1.0.0",
        "node_modules/old": "1.0.0",
        "node_modules/opt": "1.0.0",
    }
    assert not next(p for p in resolution.packages if p.name == "opt").optional
    assert [(u.name, u.reason, u.optional) for u in record.unresolved] == [
        ("native", "platform-mismatch", False)
    ]
    assert record.status == "incomplete" and resolution.passes == 1


def test_deeply_nested_untrusted_values_do_not_crash() -> None:
    deep: object = "x"
    for _ in range(100_000):
        deep = [deep]
    assert B._json_text(deep) == "<unencodable>"


# --- the stage's hooks: packuments, wants_bundle, the job summary ------------------------------


def test_registry_packuments_reads_dist_tags_and_maps_a_404_to_none(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("a", "1.0.0")
    registry.docs["a"]["dist-tags"]["beta"] = 7  # not a string: ignored
    registry.sync()
    router.add_json(packument_url("forbidden"), {"error": "no"}, status=403)
    source = B.registry_packuments(make_fetcher(tmp_path, router))
    doc = source("a")
    assert isinstance(doc, B.RegistryPackument) and doc.dist_tags == {"latest": "1.0.0"}
    assert source("absent") is None
    with pytest.raises(FetchError):
        source("forbidden")
    router.add_json(packument_url("odd"), {"name": "odd", "dist-tags": []})
    odd = source("odd")
    assert isinstance(odd, B.RegistryPackument) and odd.dist_tags == {}


@pytest.mark.parametrize(
    ("manifest", "wanted"),
    [
        ({}, False),
        ({"dependencies": {}}, False),
        ({"devDependencies": {"a": "1"}}, False),
        (
            {"peerDependencies": {"a": "1"}, "peerDependenciesMeta": {"a": {"optional": True}}},
            False,
        ),
        ({"dependencies": {"a": "1"}}, True),
        ({"optionalDependencies": {"a": "1"}}, True),
        ({"peerDependencies": {"a": "1"}}, True),
        ({"bundleDependencies": ["a"]}, True),
        ({"dependencies": "a"}, False),
    ],
)
def test_wants_bundle_matches_the_resolvers_bundle_list(
    manifest: dict[str, Any], wanted: bool
) -> None:
    assert B.wants_bundle(manifest) is wanted
    resolution = B.resolve({**ROOT, **manifest}, packuments=lambda name: None, as_of=AS_OF)
    assert resolution.needs_bundle is wanted


def test_the_job_summary_names_the_dependency_set(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("a", "1.0.0", dependencies={"@s/b": "1.0.0"})
    registry.publish("@s/b", "1.0.0")
    _, record, _ = build(tmp_path, router, registry, {**ROOT, "dependencies": {"a": "1.0.0"}})
    summary = record.job_bundle()
    assert summary.dependencies == ("@s/b", "a") and summary.top_level == ("@s/b", "a")
    assert (summary.added, summary.tar_sha256) == (2, record.tar_sha256)
    assert summary.original_sha256 == record.original_sha256
    assert summary.package_json_changes == ("bundleDependencies",)
    assert summary.assumes["npm"] == "11.12.1"
    moved = record.model_copy(
        update={"added": (record.added[0].model_copy(update={"version": "9.9.9"}),)}
    )
    assert moved.dependencies_sha256() != record.dependencies_sha256()
    assert record.dependencies_sha256() == record.model_copy().dependencies_sha256()


# --- hostile inputs and npm's own readings (2026-10-30 review) -----------------------------------


def tgz_modes(files: Mapping[str, tuple[bytes, int]]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for path, (data, mode) in files.items():
            info = tarfile.TarInfo(f"package/{path}")
            info.size, info.mode = len(data), mode
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(raw.getvalue(), mtime=0)


def retarball(registry: Registry, router: Router, name: str, version: str, body: bytes) -> None:
    dist = registry.docs[name]["versions"][version]["dist"]
    router.add_bytes(dist["tarball"], body)
    dist["integrity"] = sri_sha512(body)


def noise(kib: int) -> str:
    """Incompressible text, so a size cap is reached before the ratio limit."""
    return "".join(hashlib.sha256(str(i).encode()).hexdigest() for i in range(kib * 16))


def test_dependencies_are_read_within_what_is_left_of_the_caps(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    for name in ("a", "b", "c"):
        registry.publish(name, "1.0.0", extra_files={"blob.txt": noise(64)})
    registry.sync()
    fetcher = make_fetcher(tmp_path, router)
    root = {**ROOT, "dependencies": {"a": "1", "b": "1", "c": "1"}}
    resolution = B.resolve(root, packuments=B.registry_packuments(fetcher), as_of=AS_OF)
    for caps, cap in (
        (B.BundleCaps(max_unpacked_bytes=100_000), "unpacked-bytes"),
        (B.BundleCaps(max_files=5), "files"),
    ):
        router.requests.clear()
        with pytest.raises(B.BundleError) as caught:
            B.fetch_dependencies(resolution, fetcher, caps=caps)
        assert (caught.value.reason, caught.value.detail) == ("over-cap", cap)
        # stopped at b: c's tarball is never fetched, so a bundle never holds more than its caps
        assert not any("/c/-/" in url for url in router.requests)


def test_one_dependency_file_may_take_what_is_left_of_the_unpacked_cap(
    tmp_path: Path, router: Router, registry: Registry, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A native CLI binary is one file over `extract_tar_gz`'s default 64 MiB; it is bounded
    by the bundle's unpacked cap instead, here and in the self-check."""
    registry.publish("a", "1.0.0", extra_files={"blob.txt": noise(64)})
    registry.sync()
    fetcher = make_fetcher(tmp_path, router)
    root = {**ROOT, "dependencies": {"a": "1"}}
    resolution = B.resolve(root, packuments=B.registry_packuments(fetcher), as_of=AS_OF)
    seen: list[ExtractLimits] = []
    real = extract_tar_gz

    def spy(data: bytes, **kwargs: Any) -> Any:
        seen.append(kwargs["limits"])
        return real(data, **kwargs)

    monkeypatch.setattr(B, "extract_tar_gz", spy)
    caps = B.BundleCaps(max_unpacked_bytes=200 * 1024 * 1024)
    original = B.read_original(
        tgz({"package.json": json.dumps(root).encode()}), limits=caps.extract_limits()
    )
    B.fetch_dependencies(resolution, fetcher, caps=caps, original=original)
    left = caps.max_unpacked_bytes - sum(len(b) for b in original.files.values())
    assert [(x.max_file_bytes, x.max_total_bytes) for x in seen[1:]] == [(left, left)]
    assert seen[0].max_file_bytes == caps.extract_limits().max_file_bytes == caps.max_unpacked_bytes


def test_a_negative_declared_size_is_no_credit(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("neg", "1.0.0")
    registry.publish("big", "1.0.0")
    registry.docs["neg"]["versions"]["1.0.0"]["dist"]["unpackedSize"] = -(10**15)
    registry.docs["big"]["versions"]["1.0.0"]["dist"]["unpackedSize"] = 2_000
    registry.sync()
    source = B.registry_packuments(make_fetcher(tmp_path, router))
    resolution = B.resolve({**ROOT, "dependencies": {"neg": "1"}}, packuments=source, as_of=AS_OF)
    assert [p.declared_unpacked for p in resolution.packages] == [None]
    capped = B.resolve(
        {**ROOT, "dependencies": {"neg": "1", "big": "1"}},
        packuments=source,
        as_of=AS_OF,
        caps=B.BundleCaps(max_unpacked_bytes=1_000),
    )
    assert capped.cap_exceeded == "unpacked-bytes"


def test_a_deeply_nested_bundle_list_is_recorded_by_digest(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    """pydantic refuses JsonValue past ~255 levels; that used to crash the whole stage."""
    deep = "[" * 400 + "]" * 400
    raw = ('{"name":"kx-root","version":"1.0.0","bundleDependencies":{"a":' + deep + "}}").encode()
    data = tgz({"package.json": raw})
    built = B.make_bundle(
        data, packuments=lambda name: None, fetcher=make_fetcher(tmp_path, router), as_of=AS_OF
    )
    (change,) = built.record.package_json.changes
    assert change.field == "bundleDependencies" and change.before is None
    assert change.before_sha256 == B._digest(json.loads(raw)["bundleDependencies"])
    B.BundleRecord.load_json(built.record.model_dump_json())  # and it round-trips
    small = B.read_original(
        original({**ROOT, "bundleDependencies": ["a"], "dependencies": {"b": "1"}})
    )
    resolution = B.Resolution(
        package="kx-root",
        version="1.0.0",
        manifest_digest="",
        as_of=AS_OF,
        assumes={},
        bundle_names=("a", "b"),
    )
    _, (kept,) = B.rewrite_manifest(small.files["package.json"], small.manifest, resolution)
    assert (kept.before, kept.before_sha256) == (["a"], None)


def test_lookups_are_capped_per_bundle(tmp_path: Path, router: Router, registry: Registry) -> None:
    for i in range(6):
        registry.publish(f"d{i}", "1.0.0", readme="x" * 5_000)
    registry.sync()
    root = {**ROOT, "dependencies": {f"d{i}": "1" for i in range(6)} | {"gone": "1"}}
    for caps, cap in (
        (B.BundleCaps(max_packuments=3), "packuments"),
        (B.BundleCaps(max_edges=5), "edges"),
        (B.BundleCaps(max_packument_bytes=8_000), "packument-bytes"),
    ):
        router.requests.clear()
        source = B.registry_packuments(make_fetcher(tmp_path / cap, router))
        resolution = B.resolve(root, packuments=source, as_of=AS_OF, caps=caps)
        assert resolution.cap_exceeded == cap
        assert len(router.requests) <= 3
    # what the resolver keeps of a packument: the fields it reads, never the readme
    doc = B.RegistryPackument(registry.docs["d0"], expected_name="d0")
    kept = B._Versions.of(doc).versions["1.0.0"]
    assert set(kept) == {"name", "version", "readme"} - {"readme"} | {"dist"}
    assert set(kept["dist"]) == {"tarball", "integrity"}


def test_numbers_past_a_double_are_written_back_as_they_were(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    """JSON.parse reads 1e400 as Infinity; json.dumps would write `Infinity`, which npm's
    JSON.parse refuses (EJSONPARSE) while the record said complete."""
    registry.publish("a", "1.0.0")
    registry.sync()
    fetcher = make_fetcher(tmp_path, router)
    raw = (
        b'{\n  "name": "kx-root",\n  "version": "1.0.0",\n  "dependencies": {"a": "1"},\n'
        b'  "n": [1e400, -1E999, 1.5]\n}\n'
    )
    built = B.make_bundle(
        tgz({"package.json": raw}),
        packuments=B.registry_packuments(fetcher),
        fetcher=fetcher,
        as_of=AS_OF,
    )
    assert built.record.status == "complete"
    rewritten = files_of(built.data)["package.json"]
    assert b"1e400" in rewritten and b"-1E999" in rewritten and b"Infinity" not in rewritten
    assert json.loads(rewritten)["n"] == [math.inf, -math.inf, 1.5]
    # a package string equal to the placeholder can't be told from it: refused, not guessed
    marker = B._number_marker(0)
    clash = json.dumps({**ROOT, "dependencies": {"a": "1"}, "x": 1e308, "s": marker}).replace(
        "1e+308", "1e400"
    )
    with pytest.raises(B.BundleError, match="package-json-invalid"):
        B.make_bundle(
            tgz({"package.json": clash}),
            packuments=B.registry_packuments(fetcher),
            fetcher=fetcher,
            as_of=AS_OF,
        )
    # and the self-check reads the written package.json as JSON.parse would
    _, bom = B.write_tar_gz({"package/package.json": (b"\xef\xbb\xbf{}", False)})
    with pytest.raises(B.BundleError, match="package-json"):
        B._self_check(bom, {"package.json": (b"\xef\xbb\xbf{}", False)}, B.DEFAULT_CAPS)


def test_a_file_where_a_folder_goes_is_a_path_collision(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("foo", "1.0.0")
    # the package ships a file where its dependency's folder goes
    _, record, _ = build(
        tmp_path,
        router,
        registry,
        {**ROOT, "dependencies": {"foo": "^1"}},
        files={"node_modules/foo": "a file"},
    )
    assert record.status == "incomplete" and "path-collision" in record.incomplete_reasons
    # a dependency ships a file where a nested dependency's folder goes
    registry.publish("b", "1.0.0", latest=False)
    registry.publish("b", "2.0.0")
    registry.publish("a", "1.0.0", dependencies={"b": "1.0.0"}, extra_files={"node_modules/b": "x"})
    _, record, resolution = build(
        tmp_path / "2", router, registry, {**ROOT, "dependencies": {"a": "1", "b": "2"}}
    )
    assert "node_modules/a/node_modules/b" in locations(resolution)
    assert "path-collision" in record.incomplete_reasons
    owners = {a.location for a in record.added if "path-collision" in a.anomalies}
    assert owners == {"node_modules/a", "node_modules/a/node_modules/b"}
    # even with nothing placed under it, a file at a package-folder path is a conflict
    registry.publish("c", "1.0.0", extra_files={"node_modules/zz": "x"})
    _, record, _ = build(tmp_path / "3", router, registry, {**ROOT, "dependencies": {"c": "1"}})
    assert "path-collision" in record.incomplete_reasons
    assert B._path_clashes(["node_modules/.bin", "node_modules/a/x.js", "lib/a"]) == set()


def test_execute_bits_are_kept(tmp_path: Path, router: Router, registry: Registry) -> None:
    registry.publish("a", "1.0.0", scripts={"postinstall": "./setup.sh"})
    manifest_a = manifest_bytes(
        {"name": "a", "version": "1.0.0", "scripts": {"postinstall": "./setup.sh"}}
    )
    retarball(
        registry,
        router,
        "a",
        "1.0.0",
        tgz_modes(
            {
                "package.json": (manifest_a, 0o644),
                "setup.sh": (b"#!/bin/sh\n", 0o700),
                "lib.js": (b"1", 0o644),
            }
        ),
    )
    registry.sync()
    fetcher = make_fetcher(tmp_path, router)
    root = manifest_bytes(
        {**ROOT, "dependencies": {"a": "1"}, "scripts": {"preinstall": "./run.sh"}}
    )
    data = tgz_modes({"package.json": (root, 0o644), "run.sh": (b"#!/bin/sh\n", 0o755)})
    built = B.make_bundle(
        data, packuments=B.registry_packuments(fetcher), fetcher=fetcher, as_of=AS_OF
    )
    with tarfile.open(fileobj=io.BytesIO(built.data), mode="r:gz") as tar:
        modes = {m.name.removeprefix("package/"): m.mode for m in tar.getmembers()}
    assert modes == {
        "node_modules/a/lib.js": 0o644,
        "node_modules/a/package.json": 0o644,
        "node_modules/a/setup.sh": 0o755,
        "package.json": 0o644,
        "run.sh": 0o755,
    }
    _, written = B.write_tar_gz({"package/x": (b"1", False)})
    with pytest.raises(B.BundleError, match="modes"):
        B._self_check(written, {"x": (b"1", True)}, B.DEFAULT_CAPS)


def test_links_a_bom_and_repeated_keys_are_read_as_npm_reads_them(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("a", "1.0.0")
    registry.sync()
    fetcher = make_fetcher(tmp_path, router)
    pj = b'{"name":"kx-root","version":"0.0.1","version":"1.0.0","dependencies":{"a":"1"}}'
    data = make_tar_gz(
        [
            TarEntry("package/package.json", b"\xef\xbb\xbf" + pj),
            TarEntry("package/link", type=tarfile.SYMTYPE, linkname="/etc/passwd"),
            TarEntry("package/hard", type=tarfile.LNKTYPE, linkname="package/package.json"),
        ]
    )
    built = B.make_bundle(
        data, packuments=B.registry_packuments(fetcher), fetcher=fetcher, as_of=AS_OF
    )
    record = built.record
    assert record.status == "complete"
    assert record.normalized == (
        "link-entries-dropped",
        "package-json-bom",
        "package-json-duplicate-keys",
    )
    files = files_of(built.data)
    assert set(files) == {"package.json", "node_modules/a/index.js", "node_modules/a/package.json"}
    assert json.loads(files["package.json"])["version"] == "1.0.0"  # the last value, as JSON.parse
    assert not files["package.json"].startswith(b"\xef\xbb\xbf")
    assert built.record.summary()["normalized"] == list(record.normalized)


def test_a_shared_tarball_url_is_reused_only_with_the_same_digests(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("x", "1.0.0", latest=False)
    registry.publish("x", "2.0.0")
    registry.publish("a", "1.0.0", dependencies={"x": "1.0.0"})
    first = registry.docs["x"]["versions"]["1.0.0"]["dist"]["tarball"]
    registry.docs["x"]["versions"]["2.0.0"]["dist"]["tarball"] = first  # same URL, other digest
    _, record, _ = build(tmp_path, router, registry, {**ROOT, "dependencies": {"a": "1", "x": "2"}})
    assert [(u.name, u.reason, u.version) for u in record.unresolved] == [
        ("x", "integrity-mismatch", "2.0.0")
    ]


def test_the_queue_follows_arborists_order(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    """arborist pops shallower packages first, then by path: c (a's dependency, placed at the
    top) comes before m, so c's x@~1.2.0 is placed first and m's x@^1 reuses it. A FIFO queue
    put m's 1.5.0 at the top and nested a second x under c."""
    registry.publish("x", "1.2.9", latest=False)
    registry.publish("x", "1.5.0")
    registry.publish("c", "1.0.0", dependencies={"x": "~1.2.0"})
    registry.publish("a", "1.0.0", dependencies={"c": "1"})
    registry.publish("m", "1.0.0", dependencies={"x": "^1.0.0"})
    _, _, resolution = build(
        tmp_path, router, registry, {**ROOT, "dependencies": {"a": "1", "m": "1"}}
    )
    assert locations(resolution) == {
        "node_modules/a": "1.0.0",
        "node_modules/c": "1.0.0",
        "node_modules/m": "1.0.0",
        "node_modules/x": "1.2.9",
    }
    assert sorted(
        ["node_modules/b", "node_modules/@s/a", "node_modules/a-b", "node_modules/a_b"],
        key=B._collation_key,
    ) == [
        "node_modules/@s/a",
        "node_modules/a_b",
        "node_modules/a-b",
        "node_modules/b",
    ]


def test_a_peer_takes_the_parents_range_when_both_accept_it(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    """#loadPeerSet: d's peer x@~1.2.0 and the package's own x@^1 get one copy, 1.2.9."""
    registry.publish("x", "1.2.9", latest=False)
    registry.publish("x", "1.5.0")
    registry.publish("d", "1.0.0", peerDependencies={"x": "~1.2.0"})
    _, record, resolution = build(
        tmp_path, router, registry, {**ROOT, "dependencies": {"d": "1", "x": "^1"}}
    )
    assert locations(resolution) == {"node_modules/d": "1.0.0", "node_modules/x": "1.2.9"}
    assert record.peer_conflicts == () and record.status == "complete"


def test_a_peer_replaces_a_copy_not_yet_processed(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    """npm's REPLACE: the package's x@^1 placed 1.5.0 first (x sorts before y); y's peer
    x@~1.2.0 replaces it with 1.2.9, which still satisfies ^1."""
    registry.publish("x", "1.2.9", latest=False)
    registry.publish("x", "1.5.0")
    registry.publish("y", "1.0.0", peerDependencies={"x": "~1.2.0"})
    _, record, resolution = build(
        tmp_path, router, registry, {**ROOT, "dependencies": {"x": "^1", "y": "1"}}
    )
    assert locations(resolution) == {"node_modules/x": "1.2.9", "node_modules/y": "1.0.0"}
    x = next(p for p in resolution.packages if p.name == "x")
    assert {(r.requirer, r.spec) for r in x.required_by} == {
        ("", "^1"),
        ("node_modules/y", "~1.2.0"),
    }
    assert record.peer_conflicts == () and resolution.post_check == ()


def test_a_dependency_peer_on_the_package_itself_keeps_the_package(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("kx-root", "1.0.0", latest=False)
    registry.publish("kx-root", "2.0.0")
    registry.publish("plug", "1.0.0", peerDependencies={"kx-root": "^2"})
    _, record, resolution = build(
        tmp_path, router, registry, {**ROOT, "dependencies": {"plug": "1"}}
    )
    assert locations(resolution) == {"node_modules/plug": "1.0.0"}  # no second copy of itself
    assert [(c.name, c.found, c.found_version) for c in record.peer_conflicts] == [
        ("kx-root", "", "1.0.0")
    ]


def test_a_dependency_with_a_shrinkwrap_is_incomplete(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("d", "1.0.0", _hasShrinkwrap=True)
    _, record, resolution = build(tmp_path, router, registry, {**ROOT, "dependencies": {"d": "1"}})
    assert resolution.packages[0].has_shrinkwrap
    assert record.incomplete_reasons == ("dependency-shrinkwrap",)
    # the tarball's own file says so too, whatever the packument claims
    registry.publish("e", "1.0.0", extra_files={"npm-shrinkwrap.json": "{}"})
    _, record, _ = build(tmp_path / "2", router, registry, {**ROOT, "dependencies": {"e": "1"}})
    assert "npm-shrinkwrap" in record.added[0].anomalies
    assert record.incomplete_reasons == ("dependency-shrinkwrap",)


def test_a_shipped_folder_satisfies_only_the_packages_own_edges(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("x", "2.0.0")
    registry.publish("d", "1.0.0", dependencies={"x": "^2"})
    shipped = json.dumps({"name": "x", "version": "1.0.0", "dependencies": {"never": "1"}})
    _, record, resolution = build(
        tmp_path,
        router,
        registry,
        {**ROOT, "dependencies": {"d": "1", "x": "^9"}},
        files={"node_modules/x/package.json": shipped},
    )
    # the package's own x@^9 takes the shipped x@1; d's x@^2 gets its own copy
    assert locations(resolution) == {
        "node_modules/d": "1.0.0",
        "node_modules/d/node_modules/x": "2.0.0",
    }
    assert [(s.location, s.satisfies) for s in record.supplied_by_package] == [
        ("node_modules/x", False)
    ]
    assert record.unresolved == ()  # the shipped x's own dependency is never resolved


def test_known_downloaders_are_predicted_to_need_the_network(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("puppeteer", "1.0.0", scripts={"postinstall": "node install.mjs"})
    registry.publish("electron", "45.0.0")  # no hook: nothing to predict
    root = {**ROOT, "dependencies": {"puppeteer": "1", "electron": "45"}}
    _, record, _ = build(tmp_path, router, registry, root)
    assert [(p.package_name, p.reason) for p in record.predicted_network] == [
        ("puppeteer", "known-downloader")
    ]


def test_http_registry_tarballs_are_fetched_over_https(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    registry.publish("old", "0.1.0")
    dist = registry.docs["old"]["versions"]["0.1.0"]["dist"]
    dist["tarball"] = dist["tarball"].replace("https://", "http://")
    data, record, resolution = build(
        tmp_path, router, registry, {**ROOT, "dependencies": {"old": "0.1"}}
    )
    assert resolution.packages[0].tarball.startswith(B.REGISTRY_TARBALL_PREFIX)
    assert record.status == "complete" and "node_modules/old/package.json" in files_of(data)


def test_a_dist_tag_edge_takes_any_registry_copy(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    """dep-valid.js: a tag "presumably came from the registry and was tagged at some point"."""
    registry.publish("x", "1.0.0", latest=False)
    registry.publish("x", "2.0.0")
    registry.publish("a", "1.0.0", dependencies={"x": "1"})
    registry.publish("b", "1.0.0", dependencies={"x": "latest"})
    _, _, resolution = build(
        tmp_path, router, registry, {**ROOT, "dependencies": {"a": "1", "b": "1"}}
    )
    assert locations(resolution) == {
        "node_modules/a": "1.0.0",
        "node_modules/b": "1.0.0",
        "node_modules/x": "1.0.0",
    }
    assert resolution.post_check == ()


def test_a_long_chain_of_peers_does_not_recurse(
    tmp_path: Path, router: Router, registry: Registry
) -> None:
    for i in range(1_200):
        registry.publish(f"p{i}", "1.0.0", peerDependencies={f"p{i + 1}": "1"} if i < 1_199 else {})
    caps = B.BundleCaps(max_depth=1_300)  # the depth cap would stop a chain long before
    root = {**ROOT, "dependencies": {"p0": "1"}}
    _, _, resolution = build(tmp_path, router, registry, root, caps=caps)
    assert len(resolution.packages) == 1_200 and resolution.complete
