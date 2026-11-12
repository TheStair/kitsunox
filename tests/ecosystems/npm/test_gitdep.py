"""Git dependency specs as data: which GitHub repository and reference a spec names, which
commit that is, and which scripts npm runs when it installs it (decision 0020)."""

import pytest

from kitsunox.ecosystems.npm.gitdep import (
    GIT_HOOKS,
    GitHubSpec,
    expand_runs,
    github_spec,
    non_registry,
    npm_runs,
    presented_manifest,
    redacted,
    resolve,
)
from kitsunox.ecosystems.npm.rules.metadata import INSTALL_HOOKS

A, B, C = "a" * 40, "b" * 40, "c" * 40


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("github:o/r", GitHubSpec("o", "r")),
        ("github:o/r#v1.2.0", GitHubSpec("o", "r", committish="v1.2.0")),
        ("o/r#main", GitHubSpec("o", "r", committish="main")),
        ("o/r.git", GitHubSpec("o", "r")),
        (f"git+https://github.com/o/r.git#{A}", GitHubSpec("o", "r", committish=A)),
        ("git+https://ghp_x@github.com/O/R.git", GitHubSpec("O", "R")),  # credentials dropped
        ("git+ssh://git@github.com/o/r.git#dev", GitHubSpec("o", "r", committish="dev")),
        ("git+ssh://git@github.com:o/r.git", GitHubSpec("o", "r")),
        ("git@github.com:o/r.git#v1", GitHubSpec("o", "r", committish="v1")),
        ("git://github.com/o/r.git", GitHubSpec("o", "r")),
        ("https://github.com/o/r", GitHubSpec("o", "r")),
        ("github:o/r#semver:^1.2", GitHubSpec("o", "r", semver="^1.2")),
        (
            "github:o/r#semver:^1::path:packages/x",
            GitHubSpec("o", "r", semver="^1", path="packages/x"),
        ),
        ("github:o/r#path:../../etc", GitHubSpec("o", "r")),  # a traversal is not a directory
        (
            f"https://codeload.github.com/o/r/tar.gz/{A}",
            GitHubSpec("o", "r", committish=A, tarball=True),
        ),
        (
            "https://github.com/o/r/archive/refs/tags/v1.0.0.tar.gz",
            GitHubSpec("o", "r", committish="refs/tags/v1.0.0", tarball=True),
        ),
        (
            "https://github.com/o/r/tarball/main",
            GitHubSpec("o", "r", committish="main", tarball=True),
        ),
    ],
)
def test_github_specs(spec: str, expected: GitHubSpec) -> None:
    assert github_spec(spec) == expected


@pytest.mark.parametrize(
    "spec",
    [
        "^1.2.3",
        "npm:other@1",
        "file:../x",
        "@scope/x@1.0.0",  # a local path to npm
        "gitlab:o/r",
        "git+https://gitlab.com/o/r.git",
        "https://example.com/x.tgz",
        "https://github.com/o/r/releases/download/v1/x.tgz",  # a release asset, not the repo
        "https://github.com/o/r/tree/main",
        "github:o/..",
        "github:o/r#a b",
        "gist:abc",
    ],
)
def test_not_a_github_repository(spec: str) -> None:
    assert github_spec(spec) is None


REFS = {
    "HEAD": A,
    "refs/heads/main": A,
    "refs/heads/dev": B,
    "refs/tags/v1.2.0": B,
    "refs/tags/v1.3.1": C,
    "refs/tags/v2.0.0": A,
    "refs/pull/7/head": C,
}


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("github:o/r", (A, "the default branch")),
        (f"github:o/r#{B.upper()}", (B, "commit")),  # a full id needs no ref
        ("github:o/r#dev", (B, "branch dev")),
        ("github:o/r#v1.2.0", (B, "tag v1.2.0")),
        ("github:o/r#refs/pull/7/head", (C, "ref refs/pull/7/head")),
        ("github:o/r#pull/7/head", (C, "ref pull/7/head")),
        ("github:o/r#semver:^1.2", (C, "tag v1.3.1 (semver:^1.2)")),
        ("github:o/r#cccccccc", (C, "commit cccccccc")),
        ("github:o/r#semver:^9", None),
        ("github:o/r#gone", None),
        ("github:o/r#aaaaaaa", (A, "commit aaaaaaa")),  # HEAD, main and v2.0.0: one commit
    ],
)
def test_resolve(spec: str, expected: tuple[str, str] | None) -> None:
    parsed = github_spec(spec)
    assert parsed is not None
    assert resolve(parsed, REFS) == expected


def test_an_abbreviated_commit_must_be_unambiguous() -> None:
    parsed = github_spec("github:o/r#abcdef1")
    assert parsed is not None
    assert (
        resolve(
            parsed, {"refs/heads/x": "abcdef1" + "0" * 33, "refs/heads/y": "abcdef1" + "1" * 33}
        )
        is None
    )
    assert resolve(github_spec("github:o/r") or parsed, {}) is None  # an empty repository


def test_redacted() -> None:
    assert (
        redacted("git+https://ghp_secret@github.com/o/r.git")
        == "git+https://***@github.com/o/r.git"
    )
    assert redacted("github:o/r") == "github:o/r"


def test_expand_runs() -> None:
    declared = {
        "prebuild": "rimraf dist",
        "build": "tsc && npm run copy",
        "copy": "node scripts/copy.js",
        "postbuild": "echo done",
        "loop": "npm run loop",
    }
    assert (
        expand_runs("npm run --silent build", declared)
        == "rimraf dist && tsc && node scripts/copy.js && echo done"
    )
    assert expand_runs("yarn run missing", declared) == "yarn run missing"
    assert "npm run loop" in expand_runs("npm run loop", declared)  # stops after RUN_DEPTH


def test_npm_runs_puts_git_hooks_in_free_install_slots() -> None:
    manifest = {"scripts": {"install": "node a.js", "prepare": "npm run build", "build": "tsc"}}
    slots, held = npm_runs(manifest, GIT_HOOKS)
    assert slots == {"install": "node a.js", "postinstall": "tsc"}
    assert held == {"install": ("install",), "postinstall": ("prepare",)}
    # A remote tarball (an archive URL) runs only the install hooks.
    assert npm_runs(manifest, INSTALL_HOOKS) == (
        {"install": "node a.js"},
        {"install": ("install",)},
    )


def test_npm_runs_joins_hooks_when_no_slot_is_free() -> None:
    manifest = {
        "scripts": {
            "preinstall": "a",
            "install": "b",
            "postinstall": "c",
            "preprepare": "d",
            "prepare": "e",
        }
    }
    slots, held = npm_runs(manifest, GIT_HOOKS)
    assert slots["postinstall"] == "c && d && e"
    assert held["postinstall"] == ("postinstall", "preprepare", "prepare")
    presented = presented_manifest({**manifest, "name": "x"}, slots)
    assert presented["name"] == "x"
    assert presented["scripts"] == {"preinstall": "a", "install": "b", "postinstall": "c && d && e"}


def test_non_registry() -> None:
    manifest = {
        "dependencies": {"a": "^1", "b": "github:o/b"},
        "optionalDependencies": {"c": "x/y"},
    }
    assert non_registry(manifest) == {"b": "github:o/b", "c": "x/y"}
