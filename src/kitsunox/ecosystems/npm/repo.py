"""Where an npm release's code should come from: its GitHub repository, the package's
directory in it (`repository.directory`, for monorepos), and the commit.

The commit is `gitHead` when the release records one (`npm publish` from a git working tree
adds it). Otherwise it is the commit of a release tag, in the shapes release tools use:
`v1.2.3`, `1.2.3`, `name@1.2.3` (changesets, lerna), `name-v1.2.3` (release-please). A tag
is weaker evidence than `gitHead`: anyone with push access can move it, so the comparison
records which was used.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Final

from kitsunox.core.models import Change
from kitsunox.ecosystems.npm.rules.metadata import (
    INSTALL_HOOKS,
    runtime_dependencies,
    scripts,
    snippet,
)
from kitsunox.githost.github import GitHubRepo
from kitsunox.stages.repo import ManifestDifference

# Every dependency section a repository's manifest may list a package under: build tools move
# entries between them (and rewrite `workspace:` specs), so only the name is compared.
_DEPENDENCY_SECTIONS: Final = (
    "dependencies",
    "optionalDependencies",
    "peerDependencies",
    "devDependencies",
    "bundleDependencies",
    "bundledDependencies",
)

_SHA: Final = re.compile(r"^[0-9a-f]{40}$")


class NpmLocator:
    def repository(self, change: Change) -> tuple[GitHubRepo, str] | None:
        repo = GitHubRepo.from_url(change.repository_url)
        if repo is None:
            return None
        return repo, _directory(change.new.manifest.get("repository"))

    def commit(self, change: Change, refs: Mapping[str, str]) -> tuple[str, str] | None:
        head = change.new.publish.git_head
        if head is not None and _SHA.match(head):
            return head, "gitHead"
        for tag in release_tags(change.new.ref.name, change.new.ref.version):
            commit = refs.get(f"refs/tags/{tag}")
            if commit is not None:
                return commit, f"tag {tag}"
        return None

    def package_directory(self, change: Change, repo: Mapping[str, bytes]) -> str | None:
        """The directory of the repository's `package.json` named like the release: the root's
        if it matches, else the shallowest. Monorepos often don't set `repository.directory`,
        and their root manifest (a private workspace) says nothing about one package's scripts
        or dependencies: comparing with it reported Playwright's install hooks as missing from
        git. With no name match, the root still counts unless it is a workspace: forks and
        renamed packages (`wdio-web-reporter` from `wdio-spec-reporter`) keep their repository's
        manifest under the old name."""
        manifests = sorted(
            (
                path.removesuffix("package.json").rstrip("/")
                for path in repo
                if path.rpartition("/")[2] == "package.json" and "node_modules/" not in path
            ),
            key=lambda directory: (directory.count("/") + bool(directory), directory),
        )
        for directory in manifests:
            manifest = _manifest(repo, f"{directory}/package.json" if directory else "")
            if manifest is not None and manifest.get("name") == change.new.ref.name:
                return directory
        root = _manifest(repo)
        if root is None or "workspaces" in root or root.get("private") is True:
            return None
        return ""

    def manifest_differences(
        self, package: Mapping[str, bytes], repo: Mapping[str, bytes]
    ) -> tuple[ManifestDifference, ...]:
        """Install hooks the release runs that the repository's `package.json` doesn't have
        (or has differently), and runtime dependencies the repository's manifest doesn't name
        anywhere. Nothing if either manifest is missing or unreadable."""
        ours, theirs = _manifest(package), _manifest(repo)
        if ours is None or theirs is None:
            return ()
        differences = []
        repo_scripts = scripts(theirs)
        for hook, command in sorted(scripts(ours).items()):
            if hook in INSTALL_HOOKS and _normalised(command) != _normalised(
                repo_scripts.get(hook, "")
            ):
                differences.append(
                    ManifestDifference(
                        field=f"scripts.{hook}",
                        package=snippet(command),
                        repo=snippet(repo_scripts.get(hook)),
                    )
                )
        named: set[str] = set()
        for section in _DEPENDENCY_SECTIONS:
            listed = theirs.get(section)
            if isinstance(listed, Mapping | list):  # bundleDependencies may be a list
                named.update(name for name in listed if isinstance(name, str))
        for name, spec in sorted(runtime_dependencies(ours).items()):
            if name not in named:
                differences.append(
                    ManifestDifference(
                        field=f"dependencies.{name}", package=snippet(spec), repo=None
                    )
                )
        return tuple(differences)


def _manifest(tree: Mapping[str, bytes], path: str = "") -> dict[str, object] | None:
    raw = tree.get(path or "package.json")
    if raw is None:
        return None
    try:
        manifest = json.loads(raw)
    except ValueError:
        return None
    return manifest if isinstance(manifest, dict) else None


def _normalised(command: str) -> str:
    return " ".join(command.replace("node_modules/.bin/", "").split())


def release_tags(name: str, version: str) -> tuple[str, ...]:
    short = name.rsplit("/", 1)[-1]
    return tuple(
        dict.fromkeys(
            (
                f"v{version}",
                version,
                f"{name}@{version}",
                f"{short}@{version}",
                f"{name}@v{version}",
                f"{short}-v{version}",
                f"{short}@v{version}",
            )
        )
    )


def _directory(repository: object) -> str:
    """`repository.directory`, if it is a plain relative path; otherwise the repository root."""
    if not isinstance(repository, Mapping):
        return ""
    directory = repository.get("directory")
    if not isinstance(directory, str):
        return ""
    parts = [p for p in directory.strip().strip("/").split("/") if p not in ("", ".")]
    if any(p == ".." or "\\" in p for p in parts):
        return ""
    return "/".join(parts)
