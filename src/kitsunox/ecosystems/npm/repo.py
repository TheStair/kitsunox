"""Where an npm release's code should come from: its GitHub repository, the package's
directory in it (`repository.directory`, for monorepos), and the commit.

The commit is `gitHead` when the release records one (`npm publish` from a git working tree
adds it). Otherwise it is the commit of a release tag, in the shapes release tools use:
`v1.2.3`, `1.2.3`, `name@1.2.3` (changesets, lerna), `name-v1.2.3` (release-please). A tag
is weaker evidence than `gitHead`: anyone with push access can move it, so the comparison
records which was used.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Final

from kitsunox.core.models import Change
from kitsunox.githost.github import GitHubRepo

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
