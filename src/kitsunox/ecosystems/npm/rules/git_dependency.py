"""Stage 4: the install code of the dependencies a release installs from GitHub (decision 0020).

A git dependency's `preinstall`, `install`, `postinstall` and `prepare` scripts run when the
release is installed, as surely as the release's own hooks: `web3-mev-error-decoder@0.1.0`
(2026-11-09, malicious) shipped no install code and depended on
`github:outgoingyang/multicall-error-decoder`, whose `install` hook decrypted its strings and
downloaded and started a payload. `stages.gitdeps` reads such a dependency's install code with
the install rules (Stages 1-3) as if it were a package of its own; this rule shows what they
found under the dependency's name (`ctx.source_dependencies`):

- each finding as the rule made it (its id, severity and weight, so it scores like the
  release's own install findings), with the dependency named in the explanation and its
  evidence under `dep:<name>@<commit12>/` (`dependency_path`). A hook the rules read in an
  install slot (`postinstall`) but that the dependency declares as `prepare` is shown under
  its own name;
- one INFO summary: the repository, commit and how the reference resolved, the scripts npm
  runs, and what the install code uses (network, processes, files, decryption: `reaches`);
- an INFO note (`Not evaluated: ...`) for a dependency that wasn't read: a deleted repository
  or missing ref, an archive over the limits, the run's cap, another git host, a tarball on
  another host. Only `npm.dependency.non-registry` then speaks for it, as before;
- an INFO note listing the dependency's own non-registry dependencies (not followed).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from kitsunox.core.models import Candidate, Evidence, EvidenceKind, Finding, Severity
from kitsunox.core.rules import BaseRule
from kitsunox.ecosystems.npm.gitdep import GIT_HOOKS
from kitsunox.ecosystems.npm.rules.metadata import snippet
from kitsunox.stages.correlate import (
    NOT_EVALUATED,
    CorrelationContext,
    SourceDependency,
    dependency_path,
)

_SCRIPT: Final = "package.json:scripts."
_INLINE: Final = "package.json#scripts."
SLOT_NOTE: Final = (
    " npm runs the dependency's {hooks} when it installs it from git; the install rules read"
    " {plural} as `{slot}`."
)


def _declared(path: str, dependency: SourceDependency) -> tuple[str, str | None]:
    """`path` with an install slot replaced by the dependency's own hooks it holds, and the
    slot when they differ from it."""
    for prefix, suffix in ((_SCRIPT, ""), (_INLINE, ".js")):
        if not path.startswith(prefix):
            continue
        slot = path.removeprefix(prefix).removesuffix(suffix)
        hooks = dependency.hooks.get(slot)
        if hooks is None or hooks == (slot,):
            return path, None
        return f"{prefix}{'+'.join(hooks)}{suffix}", slot
    return path, None


def relabeled(finding: Finding, dependency: SourceDependency) -> Finding:
    """`finding` (about the dependency's files) as the release's: its evidence under the
    dependency's `dep:` prefix, the dependency named in its explanation."""
    evidence = []
    renamed: dict[str, tuple[str, ...]] = {}
    for e in finding.evidence:
        path, slot = _declared(e.path or "package.json", dependency)
        if slot is not None:
            renamed[slot] = dependency.hooks[slot]
        evidence.append(e.model_copy(update={"path": dependency_path(dependency, path)}))
    if not evidence:
        evidence.append(
            Evidence(
                kind=EvidenceKind.MANIFEST_FIELD, path=dependency_path(dependency, "package.json")
            )
        )
    notes = "".join(
        SLOT_NOTE.format(
            hooks=", ".join(f"`{h}`" for h in hooks),
            plural="it" if len(hooks) == 1 else "them",
            slot=slot,
        )
        for slot, hooks in sorted(renamed.items())
    )
    return finding.model_copy(
        update={
            "explanation": f"{_named(dependency)}: {finding.explanation}{notes}",
            "evidence": tuple(evidence),
        }
    )


def _named(dependency: SourceDependency) -> str:
    commit = (dependency.commit or "")[:12]
    return f"Git dependency `{dependency.name}` ({dependency.repo} at {commit}, {dependency.how})"


class GitDependencyCode(BaseRule):
    """See the module docstring. v1 (2026-11-12, round 10 G)."""

    id = "npm.git-dependency"
    version = 1
    severity = Severity.INFO
    weight = 0.0
    title = "Git dependency's install code"

    def evaluate_candidate(
        self, candidate: Candidate, ctx: CorrelationContext
    ) -> Sequence[Finding]:
        out: list[Finding] = []
        for dependency in ctx.source_dependencies:
            declared = Evidence(
                kind=EvidenceKind.MANIFEST_FIELD,
                path=f"package.json:dependencies.{dependency.name}",
                after=snippet(dependency.spec),
            )
            if dependency.unavailable is not None or dependency.commit is None:
                out.append(
                    self.finding(
                        f"{NOT_EVALUATED}the install code of dependency `{dependency.name}`"
                        f" (`{snippet(dependency.spec)}`): {dependency.unavailable}.",
                        declared,
                    )
                )
                continue
            out.extend(relabeled(f, dependency) for f in dependency.findings)
            out.append(self._summary(dependency, declared))
            if dependency.nested:
                out.append(
                    self.finding(
                        f"{_named(dependency)} has its own dependencies from outside the"
                        " registry, which were not read: "
                        + "; ".join(f"`{n}`" for n in dependency.nested)
                        + ".",
                        Evidence(
                            kind=EvidenceKind.MANIFEST_FIELD,
                            path=dependency_path(dependency, "package.json:dependencies"),
                        ),
                    )
                )
        return out

    def _summary(self, dependency: SourceDependency, declared: Evidence) -> Finding:
        held = {h for hooks in dependency.hooks.values() for h in hooks}
        hooks = [h for h in GIT_HOOKS if h in held]  # in the order npm runs them
        runs = (
            "npm runs its " + ", ".join(f"`{h}`" for h in hooks) + " at install"
            if hooks
            else "npm runs none of its scripts at install"
        )
        compared = (
            f", compared with {dependency.base_commit[:12]}, the commit the previous release pinned"
            if dependency.base_commit
            else ""
        )
        uses = sorted(
            {
                (e.snippet or "")[1:].partition("]")[0]
                for e in dependency.reaches
                if (e.snippet or "").startswith("[")
            }
        )
        reaches = f" Its install code uses: {', '.join(uses)}." if uses else ""
        evidence = [declared]
        for e in dependency.reaches:
            evidence.append(
                e.model_copy(update={"path": dependency_path(dependency, e.path or "")})
            )
        return self.finding(
            f"{_named(dependency)}{compared}: {runs}.{reaches}",
            *evidence,
        )


RULES: Final = (GitDependencyCode(),)
