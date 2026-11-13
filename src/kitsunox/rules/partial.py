"""Stage 2 artifact rule: what a partial read did not read (decision 0021).

A version with an install hook over Stage 2's download cap is streamed once and only its text
and code are kept (`util.archive.stream_tar_gz`); the rest is listed in the tree's `omitted`.
The reviewer needs to know that the verdict rests on part of the package: this INFO finding
says how many files and bytes were not read, and why, with the largest as evidence. Weight 0:
it explains, it never scores.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Final

from kitsunox.core.models import Evidence, EvidenceKind, Finding, Severity, VersionSnapshot
from kitsunox.core.rules import BaseRule
from kitsunox.util.archive import OmittedFile

MAX_EVIDENCE: Final = 5
REASONS: Final = {
    "binary": "binary",
    "file": "over the per-file limit",
    "budget": "past the kept-bytes budget",
}


def omitted_files(files: Mapping[str, bytes]) -> tuple[OmittedFile, ...]:
    """The files a partial read of `files` did not keep (none for a whole read)."""
    omitted = getattr(files, "omitted", ())
    return tuple(omitted) if isinstance(omitted, tuple) else ()


def megabytes(size: int) -> str:
    return f"{size / 1_000_000:.1f} MB"


def partial_summary(omitted: Sequence[OmittedFile]) -> str:
    """`N files (X MB) not read`, the decision note and the finding's opening."""
    total = sum(o.size for o in omitted)
    return f"{len(omitted)} file{'s' if len(omitted) != 1 else ''} ({megabytes(total)}) not read"


class PartialRead(BaseRule):
    """The version was read partially: some of its files were not read."""

    id = "static.partial-read"
    severity = Severity.INFO
    weight = 0.0
    title = "Partial read: some files were not read"

    def evaluate_artifact(
        self, snapshot: VersionSnapshot, files: Mapping[str, bytes]
    ) -> Sequence[Finding]:
        omitted = omitted_files(files)
        if not omitted:
            return ()
        by_reason = Counter(o.reason for o in omitted)
        reasons = ", ".join(
            f"{count} {REASONS[reason]}" for reason, count in sorted(by_reason.items())
        )
        kept = sum(len(content) for content in files.values())
        largest = sorted(omitted, key=lambda o: (-o.size, o.path))[:MAX_EVIDENCE]
        return (
            self.finding(
                f"Partial read: {partial_summary(omitted)} ({reasons}). The package declares "
                "more than Stage 2 downloads whole, and has an install hook, so its text and "
                f"code were kept ({len(files)} files, {megabytes(kept)}) and every other file "
                "only listed with its size and SHA-256. No rule read the files not kept.",
                *(
                    Evidence(
                        kind=EvidenceKind.METADATA,
                        path=o.path,
                        snippet=f"{o.size:,} bytes, {REASONS[o.reason]}, sha256 {o.sha256[:16]}",
                    )
                    for o in largest
                ),
            ),
        )
