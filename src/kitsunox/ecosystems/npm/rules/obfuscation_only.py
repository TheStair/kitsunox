"""Stage 4: a new package whose only signal is obfuscated JavaScript (`npm.obfuscation-only`).

`static.obfuscated` (Stage 2, MEDIUM) reports a version on its own. On the 3,716 verdicted live
versions, 21 were reported by it and nothing else (every other finding INFO): 20 benign, 1
unverified, no positive. Most are a publisher's own javascript-obfuscator build of a library or
CLI (`@univerjs-pro/*`'s licensed modules, `@numbors/cli`, `@oddsockets/*`, `@fcjplugins/*`,
`xgis-cog-*`). The positives the rule reports all have more: the six malicious `*-ai-sdk`
packages carry Stage 2's LOW `network`/`process-exec`/`encoded-blob` matches or
`known-signature`/`padded-code`; the `vm-day1` samples it reports alone are updates (an
obfuscated file new in an established package: `@duckdb/node-api@1.3.3`, `web3rpcs`,
`webpikes`, `akasearch`, `dreame-claude`, `dzcvhfruwluwe`), obfuscated web pages
(`mobiwaefhxc3`'s `index.html`; `mad-1.2.6.2.2.8`'s `script.js` beside its `index.html`, which
the registry's manifest doesn't show: it strips `files`) and `multi-cloud-data-migrator@1.256.25`,
a new package that declares a `prepare` script. None of the three new ones says where it comes
from (no `repository`, no `homepage`).

This rule notes (INFO, weight 0) a version where all of these hold, and Stage 4's `EXPLAINED`
then makes `static.obfuscated` LOW, weight 1, with the note, so the version is no longer
reported on obfuscation alone (the score still shows it):

- a new package (no previous release);
- `static.obfuscated` is MEDIUM on at least one file, and no other rule's finding is above INFO
  (any LOW keeps the version as it was: the `*-ai-sdk` packages);
- no obfuscated file is an HTML page, and the manifest names no HTML file (`main`, `files`,
  `browser`, `unpkg`, `jsdelivr`, `module`, `exports`, `bin`): a page served from a CDN;
- the manifest declares no script npm runs at some install (`preinstall`, `install`,
  `postinstall`, `prepare`, `preprepare`, `postprepare`, `prepublish`);
- the manifest says where the package comes from: a `repository` or a `homepage`. Without one,
  4 benign versions (`@afilimax/link-builder`, `@fcjplugins/*`,
  `@univer-cli/doc-markdown-facade`) and 1 unverified (`@fcjplugins/hooks`) stay reported, and
  so does `mad-1.2.6.2.2.8`. Both fields are the publisher's word, not proof: the reviewer
  still sees the LOW finding.

An update is never noted: an obfuscated file new in an established package is how the
`vm-day1` updates above were caught (`docs/proposals/precision-round8-P.md`, P1).
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from typing import Any, Final

from kitsunox.core.models import Candidate, Finding, Severity
from kitsunox.core.rules import BaseRule
from kitsunox.stages.correlate import OBFUSCATION_ONLY, CorrelationContext

OBFUSCATED: Final = "static.obfuscated"
HTML: Final = re.compile(r"\.x?html?$", re.IGNORECASE)
# Manifest fields that name the files a package serves or runs.
ENTRY_FIELDS: Final = ("main", "files", "browser", "unpkg", "jsdelivr", "module", "exports", "bin")
# Scripts npm runs on some install: from the registry (the install hooks) or from a git
# checkout or a local directory (`prepare` and its pre/post, the old `prepublish`).
LIFECYCLE: Final = (
    "preinstall",
    "install",
    "postinstall",
    "preprepare",
    "prepare",
    "postprepare",
    "prepublish",
)


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def names_html(manifest: dict[str, Any]) -> bool:
    """Whether the manifest's entry fields (`ENTRY_FIELDS`) name an HTML file."""
    texts = (text for field in ENTRY_FIELDS for text in _strings(manifest.get(field)))
    return any(HTML.search(text.strip()) for text in texts)


def declares_origin(manifest: dict[str, Any]) -> bool:
    """Whether the manifest names a `repository` (a URL, or an object with one) or a
    `homepage`."""
    repository = manifest.get("repository")
    if isinstance(repository, dict):
        repository = repository.get("url")
    homepage = manifest.get("homepage")
    return any(isinstance(v, str) and v.strip() for v in (repository, homepage))


def lifecycle_scripts(manifest: dict[str, Any]) -> list[str]:
    """The `LIFECYCLE` scripts the manifest declares (non-empty)."""
    declared = manifest.get("scripts")
    if not isinstance(declared, dict):
        return []
    return [s for s in LIFECYCLE if isinstance(declared.get(s), str) and declared[s].strip()]


class ObfuscationOnly(BaseRule):
    """A new package whose only signal is obfuscated JavaScript (module docstring). INFO,
    weight 0: it explains `static.obfuscated` (`stages.correlate.EXPLAINED`)."""

    id = OBFUSCATION_ONLY
    version = 1
    severity = Severity.INFO
    weight = 0.0
    title = "Obfuscation is a new package's only signal"

    def evaluate_candidate(
        self, candidate: Candidate, ctx: CorrelationContext
    ) -> Sequence[Finding]:
        change = candidate.change
        if change.previous is not None:
            return ()
        obfuscated = [f for f in candidate.findings if f.rule_id == OBFUSCATED]
        if not any(f.severity is Severity.MEDIUM for f in obfuscated):
            return ()
        if any(f.severity is Severity.HIGH for f in obfuscated):
            return ()
        if any(
            f.rule_id != OBFUSCATED and f.severity is not Severity.INFO for f in candidate.findings
        ):
            return ()
        paths = sorted({e.path for f in obfuscated for e in f.evidence if e.path})
        manifest = change.new.manifest
        if any(HTML.search(p) for p in paths) or names_html(manifest):
            return ()
        if lifecycle_scripts(manifest) or not declares_origin(manifest):
            return ()
        shown = ", ".join(f"`{p}`" for p in paths[:3]) + (" ..." if len(paths) > 3 else "")
        return (
            self.finding(
                f"A new package whose only signal is obfuscated JavaScript ({shown}): no other"
                " finding, no script npm runs at install (`prepare` included), no web page, and"
                " a declared repository or homepage. Obfuscation alone is counted LOW.",
            ),
        )


RULES: Final = (ObfuscationOnly(),)
