"""`npm.obfuscation-only` (Stage 4) and its explanation of `static.obfuscated`."""

from datetime import UTC, datetime
from typing import Any

import pytest

from kitsunox.core.models import (
    Candidate,
    Change,
    Evidence,
    EvidenceKind,
    Finding,
    PackageVersionRef,
    PublishInfo,
    Severity,
    VersionSnapshot,
)
from kitsunox.ecosystems.npm.rules.obfuscation_only import (
    ObfuscationOnly,
    declares_origin,
    lifecycle_scripts,
    names_html,
)
from kitsunox.stages.correlate import CorrelationContext, correlate
from kitsunox.stages.review import CORRELATION_RULES

T0 = datetime(2026, 11, 12, tzinfo=UTC)
CTX = CorrelationContext(as_of=T0)
RULE = ObfuscationOnly()
ORIGIN: dict[str, Any] = {"repository": {"type": "git", "url": "https://github.com/kx/kx"}}


def snap(version: str, manifest: dict[str, Any] | None = None) -> VersionSnapshot:
    return VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="kx", version=version),
        publish=PublishInfo(),
        manifest=ORIGIN if manifest is None else manifest,
    )


def finding(rule: str, severity: Severity, path: str = "dist/index.js") -> Finding:
    return Finding(
        rule_id=rule,
        rule_version=2,
        severity=severity,
        weight=3.0 if severity is Severity.MEDIUM else (0.0 if severity is Severity.INFO else 1.0),
        title="t",
        explanation="2093 obfuscator-style identifiers.",
        evidence=(Evidence(kind=EvidenceKind.FILE_SPAN, path=path, line_start=1),),
    )


OBF = finding("static.obfuscated", Severity.MEDIUM)
COMPARED = finding("repo.compared", Severity.INFO, "repository")


def cand(
    *findings: Finding,
    manifest: dict[str, Any] | None = None,
    previous: VersionSnapshot | None = None,
) -> Candidate:
    return Candidate(
        change=Change(new=snap("1.0.0", manifest), previous=previous), findings=findings
    )


def test_a_new_package_with_only_obfuscation_is_noted() -> None:
    """`@univerjs-pro/slicer@1.3.0`, `xgis-cog-cesium@0.0.1` (benign): obfuscated dist files,
    every other finding INFO, a declared repository or homepage."""
    (found,) = RULE.evaluate_candidate(
        cand(OBF, finding("static.obfuscated", Severity.MEDIUM, "lib/cjs/index.js"), COMPARED), CTX
    )
    assert (found.rule_id, found.severity, found.weight) == ("npm.obfuscation-only", "info", 0.0)
    assert "`dist/index.js`, `lib/cjs/index.js`" in found.explanation
    home = {"homepage": "https://github.com/zorrowm"}
    assert RULE.evaluate_candidate(cand(OBF, manifest=home), CTX)


@pytest.mark.parametrize(
    ("findings", "manifest", "previous"),
    [
        # an update: an obfuscated file new in an established package (`@duckdb/node-api@1.3.3`)
        ((OBF,), None, snap("0.9.0")),
        # any LOW keeps it (`tavern-ai-sdk@1.0.0`: process-exec, encoded-blob)
        ((OBF, finding("static.process-exec", Severity.LOW)), None, None),
        ((OBF, finding("npm.install-hook", Severity.MEDIUM)), None, None),
        ((finding("static.obfuscated", Severity.LOW),), None, None),  # nothing MEDIUM
        ((OBF, finding("static.obfuscated", Severity.HIGH)), None, None),
        ((finding("static.obfuscated", Severity.MEDIUM, "index.html"),), None, None),
        # a web page (`mobiwaefhxc3@1.0.0`: `main: index.html`)
        ((OBF,), {**ORIGIN, "main": "index.html"}, None),
        ((OBF,), {**ORIGIN, "files": ["script.js", "index.html"]}, None),
        # a script npm runs at some install (`multi-cloud-data-migrator@1.256.25`: prepare)
        ((OBF,), {**ORIGIN, "scripts": {"prepare": "npm run build"}}, None),
        ((OBF,), {**ORIGIN, "scripts": {"postinstall": "node x.js"}}, None),
        # no stated origin (`mad-1.2.6.2.2.8@1.0.0`, `@fcjplugins/hooks@1.0.0-bate.1`)
        ((OBF,), {}, None),
        ((OBF,), {"repository": {"type": "git"}, "homepage": " "}, None),
    ],
)
def test_not_noted(
    findings: tuple[Finding, ...], manifest: dict[str, Any] | None, previous: VersionSnapshot | None
) -> None:
    assert RULE.evaluate_candidate(cand(*findings, manifest=manifest, previous=previous), CTX) == ()


def test_manifest_helpers() -> None:
    assert names_html({"exports": {".": {"browser": "./dist/page.HTML"}}})
    assert names_html({"bin": {"x": "x.htm"}})
    assert not names_html({"main": "dist/html.js", "files": ["dist", "README.md"], "bin": 3})
    assert lifecycle_scripts({"scripts": {"prepare": " ", "prepublish": "tsc", "build": "x"}}) == [
        "prepublish"
    ]
    assert lifecycle_scripts({"scripts": ["prepare"]}) == []
    assert declares_origin({"repository": "github:kx/kx"})
    assert not declares_origin({"repository": {"url": 3}, "homepage": None})


def test_stage4_counts_the_obfuscation_low_and_does_not_report() -> None:
    """With the note, `explained` makes `static.obfuscated` LOW, weight 1: score 1, not reported.
    An update with the same findings stays reported (score 3, MEDIUM)."""
    out = correlate(cand(OBF, COMPARED), CTX, CORRELATION_RULES)
    (obf,) = [f for f in out.findings if f.rule_id == "static.obfuscated"]
    assert (obf.severity, obf.weight) == (Severity.LOW, 1.0)
    assert obf.explanation.endswith("(npm.obfuscation-only).")
    assert not out.history[-1].forwarded
    update = correlate(cand(OBF, COMPARED, previous=snap("0.9.0")), CTX, CORRELATION_RULES)
    assert update.history[-1].forwarded


def test_reports_name_its_stage() -> None:
    from kitsunox.reporting.report import stage_of

    assert stage_of("npm.obfuscation-only") == "Stage 4: correlation"
