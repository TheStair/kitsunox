"""What `npm.install-script-changed` shows a reviewer of code hidden behind whitespace (inert,
hand-written lines; nothing here runs)."""

import json

from kitsunox.core.models import PackageVersionRef, PublishInfo, VersionSnapshot
from kitsunox.ecosystems.npm.install import install_sources
from kitsunox.ecosystems.npm.rules.install_code import MAX_DIFF_LINE_CHARS, InstallScriptChanged
from kitsunox.stages.ast import CapabilityCache, code_change

CODE = "var z='-c';var a=['x','y'];(function(){for(var i=0;i<a.length;i++){f(a[i]);}})();" * 4
SNAP = VersionSnapshot(
    ref=PackageVersionRef(ecosystem="npm", name="kx", version="1.0.1"),
    publish=PublishInfo(),
    manifest={},
)
MANIFEST = json.dumps({"scripts": {"postinstall": "node scripts/postinstall.mjs"}}).encode()
CLEAN = {"package.json": MANIFEST, "scripts/postinstall.mjs": b"import fs from 'fs';\n"}


def _changed(new_file: str) -> tuple[str, str]:
    new = CLEAN | {"scripts/postinstall.mjs": new_file.encode()}
    code = code_change(SNAP, new, CLEAN, CapabilityCache(None), install_sources, "1.0.0")
    (found,) = InstallScriptChanged().evaluate_code(code)
    return found.explanation, found.evidence[0].snippet or ""


def test_a_changed_install_file_shows_the_code_a_run_hides() -> None:
    """`hauntview@0.2.9`: the added line was blank in the cut diff and "+3 -1 lines" said
    nothing of its 12 KB."""
    explanation, snippet = _changed("import fs from 'fs';\n" + "\t" * 266 + CODE + "\n")
    assert explanation.startswith(
        "`npm install` runs code that changed since 1.0.0: scripts/postinstall.mjs "
        f"(+1 -0 lines, longest added line {266 + len(CODE):,} characters)."
    )
    added = snippet.splitlines()[-1]
    assert added.startswith("+⟨266 tabs⟩var z='-c';")
    assert len(added) == MAX_DIFF_LINE_CHARS


def test_short_added_lines_keep_the_summary_and_indentation() -> None:
    explanation, snippet = _changed("import fs from 'fs';\n    fs.readFileSync(p);\n")
    assert "scripts/postinstall.mjs (+1 -0 lines)." in explanation
    assert snippet.splitlines()[-1] == "+    fs.readFileSync(p);"
