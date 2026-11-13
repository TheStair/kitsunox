"""`static.silent-native-load`: a bundled `.node` addon required inside a `try` with an empty
`catch`, in a package with no build or prebuilt-binary files.

The `.node` fixtures are a few placeholder bytes, not libraries; nothing here is loaded or run.
"""

import json

from kitsunox.core.models import PackageVersionRef, PublishInfo, Severity, VersionSnapshot
from kitsunox.ecosystems.npm.rules.artifact import RULES as NPM_ARTIFACT_RULES
from kitsunox.ecosystems.npm.rules.native_load import (
    SilentNativeLoad,
    build_files,
    swallowed_native_loads,
)

SNAP = VersionSnapshot(
    ref=PackageVersionRef(ecosystem="npm", name="str-helpers-x", version="1.0.1"),
    publish=PublishInfo(),
    manifest={},
)
ADDON = b"\x7fELF placeholder"
# `strutil-helpers-core` 1.0.1's first line, in shape.
LOADER = (
    b"try{if(process.platform==='win32')require('./native_win.node');"
    b"else require('./native.napi.node')}catch(_){}\n"
    b"'use strict';\nfunction trim(s){return s.trim()}\nmodule.exports={trim};\n"
)


def _files(index: bytes = LOADER, **extra: bytes) -> dict[str, bytes]:
    return {
        "package.json": json.dumps({"name": "str-helpers-x", "main": "index.js"}).encode(),
        "index.js": index,
        "native_win.node": ADDON,
        "native.napi.node": ADDON,
        **extra,
    }


def _fire(files: dict[str, bytes]) -> list[str]:
    return [f.rule_id for f in SilentNativeLoad().evaluate_artifact(SNAP, files)]


def test_fires_on_the_shape() -> None:
    (finding,) = SilentNativeLoad().evaluate_artifact(SNAP, _files())
    assert finding.severity is Severity.MEDIUM and finding.weight == 3.0
    assert "`native_win.node`, `native.napi.node`" in finding.explanation
    assert [(e.path, e.line_start) for e in finding.evidence] == [("index.js", 1), ("index.js", 1)]
    assert any(r.id == SilentNativeLoad.id for r in NPM_ARTIFACT_RULES)


def test_a_file_the_entry_loads_and_a_comment_only_catch_count() -> None:
    files = _files(
        b"require('./lib/boot');\nmodule.exports = {};\n",
        **{"lib/boot.js": b"try {\n  require('../native.napi.node');\n} catch {\n  // ignore\n}\n"},
    )
    assert _fire(files) == ["static.silent-native-load"]


def test_a_handled_failure_is_an_optional_addon() -> None:
    handled = b"let b;\ntry { b = require('./native.napi.node'); } catch (e) { b = null; }\n"
    assert _fire(_files(handled)) == []
    assert _fire(_files(b"module.exports = require('./native.napi.node');\n")) == []


def test_an_optional_addon_whose_exports_are_kept_is_not_the_shape() -> None:
    # `dsh-needs-you-mac` 0.2.0's shape: the failure swallowed on purpose, the addon used.
    kept = b"let a;\ntry {\n  a = require('./native.napi.node');\n} catch {\n  // none here\n}\n"
    assert _fire(_files(kept)) == []
    used = b"try { const a = require('./native.napi.node'); a.run() } catch (_) {}\n"
    assert _fire(_files(used)) == []
    bare = b"try { (require('./native.napi.node')); } catch (_) {}\n"
    assert _fire(_files(bare)) == ["static.silent-native-load"]


def test_a_function_between_the_try_and_the_require_does_not_count() -> None:
    later = b"try { module.exports = () => require('./native.napi.node'); } catch (_) {}\n"
    assert _fire(_files(later)) == []


def test_build_and_prebuilt_layouts_are_legitimate() -> None:
    assert _fire(_files(**{"binding.gyp": b"{}"})) == []
    assert _fire(_files(**{"prebuilds/linux-x64/x.node": ADDON})) == []
    for manifest in (
        {"gypfile": True},
        {"binary": {"module_name": "x"}},
        {"dependencies": {"node-gyp-build": "^4"}},
        {"optionalDependencies": {"@mapbox/node-pre-gyp": "^1"}},
    ):
        files = _files(**{"package.json": json.dumps(manifest).encode()})
        assert build_files(files), manifest
        assert _fire(files) == [], manifest
    assert not build_files(_files(**{"package.json": b"[1]"}))
    assert not build_files(_files(**{"package.json": b"not json"}))


def test_only_shipped_addons_by_a_relative_path_in_code_that_runs() -> None:
    missing = {k: v for k, v in _files().items() if not k.endswith(".node")}
    missing["other.node"] = ADDON
    assert _fire(missing) == []
    bare = b"try { require('native.napi.node') } catch (_) {}\n"
    assert _fire(_files(bare)) == []
    unused = _files(b"module.exports = {};\n", **{"tools/probe.js": LOADER})
    assert _fire(unused) == []


def test_install_code_counts_and_inline_hook_code_is_skipped() -> None:
    twice = b"try { require('./native.napi.node'); require('./native.napi.node') } catch (_) {}\n"
    manifest = {
        "name": "str-helpers-x",
        "main": "index.js",
        "scripts": {"postinstall": "node setup.js && node -e \"require('./lib.js')\""},
    }
    files = _files(
        b"require('./helpers.js'); // ships native.napi.node too\n",
        **{"package.json": json.dumps(manifest).encode(), "setup.js": twice, "helpers.js": b""},
    )
    (finding,) = SilentNativeLoad().evaluate_artifact(SNAP, files)
    assert "addon `native.napi.node`" in finding.explanation
    assert [e.path for e in finding.evidence] == ["setup.js", "setup.js"]


def test_swallowed_native_loads_helper() -> None:
    found = list(swallowed_native_loads("index.js", LOADER, _files()))
    assert [(line, addon) for line, addon, _ in found] == [
        (1, "native_win.node"),
        (1, "native.napi.node"),
    ]
    assert list(swallowed_native_loads("README.md", LOADER, _files())) == []
