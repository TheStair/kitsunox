"""`static.html-redirector`: a tiny package whose entry is a web page that fetches a value,
decrypts it and redirects the visitor.

Fixtures are short, inert pages in the shape of the `bfvkjmeikpwhqxc` / `@isla5mic/aasics`
template (a made-up dead-drop host, no key, no target); nothing here runs or is served.
"""

import json

from kitsunox.core.models import PackageVersionRef, PublishInfo, Severity, VersionSnapshot
from kitsunox.ecosystems.npm.rules.artifact import RULES as NPM_ARTIFACT_RULES
from kitsunox.ecosystems.npm.rules.hosted_page import HtmlRedirector, html_entries

SNAP = VersionSnapshot(
    ref=PackageVersionRef(ecosystem="npm", name="landing-x", version="1.0.0"),
    publish=PublishInfo(),
    manifest={},
)
PAGE = b"""<!doctype html><html><head><title>Checking your browser</title></head><body>
<script>
  function resolveTarget() {
    return fetch("https://kv.example.invalid/get", { method: "POST", body: "{}" })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        return crypto.subtle.importKey("raw", keyBytes, { name: "AES-CTR" }, false, ["decrypt"])
          .then(function (key) {
            return crypto.subtle.decrypt({ name: "AES-CTR", counter: iv, length: 128 }, key, data);
          });
      });
  }
  resolveTarget().then(function (url) { window.location.replace(url); });
</script></body></html>
"""


def _manifest(**fields: object) -> bytes:
    return json.dumps({"name": "landing-x", "version": "1.0.0", **fields}).encode()


FILES = {"package.json": _manifest(main="index.html"), "index.html": PAGE, "README.md": b"# x"}


def _fire(files: dict[str, bytes], snapshot: VersionSnapshot = SNAP) -> list[str]:
    return [f.rule_id for f in HtmlRedirector().evaluate_artifact(snapshot, files)]


def test_fires_on_the_template() -> None:
    (finding,) = HtmlRedirector().evaluate_artifact(SNAP, FILES)
    assert finding.severity is Severity.MEDIUM and finding.weight == 3.0
    assert "`index.html`" in finding.explanation and "3 files" in finding.explanation
    snippets = [e.snippet or "" for e in finding.evidence]
    assert "fetch(" in snippets[0] and "decrypt(" in snippets[1] and "replace(" in snippets[2]
    assert any(r.id == HtmlRedirector.id for r in NPM_ARTIFACT_RULES)


def test_other_forms_of_each_step() -> None:
    page = (
        b"<script>var x = new XMLHttpRequest();"
        b"var t = CryptoJS.AES.decrypt(x.responseText, k).toString();"
        b"location.href = t;</script>"
    )
    files = {"package.json": _manifest(exports="./page.htm"), "page.htm": page}
    assert _fire(files) == ["static.html-redirector"]
    script = b"$.get(u, function (v) { window.location = CryptoJS.Rabbit.decrypt(v, k); });"
    files = {"package.json": _manifest(main="index.html"), "index.html": b"<p>", "app.js": script}
    assert _fire(files) == ["static.html-redirector"]


def test_each_step_is_needed_in_one_file() -> None:
    for step in (b"fetch(", b"subtle.decrypt(", b"window.location.replace("):
        assert _fire({**FILES, "index.html": PAGE.replace(step, b"noop(")}) == [], step
    split = {
        "package.json": _manifest(main="index.html"),
        "index.html": b"<script>fetch(u); location.replace(t);</script>",
        "crypto.js": b"crypto.subtle.decrypt(a, k, d);",
    }
    assert _fire(split) == []


def test_a_page_that_is_not_the_package_s_entry_or_a_bigger_package() -> None:
    assert _fire({**FILES, "package.json": _manifest(main="index.js")}) == []
    assert _fire({**FILES, "package.json": _manifest(main="missing.html")}) == []
    bigger = {**FILES, **{f"dist/chunk-{i}.js": b"x" for i in range(3)}}
    assert _fire(bigger) == []
    assert _fire({**FILES, "package.json": b"not json"}) == []


def test_the_registry_manifest_is_used_without_a_packed_one() -> None:
    files = {"index.html": PAGE}
    assert _fire(files) == []
    snapshot = SNAP.model_copy(update={"manifest": {"main": "./index.html"}})
    assert _fire(files, snapshot) == ["static.html-redirector"]


def test_html_entries() -> None:
    files = {"a.html": b"", "b.HTM": b"", "c.js": b""}
    manifest = _manifest(main="a.html", browser="./b.HTM", exports={".": "./c.js"})
    assert html_entries({**files, "package.json": manifest}, {}) == ["a.html", "b.HTM"]
    assert html_entries({**files, "package.json": b"[]"}, {}) == []
