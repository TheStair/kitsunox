"""Tarball unpack + version diff (Claude-owned scaffolding — should pass)."""

from __future__ import annotations

from kitsunox.analysis.tarball import diff_unpacked, sniff_tarball_bytes
from kitsunox.ir import ChangeType


def test_unpack_strips_package_prefix(make_tgz, tmp_path):
    raw = make_tgz({"package.json": b'{"name":"x"}', "index.js": b"module.exports = 1;\n"})
    up = sniff_tarball_bytes(raw, "x", "1.0.0", tmp_path)
    assert set(up.files) == {"package.json", "index.js"}
    assert not up.files["index.js"].is_binary
    assert up.read_text("index.js").startswith("module.exports")


def test_diff_detects_add_modify_remove(make_tgz, tmp_path):
    prev_raw = make_tgz({"package.json": b'{"v":1}', "keep.js": b"a\n", "gone.js": b"x\n"})
    cur_raw = make_tgz({"package.json": b'{"v":2}', "keep.js": b"a\n", "new.js": b"evil()\n"})
    prev = sniff_tarball_bytes(prev_raw, "x", "1.0.0", tmp_path / "p")
    cur = sniff_tarball_bytes(cur_raw, "x", "1.1.0", tmp_path / "c")

    diffs = {d.path: d for d in diff_unpacked(prev, cur)}
    assert diffs["new.js"].change_type is ChangeType.ADDED
    assert diffs["gone.js"].change_type is ChangeType.REMOVED
    assert diffs["package.json"].change_type is ChangeType.MODIFIED
    assert "keep.js" not in diffs  # unchanged files are not emitted
    assert "evil()" in diffs["new.js"].hunks


def test_first_publish_is_all_added(make_tgz, tmp_path):
    cur = sniff_tarball_bytes(make_tgz({"index.js": b"1\n"}), "x", "1.0.0", tmp_path)
    diffs = diff_unpacked(None, cur)
    assert [d.change_type for d in diffs] == [ChangeType.ADDED]


def test_binary_file_not_diffed(make_tgz, tmp_path):
    prev = sniff_tarball_bytes(make_tgz({"a.node": b"\x00\x01\x02"}), "x", "1", tmp_path / "p")
    cur = sniff_tarball_bytes(make_tgz({"a.node": b"\x00\x09\x09"}), "x", "2", tmp_path / "c")
    (d,) = diff_unpacked(prev, cur)
    assert d.is_binary and d.hunks == ""
