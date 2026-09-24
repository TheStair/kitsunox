"""model.py — plain dataclass behavior, no I/O."""

from __future__ import annotations

from kitsunox.model import Change, FileDiff


def _change(**overrides) -> Change:
    defaults = dict(
        repo="owner/repo",
        source="push",
        sha="abc123",
        author="alice",
        committed_at=None,
    )
    defaults.update(overrides)
    return Change(**defaults)


def test_defaults_are_empty_not_none():
    c = _change()
    assert c.files == []
    assert c.shas == []
    assert c.checks_passed is None
    assert c.ground_truth is None
    assert c.approving_review_count == 0


def test_two_changes_get_independent_mutable_defaults():
    # dataclass field(default_factory=list) footgun check: two instances must not
    # share the same underlying list.
    a, b = _change(), _change()
    a.files.append(FileDiff(path="x", change_type="added", is_binary=False))
    assert b.files == []


def test_is_first_time_contributor():
    assert _change(author_association="FIRST_TIME_CONTRIBUTOR").is_first_time_contributor
    assert not _change(author_association="OWNER").is_first_time_contributor
    assert not _change(author_association=None).is_first_time_contributor


def test_merged_by_author_requires_pr_source():
    pr_self_merge = _change(source="pr", author="alice", merged_by="alice")
    assert pr_self_merge.merged_by_author

    pr_other_merge = _change(source="pr", author="alice", merged_by="bob")
    assert not pr_other_merge.merged_by_author

    # a push has no PR to "self-merge" — must be False even with matching names.
    push = _change(source="push", author="alice", merged_by="alice")
    assert not push.merged_by_author

    pr_no_merger = _change(source="pr", author="alice", merged_by=None)
    assert not pr_no_merger.merged_by_author
