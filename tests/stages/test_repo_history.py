"""A compared update's history (`with_history`) and the rules over it."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from conftest import Router
from kitsunox.core.models import (
    Candidate,
    Change,
    PackageVersionRef,
    PublishInfo,
    Severity,
    VersionSnapshot,
)
from kitsunox.ecosystems.npm.repo import NpmLocator
from kitsunox.ecosystems.npm.rules.correlate import NoNewCommits
from kitsunox.githost.github import GitHub, GitHubRepo
from kitsunox.rules.repo import CommitAfterRelease, HistoryMatch
from kitsunox.stages.correlate import CorrelationContext
from kitsunox.stages.repo import (
    API_FAILED,
    ReleaseSource,
    RepoComparison,
    RepoHistory,
    RepoMemory,
    with_history,
)
from kitsunox.util.http import BlobStore, FetchMode, HttpFetcher, Snapshot

OLD, NEW, TAGGED = "a" * 40, "b" * 40, "c" * 40
PUBLISHED = datetime(2026, 11, 1, 12, tzinfo=UTC)
REPO = GitHubRepo("o", "r")
API = "https://api.github.com/repos/o/r"


def snapshot(version: str, git_head: str | None) -> VersionSnapshot:
    return VersionSnapshot(
        ref=PackageVersionRef(ecosystem="npm", name="kx", version=version),
        publish=PublishInfo(git_head=git_head, published_at=PUBLISHED),
        manifest={},
    )


def update(
    old: str = "1.0.0", new: str = "1.0.1", *, before: str | None = OLD, after: str | None = NEW
) -> Change:
    return Change(
        new=snapshot(new, after),
        previous=snapshot(old, before),
        repository_url="https://github.com/o/r",
    )


def compared(commit: str = NEW, how: str = "gitHead", **overrides: Any) -> RepoComparison:
    return RepoComparison(
        source=ReleaseSource(repo="o/r", commit=commit, how=how), code_files=3, identical=3
    ).model_copy(update=overrides)


def api(tmp_path: Path, router: Router, token: str | None = "t") -> GitHub:  # noqa: S107
    fetcher = HttpFetcher(
        store=BlobStore(tmp_path / "blobs"),
        snapshot=Snapshot(),
        mode=FetchMode.RECORD,
        client=router.client(),
    )
    return GitHub(fetcher, token=token)


def compare_url(base: str = OLD, head: str = NEW) -> str:
    return f"{API}/compare/{base}...{head}?per_page=1&page=2"


def history(
    tmp_path: Path,
    router: Router,
    comparison: RepoComparison | None = None,
    change: Change | None = None,
    *,
    ask_range: bool = True,
    refs: dict[str, str] | None = None,
    memory: RepoMemory | None = None,
    token: str | None = "t",  # noqa: S107
) -> RepoComparison:
    return with_history(
        comparison if comparison is not None else compared(),
        change if change is not None else update(),
        NpmLocator(),
        api(tmp_path, router, token),
        memory if memory is not None else RepoMemory({REPO: refs or {}}),
        ask_range=ask_range,
    )


def test_the_same_commit_is_identical_without_asking(tmp_path: Path, router: Router) -> None:
    result = history(tmp_path, router, compared(OLD), update(after=OLD))
    assert result.history == RepoHistory(
        previous_version="1.0.0",
        previous_commit=OLD,
        previous_how="gitHead",
        status="identical",
        ahead_by=0,
        behind_by=0,
    )
    assert router.requests == []


def test_the_range_is_asked_once_a_run_and_only_when_wanted(tmp_path: Path, router: Router) -> None:
    router.add_json(compare_url(), {"status": "ahead", "ahead_by": 4, "behind_by": 0})
    memory = RepoMemory({REPO: {}})
    for _ in range(3):
        result = history(tmp_path, router, memory=memory)
        assert result.history is not None
        assert (result.history.status, result.history.ahead_by) == ("ahead", 4)
    assert router.requests == [compare_url()]
    unasked = history(tmp_path / "2", router, ask_range=False)
    assert unasked.history is not None and unasked.history.status is None
    no_token = history(tmp_path / "3", router, token=None)
    assert no_token.history is not None and no_token.history.previous_commit == OLD
    assert no_token.history.status is None
    assert router.requests == [compare_url()]


def test_the_previous_commit_comes_from_a_tag(tmp_path: Path, router: Router) -> None:
    router.add_json(compare_url(TAGGED), {"status": "behind", "ahead_by": 0, "behind_by": 2})
    result = history(
        tmp_path, router, change=update(before=None), refs={"refs/tags/v1.0.0": TAGGED}
    )
    assert result.history is not None
    assert (result.history.previous_commit, result.history.previous_how) == (TAGGED, "tag v1.0.0")
    assert (result.history.status, result.history.behind_by) == ("behind", 2)
    untagged = history(tmp_path / "2", router, change=update(before=None))
    assert untagged.history == RepoHistory(previous_version="1.0.0")


def test_a_tag_found_commit_gets_its_date(tmp_path: Path, router: Router) -> None:
    router.add_json(f"{API}/git/commits/{NEW}", {"committer": {"date": "2026-11-03T12:00:00Z"}})
    result = history(tmp_path, router, compared(how="tag v1.0.1"), ask_range=False)
    assert result.history is not None
    assert result.history.commit_date == datetime(2026, 11, 3, 12, tzinfo=UTC)
    by_head = history(tmp_path / "2", router, ask_range=False)
    assert by_head.history is not None and by_head.history.commit_date is None
    assert router.requests == [f"{API}/git/commits/{NEW}"]


def test_no_history_without_a_source_or_a_previous_release(tmp_path: Path, router: Router) -> None:
    unavailable = RepoComparison(unavailable="no commit or tag for this version")
    assert history(tmp_path, router, unavailable) == unavailable
    new_package = update().model_copy(update={"previous": None})
    assert history(tmp_path, router, change=new_package) == compared()


def test_failures_are_one_text(tmp_path: Path, router: Router) -> None:
    router.add_json(compare_url(), {"message": "API rate limit exceeded"}, status=403)
    failed = history(tmp_path, router)
    assert failed.history is not None and failed.history.unavailable == API_FAILED
    router.offline.add(f"{API}/git/commits/{NEW}")
    offline = history(tmp_path / "2", router, compared(how="tag v1.0.1"), ask_range=False)
    assert offline.history is not None and offline.history.unavailable == API_FAILED
    unknown = history(tmp_path / "3", router, compared(TAGGED), ask_range=True)  # 404
    assert unknown.history is not None
    assert unknown.history.unavailable == "GitHub doesn't know one of the commits"


def ctx(comparison: RepoComparison) -> CorrelationContext:
    return CorrelationContext(as_of=PUBLISHED, repo=comparison)


def with_range(status: str, ahead: int = 0, behind: int = 0, **comparison: Any) -> RepoComparison:
    found = RepoHistory(
        previous_version="1.0.0",
        previous_commit=OLD,
        previous_how="gitHead",
        status=status,
        ahead_by=ahead,
        behind_by=behind,
    )
    return compared(**comparison).model_copy(update={"history": found})


def test_commit_after_release() -> None:
    rule = CommitAfterRelease()
    late = compared(how="tag v1.0.1").model_copy(
        update={
            "history": RepoHistory(
                previous_version="1.0.0", commit_date=PUBLISHED + timedelta(days=16)
            )
        }
    )
    (found,) = rule.evaluate_candidate(Candidate(change=update()), ctx(late))
    assert found.severity is Severity.MEDIUM
    assert "made 16 days after this release was published" in found.explanation
    assert late.history is not None
    soon = late.history.model_copy(update={"commit_date": PUBLISHED + timedelta(hours=1)})
    assert (
        rule.evaluate_candidate(
            Candidate(change=update()), ctx(late.model_copy(update={"history": soon}))
        )
        == ()
    )
    monorepo = (
        late.model_copy(
            update={"source": late.source.model_copy(update={"directory": "packages/kx"})}
        )
        if late.source
        else late
    )
    assert rule.evaluate_candidate(Candidate(change=update()), ctx(monorepo)) == ()
    named = (
        monorepo.model_copy(
            update={"source": monorepo.source.model_copy(update={"how": "tag kx@1.0.1"})}
        )
        if monorepo.source
        else monorepo
    )
    assert rule.evaluate_candidate(Candidate(change=update()), ctx(named)) != ()
    undated = Candidate(
        change=update().model_copy(
            update={"new": snapshot("1.0.1", NEW).model_copy(update={"publish": PublishInfo()})}
        )
    )
    assert rule.evaluate_candidate(undated, ctx(late)) == ()


def test_history_match() -> None:
    rule = HistoryMatch()
    candidate = Candidate(change=update())
    (found,) = rule.evaluate_candidate(candidate, ctx(with_range("ahead", 4)))
    assert found.severity is Severity.INFO and found.weight == 0
    assert "4 commits after 1.0.0's commit aaaaaaaaaaaa (gitHead)" in found.explanation
    for comparison in (
        with_range("behind", behind=1),
        with_range("diverged", 2, 1),
        with_range("ahead", 4, identical=2, differing_count=1),  # not clean
        compared(),  # no history
    ):
        assert rule.evaluate_candidate(candidate, ctx(comparison)) == (), comparison
    late = with_range("ahead", 4, how="tag v1.0.1")
    assert late.history is not None
    dated = late.history.model_copy(update={"commit_date": PUBLISHED + timedelta(days=2)})
    assert rule.evaluate_candidate(candidate, ctx(late.model_copy(update={"history": dated}))) == ()


def test_no_new_commits() -> None:
    rule = NoNewCommits()
    dirty = {"identical": 2, "differing_count": 1}
    (found,) = rule.evaluate_candidate(
        Candidate(change=update()), ctx(with_range("identical", **dirty))
    )
    assert found.severity is Severity.LOW and found.weight == 2
    assert "built from the same commit as 1.0.0" in found.explanation
    assert "never went through git" in found.explanation
    (older,) = rule.evaluate_candidate(
        Candidate(change=update()), ctx(with_range("behind", behind=3, **dirty))
    )
    assert "3 commits older than 1.0.0" in older.explanation
    (uncompared,) = rule.evaluate_candidate(
        Candidate(change=update()),
        ctx(with_range("identical", unavailable="archive: too large", code_files=0, identical=0)),
    )
    assert "couldn't be compared (archive: too large)" in uncompared.explanation
    for change, comparison in (
        (update(), with_range("identical")),  # clean: the previous release's code again
        (update(), with_range("ahead", 2, **dirty)),
        (update("1.0.0-rc.1", "1.0.0"), with_range("identical", **dirty)),
        (update("1.0.0", "1.0.1-canary.3"), with_range("identical", **dirty)),
        (update("2.0.0", "1.9.9"), with_range("identical", **dirty)),
    ):
        assert rule.evaluate_candidate(Candidate(change=change), ctx(comparison)) == (), change
