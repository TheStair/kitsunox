"""incidents.py — the ground-truth registry and its one fixture-backed incident.

Nothing here touches the network: the four live incidents are exercised with a stubbed
`fetch.fetch_commit`, and tj-actions is loaded from its on-disk fixture for real.
"""

from __future__ import annotations

import json
import re

import pytest

from kitsunox import fetch, incidents, rules
from kitsunox.model import Change, FileDiff


@pytest.fixture
def tj_actions() -> incidents.Incident:
    return incidents.INCIDENTS_BY_KEY["tj-actions"]


def _stub_change(repo: str, sha: str) -> Change:
    return Change(
        repo=repo, source="push", sha=sha, shas=[sha], author="someone", committed_at=None
    )


# ============================================================== registry invariants


def test_registry_holds_the_five_planned_incidents():
    assert len(incidents.INCIDENTS) == 5
    assert {i.key for i in incidents.INCIDENTS} == {
        "xz-utils", "event-stream", "reviewdog", "tj-actions", "colors.js",
    }


def test_keys_are_unique_and_index_matches_the_list():
    keys = [i.key for i in incidents.INCIDENTS]
    assert len(keys) == len(set(keys))
    assert incidents.INCIDENTS_BY_KEY == {i.key: i for i in incidents.INCIDENTS}


@pytest.mark.parametrize("incident", incidents.INCIDENTS, ids=lambda i: i.key)
def test_every_incident_is_well_formed(incident):
    # A truncated or transcribed-wrong SHA resolves to nothing, and the failure would
    # surface as a confusing 422 at fetch time rather than here.
    assert re.fullmatch(r"[0-9a-f]{40}", incident.sha), incident.sha
    assert re.fullmatch(r"[\w.-]+/[\w.-]+", incident.repo), incident.repo
    assert incident.label.strip() and incident.summary.strip()
    assert 2000 < incident.year <= 2030


def test_exactly_one_incident_is_fixture_backed():
    fixture_backed = [i for i in incidents.INCIDENTS if not i.is_live]
    assert [i.key for i in fixture_backed] == ["tj-actions"]
    assert sum(i.is_live for i in incidents.INCIDENTS) == 4


def test_every_referenced_fixture_file_exists():
    for incident in incidents.INCIDENTS:
        if incident.fixture:
            assert (incidents.FIXTURE_DIR / incident.fixture).is_file(), incident.key


def test_is_live_tracks_the_fixture_field(tj_actions):
    assert tj_actions.is_live is False
    assert incidents.INCIDENTS_BY_KEY["xz-utils"].is_live is True


# ============================================================== fixture loading


def test_fixture_loads_as_a_labelled_change(tj_actions):
    change = incidents.load_incident(tj_actions)
    assert change.repo == "tj-actions/changed-files"
    assert change.sha == tj_actions.sha
    assert change.shas == [tj_actions.sha]
    assert change.source == "push"
    assert change.ground_truth == "malicious"
    assert change.committed_at is not None and change.committed_at.year == 2025
    assert all(isinstance(f, FileDiff) for f in change.files)
    assert [f.path for f in change.files] == ["dist/index.js"]


def test_fixture_annotation_keys_do_not_break_the_loader(tj_actions, tmp_path, monkeypatch):
    # Fixtures document themselves inline (`*_note`, provenance URLs). Those keys sit
    # alongside the real data and must not be splatted into FileDiff.
    raw = json.loads((incidents.FIXTURE_DIR / tj_actions.fixture).read_text(encoding="utf-8"))
    raw["files"][0]["some_future_annotation"] = "explanatory text"
    (tmp_path / tj_actions.fixture).write_text(json.dumps(raw), encoding="utf-8")
    monkeypatch.setattr(incidents, "FIXTURE_DIR", tmp_path)

    change = incidents.load_incident(tj_actions)
    assert len(change.files) == 1


def test_fixture_checks_passed_is_unknown_not_false(tj_actions):
    # The repo's history was scrubbed, so CI state is unknowable — it must not be
    # reported as a failure, which is a finding in its own right.
    assert incidents.load_incident(tj_actions).checks_passed is None


# ============================================================== fixture polarity

# The recovered source was a REVERT commit, so its diff *removes* the payload. It was
# stored that way originally, which meant every added-line rule silently missed the
# incident while the metadata still claimed `+12/-0`.


def test_fixture_payload_is_on_added_lines(tj_actions):
    patch = incidents.load_incident(tj_actions).files[0].patch
    added = [ln for ln in patch.split("\n") if ln.startswith("+") and not ln.startswith("+++")]
    removed = [ln for ln in patch.split("\n") if ln.startswith("-") and not ln.startswith("---")]
    assert added, "payload must appear as additions, not as a revert's deletions"
    assert not removed
    assert any("updateFeatures" in ln for ln in added)


def test_fixture_metadata_agrees_with_its_patch(tj_actions):
    diff = incidents.load_incident(tj_actions).files[0]
    body = diff.patch.split("\n")
    assert diff.additions == sum(1 for ln in body if ln.startswith("+") and not ln.startswith("+++"))
    assert diff.deletions == sum(1 for ln in body if ln.startswith("-") and not ln.startswith("---"))


def test_fixture_records_that_its_polarity_is_derived(tj_actions):
    raw = json.loads((incidents.FIXTURE_DIR / tj_actions.fixture).read_text(encoding="utf-8"))
    assert raw["files"][0].get("patch_note"), "the inversion must stay documented"
    assert raw.get("provenance"), "a hardcoded incident without provenance is unverifiable"


def test_fixture_incident_is_detected_offline(tj_actions):
    # End-to-end on the one incident that needs no network: registry -> fixture -> Tier 0.
    findings = rules.scan(incidents.load_incident(tj_actions))
    assert rules.should_escalate(findings)
    assert "content.encoded_blob" in {f.rule_id for f in findings}


# ============================================================== live loading


def test_live_incident_is_fetched_and_labelled(monkeypatch):
    calls = []

    def stub(owner, repo, sha):
        calls.append((owner, repo, sha))
        return _stub_change(f"{owner}/{repo}", sha)

    monkeypatch.setattr(fetch, "fetch_commit", stub)
    incident = incidents.INCIDENTS_BY_KEY["xz-utils"]
    change = incidents.load_incident(incident)

    assert calls == [("tukaani-project", "xz", incident.sha)]
    assert change.ground_truth == "malicious"


def test_repo_is_split_into_owner_and_name_exactly_once(monkeypatch):
    seen = {}
    monkeypatch.setattr(
        fetch, "fetch_commit",
        lambda o, r, s: seen.update(owner=o, repo=r) or _stub_change(f"{o}/{r}", s),
    )
    incidents.load_incident(incidents.INCIDENTS_BY_KEY["colors.js"])
    assert seen == {"owner": "Marak", "repo": "colors.js"}


def test_a_failed_fetch_names_the_incident(monkeypatch):
    # A bare "422 for <url>" gives no clue which of the five broke.
    def boom(owner, repo, sha):
        raise fetch.FetchError("422 Unprocessable Entity")

    monkeypatch.setattr(fetch, "fetch_commit", boom)
    with pytest.raises(fetch.FetchError) as exc:
        incidents.load_incident(incidents.INCIDENTS_BY_KEY["reviewdog"])

    assert "reviewdog" in str(exc.value)
    assert "422" in str(exc.value)
    assert isinstance(exc.value.__cause__, fetch.FetchError)


def test_a_failed_fetch_is_not_silently_skipped(monkeypatch):
    # Dropping an incident would quietly shrink the denominator of the detection rate.
    monkeypatch.setattr(
        fetch, "fetch_commit",
        lambda o, r, s: (_ for _ in ()).throw(fetch.FetchError("nope")),
    )
    with pytest.raises(fetch.FetchError):
        incidents.load_incidents()


# ============================================================== the whole set


def test_load_incidents_returns_all_five_in_registry_order(monkeypatch):
    monkeypatch.setattr(fetch, "fetch_commit", lambda o, r, s: _stub_change(f"{o}/{r}", s))
    changes = incidents.load_incidents()

    assert len(changes) == 5
    assert [c.repo for c in changes] == [i.repo for i in incidents.INCIDENTS]
    assert [c.sha for c in changes] == [i.sha for i in incidents.INCIDENTS]
    assert all(c.ground_truth == "malicious" for c in changes)


def test_all_five_are_pushes_not_prs(monkeypatch):
    # Documented in the module: every git-level incident in the set came from an account
    # that already had push rights. If a future incident is PR-based this should fail and
    # be updated deliberately.
    monkeypatch.setattr(fetch, "fetch_commit", lambda o, r, s: _stub_change(f"{o}/{r}", s))
    assert {c.source for c in incidents.load_incidents()} == {"push"}
