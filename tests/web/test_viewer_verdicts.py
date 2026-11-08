"""Recording verdicts in the viewer: the forms, the one POST route and its refusals, and the
verdict pages."""

from __future__ import annotations

import http.client
import threading
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlencode

import pytest

from conftest import REPORT_AS_OF, make_report, report_entry, run_manifest
from kitsunox.core.models import Severity
from kitsunox.core.run import DataDir
from kitsunox.evaluation.confirmations import Confirmations, Takedown
from kitsunox.evaluation.labels import LabelSet, MalwareLabel
from kitsunox.reporting.queue import build_queue, write_queue
from kitsunox.reporting.report import write_report
from kitsunox.reporting.verdicts import REASONS, read_verdicts, verdicts_path
from kitsunox.web import pages
from kitsunox.web.library import Library
from kitsunox.web.server import Form, ViewerServer, make_server, route

RUN = "20261029T210500Z-npm"
TOKEN = "t" * 43
CRAFTED = '<script>alert(1)</script>"x'


@pytest.fixture
def library(tmp_path: Path) -> Library:
    data = DataDir(tmp_path)
    report = make_report(
        RUN,
        report_entry(1, "evil-pkg", "1.0.3", 14, Severity.HIGH, "npm.install-hook"),
        report_entry(2, CRAFTED, "9.9.9", 9, Severity.MEDIUM, "static.exfil-endpoint"),
    )
    run_dir = data.run_dir(RUN)
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text(run_manifest(RUN).model_dump_json())
    write_report(run_dir, report)
    queue = build_queue(data, "npm", days=7)
    assert queue is not None
    write_queue(data, queue)
    return Library(tmp_path)


def post(library: Library, fields: dict[str, str], **form: object) -> tuple[int, str | None]:
    body = urlencode({"token": TOKEN, **fields}).encode()
    same_origin = bool(form.get("same_origin", True))
    content_type = str(form.get("content_type", "application/x-www-form-urlencoded"))
    response = route(
        library, "POST", "/verdict", token=TOKEN, form=Form(body, same_origin, content_type)
    )
    location = dict(response.headers).get("Location")
    return response.status, location


def test_a_verdict_takes_the_version_out_of_the_queue(library: Library) -> None:
    queue = pages.queue_page(library, TOKEN).html
    assert queue.count('action="/verdict"') == 2 and "Verified malicious: 0" in queue
    back = f"/runs/{RUN}/entries/1"
    status, location = post(
        library, {"run": RUN, "rank": "1", "verdict": "malicious", "note": "exfil", "back": back}
    )
    assert (status, location) == (303, back)
    (saved,) = read_verdicts(library.root, "npm")
    assert (saved.name, saved.version, saved.verdict, saved.by) == (
        "evil-pkg",
        "1.0.3",
        "malicious",
        "owner",
    )
    queue = pages.queue_page(library, TOKEN).html
    assert "evil-pkg" not in queue and "Verified malicious: 1" in queue
    listed = pages.verdicts_page(library, "malicious", TOKEN)
    assert listed is not None and "evil-pkg@1.0.3" in listed.html and "exfil" in listed.html
    entry = pages.entry_page(library, RUN, 1, TOKEN)
    assert entry is not None and "Not in the review queue" in entry.html
    assert 'value="reopened"' in entry.html

    status, _ = post(library, {"run": RUN, "rank": "1", "verdict": "reopened", "back": "/"})
    assert status == 303 and "evil-pkg" in pages.queue_page(library, TOKEN).html
    assert pages.verdicts_page(library, "nonsense") is None


def test_a_probe_tag_is_recorded_and_shown(library: Library) -> None:
    entry = pages.entry_page(library, RUN, 1, TOKEN)
    assert entry is not None and 'name="tag" value="probe"' in entry.html
    post(library, {"run": RUN, "rank": "1", "verdict": "malicious", "tag": "probe"})
    (saved,) = read_verdicts(library.root, "npm")
    assert saved.tags == ("probe",)
    assert "Verified malicious: 1</strong> (research probes: 1)" in pages.queue_page(library).html
    listed = pages.verdicts_page(library, "malicious")
    assert listed is not None and '<span class="tag">Research probe</span>' in listed.html


def test_package_text_stays_inert_in_forms_and_verdict_pages(library: Library) -> None:
    queued = pages.queue_page(library, TOKEN).html
    post(library, {"run": RUN, "rank": "2", "verdict": "benign", "note": CRAFTED})
    for document in (
        queued,
        pages.entry_page(library, RUN, 2, TOKEN).html,  # type: ignore[union-attr]
        pages.verdicts_page(library, "benign", TOKEN).html,  # type: ignore[union-attr]
    ):
        assert "<script>" not in document and "&lt;script&gt;" in document


@pytest.mark.parametrize(
    ("fields", "form", "status"),
    [
        ({"token": "wrong"}, {}, 403),
        ({}, {"same_origin": False}, 403),
        ({}, {"content_type": "text/plain"}, 415),
        ({"verdict": "evil"}, {}, 400),
        ({"rank": "0"}, {}, 400),
        ({"run": "../etc"}, {}, 400),
        ({"rank": "7"}, {}, 404),
        ({"note": "x" * 2001}, {}, 400),
        ({"tag": "evil"}, {}, 400),
        ({"verdict": "reopened", "tag": "probe"}, {}, 400),
        ({"verdict": "inconclusive"}, {}, 400),  # the old name is read, never written
        ({"verdict": "unverified"}, {}, 400),  # needs a reason
        ({"verdict": "unverified:lost"}, {}, 400),
        ({"verdict": "benign:gone"}, {}, 400),
        ({"verdict": "reopened:gone"}, {}, 400),
    ],
)
def test_bad_posts_record_nothing(
    library: Library, fields: dict[str, str], form: dict[str, object], status: int
) -> None:
    base = {"run": RUN, "rank": "1", "verdict": "benign"}
    assert post(library, {**base, **fields}, **form)[0] == status
    assert read_verdicts(library.root, "npm") == []


def test_repeated_fields_and_foreign_back_links(library: Library) -> None:
    body = f"token={TOKEN}&run={RUN}&rank=1&verdict=benign&verdict=malicious".encode()
    response = route(library, "POST", "/verdict", token=TOKEN, form=Form(body, True))
    assert response.status == 400
    status, location = post(
        library, {"run": RUN, "rank": "1", "verdict": "benign", "back": "https://evil.example/"}
    )
    assert (status, location) == (303, "/")


def test_a_read_only_viewer_has_no_forms_and_refuses_posts(library: Library) -> None:
    assert "<form" not in pages.queue_page(library).html
    body = urlencode({"token": "", "run": RUN, "rank": "1", "verdict": "benign"}).encode()
    response = route(library, "POST", "/verdict", form=Form(body, True))
    assert response.status == 405 and dict(response.headers)["Allow"] == "GET, HEAD"
    assert read_verdicts(library.root, "npm") == []


@pytest.fixture
def live(library: Library) -> Iterator[ViewerServer]:
    server = make_server(library.root, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def send(server: ViewerServer, body: bytes, headers: dict[str, str]) -> http.client.HTTPResponse:
    host, port = server.server_address[0], int(server.server_address[1])
    connection = http.client.HTTPConnection(str(host), port, timeout=5)
    connection.request("POST", "/verdict", body=body, headers=headers)
    return connection.getresponse()


def test_live_a_form_post_from_the_page_is_recorded(live: ViewerServer) -> None:
    assert live.token is not None
    host = f"127.0.0.1:{live.server_address[1]}"
    form = {"Content-Type": "application/x-www-form-urlencoded", "Origin": f"http://{host}"}
    body = urlencode({"token": live.token, "run": RUN, "rank": "1", "verdict": "malicious"})
    response = send(live, body.encode(), {**form, "Sec-Fetch-Site": "same-origin"})
    assert response.status == 303 and response.getheader("Location") == "/"
    foreign = send(live, body.encode(), {**form, "Origin": "http://evil.example"})
    assert foreign.status == 403
    cross = send(live, body.encode(), {**form, "Sec-Fetch-Site": "cross-site"})
    assert cross.status == 403
    big = send(live, b"x" * 20_000, form)
    assert big.status == 413
    assert [r.verdict for r in read_verdicts(live.library.root, "npm")] == ["malicious"]


def test_read_only_and_remote_servers_have_no_token(library: Library) -> None:
    with make_server(library.root, "127.0.0.1", 0, read_only=True) as server:
        assert server.token is None
    with make_server(library.root, "127.0.0.1", 0) as server:
        assert server.token is not None and len(server.token) >= 40


def test_one_verdict_covers_every_listed_version_of_a_package(tmp_path: Path) -> None:
    data = DataDir(tmp_path)
    report = make_report(
        RUN,
        report_entry(1, "kx", "1.0.2", 9, Severity.HIGH),
        report_entry(2, "kx", "1.0.1", 8, Severity.HIGH),
        report_entry(3, "other", "2.0.0", 7, Severity.MEDIUM),
    )
    run_dir = data.run_dir(RUN)
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text(run_manifest(RUN).model_dump_json())
    write_report(run_dir, report)
    queue = build_queue(data, "npm", days=7)
    assert queue is not None
    write_queue(data, queue)
    library = Library(tmp_path)
    assert "All 2 versions:" in pages.queue_page(library, TOKEN).html

    def send(entries: list[str], verdict: str = "benign") -> int:
        body = urlencode([("token", TOKEN), ("verdict", verdict)] + [("entry", e) for e in entries])
        form = Form(body.encode(), True)
        return route(library, "POST", "/verdict", token=TOKEN, form=form).status

    assert send([f"{RUN}:1", f"{RUN}:3"]) == 400  # two packages: refused, nothing recorded
    assert send([f"{RUN}:1", f"{RUN}:1"]) == 400  # repeated
    assert send(["../x:1"]) == 400
    assert read_verdicts(tmp_path, "npm") == []
    assert send([f"{RUN}:1", f"{RUN}:2"]) == 303
    assert sorted(r.version for r in read_verdicts(tmp_path, "npm")) == ["1.0.1", "1.0.2"]
    assert "kx" not in pages.queue_page(library, TOKEN).html.split("Packages to review")[1]


def test_versions_confirmed_since_are_flagged_on_every_page(library: Library) -> None:
    """A registry takedown or an OSV record shows next to the version (queue, verdict list,
    entry) and a benign verdict it contradicts is listed to review again. OSV ids are outside
    data and are escaped."""
    data = DataDir(library.root)
    status, _ = post(library, {"run": RUN, "rank": "1", "verdict": "benign", "back": "/"})
    assert status == 303
    takedown = Takedown(
        name="evil-pkg", version="0.0.1-security", published_at=REPORT_AS_OF, run_id=RUN
    )
    labels = LabelSet(
        ecosystem="npm",
        source="s",
        fetched_at=REPORT_AS_OF,
        source_sha256="0",
        labels={
            CRAFTED: (MalwareLabel(id="<b>MAL</b>", published=REPORT_AS_OF, versions=("9.9.9",)),)
        },
    )
    queue = build_queue(
        data, "npm", days=7, confirmations=Confirmations([takedown], labels, REPORT_AS_OF)
    )
    assert queue is not None
    write_queue(data, queue)

    page = pages.queue_page(library, TOKEN).html
    assert "Review these again:" in page and "Benign" in page
    assert "removed by the registry 2026-10-29" in page
    assert "Confirmed since: &lt;b&gt;MAL&lt;/b&gt;" in page and "<b>MAL" not in page
    listed = pages.verdicts_page(library, "benign", TOKEN)
    assert listed is not None and "Confirmed since: removed by the registry" in listed.html
    entry = pages.entry_page(library, RUN, 1, TOKEN)
    assert entry is not None and "not part of the score" in entry.html


def test_unwanted_and_unverified_verdicts_with_their_reason(library: Library) -> None:
    entry = pages.entry_page(library, RUN, 1, TOKEN)
    assert entry is not None
    for value in ("malicious", "unwanted", "benign", *(f"unverified:{r}" for r in REASONS)):
        assert f'name="verdict" value="{value}"' in entry.html
    assert 'value="unverified"' not in entry.html and "<script" not in entry.html
    assert 'href="/verdicts/unwanted"' in entry.html and 'href="/verdicts/unverified"' in entry.html
    back = f"/runs/{RUN}/entries/1"
    status, location = post(
        library, {"run": RUN, "rank": "1", "verdict": "unverified:remote", "back": back}
    )
    assert (status, location) == (303, back)
    (saved,) = read_verdicts(library.root, "npm")
    assert (saved.verdict, saved.reason) == ("unverified", "remote")
    shown = pages.entry_page(library, RUN, 1, TOKEN)
    assert shown is not None and '<span class="tag">remote payload</span>' in shown.html
    listed = pages.verdicts_page(library, "unverified", TOKEN)
    assert listed is not None and "Unverified (1)" in listed.html
    assert "Unverified</a>: 1 (remote payload 1)" in listed.html
    status, _ = post(library, {"run": RUN, "rank": "2", "verdict": "unwanted", "note": CRAFTED})
    assert status == 303
    unwanted = pages.verdicts_page(library, "unwanted", TOKEN)
    assert unwanted is not None and "Unwanted (1)" in unwanted.html
    assert "<script>" not in unwanted.html and "&lt;script&gt;" in unwanted.html
    assert pages.verdicts_page(library, "inconclusive") is None


def test_a_legacy_inconclusive_verdict_shows_as_unverified_without_a_reason(
    library: Library,
) -> None:
    post(library, {"run": RUN, "rank": "1", "verdict": "malicious"})
    path = verdicts_path(library.root, "npm")
    path.write_text(path.read_text().replace('"malicious"', '"inconclusive"'))
    listed = pages.verdicts_page(library, "unverified")
    assert listed is not None and "Unverified (1)" in listed.html
    assert '<span class="tag">no reason (was inconclusive)</span>' in listed.html
