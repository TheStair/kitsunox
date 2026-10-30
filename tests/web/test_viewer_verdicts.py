"""Recording verdicts in the viewer: the forms, the one POST route and its refusals, and the
verdict pages."""

from __future__ import annotations

import http.client
import threading
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlencode

import pytest

from conftest import make_report, report_entry, run_manifest
from kitsunox.core.models import Severity
from kitsunox.core.run import DataDir
from kitsunox.reporting.queue import build_queue, write_queue
from kitsunox.reporting.report import write_report
from kitsunox.reporting.verdicts import read_verdicts
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
