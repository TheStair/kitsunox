"""The viewer's HTTP layer: routing, traversal, the Host check, headers, binding."""

from __future__ import annotations

import contextlib
import http.client
import ipaddress
import socket
import threading
import time
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from conftest import make_report, report_entry, run_manifest
from kitsunox.core.models import Severity
from kitsunox.core.run import DataDir
from kitsunox.reporting.report import write_report
from kitsunox.web import server as server_module
from kitsunox.web.library import Library
from kitsunox.web.server import (
    SECURITY_HEADERS,
    RemoteBindRefusedError,
    ViewerServer,
    allowed_hosts,
    check_bind_host,
    host_allowed,
    is_loopback,
    make_server,
    route,
    serve,
)

RUN = "20261029T210500Z-npm"
UNREPORTED = "20261029T190500Z-npm"
CSP = (
    "default-src 'none'; style-src 'self'; img-src 'none'; frame-ancestors 'none'; "
    "base-uri 'none'; form-action 'none'"
)


@pytest.fixture
def library(tmp_path: Path) -> Library:
    data = DataDir(tmp_path)
    report = make_report(RUN, report_entry(1, "a", "1.0.0", 3, Severity.MEDIUM, "static.x"))
    run_dir = data.run_dir(RUN)
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text(run_manifest(RUN).model_dump_json())
    write_report(run_dir, report)
    data.run_dir(UNREPORTED).mkdir(parents=True)
    (tmp_path / "secret.txt").write_text("do not serve")
    return Library(tmp_path)


# ----------------------------------------------------------------------------- routing


@pytest.mark.parametrize(
    "target",
    [
        "/",
        "/runs",
        "/runs/",
        f"/runs/{RUN}",
        f"/runs/{RUN}/",
        f"/runs/{RUN}/entries/1",
        f"/runs/{RUN}?x=<y>",
        "/?q=1#frag",
    ],
)
def test_known_pages(library: Library, target: str) -> None:
    response = route(library, "GET", target)
    assert response.status == 200
    assert response.content_type == "text/html; charset=utf-8"
    assert response.body.startswith(b"<!DOCTYPE html>")


@pytest.mark.parametrize(
    "target",
    [
        "/../secret.txt",
        "/runs/../secret.txt",
        "/runs/../../etc/passwd",
        f"/runs/{RUN}/../../secret.txt",
        f"/runs/{RUN}/../{RUN}",
        "/runs/%2e%2e/secret.txt",
        "/runs/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        f"/runs/{RUN}%2f..%2f..%2fsecret.txt",
        "/runs/..%5c..%5csecret.txt",
        "//etc/passwd",
        "/etc/passwd",
        "/secret.txt",
        f"/runs/{RUN}\x00",
        f"/runs/{RUN}%00",
        f"/runs/{RUN}/entries/1%00",
        "/static/../secret.txt",
        "/static/style.css/..",
        "/static/other.css",
        "/static/",
        f"/runs/{RUN}/report/report.json",
        f"/runs/{RUN}/manifest.json",
        f"/runs/{RUN}/entries/0",
        f"/runs/{RUN}/entries/01",
        f"/runs/{RUN}/entries/-1",
        f"/runs/{RUN}/entries/2",
        f"/runs/{RUN}/entries/9999999999",
        f"/runs/{RUN.upper()}",
        "/runs/20991029T210500Z-npm",  # well formed, not on disk
        f"/runs/{UNREPORTED}",  # on disk, no report
        f"/runs/{UNREPORTED}/entries/1",
        "/runs/page/0",
        "/runs/page/2",
        "/runs/page/x",
        "/runs//",
        "/queue/queue.json",
    ],
)
def test_traversal_and_unknown_ids_are_404(library: Library, target: str) -> None:
    response = route(library, "GET", target)
    assert response.status == 404
    assert b"do not serve" not in response.body
    assert b"Not found" in response.body


@pytest.mark.parametrize("target", ["http://evil.example/", "*", "C:\\secret.txt", ""])
def test_non_path_targets_are_400(library: Library, target: str) -> None:
    assert route(library, "GET", target).status == 400


def test_only_get_and_head(library: Library) -> None:
    assert route(library, "HEAD", "/").status == 200
    response = route(library, "POST", "/")
    assert response.status == 405
    assert response.headers == (("Allow", "GET, HEAD"),)


def test_stylesheet_is_served_and_fetches_nothing(library: Library) -> None:
    response = route(library, "GET", "/static/style.css?v=1")
    assert (response.status, response.content_type) == (200, "text/css; charset=utf-8")
    assert b"url(" not in response.body and b"@import" not in response.body
    assert b"body" in response.body


# ----------------------------------------------------------------------------- hosts


@pytest.mark.parametrize(
    ("header", "ok"),
    [
        ("127.0.0.1:8000", True),
        ("127.0.0.1", True),
        ("localhost:9000", True),  # an SSH tunnel's local port
        ("LOCALHOST:8000", True),
        ("[::1]:8000", True),
        ("[::1]", True),
        ("evil.example:8000", False),
        ("evil.example", False),
        ("127.0.0.1.evil.example", False),
        ("localhost.", False),
        ("localhost:80:80", False),
        ("localhost:http", False),
        ("[::1", False),
        ("[::1]x", False),
        ("::1", False),
        ("", False),
        (None, False),
    ],
)
def test_host_header_check(header: str | None, ok: bool) -> None:
    assert host_allowed(header, allowed_hosts("127.0.0.1")) is ok


def test_allowed_hosts_include_the_bound_address() -> None:
    assert "[fd00::5]" in allowed_hosts("fd00::5")
    assert "[fd00::5]" in allowed_hosts("[fd00::5]")
    assert host_allowed("192.168.1.5:8000", allowed_hosts("192.168.1.5"))
    assert not host_allowed("192.168.1.6:8000", allowed_hosts("192.168.1.5"))


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "localhost", "::1", "[::1]"])
def test_loopback_hosts_may_be_bound(host: str) -> None:
    assert is_loopback(host)
    check_bind_host(host, allow_remote=False)


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "", "192.168.1.5", "example.com"])  # noqa: S104
def test_other_hosts_are_refused_by_default(host: str) -> None:
    assert not is_loopback(host)
    with pytest.raises(RemoteBindRefusedError, match="not a loopback address"):
        check_bind_host(host, allow_remote=False)


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "[::]", ""])  # noqa: S104
def test_every_interface_is_refused_even_when_allowed(host: str) -> None:
    with pytest.raises(RemoteBindRefusedError, match="every interface"):
        check_bind_host(host, allow_remote=True)


@pytest.mark.parametrize("host", ["192.168.1.5", "vm.example"])
def test_a_specific_remote_host_needs_the_flag(host: str) -> None:
    check_bind_host(host, allow_remote=True)


def test_make_server_refuses_remote_hosts(tmp_path: Path) -> None:
    with pytest.raises(RemoteBindRefusedError):
        make_server(tmp_path, "0.0.0.0", 0)  # noqa: S104


# ----------------------------------------------------------------------------- live server


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


def request(
    server: ViewerServer, method: str, path: str, headers: dict[str, str] | None = None
) -> http.client.HTTPResponse:
    host, port = server.server_address[0], int(server.server_address[1])
    connection = http.client.HTTPConnection(str(host), port, timeout=5)
    connection.request(method, path, headers=headers or {})
    return connection.getresponse()


def raw(server: ViewerServer, data: bytes) -> bytes:
    host, port = server.server_address[0], int(server.server_address[1])
    with socket.create_connection((str(host), port), timeout=5) as sock:
        sock.sendall(data)
        chunks = []
        while chunk := sock.recv(65536):
            chunks.append(chunk)
    return b"".join(chunks)


def assert_security_headers(response: http.client.HTTPResponse) -> None:
    assert response.getheader("Content-Security-Policy") == CSP
    assert response.getheader("X-Content-Type-Options") == "nosniff"
    assert response.getheader("Referrer-Policy") == "no-referrer"
    for name, value in SECURITY_HEADERS:
        assert response.getheader(name) == value


def test_live_pages_carry_the_security_headers(live: ViewerServer) -> None:
    assert live.url.startswith("http://127.0.0.1:")
    for path, status in (("/", 200), (f"/runs/{RUN}/entries/1", 200), ("/nope", 404)):
        response = request(live, "GET", path)
        body = response.read()
        assert response.status == status
        assert_security_headers(response)
        assert response.getheader("Content-Length") == str(len(body))
        assert b"<script" not in body and b"style=" not in body and b"<style" not in body
    css = request(live, "GET", "/static/style.css")
    assert css.getheader("Content-Type") == "text/css; charset=utf-8"
    assert_security_headers(css)
    assert "Python" not in (css.getheader("Server") or "")


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "OPTIONS"])
def test_live_writes_are_refused(live: ViewerServer, method: str) -> None:
    response = request(live, method, "/", {"Content-Length": "0"})
    assert response.status == 405
    assert_security_headers(response)


def test_live_head_has_no_body_and_post_is_refused(live: ViewerServer) -> None:
    head = request(live, "HEAD", "/")
    assert head.status == 200 and head.read() == b""
    assert int(head.getheader("Content-Length") or 0) > 0
    post = request(live, "POST", "/", {"Content-Length": "0"})
    assert post.status == 405 and post.getheader("Allow") == "GET, HEAD"
    assert_security_headers(post)


@pytest.mark.parametrize("host", ["evil.example", "evil.example:8000", "127.0.0.1.nip.io"])
def test_live_foreign_host_headers_are_refused(live: ViewerServer, host: str) -> None:
    response = request(live, "GET", "/", {"Host": host})
    assert response.status == 400
    assert b"Host header" in response.read()
    assert_security_headers(response)


def test_live_missing_or_repeated_host_is_refused(live: ViewerServer) -> None:
    assert raw(live, b"GET / HTTP/1.0\r\n\r\n").startswith(b"HTTP/1.0 400")
    repeated = b"GET / HTTP/1.1\r\nHost: localhost\r\nHost: evil.example\r\n\r\n"
    assert raw(live, repeated).startswith(b"HTTP/1.0 400")


def test_live_malformed_requests_get_our_error_page(live: ViewerServer) -> None:
    for line, status in ((b"BREW / HTTP/1.0", b"501"), (b"GET / HTTP/9.9", b"505")):
        answer = raw(live, line + b"\r\nHost: localhost\r\n\r\n")
        assert answer.startswith(b"HTTP/1.0 " + status)
        assert b"Content-Security-Policy: default-src 'none'" in answer
        assert b"Kitsunox" in answer
    traversal = raw(live, b"GET /runs/../secret.txt HTTP/1.0\r\nHost: localhost\r\n\r\n")
    assert traversal.startswith(b"HTTP/1.0 404") and b"do not serve" not in traversal


def test_live_render_errors_show_no_traceback(
    live: ViewerServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*args: object) -> object:
        raise RuntimeError("secret <detail>")

    monkeypatch.setattr(server_module, "route", broken)
    response = request(live, "GET", "/")
    body = response.read()
    assert response.status == 500
    assert b"could not be rendered" in body
    assert b"secret" not in body and b"Traceback" not in body
    assert_security_headers(response)


def test_send_error_with_an_unknown_code(live: ViewerServer) -> None:
    handler = server_module.ViewerHandler.__new__(server_module.ViewerHandler)
    sent: list[int] = []
    handler.log_error = lambda *args: None  # type: ignore[method-assign]
    handler._send = lambda response: sent.append(response.status)  # type: ignore[method-assign]
    handler.send_error(599)
    assert sent == [599]


def test_ipv6_loopback(tmp_path: Path) -> None:
    try:
        server = make_server(tmp_path, "::1", 0)
    except OSError:
        pytest.skip("no IPv6 loopback")
    with server:
        assert server.url.startswith("http://[::1]:")
        assert "[::1]" in server.allowed


def test_serve_announces_and_stops_on_interrupt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupted(self: ViewerServer, poll_interval: float = 0.5) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(ViewerServer, "serve_forever", interrupted)
    urls: list[str] = []
    serve(tmp_path, "127.0.0.1", 0, announce=urls.append)
    serve(tmp_path, "127.0.0.1", 0)
    assert len(urls) == 1 and urls[0].startswith("http://127.0.0.1:")


# ----------------------------------------------------------------------------- hardening


@pytest.mark.parametrize("host", ["0", "0.0", "0.0.0"])
def test_names_that_bind_every_interface_are_refused(tmp_path: Path, host: str) -> None:
    with pytest.raises(RemoteBindRefusedError, match="not a loopback address"):
        make_server(tmp_path, host, 0)
    with pytest.raises(RemoteBindRefusedError, match=r"binds 0\.0\.0\.0, every interface"):
        make_server(tmp_path, host, 0, allow_remote=True)


def test_a_loopback_name_bound_elsewhere_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`localhost` mapped to a LAN address in /etc/hosts passes the name check, not the bind
    check."""
    closed: list[bool] = []
    monkeypatch.setattr(
        ViewerServer, "bound_address", property(lambda self: ipaddress.ip_address("192.0.2.7"))
    )
    monkeypatch.setattr(ViewerServer, "server_close", lambda self: closed.append(True))
    with pytest.raises(RemoteBindRefusedError, match=r"binds 192\.0\.2\.7, not a loopback"):
        make_server(tmp_path, "localhost", 0)
    assert closed == [True]
    server = make_server(tmp_path, "localhost", 0, allow_remote=True)
    assert "192.0.2.7" in server.allowed  # the Host check accepts the bound address


def test_bound_address_of_a_live_server(live: ViewerServer) -> None:
    assert live.bound_address == ipaddress.ip_address("127.0.0.1")
    assert "127.0.0.1" in live.allowed


@pytest.mark.parametrize("line", [b"GET /", b"GET /runs", b"POST /", b"GARBAGE"])
def test_live_http09_and_bare_request_lines_are_refused(live: ViewerServer, line: bytes) -> None:
    answer = raw(live, line + b"\r\n")
    assert answer.startswith(b"HTTP/1.0 400"), answer[:40]
    assert b"Content-Security-Policy: default-src 'none'" in answer
    assert b"Kitsunox" in answer


def test_live_client_hangups_and_errors_print_no_traceback(
    live: ViewerServer, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def hang_up(self: object, response: object) -> None:
        raise ConnectionResetError(104, "reset by peer at /home/someone/secret")

    monkeypatch.setattr(server_module.ViewerHandler, "_send", hang_up)
    assert raw(live, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n") == b""
    err = capsys.readouterr().err
    assert "Traceback" not in err and "secret" not in err and "ConnectionResetError" not in err
    for exc in (BrokenPipeError(32, "pipe"), TimeoutError(), RuntimeError("/home/x/secret")):
        try:
            raise exc
        except Exception:
            live.handle_error(None, ("127.0.0.1", 1))
    err = capsys.readouterr().err
    assert err == "kitsunox view: error handling a request (RuntimeError)\n"


def test_live_slow_clients_are_cut_at_the_deadline(live: ViewerServer) -> None:
    live.deadline = 0.3
    host, port = live.server_address[0], int(live.server_address[1])
    with socket.create_connection((str(host), port), timeout=5) as sock:
        started = time.monotonic()
        sock.sendall(b"GET / HTTP/1.1\r\n")  # and never the rest
        with contextlib.suppress(ConnectionResetError):
            assert sock.recv(1024) == b""
        assert time.monotonic() - started < 4  # well before the 30 s idle timeout


def test_live_connections_beyond_the_cap_get_503(live: ViewerServer) -> None:
    live.slots = threading.BoundedSemaphore(1)
    host, port = live.server_address[0], int(live.server_address[1])
    with socket.create_connection((str(host), port), timeout=5) as holder:
        # Accepted first (the listen queue is in order), so it holds the only slot.
        busy = raw(live, b"")
        assert busy.startswith(b"HTTP/1.0 503 Service Unavailable\r\n")
        assert b"Content-Security-Policy: default-src 'none'" in busy
        head, body = busy.split(b"\r\n\r\n", 1)
        assert f"Content-Length: {len(body)}".encode() in head and b"Busy" in body
        holder.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        assert holder.recv(12) == b"HTTP/1.0 200"
    for _ in range(50):  # the slot comes back once the holder's thread finishes
        if live.slots.acquire(blocking=False):
            live.slots.release()
            break
        time.sleep(0.05)
    assert raw(live, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n").startswith(b"HTTP/1.0 200")


def test_a_thread_that_cannot_start_returns_its_slot(
    live: ViewerServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    live.slots = threading.BoundedSemaphore(1)

    def no_thread(self: object, request: object, client_address: object) -> None:
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(ThreadingHTTPServer, "process_request", no_thread)
    with pytest.raises(RuntimeError):
        live.process_request(None, ("127.0.0.1", 1))
    assert live.slots.acquire(blocking=False)


def test_a_deadline_timer_that_cannot_start_closes_and_returns_its_slot(
    live: ViewerServer, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    live.slots = threading.BoundedSemaphore(1)
    original = threading.Timer.start
    failures = [1]

    def flaky_start(self: threading.Timer) -> None:
        if failures:
            failures.pop()
            raise RuntimeError("can't start new thread")
        original(self)

    monkeypatch.setattr(threading.Timer, "start", flaky_start)
    # Closed unserved (an unread request may make the close a reset), not left hanging.
    with contextlib.suppress(ConnectionResetError):
        assert raw(live, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n") == b""
    for _ in range(50):  # the slot comes back once the worker thread returns
        if live.slots.acquire(blocking=False):
            live.slots.release()
            break
        time.sleep(0.05)
    assert "Traceback" not in capsys.readouterr().err
    assert raw(live, b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n").startswith(b"HTTP/1.0 200")
