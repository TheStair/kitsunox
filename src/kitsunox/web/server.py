"""The local HTTP server: routing, the Host check and the response headers.

- **Loopback only by default.** `serve` refuses to bind anything but a loopback address unless
  `allow_remote` is set, and even then refuses the unspecified address (`0.0.0.0`, `::`), so
  the Host check below always knows the names it may accept. The address actually bound is
  checked too, because names like `0` or `0.0` resolve to `0.0.0.0`. There is no TLS and no
  login.
- **Host check** (DNS-rebinding defence): a page on another site that rebinds its name to
  127.0.0.1 still sends its own name in `Host`, so only loopback names (and the bound address)
  are accepted, with any port (an SSH tunnel may use another local port).
- **Routing never touches the filesystem with request text.** The raw request path is split
  and matched segment by segment against fixed names and regexes; nothing is percent-decoded,
  so `%2e%2e`, `..`, NUL or absolute forms simply match nothing (404). Run ids are then looked
  up among the runs actually on disk (`Library.find_run`).
- **Headers on every response:** a Content-Security-Policy that allows only the one stylesheet
  (no script, no inline style, no images, no frames, no forms), `nosniff`, no referrer.
- Only GET and HEAD, HTTP/1.0 and 1.1 (HTTP/0.9 has no headers, so it is refused). The handler
  never writes to the data directory and never fetches.
- **Slow or many clients:** each connection has an idle timeout and a total deadline (both
  `REQUEST_TIMEOUT_SECONDS`), after which its socket is shut down; at most `MAX_CONNECTIONS`
  are served at once, and the rest get a 503 and are closed.
- **Errors are short:** a client that hangs up is ignored; any other error is logged as its
  exception type only, never a traceback (which would show paths).
"""

from __future__ import annotations

import contextlib
import ipaddress
import re
import socket
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any, Final, cast

from kitsunox.web.html import STYLESHEET
from kitsunox.web.library import RUN_ID, Library
from kitsunox.web.pages import Page, entry_page, failure, not_found, queue_page, run_page, runs_page

SECURITY_HEADERS: Final = (
    (
        "Content-Security-Policy",
        "default-src 'none'; style-src 'self'; img-src 'none'; frame-ancestors 'none'; "
        "base-uri 'none'; form-action 'none'",
    ),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Frame-Options", "DENY"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Cache-Control", "no-store"),
)
HTML: Final = "text/html; charset=utf-8"
CSS: Final = "text/css; charset=utf-8"
LOOPBACK_NAMES: Final = frozenset({"localhost", "127.0.0.1", "[::1]"})
REQUEST_TIMEOUT_SECONDS: Final = 30
MAX_CONNECTIONS: Final = 32
_NUMBER: Final = re.compile(r"[1-9][0-9]{0,8}")
_PORT: Final = re.compile(r":[0-9]{1,5}")


class RemoteBindRefusedError(ValueError):
    """The viewer was asked to listen on an address other machines can reach."""


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    content_type: str
    body: bytes
    headers: tuple[tuple[str, str], ...] = field(default=())


def stylesheet() -> bytes:
    return resources.files("kitsunox.web").joinpath("style.css").read_bytes()


def _html(page: Page) -> Response:
    return Response(page.status, HTML, page.html.encode())


def _busy() -> bytes:
    """A whole 503 response, for a connection refused before a handler exists."""
    body = failure(503, "Busy", "Too many connections at once; try again shortly.").html.encode()
    headers = [("Content-Type", HTML), ("Content-Length", str(len(body))), *SECURITY_HEADERS]
    head = "".join(f"{name}: {value}\r\n" for name, value in headers)
    return f"HTTP/1.0 503 Service Unavailable\r\n{head}Connection: close\r\n\r\n".encode() + body


def route(library: Library, method: str, target: str) -> Response:
    """The response for one request. `target` is the raw request target, never decoded."""
    if method not in ("GET", "HEAD"):
        page = failure(405, "Method not allowed", "This viewer is read-only: GET and HEAD only.")
        return Response(405, HTML, page.html.encode(), (("Allow", "GET, HEAD"),))
    if not target.startswith("/"):
        return _html(failure(400, "Bad request", "Only paths are accepted."))
    path = target.split("?", 1)[0].split("#", 1)[0]
    if path == STYLESHEET:
        return Response(200, CSS, stylesheet())
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    found = _page(library, path.split("/")[1:])
    return _html(found if found is not None else not_found())


def _page(library: Library, parts: list[str]) -> Page | None:
    match parts:
        case [""]:
            return queue_page(library)
        case ["runs"]:
            return runs_page(library)
        case ["runs", "page", number] if _NUMBER.fullmatch(number):
            return runs_page(library, int(number))
        case ["runs", run_id] if RUN_ID.fullmatch(run_id):
            return run_page(library, run_id)
        case ["runs", run_id, "entries", rank] if RUN_ID.fullmatch(run_id) and _NUMBER.fullmatch(
            rank
        ):
            return entry_page(library, run_id, int(rank))
        case _:
            return None


# ----------------------------------------------------------------------------- hosts


def is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.removeprefix("[").removesuffix("]")).is_loopback
    except ValueError:
        return False


def check_bind_host(host: str, *, allow_remote: bool) -> None:
    """Raise `RemoteBindRefusedError` unless the viewer may listen on `host`."""
    if is_loopback(host):
        return
    if not allow_remote:
        raise RemoteBindRefusedError(
            f"refusing to listen on {host!r}: not a loopback address. The viewer has no login "
            "or TLS; use an SSH tunnel (ssh -L 8000:127.0.0.1:8000 <vm>), or allow remote "
            "access explicitly."
        )
    try:
        unspecified = ipaddress.ip_address(host.strip("[]")).is_unspecified
    except ValueError:
        unspecified = host == ""
    if unspecified:
        raise RemoteBindRefusedError(
            f"refusing to listen on {host!r} (every interface): give one specific address, so "
            "requests can be checked against it."
        )


def allowed_hosts(host: str) -> frozenset[str]:
    """Host header names accepted when listening on `host`: loopback names plus `host`."""
    name = host.lower()
    if ":" in name and not name.startswith("["):
        name = f"[{name}]"
    return LOOPBACK_NAMES | {name}


def host_allowed(header: str | None, allowed: frozenset[str]) -> bool:
    """Whether a `Host` header names this viewer (any port)."""
    if header is None:
        return False
    value = header.strip().lower()
    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            return False
        name, port = value[: end + 1], value[end + 1 :]
    else:
        name, colon, rest = value.partition(":")
        port = colon + rest
    if port and not _PORT.fullmatch(port):
        return False
    return name in allowed


# ----------------------------------------------------------------------------- server


class ViewerServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], library: Library, allowed: frozenset[str]):
        self.library = library
        self.allowed = allowed
        self.deadline: float = REQUEST_TIMEOUT_SECONDS
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, ViewerHandler)

    @property
    def bound_address(self) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        return ipaddress.ip_address(str(self.server_address[0]).split("%", 1)[0])

    def process_request(self, request: Any, client_address: Any) -> None:
        """One thread per connection, at most `MAX_CONNECTIONS` at once; beyond that a short
        503 and close."""
        if not self.slots.acquire(blocking=False):
            with contextlib.suppress(OSError):
                request.settimeout(1)
                request.sendall(_busy())
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        """Serve one connection, shutting its socket down at the deadline however busy the
        client keeps it (the per-read timeout alone lets a client trickle bytes forever). If
        the deadline thread can't start, the connection is closed unserved (never served
        without a deadline) and its slot still comes back."""
        timer = threading.Timer(self.deadline, _cut, (request,))
        timer.daemon = True
        try:
            try:
                timer.start()
            except RuntimeError:
                self.shutdown_request(request)
                return
            super().process_request_thread(request, client_address)
        finally:
            timer.cancel()
            self.slots.release()

    def handle_error(self, request: Any, client_address: Any) -> None:
        """No traceback (it shows paths): a client hanging up is normal, anything else is
        logged as its type."""
        exc = sys.exception()
        if isinstance(exc, ConnectionError | TimeoutError):
            return
        sys.stderr.write(f"kitsunox view: error handling a request ({type(exc).__name__})\n")

    @property
    def url(self) -> str:
        host, port = str(self.server_address[0]), int(self.server_address[1])
        shown = f"[{host}]" if ":" in host else host
        return f"http://{shown}:{port}/"


def _cut(request: socket.socket) -> None:
    with contextlib.suppress(OSError):
        request.shutdown(socket.SHUT_RDWR)


class ViewerHandler(BaseHTTPRequestHandler):
    server_version = "kitsunox-viewer"
    sys_version = ""
    timeout = REQUEST_TIMEOUT_SECONDS

    def do_GET(self) -> None:
        self._handle()

    def do_HEAD(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def do_PUT(self) -> None:
        self._handle()

    def do_DELETE(self) -> None:
        self._handle()

    def do_PATCH(self) -> None:
        self._handle()

    def do_OPTIONS(self) -> None:
        self._handle()

    def parse_request(self) -> bool:
        """Refuse HTTP/0.9 ("GET /" with no version): it has no headers, so neither the Host
        check nor our response headers would apply."""
        if not super().parse_request():
            return False
        if self.request_version == "HTTP/0.9":
            self.send_error(400, "HTTP/0.9 request")
            return False
        return True

    def _handle(self) -> None:
        server = cast(ViewerServer, self.server)
        hosts = self.headers.get_all("Host") or []
        if len(hosts) != 1 or not host_allowed(hosts[0], server.allowed):
            page = failure(400, "Bad request", "The Host header doesn't name this viewer.")
            self._send(_html(page))
            return
        try:
            response = route(server.library, self.command, self.path)
        except Exception as exc:  # a page must never show a traceback
            self.log_error("error rendering a page: %s", type(exc).__name__)
            page = failure(500, "Error", "This page could not be rendered.")
            response = _html(page)
        self._send(response)

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        """Errors raised by `http.server` itself (malformed request, unknown method, line too
        long) get the same page and headers as ours; its own template is not used."""
        self.log_error("code %d, message %s", code, message)
        self.close_connection = True
        if getattr(self, "request_version", "") == "HTTP/0.9":
            # `http.server` writes no status line or headers for HTTP/0.9, which is also its
            # default before a request line is understood ("GARBAGE"): answer as HTTP/1.0.
            self.request_version = "HTTP/1.0"
        try:
            title = HTTPStatus(code).phrase
        except ValueError:
            title = "Error"
        self._send(_html(failure(code, title, "The request could not be handled.")))

    def _send(self, response: Response) -> None:
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(response.body)))
        for name, value in (*SECURITY_HEADERS, *response.headers):
            self.send_header(name, value)
        self.end_headers()
        if getattr(self, "command", None) != "HEAD":
            self.wfile.write(response.body)


def make_server(
    data_dir: Path, host: str = "127.0.0.1", port: int = 8000, *, allow_remote: bool = False
) -> ViewerServer:
    """A server for `data_dir`, bound but not yet serving. Port 0 picks a free port.

    `host` is checked before binding and the address it resolved to after: a name such as `0`
    or `0.0` passes the first check but binds every interface."""
    check_bind_host(host, allow_remote=allow_remote)
    server = ViewerServer((host.strip("[]"), port), Library(data_dir), allowed_hosts(host))
    bound = server.bound_address
    if bound.is_unspecified:
        server.server_close()
        raise RemoteBindRefusedError(
            f"refusing to listen on {host!r}: it binds {bound}, every interface. Give one "
            "specific address, so requests can be checked against it."
        )
    if not bound.is_loopback and not allow_remote:
        server.server_close()
        raise RemoteBindRefusedError(
            f"refusing to listen on {host!r}: it binds {bound}, not a loopback address."
        )
    server.allowed = server.allowed | allowed_hosts(str(bound))
    return server


def serve(
    data_dir: Path,
    host: str = "127.0.0.1",
    port: int = 8000,
    *,
    allow_remote: bool = False,
    announce: Callable[[str], None] | None = None,
) -> None:
    """Serve the viewer until interrupted (Ctrl-C). `announce` gets the URL once listening.
    Raises `RemoteBindRefusedError` for a host it may not listen on, `OSError` if the port
    can't be bound."""
    with make_server(data_dir, host, port, allow_remote=allow_remote) as server:
        if announce is not None:
            announce(server.url)
        with contextlib.suppress(KeyboardInterrupt):
            server.serve_forever()
