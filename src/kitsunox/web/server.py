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
  (no script, no inline style, no images, no frames; forms only to this viewer), `nosniff`, no
  referrer.
- GET and HEAD, HTTP/1.0 and 1.1 (HTTP/0.9 has no headers, so it is refused). The handler never
  fetches. **One write:** `POST /verdict` appends a reviewer's verdict to the verdict log
  (`reporting.verdicts`). It needs the token this server made at start (`secrets`, in every
  form it serves; a page on another site can't read it), an `Origin` naming this viewer when
  the browser sends one, and `Sec-Fetch-Site: same-origin` when sent; the body is a small
  urlencoded form. The package and version come from the run's report on disk, looked up by
  run id and rank, never from the form. A server listening on a non-loopback address
  (`--allow-remote`: no login) or started `read_only` has no token and refuses every POST.
- **Slow or many clients:** each connection has an idle timeout and a total deadline (both
  `REQUEST_TIMEOUT_SECONDS`), after which its socket is shut down; at most `MAX_CONNECTIONS`
  are served at once, and the rest get a 503 and are closed.
- **Errors are short:** a client that hangs up is ignored; any other error is logged as its
  exception type only, never a traceback (which would show paths).
"""

from __future__ import annotations

import contextlib
import hmac
import ipaddress
import re
import secrets
import socket
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any, Final, cast
from urllib.parse import parse_qs

from kitsunox.reporting.report import Report
from kitsunox.reporting.verdicts import (
    MAX_NOTE_CHARS,
    OWNER,
    REASONS,
    TAGS,
    VERDICTS,
    Reason,
    Verdict,
    verdict_record,
)
from kitsunox.web.html import STYLESHEET
from kitsunox.web.library import LIVE_ID, RUN_ID, SAMPLE_DAY, Library
from kitsunox.web.pages import (
    QUEUE,
    Page,
    entry_page,
    failure,
    not_found,
    queue_page,
    run_page,
    runs_page,
    verdicts_index,
    verdicts_page,
)
from kitsunox.web.results import dashboard_page, results_page, sample_page

SECURITY_HEADERS: Final = (
    (
        "Content-Security-Policy",
        "default-src 'none'; style-src 'self'; img-src 'none'; frame-ancestors 'none'; "
        "base-uri 'none'; form-action 'self'",
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
MAX_FORM_BYTES: Final = 16 * 1024
MAX_ENTRIES: Final = 50  # versions one form may give a verdict (`pages.package_form`)
_ENTRY: Final = re.compile(r"([0-9]{8}T[0-9]{6}Z-[a-z0-9]{1,32}):([1-9][0-9]{0,8})")
FORM_TYPE: Final = "application/x-www-form-urlencoded"
_BACK: Final = re.compile(
    r"/(?:queue|runs/[0-9]{8}T[0-9]{6}Z-[a-z0-9]{1,32}/entries/[1-9][0-9]{0,8}"
    r"|verdicts/(?:malicious|unwanted|benign|unverified))?"
)


@dataclass(frozen=True, slots=True)
class Form:
    """A POST as `route` sees it: the body, and whether the request came from this viewer's
    own pages (`Origin` and `Sec-Fetch-Site`, when the browser sent them)."""

    body: bytes
    same_origin: bool
    content_type: str | None = FORM_TYPE


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


def route(
    library: Library,
    method: str,
    target: str,
    *,
    token: str | None = None,
    form: Form | None = None,
) -> Response:
    """The response for one request. `target` is the raw request target, never decoded.
    `token`: the server's form token (None: read-only)."""
    if not target.startswith("/"):
        return _html(failure(400, "Bad request", "Only paths are accepted."))
    path = target.split("?", 1)[0].split("#", 1)[0]
    if method == "POST" and path == "/verdict" and token is not None:
        return _post_verdict(library, token, form)
    if method not in ("GET", "HEAD"):
        allowed = "GET, HEAD, POST" if token is not None else "GET, HEAD"
        page = failure(405, "Method not allowed", "Only pages, and verdicts at /verdict.")
        return Response(405, HTML, page.html.encode(), (("Allow", allowed),))
    if path == STYLESHEET:
        return Response(200, CSS, stylesheet())
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    found = _page(library, path.split("/")[1:], token)
    return _html(found if found is not None else not_found())


def _page(library: Library, parts: list[str], token: str | None = None) -> Page | None:
    match parts:
        case [""]:
            return dashboard_page(library)
        case ["queue"]:
            return queue_page(library, token)
        case ["results"]:
            return results_page(library)
        case ["results", "sample"]:
            return sample_page(library)
        case ["results", "sample", day] if SAMPLE_DAY.fullmatch(day):
            return sample_page(library, day)
        case ["results", dataset] if LIVE_ID.fullmatch(dataset):
            return results_page(library, dataset)
        case ["verdicts"]:
            return verdicts_index(library)
        case ["verdicts", kind]:
            return verdicts_page(library, kind, token)
        case ["runs"]:
            return runs_page(library)
        case ["runs", "page", number] if _NUMBER.fullmatch(number):
            return runs_page(library, int(number))
        case ["runs", run_id] if RUN_ID.fullmatch(run_id):
            return run_page(library, run_id)
        case ["runs", run_id, "entries", rank] if RUN_ID.fullmatch(run_id) and _NUMBER.fullmatch(
            rank
        ):
            return entry_page(library, run_id, int(rank), token)
        case _:
            return None


def _targets(
    fields: dict[str, list[str]], one: Callable[[str], str | None]
) -> list[tuple[str, int]]:
    """The entries a form names: `run` and `rank`, or up to MAX_ENTRIES `entry` fields
    (`run:rank`, each once); [] if malformed."""
    if "entry" in fields:
        if "run" in fields or "rank" in fields or len(fields["entry"]) > MAX_ENTRIES:
            return []
        parsed = [_ENTRY.fullmatch(value) for value in fields["entry"]]
        if not all(parsed) or len(set(fields["entry"])) != len(fields["entry"]):
            return []
        return [(m.group(1), int(m.group(2))) for m in parsed if m]
    run, rank = one("run") or "", one("rank") or ""
    if not RUN_ID.fullmatch(run) or not _NUMBER.fullmatch(rank):
        return []
    return [(run, int(rank))]


def _choice(value: str) -> tuple[Verdict, Reason | None] | None:
    """A form's `verdict` value: a verdict, or `unverified:<reason>` (an unverified verdict
    always names its reason, and nothing else does: decision 0015)."""
    name, _, why = value.partition(":")
    verdict = VERDICTS.get(name)
    if verdict == "unverified":
        reason = REASONS.get(why)
        return None if reason is None else (verdict, reason)
    return None if verdict is None or why else (verdict, None)


def _post_verdict(library: Library, token: str, form: Form | None) -> Response:
    """Record one verdict from a viewer form, then send the reviewer back (303)."""
    if form is None or not form.same_origin:
        return _html(failure(403, "Forbidden", "Verdicts come from this viewer's own pages."))
    if (form.content_type or "").split(";", 1)[0].strip().lower() != FORM_TYPE:
        return _html(failure(415, "Unsupported", "Send the form as the page does."))
    try:
        fields = parse_qs(
            form.body.decode("utf-8"),
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=MAX_ENTRIES + 8,
        )
    except UnicodeDecodeError, ValueError:
        return _html(failure(400, "Bad request", "The form could not be read."))

    def one(name: str) -> str | None:
        values = fields.get(name, [])
        return values[0] if len(values) == 1 else None

    given = one("token") or ""
    if not hmac.compare_digest(given.encode(), token.encode()):
        return _html(failure(403, "Forbidden", "This form is from an older viewer; reload it."))
    note = one("note") or ""
    choice = _choice(one("verdict") or "")
    targets = _targets(fields, one)
    if not targets or choice is None:
        return _html(failure(400, "Bad request", "The form names no verdict on an entry."))
    verdict, reason = choice
    if len(note) > MAX_NOTE_CHARS:
        return _html(failure(400, "Bad request", f"A note is at most {MAX_NOTE_CHARS} characters."))
    named = fields.get("tag", [])
    if any(t not in TAGS for t in named) or (named and verdict == "reopened"):
        return _html(failure(400, "Bad request", "The form names a tag this viewer doesn't have."))
    tags = [TAGS[t] for t in named]
    records = []
    now = datetime.now(UTC)
    for run, rank in targets:
        report = library.report(run)
        entry = (
            next((e for e in report.entries if e.rank == rank), None)
            if isinstance(report, Report)
            else None
        )
        if not isinstance(report, Report) or entry is None:
            return _html(not_found("That run or entry is not on disk any more."))
        records.append(
            verdict_record(
                report, entry, verdict, by=OWNER, note=note, tags=tags, reason=reason, at=now
            )
        )
    if len({r.name for r in records}) > 1:
        return _html(failure(400, "Bad request", "One form gives a verdict on one package."))
    try:
        for record in records:
            library.record_verdict(record)
    except OSError as exc:
        message = f"The verdict could not be written ({type(exc).__name__})."
        return _html(failure(500, "Not saved", message))
    back = one("back") or QUEUE
    if not _BACK.fullmatch(back):
        back = QUEUE
    return Response(303, HTML, b"", (("Location", back),))


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

    def __init__(
        self,
        address: tuple[str, int],
        library: Library,
        allowed: frozenset[str],
        token: str | None = None,
    ):
        self.library = library
        self.allowed = allowed
        self.token = token  # None: read-only
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
        form = None
        if self.command == "POST":
            form = self._form(hosts[0])
            if form is None:
                return
        try:
            response = route(server.library, self.command, self.path, token=server.token, form=form)
        except Exception as exc:  # a page must never show a traceback
            self.log_error("error rendering a page: %s", type(exc).__name__)
            page = failure(500, "Error", "This page could not be rendered.")
            response = _html(page)
        self._send(response)

    def _form(self, host: str) -> Form | None:
        """The POST body (at most MAX_FORM_BYTES; else a 413 is sent and None returned) and
        whether the browser says it came from this viewer."""
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            length = -1
        if not 0 <= length <= MAX_FORM_BYTES:
            self.close_connection = True
            self._send(_html(failure(413, "Too large", "A verdict form is small.")))
            return None
        body = self.rfile.read(length)
        origin = self.headers.get("Origin")
        site = self.headers.get("Sec-Fetch-Site")
        same = (origin is None or origin.strip().lower() == f"http://{host.strip().lower()}") and (
            site is None or site.strip().lower() == "same-origin"
        )
        return Form(body, same, self.headers.get("Content-Type"))

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
    data_dir: Path,
    host: str = "127.0.0.1",
    port: int = 8000,
    *,
    allow_remote: bool = False,
    read_only: bool = False,
) -> ViewerServer:
    """A server for `data_dir`, bound but not yet serving. Port 0 picks a free port.

    `host` is checked before binding and the address it resolved to after: a name such as `0`
    or `0.0` passes the first check but binds every interface. Verdicts can be recorded only
    on a loopback address and without `read_only`."""
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
    if not read_only and bound.is_loopback:
        server.token = secrets.token_urlsafe(32)
    return server


def serve(
    data_dir: Path,
    host: str = "127.0.0.1",
    port: int = 8000,
    *,
    allow_remote: bool = False,
    read_only: bool = False,
    announce: Callable[[str], None] | None = None,
) -> None:
    """Serve the viewer until interrupted (Ctrl-C). `announce` gets the URL once listening.
    Raises `RemoteBindRefusedError` for a host it may not listen on, `OSError` if the port
    can't be bound."""
    with make_server(
        data_dir, host, port, allow_remote=allow_remote, read_only=read_only
    ) as server:
        if announce is not None:
            announce(server.url)
        with contextlib.suppress(KeyboardInterrupt):
            server.serve_forever()
