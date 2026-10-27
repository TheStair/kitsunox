"""Shared test helpers. Everything here is offline and inert."""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import tarfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@dataclass
class TarEntry:
    name: str
    data: bytes = b""
    type: bytes = tarfile.REGTYPE
    linkname: str = ""


def make_tar_gz(entries: Iterable[TarEntry]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for entry in entries:
            info = tarfile.TarInfo(entry.name)
            info.type = entry.type
            info.linkname = entry.linkname
            info.size = len(entry.data) if entry.type == tarfile.REGTYPE else 0
            tar.addfile(info, io.BytesIO(entry.data) if info.size else None)
    return gzip.compress(buffer.getvalue(), mtime=0)


def sri_sha512(data: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


@dataclass
class Router:
    """Mock HTTP server: exact URL -> (status, body). Records every request it sees."""

    routes: dict[str, tuple[int, bytes]] = field(default_factory=dict)
    requests: list[str] = field(default_factory=list)

    def add_json(self, url: str, payload: object, status: int = 200) -> None:
        self.routes[url] = (status, json.dumps(payload).encode())

    def add_bytes(self, url: str, body: bytes, status: int = 200) -> None:
        self.routes[url] = (status, body)

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.requests.append(url)
        status, body = self.routes.get(url, (404, b'{"error":"not found"}'))
        return httpx.Response(status, content=body)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))


@pytest.fixture
def router() -> Router:
    return Router()


@pytest.fixture
def load_fixture() -> Callable[[str], object]:
    def load(relative: str) -> object:
        return json.loads((FIXTURES / relative).read_text())

    return load
