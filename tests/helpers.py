"""Shared test utilities for spinning up local proxy instances and reading raw HTTP."""

import contextlib
import socket
import threading
import time
from collections.abc import Iterator
from typing import Any

from impersonate_proxy.context import ProxyContext
from impersonate_proxy.server import ThreadingHTTPServer, create_handler_class


class FakeResponse:
    """Minimal stand-in for a curl_cffi Response."""

    def __init__(self, status_code: int = 200, body: bytes = b"resp-body"):
        self.status_code = status_code
        self.headers: Any = {"Content-Type": "text/plain"}
        self._body = body

    def iter_content(self) -> Iterator[bytes]:
        yield self._body

    def close(self) -> None:
        pass


def get_free_port() -> int:
    """Allocate and return an available ephemeral TCP port on 127.0.0.1."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def wait_ready(port: int, timeout: float = 5.0) -> None:
    """Block until a TCP listener on 127.0.0.1:port accepts connections."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with contextlib.suppress(OSError):
            s = socket.create_connection(("127.0.0.1", port), timeout=0.1)
            s.close()
            return
        time.sleep(0.05)
    raise RuntimeError(f"server on 127.0.0.1:{port} never became ready")


def start_proxy(ctx: ProxyContext) -> tuple[ThreadingHTTPServer, str]:
    """Start a ThreadingHTTPServer bound to ctx on a free loopback port."""
    port = get_free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), create_handler_class(ctx), ctx)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    wait_ready(port)
    return server, f"http://127.0.0.1:{port}"


def read_http_response(sock: socket.socket) -> tuple[int, bytes]:
    """Read one HTTP response (chunked or Content-Length framed) from a socket."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("connection closed before response headers")
        buf += chunk
    head, _, stream = buf.partition(b"\r\n\r\n")
    status = int(head.split(b" ", 2)[1])
    head_lower = head.lower()
    body = b""
    if b"transfer-encoding: chunked" in head_lower:
        while True:
            while b"\r\n" not in stream:
                stream += sock.recv(4096)
            size_line, _, stream = stream.partition(b"\r\n")
            size = int(size_line.split(b";")[0], 16)
            if size == 0:
                break
            while len(stream) < size + 2:
                stream += sock.recv(4096)
            body += stream[:size]
            stream = stream[size + 2 :]
    elif b"content-length:" in head_lower:
        cl = int(head.split(b"Content-Length: ", 1)[1].split(b"\r\n", 1)[0])
        while len(stream) < cl:
            stream += sock.recv(4096)
        body = stream[:cl]
    return status, body
