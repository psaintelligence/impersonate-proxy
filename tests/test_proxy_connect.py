"""Unit tests for HTTPS CONNECT tunnel handling: MITM keep-alive, body limits, host blocking."""

import os
import socket
import ssl
import tempfile
import threading
import time
from unittest.mock import patch

import pytest

from impersonate_proxy.cert_manager import init_ca
from impersonate_proxy.context import ProxyConfig, ProxyContext
from impersonate_proxy.server import ThreadingHTTPServer, create_handler_class


class _FakeResponse:
    """Minimal stand-in for a curl_cffi Response."""

    def __init__(self, status_code: int = 200, body: bytes = b"resp-body"):
        self.status_code = status_code
        self.headers = {"Content-Type": "text/plain"}
        self._body = body

    def iter_content(self):
        yield self._body

    def close(self) -> None:
        pass


def _get_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_ready(port: int) -> None:
    for _ in range(50):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.1)
            s.close()
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("proxy never became ready")


@pytest.fixture()
def mitm_proxy():
    """Start a real proxy with CA + MITM enabled; upstream requests are faked."""
    with tempfile.TemporaryDirectory() as ca_dir:
        ctx = ProxyContext(ProxyConfig(ca_dir=ca_dir))
        init_ca(ctx, ca_dir)
        port = _get_free_port()
        server = ThreadingHTTPServer(("127.0.0.1", port), create_handler_class(ctx), ctx)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        _wait_ready(port)
        yield ctx, f"http://127.0.0.1:{port}", ca_dir
        server.shutdown()
        ctx.clear_session_pool()


def _read_response(sock) -> tuple[int, bytes]:
    """Read one HTTP response (chunked or Content-Length framed) from the socket."""
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


def _open_tunnel(proxy_url: str, host: str, ca_dir: str) -> ssl.SSLSocket:
    """Issue CONNECT and perform the client-side TLS handshake against the MITM cert."""
    proxy_host, proxy_port = proxy_url.split("//")[1].split(":")
    raw = socket.create_connection((proxy_host, int(proxy_port)), timeout=10)
    raw.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = raw.recv(4096)
        if not chunk:
            raise ConnectionError("closed before CONNECT response")
        buf += chunk
    status = int(buf.split(b" ", 2)[1])
    assert status == 200, f"CONNECT failed: {buf[:120]!r}"
    tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls_ctx.load_verify_locations(cafile=os.path.join(ca_dir, "ca.crt"))
    return tls_ctx.wrap_socket(raw, server_hostname=host)


class TestConnectKeepAlive:
    def test_two_requests_on_one_tunnel(self, mitm_proxy):
        ctx, proxy_url, ca_dir = mitm_proxy
        calls: list[tuple[str, bytes | None]] = []

        def fake_do_request(c, method, url, headers, body, allow_redirects=False):
            calls.append((url, body))
            return _FakeResponse()

        with patch("impersonate_proxy.server.do_request", fake_do_request):
            tls = _open_tunnel(proxy_url, "keepalive.test", ca_dir)
            try:
                tls.sendall(b"GET /one HTTP/1.1\r\nHost: keepalive.test\r\n\r\n")
                s1, b1 = _read_response(tls)
                tls.sendall(b"GET /two HTTP/1.1\r\nHost: keepalive.test\r\n\r\n")
                s2, b2 = _read_response(tls)
            finally:
                tls.close()

        assert (s1, b1) == (200, b"resp-body")
        assert (s2, b2) == (200, b"resp-body")
        assert calls == [("https://keepalive.test/one", None), ("https://keepalive.test/two", None)]

    def test_keep_alive_response_lacks_close(self, mitm_proxy):
        ctx, proxy_url, ca_dir = mitm_proxy
        with patch("impersonate_proxy.server.do_request", lambda *a, **k: _FakeResponse()):
            tls = _open_tunnel(proxy_url, "keepalive.test", ca_dir)
            try:
                tls.sendall(b"GET /one HTTP/1.1\r\nHost: keepalive.test\r\n\r\n")
                buf = tls.recv(4096)
            finally:
                tls.close()
        assert b"200" in buf
        assert b"Connection: keep-alive" in buf
        assert b"Connection: close" not in buf

    def test_connection_close_ends_tunnel(self, mitm_proxy):
        ctx, proxy_url, ca_dir = mitm_proxy
        with patch("impersonate_proxy.server.do_request", lambda *a, **k: _FakeResponse()):
            tls = _open_tunnel(proxy_url, "keepalive.test", ca_dir)
            try:
                tls.sendall(b"GET /one HTTP/1.1\r\nHost: keepalive.test\r\nConnection: close\r\n\r\n")
                s1, _ = _read_response(tls)
                assert s1 == 200
                tls.sendall(b"GET /two HTTP/1.1\r\nHost: keepalive.test\r\n\r\n")
                eof = b"open"
                try:
                    eof = tls.recv(4096)
                except OSError:
                    eof = b""
            finally:
                tls.close()
        assert eof == b""

    def test_502_upstream_failure_ends_tunnel(self, mitm_proxy):
        ctx, proxy_url, ca_dir = mitm_proxy

        def failing_do_request(c, method, url, headers, body, allow_redirects=False):
            return None

        with patch("impersonate_proxy.server.do_request", failing_do_request):
            tls = _open_tunnel(proxy_url, "keepalive.test", ca_dir)
            try:
                tls.sendall(b"GET /one HTTP/1.1\r\nHost: keepalive.test\r\n\r\n")
                s1, _ = _read_response(tls)
            finally:
                tls.close()
        assert s1 == 502


class TestMaxBodySize:
    def test_mitm_oversized_content_length_413(self, mitm_proxy):
        ctx, proxy_url, ca_dir = mitm_proxy
        ctx.config.max_body_size = 1024
        with patch("impersonate_proxy.server.do_request", lambda *a, **k: _FakeResponse()):
            tls = _open_tunnel(proxy_url, "body.test", ca_dir)
            try:
                tls.sendall(b"POST /upload HTTP/1.1\r\nHost: body.test\r\nContent-Length: 9999999\r\n\r\n")
                status, _ = _read_response(tls)
            finally:
                tls.close()
        assert status == 413

    def test_mitm_normal_body_passes(self, mitm_proxy):
        ctx, proxy_url, ca_dir = mitm_proxy
        ctx.config.max_body_size = 1024
        seen: list[bytes | None] = []

        def fake_do_request(c, method, url, headers, body, allow_redirects=False):
            seen.append(body)
            return _FakeResponse()

        with patch("impersonate_proxy.server.do_request", fake_do_request):
            tls = _open_tunnel(proxy_url, "body.test", ca_dir)
            try:
                tls.sendall(
                    b"POST /upload HTTP/1.1\r\nHost: body.test\r\n"
                    b"Content-Length: 11\r\n\r\nhello-world"
                )
                status, _ = _read_response(tls)
            finally:
                tls.close()
        assert status == 200
        assert seen == [b"hello-world"]

    def test_mitm_chunked_body_forwarded(self, mitm_proxy):
        ctx, proxy_url, ca_dir = mitm_proxy
        seen: list[bytes | None] = []

        def fake_do_request(c, method, url, headers, body, allow_redirects=False):
            seen.append(body)
            return _FakeResponse()

        with patch("impersonate_proxy.server.do_request", fake_do_request):
            tls = _open_tunnel(proxy_url, "body.test", ca_dir)
            try:
                tls.sendall(
                    b"POST /upload HTTP/1.1\r\nHost: body.test\r\n"
                    b"Transfer-Encoding: chunked\r\n\r\n"
                    b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
                )
                status, _ = _read_response(tls)
            finally:
                tls.close()
        assert status == 200
        assert seen == [b"hello world"]

    def test_mitm_invalid_content_length_400(self, mitm_proxy):
        ctx, proxy_url, ca_dir = mitm_proxy
        with patch("impersonate_proxy.server.do_request", lambda *a, **k: _FakeResponse()):
            tls = _open_tunnel(proxy_url, "body.test", ca_dir)
            try:
                tls.sendall(b"POST /upload HTTP/1.1\r\nHost: body.test\r\nContent-Length: abc\r\n\r\n")
                status, _ = _read_response(tls)
            finally:
                tls.close()
        assert status == 400


class TestHostBlocking:
    def test_connect_blocked_host_403(self):
        ctx = ProxyContext(ProxyConfig(block_hosts=("blocked.test",)))
        port = _get_free_port()
        server = ThreadingHTTPServer(("127.0.0.1", port), create_handler_class(ctx), ctx)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        _wait_ready(port)
        try:
            raw = socket.create_connection(("127.0.0.1", port), timeout=10)
            raw.sendall(b"CONNECT blocked.test:443 HTTP/1.1\r\nHost: blocked.test\r\n\r\n")
            status, _ = _read_response(raw)
            raw.close()
            assert status == 403
        finally:
            server.shutdown()
            ctx.clear_session_pool()

    def test_plain_http_blocked_host_403_and_allowed_200(self):
        ctx = ProxyContext(ProxyConfig(block_hosts=("blocked.test",)))
        port = _get_free_port()
        server = ThreadingHTTPServer(("127.0.0.1", port), create_handler_class(ctx), ctx)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        _wait_ready(port)
        try:
            with patch("impersonate_proxy.server.do_request", lambda *a, **k: _FakeResponse()):
                raw = socket.create_connection(("127.0.0.1", port), timeout=10)
                raw.sendall(b"GET http://blocked.test/x HTTP/1.1\r\nHost: blocked.test\r\n\r\n")
                status, _ = _read_response(raw)
                raw.close()
                assert status == 403

                raw = socket.create_connection(("127.0.0.1", port), timeout=10)
                raw.sendall(b"GET http://allowed.test/x HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
                status, _ = _read_response(raw)
                raw.close()
                assert status == 200
        finally:
            server.shutdown()
            ctx.clear_session_pool()

    def test_subdomain_of_blocked_host_rejected(self):
        ctx = ProxyContext(ProxyConfig(block_hosts=("blocked.test",)))
        port = _get_free_port()
        server = ThreadingHTTPServer(("127.0.0.1", port), create_handler_class(ctx), ctx)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        _wait_ready(port)
        try:
            raw = socket.create_connection(("127.0.0.1", port), timeout=10)
            raw.sendall(b"CONNECT sub.blocked.test:443 HTTP/1.1\r\nHost: sub.blocked.test\r\n\r\n")
            status, _ = _read_response(raw)
            raw.close()
            assert status == 403
        finally:
            server.shutdown()
            ctx.clear_session_pool()


class TestRawTunnelFallback:
    def test_connect_without_ca_falls_back_to_raw_tunnel(self):
        """Without a CA the tunnel must still relay bytes (no impersonation)."""
        ctx = ProxyContext(ProxyConfig(ca_dir=None))
        ctx.ca_key = None
        port = _get_free_port()

        upstream = socket.socket()
        upstream.bind(("127.0.0.1", 0))
        upstream.listen(1)
        upstream_port = upstream.getsockname()[1]

        server = ThreadingHTTPServer(("127.0.0.1", port), create_handler_class(ctx), ctx)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        _wait_ready(port)
        try:
            raw = socket.create_connection(("127.0.0.1", port), timeout=10)
            raw.sendall(f"CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
            _read_response(raw)
            raw.sendall(b"ping-through-tunnel")
            conn, _ = upstream.accept()
            received = conn.recv(4096)
            conn.sendall(b"pong")
            conn.close()
            upstream.close()
            echoed = raw.recv(4096)
            raw.close()
            assert received == b"ping-through-tunnel"
            assert echoed == b"pong"
        finally:
            server.shutdown()
            ctx.clear_session_pool()
