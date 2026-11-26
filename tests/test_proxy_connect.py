"""Unit tests for HTTPS CONNECT tunnel handling: MITM keep-alive, body limits, host blocking."""

import os
import socket
import ssl
import tempfile
from unittest.mock import patch

import pytest

from impersonate_proxy.cert_manager import init_ca
from impersonate_proxy.context import ProxyConfig, ProxyContext
from tests.helpers import FakeResponse as _FakeResponse
from tests.helpers import read_http_response as _read_response
from tests.helpers import start_proxy


@pytest.fixture()
def mitm_proxy():
    """Start a real proxy with CA + MITM enabled; upstream requests are faked."""
    with tempfile.TemporaryDirectory() as ca_dir:
        ctx = ProxyContext(ProxyConfig(ca_dir=ca_dir))
        init_ca(ctx, ca_dir)
        server, proxy_url = start_proxy(ctx)
        yield ctx, proxy_url, ca_dir
        server.shutdown()
        ctx.clear_session_pool()


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

    def test_mitm_preserves_multiple_set_cookie_headers(self, mitm_proxy):
        """Multiple Set-Cookie headers from curl_cffi must be emitted separately on the tunnel."""
        from curl_cffi.requests.headers import Headers

        ctx, proxy_url, ca_dir = mitm_proxy
        resp = _FakeResponse()
        resp.headers = Headers(
            [
                ("Content-Type", "text/plain"),
                ("Set-Cookie", "a=1; Path=/"),
                ("Set-Cookie", "b=2; Path=/; HttpOnly"),
            ]
        )

        with patch("impersonate_proxy.server.do_request", lambda *a, **k: resp):
            tls = _open_tunnel(proxy_url, "cookies.test", ca_dir)
            try:
                tls.sendall(b"GET /login HTTP/1.1\r\nHost: cookies.test\r\nConnection: close\r\n\r\n")
                raw = b""
                while True:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    raw += chunk
            finally:
                tls.close()
        head = raw.partition(b"\r\n\r\n")[0].decode("latin-1")
        set_cookie_lines = [line for line in head.split("\r\n") if line.lower().startswith("set-cookie:")]
        assert set_cookie_lines == [
            "Set-Cookie: a=1; Path=/",
            "Set-Cookie: b=2; Path=/; HttpOnly",
        ]

    def test_lowercase_headers_and_duplicate_cookies_in_mitm(self, mitm_proxy):
        """Lowercase content-length/connection/transfer-encoding and duplicate Cookie
        headers must be parsed case-insensitively inside the MITM tunnel."""
        ctx, proxy_url, ca_dir = mitm_proxy
        seen: list[tuple[dict[str, str], bytes | None]] = []

        def fake_do_request(c, method, url, headers, body, allow_redirects=False):
            seen.append((headers, body))
            return _FakeResponse()

        with patch("impersonate_proxy.server.do_request", fake_do_request):
            tls = _open_tunnel(proxy_url, "lower.test", ca_dir)
            try:
                tls.sendall(
                    b"POST /one HTTP/1.1\r\n"
                    b"host: lower.test\r\n"
                    b"cookie: a=1\r\n"
                    b"cookie: b=2\r\n"
                    b"content-length: 5\r\n"
                    b"connection: close\r\n\r\n"
                    b"hello"
                )
                status, _ = _read_response(tls)
                eof = tls.recv(4096)
            finally:
                tls.close()
        assert status == 200
        assert eof == b""
        assert seen == [({"cookie": "a=1; b=2", "content-length": "5"}, b"hello")]

    def test_lowercase_chunked_and_conflicting_te_cl_rejected(self, mitm_proxy):
        """Lowercase transfer-encoding: chunked is decoded; simultaneous TE+CL gets 400."""
        ctx, proxy_url, ca_dir = mitm_proxy
        seen: list[bytes | None] = []

        def fake_do_request(c, method, url, headers, body, allow_redirects=False):
            seen.append(body)
            return _FakeResponse()

        with patch("impersonate_proxy.server.do_request", fake_do_request):
            tls = _open_tunnel(proxy_url, "chunked.test", ca_dir)
            try:
                tls.sendall(
                    b"POST /chunk HTTP/1.1\r\n"
                    b"host: chunked.test\r\n"
                    b"transfer-encoding: chunked\r\n\r\n"
                    b"3\r\nabc\r\n0\r\n\r\n"
                )
                s1, _ = _read_response(tls)
                tls.sendall(
                    b"POST /smuggle HTTP/1.1\r\n"
                    b"host: chunked.test\r\n"
                    b"transfer-encoding: chunked\r\n"
                    b"content-length: 5\r\n\r\n"
                    b"0\r\n\r\n"
                )
                s2, _ = _read_response(tls)
            finally:
                tls.close()
        assert s1 == 200
        assert seen == [b"abc"]
        assert s2 == 400

    def test_bodyless_responses_keep_alive_without_desync(self, mitm_proxy):
        """HEAD, 204, and 304 responses must omit Transfer-Encoding: chunked and
        the 0-chunk terminator so subsequent keep-alive requests do not desync."""
        ctx, proxy_url, ca_dir = mitm_proxy
        responses = [
            _FakeResponse(status_code=200, body=b""),
            _FakeResponse(status_code=204, body=b""),
            _FakeResponse(status_code=304, body=b""),
            _FakeResponse(status_code=200, body=b"after-bodyless"),
        ]
        responses[0].headers["Content-Length"] = "123"
        it = iter(responses)

        with patch("impersonate_proxy.server.do_request", lambda *a, **k: next(it)):
            tls = _open_tunnel(proxy_url, "bodyless.test", ca_dir)
            try:
                tls.sendall(b"HEAD /h HTTP/1.1\r\nHost: bodyless.test\r\n\r\n")
                head_raw = tls.recv(4096)
                assert b"HTTP/1.1 200" in head_raw
                assert b"Transfer-Encoding: chunked" not in head_raw
                assert b"Content-Length: 123" in head_raw
                assert head_raw.endswith(b"\r\n\r\n")

                tls.sendall(b"DELETE /d HTTP/1.1\r\nHost: bodyless.test\r\n\r\n")
                r204 = tls.recv(4096)
                assert b"HTTP/1.1 204" in r204
                assert b"Transfer-Encoding: chunked" not in r204
                assert r204.endswith(b"\r\n\r\n")

                tls.sendall(b"GET /cached HTTP/1.1\r\nHost: bodyless.test\r\n\r\n")
                r304 = tls.recv(4096)
                assert b"HTTP/1.1 304" in r304
                assert b"Transfer-Encoding: chunked" not in r304
                assert r304.endswith(b"\r\n\r\n")

                # Subsequent normal GET on the same tunnel must parse cleanly (no desync).
                tls.sendall(b"GET /final HTTP/1.1\r\nHost: bodyless.test\r\n\r\n")
                status, body = _read_response(tls)
            finally:
                tls.close()
        assert (status, body) == (200, b"after-bodyless")


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
                tls.sendall(b"POST /upload HTTP/1.1\r\nHost: body.test\r\nContent-Length: 11\r\n\r\nhello-world")
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
        server, proxy_url = start_proxy(ctx)
        port = int(proxy_url.rsplit(":", 1)[1])
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
        server, proxy_url = start_proxy(ctx)
        port = int(proxy_url.rsplit(":", 1)[1])
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
        server, proxy_url = start_proxy(ctx)
        port = int(proxy_url.rsplit(":", 1)[1])
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

        upstream = socket.socket()
        upstream.bind(("127.0.0.1", 0))
        upstream.listen(1)
        upstream_port = upstream.getsockname()[1]

        server, proxy_url = start_proxy(ctx)
        port = int(proxy_url.rsplit(":", 1)[1])
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

    def test_raw_tunnel_host_bypasses_mitm_even_with_ca(self):
        """A host listed in --raw-tunnel-host relays raw bytes instead of MITM decryption."""
        with tempfile.TemporaryDirectory() as ca_dir:
            ctx = ProxyContext(ProxyConfig(ca_dir=ca_dir, raw_tunnel_hosts=("127.0.0.1",)))
            init_ca(ctx, ca_dir)
            assert ctx.ca_key is not None

            upstream = socket.socket()
            upstream.bind(("127.0.0.1", 0))
            upstream.listen(1)
            upstream_port = upstream.getsockname()[1]

            server, proxy_url = start_proxy(ctx)
            port = int(proxy_url.rsplit(":", 1)[1])
            try:
                raw = socket.create_connection(("127.0.0.1", port), timeout=10)
                raw.sendall(f"CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode())
                _read_response(raw)
                raw.sendall(b"raw-pinned-bytes")
                conn, _ = upstream.accept()
                received = conn.recv(4096)
                conn.sendall(b"raw-reply")
                conn.close()
                upstream.close()
                echoed = raw.recv(4096)
                raw.close()
                assert received == b"raw-pinned-bytes"
                assert echoed == b"raw-reply"
                assert ctx.stats.snapshot(0).requests.get("raw_tunnel") == 1
            finally:
                server.shutdown()
                ctx.clear_session_pool()
