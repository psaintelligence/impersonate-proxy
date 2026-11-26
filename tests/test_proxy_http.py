"""Integration tests for plain HTTP proxy operations using mock servers."""

import concurrent.futures
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

import pytest
import requests

from impersonate_proxy.context import ProxyConfig, ProxyContext
from impersonate_proxy.server import ThreadingHTTPServer, create_handler_class

_UPSTREAM_ACTIVE = 0
_UPSTREAM_PEAK = 0
_UPSTREAM_LOCK = threading.Lock()


class _ThreadingUpstream(ThreadingMixIn, HTTPServer):
    """Threaded upstream so concurrent proxy threads overlap in handlers."""

    daemon_threads = True


class MockUpstreamHandler(BaseHTTPRequestHandler):
    """Simple HTTP server that echoes back request info."""

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == "/slow":
            # Track concurrent handlers for the max-threads cap tests.
            global _UPSTREAM_ACTIVE, _UPSTREAM_PEAK
            with _UPSTREAM_LOCK:
                _UPSTREAM_ACTIVE += 1
                _UPSTREAM_PEAK = max(_UPSTREAM_PEAK, _UPSTREAM_ACTIVE)
            time.sleep(0.2)
            with _UPSTREAM_LOCK:
                _UPSTREAM_ACTIVE -= 1
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"OK")
            return

        if self.path == "/set-cookies":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Set-Cookie", "a=1; Path=/")
            self.send_header("Set-Cookie", "b=2; Path=/")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"OK")
            return

        if self.path == "/echo-cookie":
            cookie_val = self.headers.get("Cookie", "")
            body = f"cookie={cookie_val}".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/redirected")
            self.end_headers()
            return

        if self.path == "/large":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            chunk = b"x" * 65536
            total = chunk * 16  # ~1 MB
            self.send_header("Content-Length", str(len(total)))
            self.end_headers()
            self.wfile.write(total)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("X-Test-Header", "upstream-value")
        body = f"GET {self.path}".encode()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body_in = self.rfile.read(content_length)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        body = f"POST {self.path} body={body_in.decode()}".encode()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "42")
        self.end_headers()


def _get_free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def upstream_server():
    """Start a mock upstream HTTP server."""
    port = _get_free_port()
    server = _ThreadingUpstream(("127.0.0.1", port), MockUpstreamHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    for _ in range(50):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.1)
            s.close()
            break
        except OSError:
            time.sleep(0.1)
    else:
        raise RuntimeError("upstream server never became ready")
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.fixture(scope="module")
def proxy_ctx():
    """ProxyContext shared by the proxy_server fixture and quiet-mode tests."""
    return ProxyContext(ProxyConfig())


@pytest.fixture(scope="module")
def proxy_server(proxy_ctx):
    """Start the TLS impersonate proxy bound to a dedicated ProxyContext."""
    port = _get_free_port()
    proxy_url = f"http://127.0.0.1:{port}"

    server = ThreadingHTTPServer(("127.0.0.1", port), create_handler_class(proxy_ctx), proxy_ctx)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    for _ in range(50):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.1)
            s.close()
            break
        except OSError:
            time.sleep(0.1)
    else:
        raise RuntimeError("proxy server never became ready")

    yield proxy_url
    server.shutdown()
    proxy_ctx.clear_session_pool()


class TestProxyHTTP:
    def test_proxy_get(self, proxy_server, upstream_server):
        resp = requests.get(f"{upstream_server}/hello", proxies={"http": proxy_server})
        assert resp.status_code == 200
        assert resp.text == "GET /hello"

    def test_proxy_get_with_query(self, proxy_server, upstream_server):
        resp = requests.get(f"{upstream_server}/path?key=value", proxies={"http": proxy_server})
        assert resp.status_code == 200
        assert resp.text == "GET /path?key=value"

    def test_proxy_post(self, proxy_server, upstream_server):
        resp = requests.post(f"{upstream_server}/submit", data="test-body", proxies={"http": proxy_server})
        assert resp.status_code == 200
        assert "POST /submit body=test-body" in resp.text

    def test_proxy_head_no_body(self, proxy_server, upstream_server):
        resp = requests.head(f"{upstream_server}/resource", proxies={"http": proxy_server})
        assert resp.status_code == 200
        assert resp.text == ""
        assert resp.headers.get("Content-Length") == "42"

    def test_proxy_preserves_upstream_headers(self, proxy_server, upstream_server):
        resp = requests.get(f"{upstream_server}/hello", proxies={"http": proxy_server})
        assert resp.headers.get("X-Test-Header") == "upstream-value"

    def test_proxy_strips_hop_by_hop_headers(self, proxy_server, upstream_server):
        """Hop-by-hop headers from client should not reach upstream."""
        resp = requests.get(
            f"{upstream_server}/hello",
            headers={"Proxy-Connection": "keep-alive", "X-Custom": "preserved"},
            proxies={"http": proxy_server},
        )
        assert resp.status_code == 200

    def test_proxy_bad_url(self, proxy_server):
        s = socket.create_connection(
            (proxy_server.split("//")[1].split(":")[0], int(proxy_server.split(":")[-1])),
        )
        s.sendall(b"GET /relative-path HTTP/1.1\r\nHost: localhost\r\n\r\n")
        resp = s.recv(4096)
        s.close()
        assert b"400" in resp

    def test_proxy_upstream_down(self, proxy_server):
        resp = requests.get("http://127.0.0.1:1/unreachable", proxies={"http": proxy_server})
        assert resp.status_code == 502

    def test_proxy_oversized_content_length_413(self, proxy_server):
        """A Content-Length beyond max_body_size must be rejected with 413, never buffered."""
        host, port = proxy_server.split("//")[1].split(":")
        s = socket.create_connection((host, int(port)), timeout=10)
        try:
            s.sendall(
                b"POST http://blocked-upstream.test/upload HTTP/1.1\r\n"
                b"Host: blocked-upstream.test\r\nContent-Length: 999999999999\r\n\r\n"
            )
            resp = s.recv(4096)
        finally:
            s.close()
        assert b"413" in resp.split(b" ", 3)[1]

    def test_proxy_invalid_content_length_400(self, proxy_server):
        """A non-integer Content-Length must be rejected with 400."""
        host, port = proxy_server.split("//")[1].split(":")
        s = socket.create_connection((host, int(port)), timeout=10)
        try:
            s.sendall(
                b"POST http://blocked-upstream.test/upload HTTP/1.1\r\n"
                b"Host: blocked-upstream.test\r\nContent-Length: abc\r\n\r\n"
            )
            resp = s.recv(4096)
        finally:
            s.close()
        assert b"400" in resp.split(b" ", 3)[1]

    def test_proxy_redirect_passthrough(self, proxy_server, upstream_server):
        """Proxy should forward 302 without following it."""
        resp = requests.get(
            f"{upstream_server}/redirect",
            proxies={"http": proxy_server},
            allow_redirects=False,
        )
        assert resp.status_code == 302
        assert "/redirected" in resp.headers.get("Location", "")

    def test_proxy_large_response(self, proxy_server, upstream_server):
        """Proxy should handle large streamed responses."""
        resp = requests.get(f"{upstream_server}/large", proxies={"http": proxy_server})
        assert resp.status_code == 200
        assert len(resp.content) == 65536 * 16  # 1 MB

    def test_proxy_concurrent_requests(self, proxy_server, upstream_server):
        """Proxy should handle concurrent requests without errors."""

        def fetch(i):
            resp = requests.get(f"{upstream_server}/concurrent-{i}", proxies={"http": proxy_server})
            return resp.status_code, resp.text

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            futures = [pool.submit(fetch, i) for i in range(20)]
            results = [f.result() for f in futures]

        for status, text in results:
            assert status == 200
            assert text.startswith("GET /concurrent-")

    def test_proxy_connection_logging(self, proxy_server, upstream_server, caplog):
        """Proxy should log connection details in INFO mode."""
        import logging

        with caplog.at_level(logging.INFO, logger="impersonate-proxy"):
            resp = requests.get(f"{upstream_server}/hello", proxies={"http": proxy_server})
            assert resp.status_code == 200

            # Check for a log entry like: GET request from 127.0.0.0/24 to 127.0.0.1
            log_found = False
            for record in caplog.records:
                if "request from" in record.message and "127.0.0.0/24" in record.message:
                    log_found = True
                    break
            assert log_found, f"Expected connection log not found. Logs: {[r.message for r in caplog.records]}"

    def test_proxy_quiet_logging(self, proxy_ctx, proxy_server, upstream_server, caplog):
        """Proxy should not log traffic when quiet mode is True.

        Only records tied to this test's unique path are judged: earlier tests'
        handler threads may still be emitting through the shared logger name
        while this test runs.
        """
        import logging

        proxy_ctx.config.quiet = True
        try:
            with caplog.at_level(logging.INFO, logger="impersonate-proxy"):
                resp = requests.get(f"{upstream_server}/quiet-mode-check", proxies={"http": proxy_server})
                assert resp.status_code == 200

            for record in caplog.records:
                assert "quiet-mode-check" not in record.message, f"quiet mode logged traffic: {record.message}"
        finally:
            proxy_ctx.config.quiet = False

    def test_upstream_proxy_configuration(self):
        """Verify that upstream_proxy is passed to curl_cffi request call."""
        from unittest.mock import patch

        from impersonate_proxy.context import ProxyConfig, ProxyContext
        from impersonate_proxy.session_pool import do_request

        ctx = ProxyContext(
            ProxyConfig(upstream_proxy="http://parent.proxy:8080", connect_timeout=5.0, read_timeout=60.0)
        )
        with patch("impersonate_proxy.session_pool.get_session") as mock_get_session:
            mock_sess = mock_get_session.return_value
            do_request(ctx, "GET", "http://example.com", {"Host": "example.com"}, None)
            mock_sess.request.assert_called_once()
            call_kwargs = mock_sess.request.call_args[1]
            assert call_kwargs["proxies"] == {"http": "http://parent.proxy:8080", "https": "http://parent.proxy:8080"}
            assert call_kwargs["timeout"] == (5.0, 60.0)

    def test_passthrough_skips_fingerprint_and_extra_fp(self):
        """In passthrough mode, do_request must forward client headers untouched
        and must not inject extra_fp header_order or Cache-Control suppression."""
        from unittest.mock import patch

        from impersonate_proxy.context import ProxyConfig, ProxyContext
        from impersonate_proxy.session_pool import do_request

        ctx = ProxyContext(ProxyConfig(header_mode="passthrough", fingerprint_real=True))
        client_headers = {"User-Agent": "custom-client/1.0", "X-Custom": "1"}
        with patch("impersonate_proxy.session_pool.get_session") as mock_get_session:
            mock_sess = mock_get_session.return_value
            do_request(ctx, "GET", "http://example.com", client_headers, None)
            mock_sess.request.assert_called_once()
            call_kwargs = mock_sess.request.call_args[1]
            assert call_kwargs["headers"] == client_headers
            assert call_kwargs["extra_fp"] is None

    def test_pooled_sessions_do_not_bleed_or_clobber_cookies(self, upstream_server):
        """Set-Cookie from one request must never bleed into or overwrite another
        client's Cookie header when reusing a pooled curl_cffi session."""
        ctx = ProxyContext(ProxyConfig(session_pool_max=1))
        server, proxy_url = _start_proxy_with_ctx(ctx)
        try:
            r1 = requests.get(f"{upstream_server}/set-cookies", proxies={"http": proxy_url}, timeout=10)
            assert r1.status_code == 200
            # Multiple Set-Cookie headers must be preserved individually, not comma-joined.
            set_cookies = r1.raw.headers.getlist("Set-Cookie")
            assert set_cookies == ["a=1; Path=/", "b=2; Path=/"]

            # Next request with no Cookie header must not inherit r1's cookies.
            r2 = requests.get(f"{upstream_server}/echo-cookie", proxies={"http": proxy_url}, timeout=10)
            assert r2.status_code == 200
            assert r2.text == "cookie="

            # Client-supplied Cookie header must reach upstream intact (not clobbered).
            r3 = requests.get(
                f"{upstream_server}/echo-cookie",
                headers={"Cookie": "client=99"},
                proxies={"http": proxy_url},
                timeout=10,
            )
            assert r3.status_code == 200
            assert r3.text == "cookie=client=99"
        finally:
            server.shutdown()
            ctx.clear_session_pool()

    def test_session_ignores_ambient_proxy_env(self, upstream_server, monkeypatch):
        """Ambient HTTP_PROXY/HTTPS_PROXY must not cause curl_cffi to loop or fail."""
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
        ctx = ProxyContext(ProxyConfig())
        server, proxy_url = _start_proxy_with_ctx(ctx)
        try:
            resp = requests.get(f"{upstream_server}/hello", proxies={"http": proxy_url}, timeout=10)
            assert resp.status_code == 200
            assert resp.text == "GET /hello"
        finally:
            server.shutdown()
            ctx.clear_session_pool()


def _start_proxy_with_ctx(ctx: ProxyContext) -> tuple[ThreadingHTTPServer, str]:
    port = _get_free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), create_handler_class(ctx), ctx)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    for _ in range(50):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.1)
            s.close()
            break
        except OSError:
            time.sleep(0.1)
    else:
        raise RuntimeError("proxy server never became ready")
    return server, f"http://127.0.0.1:{port}"


class TestMaxThreads:
    def _run_burst(self, upstream_server: str, proxy_url: str) -> None:
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(
                pool.map(
                    lambda i: (
                        requests.get(f"{upstream_server}/slow", proxies={"http": proxy_url}, timeout=15).status_code
                    ),
                    range(8),
                )
            )
        assert all(status == 200 for status in results)

    def test_max_threads_caps_concurrent_handlers(self, upstream_server):
        global _UPSTREAM_PEAK
        _UPSTREAM_PEAK = 0
        ctx = ProxyContext(ProxyConfig(max_threads=2))
        server, proxy_url = _start_proxy_with_ctx(ctx)
        try:
            self._run_burst(upstream_server, proxy_url)
            assert _UPSTREAM_PEAK <= 2
        finally:
            server.shutdown()
            ctx.clear_session_pool()

    def test_unlimited_by_default(self, upstream_server):
        global _UPSTREAM_PEAK
        _UPSTREAM_PEAK = 0
        ctx = ProxyContext(ProxyConfig())
        server, proxy_url = _start_proxy_with_ctx(ctx)
        try:
            self._run_burst(upstream_server, proxy_url)
            assert _UPSTREAM_PEAK >= 3
        finally:
            server.shutdown()
            ctx.clear_session_pool()
