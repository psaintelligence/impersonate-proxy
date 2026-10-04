"""Live integration tests for proxy operations hitting public domains."""

import socket
import tempfile
import threading
import time

import pytest
import requests

from impersonate_proxy.cert_manager import init_ca
from impersonate_proxy.context import ProxyConfig, ProxyContext
from impersonate_proxy.server import ThreadingHTTPServer, create_handler_class


def _get_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.live
class TestProxyLive:
    """Tests that hit real URLs. Run with: pytest -m live"""

    def test_fetch_kosmi_webm(self):
        """Fetch a real video file through the proxy using curl_cffi."""
        port = _get_free_port()
        proxy_url = f"http://127.0.0.1:{port}"

        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = ProxyContext(ProxyConfig(ca_dir=tmpdir))
            init_ca(ctx, tmpdir)
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

            try:
                resp = requests.get(
                    "http://kosmi.io/kosmishort.webm",
                    proxies={"http": proxy_url},
                    timeout=30,
                )
                assert resp.status_code == 200
                assert len(resp.content) > 10000
                assert resp.headers.get("Content-Type") in (
                    "video/webm",
                    "application/octet-stream",
                    None,
                ) or "webm" in resp.headers.get("Content-Type", "")
            finally:
                server.shutdown()
                ctx.clear_session_pool()
