"""Live integration tests for proxy operations hitting public domains."""

import tempfile

import pytest
import requests

from impersonate_proxy.cert_manager import init_ca
from impersonate_proxy.context import ProxyConfig, ProxyContext
from tests.helpers import start_proxy


@pytest.mark.live
class TestProxyLive:
    """Tests that hit real URLs. Run with: pytest -m live"""

    def test_fetch_kosmi_webm(self):
        """Fetch a real video file through the proxy using curl_cffi."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = ProxyContext(ProxyConfig(ca_dir=tmpdir))
            init_ca(ctx, tmpdir)
            server, proxy_url = start_proxy(ctx)

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
