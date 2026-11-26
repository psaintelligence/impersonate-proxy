"""Unit tests for the request statistics counters and the Prometheus metrics endpoint."""

from unittest.mock import patch

import requests

from impersonate_proxy.context import ProxyConfig, ProxyContext
from impersonate_proxy.stats import ProxyStats, render_metrics, start_stats_server
from tests.helpers import FakeResponse as _FakeResponse
from tests.helpers import get_free_port as _get_free_port
from tests.helpers import start_proxy as _start_proxy
from tests.helpers import wait_ready as _wait_ready


class TestProxyStatsCounters:
    def test_request_counters_by_mode(self):
        stats = ProxyStats()
        stats.record_request("mitm")
        stats.record_request("mitm")
        stats.record_request("plain_http")
        assert stats.snapshot(0).requests == {"mitm": 2, "plain_http": 1}

    def test_status_classes_ignore_successes(self):
        stats = ProxyStats()
        stats.record_status(200)
        stats.record_status(302)
        assert stats.snapshot(0).status_classes == {}
        stats.record_status(404)
        stats.record_status(413)
        stats.record_status(502)
        assert stats.snapshot(0).status_classes == {"4xx": 2, "5xx": 1}

    def test_upstream_failures(self):
        stats = ProxyStats()
        stats.record_upstream_failure()
        stats.record_upstream_failure()
        assert stats.snapshot(0).upstream_failures == 2

    def test_pool_high_water_tracks_concurrency(self):
        stats = ProxyStats()
        stats.record_session_leased()
        stats.record_session_leased()
        stats.record_session_leased()
        stats.record_session_released()
        stats.record_session_leased()
        stats.record_session_leased()
        assert stats.snapshot(0).pool_high_water == 4

    def test_release_never_goes_negative(self):
        stats = ProxyStats()
        stats.record_session_released()
        stats.record_session_leased()
        assert stats.snapshot(0).pool_high_water == 1


class TestRenderMetrics:
    def test_prometheus_text_format(self):
        stats = ProxyStats()
        stats.record_request("mitm")
        stats.record_request("mitm")
        stats.record_request("plain_http")
        stats.record_status(404)
        stats.record_status(502)
        stats.record_upstream_failure()
        stats.record_session_leased()
        text = render_metrics(stats.snapshot(7))
        assert "# TYPE impersonate_proxy_requests_total counter" in text
        assert 'impersonate_proxy_requests_total{mode="mitm"} 2' in text
        assert 'impersonate_proxy_requests_total{mode="plain_http"} 1' in text
        assert "impersonate_proxy_upstream_failures_total 1" in text
        assert 'impersonate_proxy_client_status_total{status_class="4xx"} 1' in text
        assert 'impersonate_proxy_client_status_total{status_class="5xx"} 1' in text
        assert "impersonate_proxy_session_pool_high_water 1" in text
        assert "impersonate_proxy_cert_cache_size 7" in text
        assert text.endswith("\n")


class TestMetricsEndpoint:
    def test_scrape_reflects_direct_counters(self):
        ctx = ProxyContext(ProxyConfig())
        port = _get_free_port()
        stats_server = start_stats_server(ctx, "127.0.0.1", port)
        _wait_ready(port)
        try:
            ctx.stats.record_request("mitm")
            ctx.stats.record_status(404)
            resp = requests.get(f"http://127.0.0.1:{port}/metrics", timeout=5)
            assert resp.status_code == 200
            assert "text/plain" in resp.headers["Content-Type"]
            assert 'impersonate_proxy_requests_total{mode="mitm"} 1' in resp.text
            assert 'impersonate_proxy_client_status_total{status_class="4xx"} 1' in resp.text

            other = requests.get(f"http://127.0.0.1:{port}/other", timeout=5)
            assert other.status_code == 404
        finally:
            stats_server.shutdown()
            stats_server.server_close()

    def test_end_to_end_plain_http_counting(self):
        ctx = ProxyContext(ProxyConfig())
        server, proxy_url = _start_proxy(ctx)
        stats_port = _get_free_port()
        stats_server = start_stats_server(ctx, "127.0.0.1", stats_port)
        _wait_ready(stats_port)
        try:
            with patch("impersonate_proxy.server.do_request", lambda *a, **k: _FakeResponse()):
                resp = requests.get("http://upstream.test/x", proxies={"http": proxy_url}, timeout=10)
            assert resp.status_code == 200

            metrics = requests.get(f"http://127.0.0.1:{stats_port}/metrics", timeout=5).text
            assert 'impersonate_proxy_requests_total{mode="plain_http"} 1' in metrics
        finally:
            server.shutdown()
            stats_server.shutdown()
            stats_server.server_close()
            ctx.clear_session_pool()
