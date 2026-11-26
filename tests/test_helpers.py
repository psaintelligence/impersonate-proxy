"""Unit tests for utility and helper functions."""

from impersonate_proxy.context import ProxyConfig, ProxyContext
from impersonate_proxy.header_filter import sanitize_headers
from impersonate_proxy.server import get_client_netblock
from impersonate_proxy.session_pool import get_session, release_session


class TestHostPortParsing:
    def test_standard_host_port(self):
        path = "example.com:443"
        host, _, port_str = path.rpartition(":")
        host = host.strip("[]")
        assert host == "example.com"
        assert int(port_str) == 443

    def test_ipv6_host_port(self):
        path = "[::1]:443"
        host, _, port_str = path.rpartition(":")
        host = host.strip("[]")
        assert host == "::1"
        assert int(port_str) == 443

    def test_custom_port(self):
        path = "example.com:8080"
        host, _, port_str = path.rpartition(":")
        host = host.strip("[]")
        assert host == "example.com"
        assert int(port_str) == 8080


class TestSessionManagement:
    def test_get_session_returns_session(self):
        ctx = ProxyContext(ProxyConfig())
        session = get_session(ctx)
        assert session is not None
        release_session(ctx, session)

    def test_session_release_and_reuse(self):
        ctx = ProxyContext(ProxyConfig())
        s1 = get_session(ctx)
        release_session(ctx, s1)
        # Reuse same session from pool
        s2 = get_session(ctx)
        assert s1 is s2
        release_session(ctx, s2)

    def test_get_session_concurrency_creates_new_sessions(self):
        ctx = ProxyContext(ProxyConfig())
        s1 = get_session(ctx)
        s2 = get_session(ctx)
        assert s1 is not s2
        release_session(ctx, s1)
        release_session(ctx, s2)

    def test_custom_close_releases_and_discards_session_on_close_error(self):
        """If resp.close() raises, custom_close must still release/discard the session
        so leased-session counters never leak and broken handles are not pooled."""
        from unittest.mock import MagicMock, patch

        import pytest

        from impersonate_proxy.session_pool import do_request

        ctx = ProxyContext(ProxyConfig(session_pool_max=4))
        fake_sess = MagicMock()
        fake_resp = MagicMock()
        fake_resp.close.side_effect = RuntimeError("close boom")
        fake_sess.request.return_value = fake_resp

        with patch("impersonate_proxy.session_pool.cffi_requests.Session", return_value=fake_sess):
            resp = do_request(ctx, "GET", "http://example.com/", {}, None)
            assert resp is fake_resp
            assert ctx.stats._sessions_leased == 1
            with pytest.raises(RuntimeError, match="close boom"):
                resp.close()
        assert ctx.stats._sessions_leased == 0
        assert ctx.session_pool.empty()
        fake_sess.close.assert_called_once()

    def test_curl_share_reused_and_recreated_after_clear(self):
        """ProxyContext shares a single CurlShare across sessions and recreates cleanly after clear."""
        ctx = ProxyContext(ProxyConfig())
        share1 = ctx.get_curl_share()
        assert ctx.get_curl_share() is share1
        s1 = get_session(ctx)
        release_session(ctx, s1)
        ctx.clear_session_pool()
        share2 = ctx.get_curl_share()
        assert share2 is not share1
        ctx.clear_session_pool()

    def test_parse_dns_option_ip_list_and_doh(self):
        from impersonate_proxy.session_pool import _parse_dns_option

        assert _parse_dns_option(None) == (None, None)
        assert _parse_dns_option("   ") == (None, None)
        assert _parse_dns_option("1.1.1.1, 8.8.8.8") == (["1.1.1.1", "8.8.8.8"], None)
        assert _parse_dns_option("https://1.1.1.1/dns-query") == (None, "https://1.1.1.1/dns-query")

    def test_get_session_wires_curl_share_dns_and_safety_flags(self):
        """get_session must pass discard_cookies=True, trust_env=False, curl_share, and dns/doh_url."""
        from unittest.mock import patch

        ctx_doh = ProxyContext(ProxyConfig(impersonate="chrome", dns="https://1.1.1.1/dns-query"))
        with patch("impersonate_proxy.session_pool.cffi_requests.Session") as mock_cls:
            get_session(ctx_doh)
            mock_cls.assert_called_once_with(
                impersonate="chrome",
                discard_cookies=True,
                trust_env=False,
                curl_share=ctx_doh.get_curl_share(),
                dns=None,
                doh_url="https://1.1.1.1/dns-query",
            )
        ctx_doh.clear_session_pool()

        ctx_ip = ProxyContext(ProxyConfig(impersonate="firefox", dns="1.1.1.1, 8.8.8.8"))
        with patch("impersonate_proxy.session_pool.cffi_requests.Session") as mock_cls:
            get_session(ctx_ip)
            mock_cls.assert_called_once_with(
                impersonate="firefox",
                discard_cookies=True,
                trust_env=False,
                curl_share=ctx_ip.get_curl_share(),
                dns=["1.1.1.1", "8.8.8.8"],
                doh_url=None,
            )
        ctx_ip.clear_session_pool()


class TestRedactionUtilities:
    def test_show_identifying_redacts_by_default(self):
        ctx = ProxyContext(ProxyConfig(debug=False))
        assert ctx.show_identifying("secret-domain.com") == "[redacted]"

    def test_show_identifying_reveals_in_debug(self):
        ctx = ProxyContext(ProxyConfig(debug=True))
        assert ctx.show_identifying("secret-domain.com") == "secret-domain.com"

    def test_sanitize_headers_redacts_sensitive_keys(self):
        headers = {
            "Host": "example.com",
            "Authorization": "Bearer token123",
            "Cookie": "session=abc",
            "X-Custom-Header": "value",
        }
        sanitized = sanitize_headers(headers)
        assert sanitized["Host"] == "example.com"
        assert sanitized["X-Custom-Header"] == "value"
        assert sanitized["Authorization"] == "[redacted-sensitive]"
        assert sanitized["Cookie"] == "[redacted-sensitive]"


class TestNetblockUtilities:
    def test_ipv4_netblock(self):
        assert get_client_netblock("192.168.1.55") == "192.168.1.0/24"
        assert get_client_netblock("127.0.0.1") == "127.0.0.0/24"

    def test_ipv6_netblock(self):
        assert get_client_netblock("::1") == "::/64"
        assert get_client_netblock("2001:db8:abcd:0012::1") == "2001:db8:abcd:12::/64"

    def test_invalid_ip_fallback(self):
        assert get_client_netblock("invalid-ip") == "invalid-ip"
