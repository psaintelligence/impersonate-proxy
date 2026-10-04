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
