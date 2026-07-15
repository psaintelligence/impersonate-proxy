"""Unit tests for utility and helper functions."""

from impersonate_proxy import main as impersonate_proxy


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
        session = impersonate_proxy._get_session()
        assert session is not None
        impersonate_proxy._release_session(session)

    def test_session_release_and_reuse(self):
        # Clear pool first
        impersonate_proxy._clear_session_pool()
        s1 = impersonate_proxy._get_session()
        impersonate_proxy._release_session(s1)
        # Reuse same session from pool
        s2 = impersonate_proxy._get_session()
        assert s1 is s2
        impersonate_proxy._release_session(s2)

    def test_get_session_concurrency_creates_new_sessions(self):
        impersonate_proxy._clear_session_pool()
        s1 = impersonate_proxy._get_session()
        s2 = impersonate_proxy._get_session()
        assert s1 is not s2
        impersonate_proxy._release_session(s1)
        impersonate_proxy._release_session(s2)


class TestRedactionUtilities:
    def test_show_identifying_redacts_by_default(self):
        impersonate_proxy._DEBUG = False
        assert impersonate_proxy._show_identifying("secret-domain.com") == "[redacted]"

    def test_show_identifying_reveals_in_debug(self):
        impersonate_proxy._DEBUG = True
        assert impersonate_proxy._show_identifying("secret-domain.com") == "secret-domain.com"
        # Reset debug flag
        impersonate_proxy._DEBUG = False

    def test_sanitize_headers_redacts_sensitive_keys(self):
        headers = {
            "Host": "example.com",
            "Authorization": "Bearer token123",
            "Cookie": "session=abc",
            "X-Custom-Header": "value",
        }
        sanitized = impersonate_proxy._sanitize_headers(headers)
        assert sanitized["Host"] == "example.com"
        assert sanitized["X-Custom-Header"] == "value"
        assert sanitized["Authorization"] == "[redacted-sensitive]"
        assert sanitized["Cookie"] == "[redacted-sensitive]"
