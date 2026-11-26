"""Unit tests for open-proxy guardrails: proxy authentication and client allowlist."""

import base64
import socket
from unittest.mock import patch

import pytest

from impersonate_proxy.cert_manager import init_ca
from impersonate_proxy.context import ProxyConfig, ProxyContext
from impersonate_proxy.server import is_client_allowed, is_target_private, proxy_auth_ok
from tests.helpers import FakeResponse as _FakeResponse
from tests.helpers import read_http_response as _read_response
from tests.helpers import start_proxy as _start_server

_AUTH_TOKEN = base64.b64encode(b"user:secret").decode()


def _raw_request(proxy_url: str, payload: bytes) -> tuple[int, bytes]:
    host, port = proxy_url.split("//")[1].split(":")
    s = socket.create_connection((host, int(port)), timeout=10)
    try:
        s.sendall(payload)
        return _read_response(s)
    finally:
        s.close()


class TestProxyAuthUnit:
    def test_no_config_allows_all(self):
        ctx = ProxyContext(ProxyConfig())
        assert proxy_auth_ok(ctx, None) is True
        assert proxy_auth_ok(ctx, "Basic whatever") is True

    def test_correct_credentials_accepted(self):
        ctx = ProxyContext(ProxyConfig(proxy_auth="user:secret"))
        assert proxy_auth_ok(ctx, f"Basic {_AUTH_TOKEN}") is True
        assert proxy_auth_ok(ctx, f"basic {_AUTH_TOKEN}") is True

    def test_wrong_or_missing_credentials_rejected(self):
        ctx = ProxyContext(ProxyConfig(proxy_auth="user:secret"))
        assert proxy_auth_ok(ctx, None) is False
        assert proxy_auth_ok(ctx, "Basic wrongtoken") is False
        assert proxy_auth_ok(ctx, "Bearer x") is False
        assert proxy_auth_ok(ctx, "") is False


class TestProxyAuthPlainHTTP:
    @pytest.fixture()
    def auth_server(self):
        ctx = ProxyContext(ProxyConfig(proxy_auth="user:secret"))
        server, proxy_url = _start_server(ctx)
        yield ctx, proxy_url
        server.shutdown()
        ctx.clear_session_pool()

    def test_missing_credentials_407(self, auth_server):
        _, proxy_url = auth_server
        status, _ = _raw_request(proxy_url, b"GET http://allowed.test/x HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
        assert status == 407

    def test_wrong_credentials_407(self, auth_server):
        _, proxy_url = auth_server
        status, _ = _raw_request(
            proxy_url,
            b"GET http://allowed.test/x HTTP/1.1\r\nHost: allowed.test\r\n"
            b"Proxy-Authorization: Basic d3Jvbmc6d3Jvbmc=\r\n\r\n",
        )
        assert status == 407

    def test_correct_credentials_pass(self, auth_server):
        _, proxy_url = auth_server
        with patch("impersonate_proxy.server.do_request", lambda *a, **k: _FakeResponse()):
            status, _ = _raw_request(
                proxy_url,
                f"GET http://allowed.test/x HTTP/1.1\r\nHost: allowed.test\r\n"
                f"Proxy-Authorization: Basic {_AUTH_TOKEN}\r\n\r\n".encode(),
            )
        assert status == 200


class TestProxyAuthConnect:
    def test_missing_credentials_407_before_tunnel(self):
        ctx = ProxyContext(ProxyConfig(proxy_auth="user:secret"))
        server, proxy_url = _start_server(ctx)
        try:
            status, _ = _raw_request(proxy_url, b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
            assert status == 407
        finally:
            server.shutdown()
            ctx.clear_session_pool()

    def test_correct_credentials_get_200(self):
        ctx = ProxyContext(ProxyConfig(proxy_auth="user:secret"))
        init_ca(ctx, None)
        server, proxy_url = _start_server(ctx)
        try:
            with patch("impersonate_proxy.server.do_request", lambda *a, **k: _FakeResponse()):
                host, port = proxy_url.split("//")[1].split(":")
                s = socket.create_connection((host, int(port)), timeout=10)
                try:
                    s.sendall(
                        f"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n"
                        f"Proxy-Authorization: Basic {_AUTH_TOKEN}\r\n\r\n".encode()
                    )
                    status, _ = _read_response(s)
                finally:
                    s.close()
            assert status == 200
        finally:
            server.shutdown()
            ctx.clear_session_pool()


class TestAllowFromUnit:
    def test_empty_allows_all(self):
        ctx = ProxyContext(ProxyConfig())
        assert is_client_allowed(ctx, "203.0.113.7") is True

    def test_bare_ip_matches_auto_netblock(self):
        ctx = ProxyContext(ProxyConfig(allow_from=("192.168.1.7",)))
        assert is_client_allowed(ctx, "192.168.1.55") is True
        assert is_client_allowed(ctx, "10.0.0.1") is False

    def test_explicit_cidr_membership(self):
        ctx = ProxyContext(ProxyConfig(allow_from=("10.0.0.0/8",)))
        assert is_client_allowed(ctx, "10.200.1.2") is True
        assert is_client_allowed(ctx, "11.0.0.1") is False

    def test_ipv6_and_mixed_entries(self):
        ctx = ProxyContext(ProxyConfig(allow_from=("2001:db8::/32", "192.168.1.7")))
        assert is_client_allowed(ctx, "2001:db8::1") is True
        assert is_client_allowed(ctx, "2001:db9::1") is False
        assert is_client_allowed(ctx, "192.168.1.9") is True

    def test_unverifiable_ip_denied_when_list_active(self):
        ctx = ProxyContext(ProxyConfig(allow_from=("10.0.0.0/8",)))
        assert is_client_allowed(ctx, "not-an-ip") is False

    def test_invalid_entries_skipped(self):
        ctx = ProxyContext(ProxyConfig(allow_from=("garbage", "127.0.0.1")))
        assert is_client_allowed(ctx, "127.0.0.1") is True


class TestAllowFromIntegration:
    def test_foreign_client_ip_403(self):
        ctx = ProxyContext(ProxyConfig(allow_from=("10.0.0.0/8",)))
        server, proxy_url = _start_server(ctx)
        try:
            status, _ = _raw_request(proxy_url, b"GET http://allowed.test/x HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
            assert status == 403
        finally:
            server.shutdown()
            ctx.clear_session_pool()

    def test_loopback_allowed_when_listed(self):
        ctx = ProxyContext(ProxyConfig(allow_from=("127.0.0.1",)))
        server, proxy_url = _start_server(ctx)
        try:
            with patch("impersonate_proxy.server.do_request", lambda *a, **k: _FakeResponse()):
                status, _ = _raw_request(proxy_url, b"GET http://allowed.test/x HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
            assert status == 200
        finally:
            server.shutdown()
            ctx.clear_session_pool()


class TestBlockPrivateIPs:
    @pytest.mark.parametrize(
        "target",
        [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.5.4",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
        ],
    )
    def test_private_ip_literals_blocked_when_enabled(self, target: str):
        ctx = ProxyContext(ProxyConfig(block_private_ips=True))
        assert is_target_private(ctx, target) is True
        ctx_off = ProxyContext(ProxyConfig(block_private_ips=False))
        assert is_target_private(ctx_off, target) is False

    @pytest.mark.parametrize("target", ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"])
    def test_public_ip_literals_allowed(self, target: str):
        ctx = ProxyContext(ProxyConfig(block_private_ips=True))
        assert is_target_private(ctx, target) is False

    def test_hostname_resolving_to_private_ip_blocked(self):
        ctx = ProxyContext(ProxyConfig(block_private_ips=True))
        fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 0))]
        with patch("socket.getaddrinfo", return_value=fake_addrinfo):
            assert is_target_private(ctx, "metadata.internal.example") is True

        public_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
        with patch("socket.getaddrinfo", return_value=public_addrinfo):
            assert is_target_private(ctx, "example.com") is False

    def test_block_private_ips_rejects_connect_and_plain_http_with_403(self):
        ctx = ProxyContext(ProxyConfig(block_private_ips=True))
        server, proxy_url = _start_server(ctx)
        try:
            s1, _ = _raw_request(proxy_url, b"CONNECT 169.254.169.254:443 HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n")
            assert s1 == 403
            s2, _ = _raw_request(proxy_url, b"GET http://127.0.0.1:8080/secret HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            assert s2 == 403
        finally:
            server.shutdown()
            ctx.clear_session_pool()
