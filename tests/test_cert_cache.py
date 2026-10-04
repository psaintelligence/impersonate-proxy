"""Unit tests for CA initialization and host certificate caching."""

import os
import tempfile

import pytest

from impersonate_proxy.cert_manager import get_cert_for_host, init_ca
from impersonate_proxy.context import ProxyConfig, ProxyContext


@pytest.fixture()
def ctx() -> ProxyContext:
    return ProxyContext(ProxyConfig())


class TestCertCache:
    @pytest.fixture(autouse=True)
    def setup_ca(self, ctx: ProxyContext):
        with tempfile.TemporaryDirectory() as tmpdir:
            init_ca(ctx, tmpdir)
            yield

    def test_init_ca(self, ctx: ProxyContext):
        assert ctx.ca_key is not None
        assert ctx.ca_cert is not None

    def test_init_ca_saves_and_loads(self):
        fresh_ctx = ProxyContext(ProxyConfig())
        with tempfile.TemporaryDirectory() as tmpdir:
            init_ca(fresh_ctx, tmpdir)
            key_path = os.path.join(tmpdir, "ca.key")
            cert_path = os.path.join(tmpdir, "ca.crt")
            assert os.path.exists(key_path)
            assert os.path.exists(cert_path)

            with open(cert_path, "rb") as f:
                cert1_pem = f.read()

            # Second call should load existing key/cert
            init_ca(fresh_ctx, tmpdir)
            with open(cert_path, "rb") as f:
                cert2_pem = f.read()
            assert cert1_pem == cert2_pem

    def test_get_cert_for_host_caches(self, ctx: ProxyContext):
        ctx.host_cert_cache.clear()
        ssl_ctx1 = get_cert_for_host(ctx, "test.example.com")
        ssl_ctx2 = get_cert_for_host(ctx, "test.example.com")
        assert ssl_ctx1 is ssl_ctx2

    def test_get_cert_for_host_different_hosts(self, ctx: ProxyContext):
        ctx.host_cert_cache.clear()
        ssl_ctx1 = get_cert_for_host(ctx, "host1.example.com")
        ssl_ctx2 = get_cert_for_host(ctx, "host2.example.com")
        assert ssl_ctx1 is not ssl_ctx2

    def test_get_cert_for_ip_address(self, ctx: ProxyContext):
        ctx.host_cert_cache.clear()
        ssl_ctx = get_cert_for_host(ctx, "1.2.3.4")
        assert ssl_ctx is not None

    def test_cache_eviction(self, ctx: ProxyContext):
        ctx.host_cert_cache.clear()
        old_max = ctx.host_cert_max
        ctx.host_cert_max = 3
        try:
            for i in range(5):
                get_cert_for_host(ctx, f"host{i}.example.com")
            assert len(ctx.host_cert_cache) == 3
            assert "host0.example.com" not in ctx.host_cert_cache
            assert "host4.example.com" in ctx.host_cert_cache
        finally:
            ctx.host_cert_max = old_max
