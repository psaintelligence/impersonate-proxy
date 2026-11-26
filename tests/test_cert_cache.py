"""Unit tests for CA initialization and host certificate caching."""

import os
import tempfile

import pytest

from impersonate_proxy.cert_manager import _load_ca_files, get_cert_for_host, init_ca
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

    def test_cache_eviction_is_lru(self, ctx: ProxyContext):
        """Touching a cached host promotes it so the least-recently-used host is evicted."""
        ctx.host_cert_cache.clear()
        old_max = ctx.host_cert_max
        ctx.host_cert_max = 3
        try:
            get_cert_for_host(ctx, "hot.example.com")
            get_cert_for_host(ctx, "cold.example.com")
            get_cert_for_host(ctx, "warm.example.com")
            # Touch hot.example.com so cold.example.com becomes the LRU entry.
            get_cert_for_host(ctx, "hot.example.com")
            get_cert_for_host(ctx, "new.example.com")
            assert "hot.example.com" in ctx.host_cert_cache
            assert "cold.example.com" not in ctx.host_cert_cache
        finally:
            ctx.host_cert_max = old_max

    def test_expired_cert_entry_is_regenerated(self, ctx: ProxyContext):
        """An expired cache entry must be replaced with a fresh SSLContext."""
        ctx.host_cert_cache.clear()
        ssl_ctx1 = get_cert_for_host(ctx, "expire.example.com")
        # Backdate the entry's monotonic expiry so it is treated as expired.
        ctx.host_cert_cache["expire.example.com"] = (ssl_ctx1, 0.0)
        ssl_ctx2 = get_cert_for_host(ctx, "expire.example.com")
        assert ssl_ctx2 is not ssl_ctx1


class TestInitCaConcurrency:
    def test_concurrent_first_starts_yield_consistent_pair(self):
        """Simulated concurrent first starts on one ca_dir must agree on one
        key/cert pair — never torn or mismatched files."""
        import threading

        with tempfile.TemporaryDirectory() as tmpdir:
            contexts = [ProxyContext(ProxyConfig()) for _ in range(8)]
            threads = [threading.Thread(target=init_ca, args=(c, tmpdir)) for c in contexts]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)

            # Every context must have loaded the same, consistent pair.
            assert all(c.ca_key is not None and c.ca_cert is not None for c in contexts)
            first_pub = contexts[0].ca_key.public_key().public_numbers()
            for c in contexts:
                assert c.ca_key.public_key().public_numbers() == first_pub
                assert c.ca_cert.public_key().public_numbers() == first_pub

            # The files on disk must form the same consistent pair.
            final_ctx = ProxyContext(ProxyConfig())
            assert _load_ca_files(final_ctx, os.path.join(tmpdir, "ca.key"), os.path.join(tmpdir, "ca.crt"))
            assert final_ctx.ca_key.public_key().public_numbers() == first_pub

            # The claim file must be cleaned up.
            assert not os.path.exists(os.path.join(tmpdir, ".generate-claim"))

    def test_reclaims_stale_generate_claim_after_crash(self):
        """A stale .generate-claim file left by a killed process must be reclaimed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            claim_path = os.path.join(tmpdir, ".generate-claim")
            with open(claim_path, "wb"):
                pass
            # Backdate mtime well past _CA_CLAIM_STALE_SECONDS.
            stale_ts = os.path.getmtime(claim_path) - 120.0
            os.utime(claim_path, (stale_ts, stale_ts))

            ctx = ProxyContext(ProxyConfig())
            init_ca(ctx, tmpdir)
            assert ctx.ca_key is not None
            assert ctx.ca_cert is not None
            assert not os.path.exists(claim_path)
