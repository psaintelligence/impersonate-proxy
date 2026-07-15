"""Unit tests for CA initialization and host certificate caching."""

import os
import tempfile

import pytest

from impersonate_proxy import main as impersonate_proxy


class TestCertCache:
    @pytest.fixture(autouse=True)
    def setup_ca(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            impersonate_proxy._init_ca(tmpdir)
            yield

    def test_init_ca(self):
        assert impersonate_proxy._CA_KEY is not None
        assert impersonate_proxy._CA_CERT is not None

    def test_init_ca_saves_and_loads(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            impersonate_proxy._init_ca(tmpdir)
            key_path = os.path.join(tmpdir, "ca.key")
            cert_path = os.path.join(tmpdir, "ca.crt")
            assert os.path.exists(key_path)
            assert os.path.exists(cert_path)

            with open(cert_path, "rb") as f:
                cert1_pem = f.read()

            # Second call should load existing key/cert
            impersonate_proxy._init_ca(tmpdir)
            with open(cert_path, "rb") as f:
                cert2_pem = f.read()
            assert cert1_pem == cert2_pem

    def test_get_cert_for_host_caches(self):
        impersonate_proxy._HOST_CERT_CACHE.clear()
        ctx1 = impersonate_proxy._get_cert_for_host("test.example.com")
        ctx2 = impersonate_proxy._get_cert_for_host("test.example.com")
        assert ctx1 is ctx2

    def test_get_cert_for_host_different_hosts(self):
        impersonate_proxy._HOST_CERT_CACHE.clear()
        ctx1 = impersonate_proxy._get_cert_for_host("host1.example.com")
        ctx2 = impersonate_proxy._get_cert_for_host("host2.example.com")
        assert ctx1 is not ctx2

    def test_get_cert_for_ip_address(self):
        impersonate_proxy._HOST_CERT_CACHE.clear()
        ctx = impersonate_proxy._get_cert_for_host("1.2.3.4")
        assert ctx is not None

    def test_cache_eviction(self):
        impersonate_proxy._HOST_CERT_CACHE.clear()
        old_max = impersonate_proxy._HOST_CERT_MAX
        impersonate_proxy._HOST_CERT_MAX = 3
        try:
            for i in range(5):
                impersonate_proxy._get_cert_for_host(f"host{i}.example.com")
            assert len(impersonate_proxy._HOST_CERT_CACHE) == 3
            assert "host0.example.com" not in impersonate_proxy._HOST_CERT_CACHE
            assert "host4.example.com" in impersonate_proxy._HOST_CERT_CACHE
        finally:
            impersonate_proxy._HOST_CERT_MAX = old_max
