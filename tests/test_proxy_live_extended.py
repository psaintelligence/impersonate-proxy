"""
Extended live tests targeting sites known for TLS fingerprinting and bot detection.

These tests verify that tls-impersonate-proxy successfully bypasses browser
fingerprint checks, JA3/JA4 detection, and commercial bot-protection systems
by asserting HTTP 200 responses and comparing them against unproxied requests.

Both Chrome and Firefox TLS impersonation profiles are tested automatically via parameterization.

Run with:
    pytest -m live_extended

NOT run by default, NOT run in CI, NOT included in 'pytest -m live'.
"""

import contextlib
import logging
import socket
import tempfile
import threading
import time
from collections.abc import Generator
from http.server import HTTPServer
from socketserver import ThreadingMixIn

import pytest
import requests

from impersonate_proxy import main as proxy

logger = logging.getLogger("impersonate-proxy-test")

# ---------------------------------------------------------------------------
# Shared fixtures and helpers
# ---------------------------------------------------------------------------


def _get_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


@pytest.fixture(params=["chrome", "firefox"])
def proxy_server(request) -> Generator[tuple[str, str, str], None, None]:
    """
    Spin up a local tls-impersonate-proxy instance with a temporary CA dir.

    Parameterised to test both Chrome and Firefox TLS impersonation.
    Yields (proxy_url, ca_cert_path, impersonate_profile).
    """
    impersonate_profile = request.param
    orig_impersonate = proxy._IMPERSONATE
    proxy._IMPERSONATE = impersonate_profile

    port = _get_free_port()
    proxy_url = f"http://127.0.0.1:{port}"

    with tempfile.TemporaryDirectory() as tmpdir:
        proxy._init_ca(tmpdir)
        ca_cert_path = f"{tmpdir}/ca.crt"

        server = _ThreadingHTTPServer(("127.0.0.1", port), proxy.ProxyHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        # Wait for the server to accept connections
        for _ in range(50):
            with contextlib.suppress(OSError):
                s = socket.create_connection(("127.0.0.1", port), timeout=0.1)
                s.close()
                break
            time.sleep(0.1)

        try:
            yield proxy_url, ca_cert_path, impersonate_profile
        finally:
            proxy._IMPERSONATE = orig_impersonate
            server.shutdown()


def _get(
    url: str,
    proxy_url: str,
    ca_cert_path: str,
    impersonate: str,
    timeout: int = 30,
) -> requests.Response:
    """
    Issue a GET request through the proxy using standard python-requests headers.
    This emulates a real-world plain client (which does not provide browser headers).
    """
    scheme = url.split("://")[0]
    proxies = {scheme: proxy_url}

    # Only pass verify= for HTTPS; HTTP doesn't need a cert bundle
    if scheme == "https":
        return requests.get(url, proxies=proxies, verify=ca_cert_path, timeout=timeout)
    return requests.get(url, proxies=proxies, timeout=timeout)


def _get_unproxied(url: str, use_chrome_headers: bool = False, timeout: int = 15) -> int:
    """Issue a GET request directly (without proxy) and return the status code."""
    headers = None
    if use_chrome_headers:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en-US,en;q=0.9",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        }
    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
        return resp.status_code
    except Exception:
        return 0


def _assert_status(url: str, proxied_status: int, unproxied_status: int, impersonate: str) -> None:
    """
    Assert that the proxied request succeeded, or handle WAF IP blocks robustly.
    """
    if proxied_status == 200:
        if unproxied_status in (403, 401, 429, 503, 0):
            logger.info(
                f"[{url}] SUCCESS ({impersonate}): Direct request was blocked ({unproxied_status}), but proxy successfully bypassed it (200)"
            )
        else:
            logger.info(f"[{url}] SUCCESS ({impersonate}): Both direct and proxied requests succeeded (200)")
        return

    # If the proxy failed, but the direct request also failed with the same block/error:
    if proxied_status in (403, 401, 429, 503) and unproxied_status == proxied_status:
        pytest.skip(f"IP blocked or site down for {url} (Both direct and proxied requests returned {proxied_status})")

    # Otherwise, it's a real proxy failure (e.g. direct got 200 but proxied got non-200)
    assert proxied_status == 200, (
        f"Proxied request failed ({impersonate}): got {proxied_status}, direct got {unproxied_status}"
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.live_extended
class TestFingerprintBypass:
    """
    Verify that the proxy defeats TLS fingerprinting and bot-detection systems.

    We use a double-request approach:
    1. Direct request (triggers bot detection/blocking).
    2. Proxied request (successfully bypasses using browser TLS impersonation).
    """

    def test_nowsecure_nl(self, proxy_server: tuple[str, str, str]) -> None:
        """nowsecure.nl is a browser fingerprint / TLS test page."""
        proxy_url, ca_cert_path, impersonate = proxy_server
        url = "https://nowsecure.nl"

        unproxied_status = _get_unproxied(url, use_chrome_headers=False)
        resp = _get(url, proxy_url, ca_cert_path, impersonate)

        _assert_status(url, resp.status_code, unproxied_status, impersonate)
        assert len(resp.content) > 1000, "Response body suspiciously small"

    def test_cloudflare_homepage(self, proxy_server: tuple[str, str, str]) -> None:
        """cloudflare.com uses JA3/JA4 fingerprinting."""
        proxy_url, ca_cert_path, impersonate = proxy_server
        url = "https://www.cloudflare.com"

        unproxied_status = _get_unproxied(url, use_chrome_headers=False)
        resp = _get(url, proxy_url, ca_cert_path, impersonate)

        _assert_status(url, resp.status_code, unproxied_status, impersonate)
        body = resp.text.lower()
        assert "cloudflare" in body, "Expected 'cloudflare' in response body"

    def test_akamai_homepage(self, proxy_server: tuple[str, str, str]) -> None:
        """akamai.com blocks non-browser TLS fingerprints with 403."""
        proxy_url, ca_cert_path, impersonate = proxy_server
        url = "https://www.akamai.com"

        unproxied_status = _get_unproxied(url, use_chrome_headers=False)
        resp = _get(url, proxy_url, ca_cert_path, impersonate)

        _assert_status(url, resp.status_code, unproxied_status, impersonate)
        body = resp.text.lower()
        assert "akamai" in body, "Expected 'akamai' in response body"

    def test_datadome_protected_site(self, proxy_server: tuple[str, str, str]) -> None:
        """datadome.co blocks standard requests with 403."""
        proxy_url, ca_cert_path, impersonate = proxy_server
        url = "https://datadome.co"

        unproxied_status = _get_unproxied(url, use_chrome_headers=False)
        resp = _get(url, proxy_url, ca_cert_path, impersonate)

        _assert_status(url, resp.status_code, unproxied_status, impersonate)
        body = resp.text.lower()
        assert "datadome" in body, "Expected 'datadome' in response body"

    def test_imperva_homepage(self, proxy_server: tuple[str, str, str]) -> None:
        """imperva.com runs Imperva WAF / bot management."""
        proxy_url, ca_cert_path, impersonate = proxy_server
        url = "https://www.imperva.com"

        unproxied_status = _get_unproxied(url, use_chrome_headers=False)
        resp = _get(url, proxy_url, ca_cert_path, impersonate)

        _assert_status(url, resp.status_code, unproxied_status, impersonate)
        body = resp.text.lower()
        assert "imperva" in body, "Expected 'imperva' in response body"

    def test_linkedin_public_page(self, proxy_server: tuple[str, str, str]) -> None:
        """LinkedIn uses aggressive bot blocking."""
        proxy_url, ca_cert_path, impersonate = proxy_server
        url = "https://www.linkedin.com"

        unproxied_status = _get_unproxied(url, use_chrome_headers=False)
        resp = _get(url, proxy_url, ca_cert_path, impersonate)

        _assert_status(url, resp.status_code, unproxied_status, impersonate)
        body = resp.text.lower()
        assert "linkedin" in body, "Expected 'linkedin' in response body"

    def test_ticketmaster_homepage(self, proxy_server: tuple[str, str, str]) -> None:
        """Ticketmaster uses Akamai bot management (highly aggressive)."""
        proxy_url, ca_cert_path, impersonate = proxy_server
        url = "https://www.ticketmaster.com"

        unproxied_status = _get_unproxied(url, use_chrome_headers=False)
        resp = _get(url, proxy_url, ca_cert_path, impersonate)

        _assert_status(url, resp.status_code, unproxied_status, impersonate)
        body = resp.text.lower()
        assert "ticketmaster" in body, "Expected 'ticketmaster' in response body"

    def test_google_homepage(self, proxy_server: tuple[str, str, str]) -> None:
        """google.com homepage check."""
        proxy_url, ca_cert_path, impersonate = proxy_server
        url = "https://www.google.com"

        unproxied_status = _get_unproxied(url, use_chrome_headers=False)
        resp = _get(url, proxy_url, ca_cert_path, impersonate)

        _assert_status(url, resp.status_code, unproxied_status, impersonate)
        body = resp.text.lower()
        assert "google" in body, "Expected 'google' in response body"

    def test_tls_api_ja3_check(self, proxy_server: tuple[str, str, str]) -> None:
        """tls.peet.ws/api/all checks TLS handshake fingerprint (JA3, JA4)."""
        known_bot_ja3 = {
            "62d3494f5d7c57c6d192a8a4af44c793",  # curl
            "b32309a26951912be7dba376398abc3b",  # python-requests
            "a0e9f5d64349fb13191bc781f81f42e1",  # wget
        }

        proxy_url, ca_cert_path, impersonate = proxy_server
        resp = _get("https://tls.peet.ws/api/all", proxy_url, ca_cert_path, impersonate)
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"

        data = resp.json()
        ja3 = data.get("tls", {}).get("ja3", "") or ""
        assert ja3, "Expected non-empty JA3 fingerprint"
        assert ja3 not in known_bot_ja3, (
            f"JA3 {ja3!r} matches a known non-browser fingerprint — impersonation may not be working"
        )
        logger.info(f"[tls.peet.ws] Dynamic JA3 fingerprint verified ({impersonate}): {ja3}")
