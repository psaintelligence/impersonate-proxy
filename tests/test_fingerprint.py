"""Tests for realistic browser fingerprint injection."""

import pytest

from impersonate_proxy.fingerprint import BrowserFingerprint, fingerprint_for

_CHROME_TARGETS = [
    "chrome",
    "chrome152",
    "chrome152_macos",
    "chrome151",
    "chrome151_macos",
    "chrome150",
    "chrome146",
]
_FIREFOX_TARGETS = ["firefox", "firefox155", "firefox154", "firefox153", "firefox147"]


def _parse_brand_list(header_val: str) -> list[tuple[str, str]]:
    """Parse a Sec-CH-UA(-Full-Version-List) string into [(brand, version), ...]."""
    out: list[tuple[str, str]] = []
    for part in header_val.split(","):
        brand_part, version_part = part.strip().split(";v=", 1)
        out.append((brand_part.strip('"'), version_part.strip('"')))
    return out


def _major_of(sec_ch_ua: str) -> str:
    """Extract the Google Chrome major from a Sec-CH-UA-style string."""
    for brand, version in _parse_brand_list(sec_ch_ua):
        if brand == "Google Chrome":
            return version
    raise AssertionError(f"no Google Chrome brand in {sec_ch_ua!r}")


class TestFingerprintFor:
    def test_chrome_alias_resolves_to_chrome152(self):
        fp = fingerprint_for("chrome")
        assert fp is not None
        assert isinstance(fp, BrowserFingerprint)
        assert fp == fingerprint_for("chrome152")

    def test_explicit_chrome152(self):
        fp = fingerprint_for("chrome152")
        assert fp is not None
        assert "Chrome/152." in fp.user_agent
        assert "Safari/537.36" in fp.user_agent

    def test_explicit_chrome152_macos(self):
        fp = fingerprint_for("chrome152_macos")
        assert fp is not None
        assert "Chrome/152." in fp.user_agent
        assert "Macintosh" in fp.user_agent
        assert fp.sec_ch_ua_platform == '"macOS"'

    def test_explicit_chrome151(self):
        fp = fingerprint_for("chrome151")
        assert fp is not None
        assert "Chrome/151." in fp.user_agent

    def test_explicit_chrome150(self):
        fp = fingerprint_for("chrome150")
        assert fp is not None
        assert "Chrome/150." in fp.user_agent
        assert "Safari/537.36" in fp.user_agent

    def test_chrome146(self):
        fp = fingerprint_for("chrome146")
        assert fp is not None
        assert "Chrome/146." in fp.user_agent

    def test_unknown_target_returns_none(self):
        assert fingerprint_for("bogus-target") is None


class TestFirefoxFingerprint:
    """Firefox curation is UA-only: no client hints, no order override."""

    def test_alias_resolves_to_firefox155(self):
        assert fingerprint_for("firefox") is not None
        assert fingerprint_for("firefox") == fingerprint_for("firefox155")

    @pytest.mark.parametrize("target", _FIREFOX_TARGETS)
    def test_ua_coherent(self, target: str):
        fp = fingerprint_for(target)
        assert fp is not None
        assert fp.browser == "firefox"
        # rv must match the Firefox/ version (platform coherence within the UA).
        rv = [p for p in fp.user_agent.split() if p.startswith("rv:")][0].rstrip(")")
        firefox = [p for p in fp.user_agent.split() if p.startswith("Firefox/")][0]
        assert rv == f"rv:{firefox.split('/')[1]}"
        assert "Windows NT 10.0" in fp.user_agent

    @pytest.mark.parametrize("target", _FIREFOX_TARGETS)
    def test_headers_are_ua_only(self, target: str):
        fp = fingerprint_for(target)
        assert fp is not None
        headers = fp.to_headers()
        assert set(headers) == {"User-Agent"}
        assert "sec-ch-ua" not in {k.lower() for k in headers}

    @pytest.mark.parametrize("target", _FIREFOX_TARGETS)
    def test_no_header_order_override(self, target: str):
        # curl_cffi's firefox profile already carries the authentic captured
        # order; overriding it would be a regression.
        fp = fingerprint_for(target)
        assert fp is not None
        assert fp.header_order == ""


class TestFingerprintCoherence:
    """A real browser's UA, Sec-CH-UA and CH family must all agree."""

    @pytest.mark.parametrize("target", _CHROME_TARGETS)
    def test_ua_build_not_scrubbed(self, target: str):
        """The scrubbed Chrome/X.0.0.0 build is the tell — must never appear."""
        fp = fingerprint_for(target)
        assert fp is not None
        ua = fp.user_agent
        # Extract Chrome/MAJOR.BUILD
        chrome = [p for p in ua.split() if p.startswith("Chrome/")][0]
        version = chrome.split("/")[1]
        parts = version.split(".")
        assert parts[1:] != ["0", "0", "0"], f"scrubbed build in UA: {ua}"

    @pytest.mark.parametrize("target", _CHROME_TARGETS)
    def test_ua_and_full_version_list_agree(self, target: str):
        fp = fingerprint_for(target)
        assert fp is not None
        ua_chrome = [p for p in fp.user_agent.split() if p.startswith("Chrome/")][0]
        ua_version = ua_chrome.split("/")[1]
        assert f'"Chromium";v="{ua_version}"' in fp.sec_ch_ua_full_version_list
        assert f'"Google Chrome";v="{ua_version}"' in fp.sec_ch_ua_full_version_list

    @pytest.mark.parametrize("target", _CHROME_TARGETS)
    def test_base_sec_ch_ua_major_matches_ua(self, target: str):
        fp = fingerprint_for(target)
        assert fp is not None
        ua_chrome = [p for p in fp.user_agent.split() if p.startswith("Chrome/")][0]
        ua_major = ua_chrome.split("/")[1].split(".")[0]
        assert _major_of(fp.sec_ch_ua) == ua_major

    @pytest.mark.parametrize("target", _CHROME_TARGETS)
    def test_grease_brand_coherent_and_valid(self, target: str):
        """Short and full brand lists must carry the same GREASE brand, order,
        and authentic Chromium GREASE version (one of 8, 24, 99)."""
        fp = fingerprint_for(target)
        assert fp is not None
        short_list = _parse_brand_list(fp.sec_ch_ua)
        full_list = _parse_brand_list(fp.sec_ch_ua_full_version_list)
        assert [b for b, _ in short_list] == [b for b, _ in full_list]
        grease_short = [(b, v) for b, v in short_list if b not in ("Chromium", "Google Chrome")]
        grease_full = [(b, v) for b, v in full_list if b not in ("Chromium", "Google Chrome")]
        assert len(grease_short) == 1
        brand, ver = grease_short[0]
        assert ver in ("8", "24", "99"), f"non-Chromium GREASE version {ver!r} in {target}"
        assert grease_full == [(brand, f"{ver}.0.0.0")]

    @pytest.mark.parametrize("target", _CHROME_TARGETS)
    def test_platform_coherent(self, target: str):
        """UA platform token must match Sec-CH-UA-Platform."""
        fp = fingerprint_for(target)
        assert fp is not None
        assert 'name="platform"' not in fp.user_agent  # placeholder never present
        if target.endswith("_macos"):
            assert "Macintosh; Intel Mac OS X" in fp.user_agent
            assert fp.sec_ch_ua_platform == '"macOS"'
        else:
            assert "Win64" in fp.user_agent
            assert fp.sec_ch_ua_platform == '"Windows"'
            assert fp.sec_ch_ua_platform_version == '"10.0.0"'

    def test_headers_include_full_family(self):
        fp = fingerprint_for("chrome152")
        assert fp is not None
        headers = fp.to_headers()
        for h in [
            "User-Agent",
            "Sec-CH-UA",
            "Sec-CH-UA-Full-Version-List",
            "Sec-CH-UA-Platform",
            "Sec-CH-UA-Platform-Version",
            "Sec-CH-UA-Arch",
            "Sec-CH-UA-Bitness",
        ]:
            assert h in headers, f"missing {h}"

    def test_empty_model_dropped(self):
        fp = fingerprint_for("chrome152")
        assert fp is not None
        headers = fp.to_headers()
        assert "Sec-CH-UA-Model" not in headers  # desktop Chrome sends empty model

    def test_header_order_canonical(self):
        fp = fingerprint_for("chrome152")
        assert fp is not None
        order = [h.strip() for h in fp.header_order.split(",")]
        # Canonical Chrome: full CH family grouped, UA before accept, fetch-* cluster.
        assert (
            order.index("sec-ch-ua")
            < order.index("sec-ch-ua-full-version-list")
            < order.index("sec-ch-ua-platform-version")
        )
        assert order.index("user-agent") < order.index("accept")
        assert order.index("sec-fetch-site") < order.index("sec-fetch-mode") < order.index("sec-fetch-dest")


class TestFingerprintThroughProxy:
    """Live integration: headers reflected through the proxy must carry a real
    full-build UA + complete Sec-CH-UA family. Run with: pytest -m live"""

    @pytest.mark.live
    def test_reflected_headers_are_coherent(self):
        import os
        import socket
        import tempfile
        import threading
        import time

        import requests

        from impersonate_proxy.cert_manager import init_ca
        from impersonate_proxy.context import ProxyConfig, ProxyContext
        from impersonate_proxy.server import ThreadingHTTPServer, create_handler_class

        def _free_port():
            with socket.socket() as s:
                s.bind(("127.0.0.1", 0))
                return s.getsockname()[1]

        port = _free_port()
        proxy_url = f"http://127.0.0.1:{port}"
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = ProxyContext(ProxyConfig(ca_dir=tmpdir))
            init_ca(ctx, tmpdir)
            ca_cert = os.path.join(tmpdir, "ca.crt")
            server = ThreadingHTTPServer(("127.0.0.1", port), create_handler_class(ctx), ctx)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            for _ in range(50):
                try:
                    sock = socket.create_connection(("127.0.0.1", port), timeout=0.1)
                    sock.close()
                    break
                except OSError:
                    time.sleep(0.1)
            try:
                resp = requests.get(
                    "https://whoami.projects.psaintelligence.com/",
                    proxies={"http": proxy_url, "https": proxy_url},
                    timeout=30,
                    verify=ca_cert,
                )
                assert resp.status_code == 200
                text = resp.text
            finally:
                server.shutdown()
                ctx.clear_session_pool()

        # Strings the reflection service echoes back verbatim.
        assert "Chrome/152.0.7977.83" in text, f"scrubbed or unexpected UA; got:\n{text}"
        assert "Sec-Ch-Ua-Full-Version-List" in text, "missing full CH family"
        assert "Sec-Ch-Ua-Platform-Version" in text, "missing platform version"
        assert 'Sec-Ch-Ua-Platform: "Windows"' in text
        # No scrubbed build anywhere.
        assert "Chrome/152.0.0.0" not in text
        assert "Chrome/150.0.0.0" not in text
        assert "Chrome/146.0.0.0" not in text

    @pytest.mark.live
    def test_http2_header_order_canonical(self):
        """HTTP/2 header order through the proxy must match Chrome's canonical
        order (CH family grouped, UA before accept, fetch-* cluster). Uses
        tls.peet.ws which reports the true on-the-wire HTTP/2 HEADERS frame.
        """
        import os
        import socket
        import tempfile
        import threading
        import time

        import requests

        from impersonate_proxy.cert_manager import init_ca
        from impersonate_proxy.context import ProxyConfig, ProxyContext
        from impersonate_proxy.server import ThreadingHTTPServer, create_handler_class

        def _free_port():
            with socket.socket() as s:
                s.bind(("127.0.0.1", 0))
                return s.getsockname()[1]

        port = _free_port()
        proxy_url = f"http://127.0.0.1:{port}"
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = ProxyContext(ProxyConfig(ca_dir=tmpdir))
            init_ca(ctx, tmpdir)
            ca_cert = os.path.join(tmpdir, "ca.crt")
            server = ThreadingHTTPServer(("127.0.0.1", port), create_handler_class(ctx), ctx)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            for _ in range(50):
                try:
                    sock = socket.create_connection(("127.0.0.1", port), timeout=0.1)
                    sock.close()
                    break
                except OSError:
                    time.sleep(0.1)
            try:
                data = None
                for attempt in range(3):
                    try:
                        resp = requests.get(
                            "https://tls.peet.ws/api/all",
                            proxies={"http": proxy_url, "https": proxy_url},
                            timeout=30,
                            verify=ca_cert,
                        )
                        assert resp.status_code == 200
                        data = resp.json()
                        break
                    except (
                        requests.exceptions.ChunkedEncodingError,
                        requests.exceptions.ConnectionError,
                        requests.exceptions.Timeout,
                    ):
                        if attempt == 2:
                            raise
                        time.sleep(1.0)
                assert data is not None
            finally:
                server.shutdown()
                ctx.clear_session_pool()

        frames = data["http2"]["sent_frames"]
        headers: list[str] = []
        for frame in frames:
            if frame.get("frame_type") == "HEADERS":
                for h in frame["headers"]:
                    if not h.startswith(":"):
                        headers.append(h.split(":")[0].strip().lower())
                break

        def idx(name: str) -> int:
            assert name in headers, f"{name} missing from HTTP/2 order: {headers}"
            return headers.index(name)

        # Canonical Chrome order assertions.
        assert idx("sec-ch-ua") < idx("sec-ch-ua-full-version-list") < idx("sec-ch-ua-platform-version")
        assert idx("sec-ch-ua-mobile") < idx("sec-ch-ua-platform")
        assert idx("user-agent") < idx("accept")
        assert idx("sec-fetch-site") < idx("sec-fetch-mode") < idx("sec-fetch-dest")
        assert "cache-control" not in headers
