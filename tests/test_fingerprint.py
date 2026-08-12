"""Tests for realistic browser fingerprint injection."""

import pytest

from impersonate_proxy.fingerprint import BrowserFingerprint, fingerprint_for


def _major_of(sec_ch_ua: str) -> str:
    """Extract the Google Chrome major from a Sec-CH-UA-style string."""
    for part in sec_ch_ua.split(","):
        part = part.strip()
        if part.startswith('"Google Chrome"'):
            return part.split("v=")[1].strip('"')
    raise AssertionError(f"no Google Chrome brand in {sec_ch_ua!r}")


class TestFingerprintFor:
    def test_chrome_alias_resolves(self):
        fp = fingerprint_for("chrome")
        assert fp is not None
        assert isinstance(fp, BrowserFingerprint)

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
        assert fingerprint_for("firefox") is None


class TestFingerprintCoherence:
    """A real browser's UA, Sec-CH-UA and CH family must all agree."""

    @pytest.mark.parametrize("target", ["chrome", "chrome150", "chrome146"])
    def test_ua_build_not_scrubbed(self, target):
        """The scrubbed Chrome/X.0.0.0 build is the tell — must never appear."""
        fp = fingerprint_for(target)
        assert fp is not None
        ua = fp.user_agent
        # Extract Chrome/MAJOR.BUILD
        chrome = [p for p in ua.split() if p.startswith("Chrome/")][0]
        version = chrome.split("/")[1]
        parts = version.split(".")
        assert parts[1:] != ["0", "0", "0"], f"scrubbed build in UA: {ua}"

    def test_ua_and_full_version_list_agree(self):
        fp = fingerprint_for("chrome150")
        ua_chrome = [p for p in fp.user_agent.split() if p.startswith("Chrome/")][0]
        ua_version = ua_chrome.split("/")[1]
        assert f'"Chromium";v="{ua_version}"' in fp.sec_ch_ua_full_version_list
        assert f'"Google Chrome";v="{ua_version}"' in fp.sec_ch_ua_full_version_list

    def test_base_sec_ch_ua_major_matches_ua(self):
        fp = fingerprint_for("chrome150")
        ua_chrome = [p for p in fp.user_agent.split() if p.startswith("Chrome/")][0]
        ua_major = ua_chrome.split("/")[1].split(".")[0]
        assert _major_of(fp.sec_ch_ua) == ua_major

    def test_platform_coherent(self):
        """UA platform token must match Sec-CH-UA-Platform (Win64/x64 <-> "Windows")."""
        fp = fingerprint_for("chrome150")
        assert "Win64" in fp.user_agent
        assert 'name="platform"' not in fp.user_agent  # placeholder never present
        assert fp.sec_ch_ua_platform == '"Windows"'
        assert fp.sec_ch_ua_platform_version == '"10.0.0"'

    def test_headers_include_full_family(self):
        fp = fingerprint_for("chrome150")
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
        fp = fingerprint_for("chrome150")
        headers = fp.to_headers()
        assert "Sec-CH-UA-Model" not in headers  # desktop Chrome sends empty model

    def test_header_order_canonical(self):
        fp = fingerprint_for("chrome150")
        order = [h.strip() for h in fp.header_order.split(",")]
        # Canonical Chrome: full CH family grouped, UA before accept, fetch-* cluster.
        assert order.index("sec-ch-ua") < order.index("sec-ch-ua-full-version-list") < order.index("sec-ch-ua-platform-version")
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
        from http.server import HTTPServer
        from socketserver import ThreadingMixIn

        import requests

        from impersonate_proxy import main as impersonate_proxy

        def _free_port():
            with socket.socket() as s:
                s.bind(("127.0.0.1", 0))
                return s.getsockname()[1]

        class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
            daemon_threads = True

        port = _free_port()
        proxy_url = f"http://127.0.0.1:{port}"
        with tempfile.TemporaryDirectory() as tmpdir:
            impersonate_proxy._init_ca(tmpdir)
            ca_cert = os.path.join(tmpdir, "ca.crt")
            server = ThreadingHTTPServer(("127.0.0.1", port), impersonate_proxy.ProxyHandler)
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

        # Strings the reflection service echoes back verbatim.
        assert "Chrome/150.0.6585.24" in text, f"scrubbed or unexpected UA; got:\n{text}"
        assert "Sec-Ch-Ua-Full-Version-List" in text, "missing full CH family"
        assert "Sec-Ch-Ua-Platform-Version" in text, "missing platform version"
        assert 'Sec-Ch-Ua-Platform: "Windows"' in text
        # No scrubbed build anywhere.
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
        from http.server import HTTPServer
        from socketserver import ThreadingMixIn

        import requests

        from impersonate_proxy import main as impersonate_proxy

        def _free_port():
            with socket.socket() as s:
                s.bind(("127.0.0.1", 0))
                return s.getsockname()[1]

        class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
            daemon_threads = True

        port = _free_port()
        proxy_url = f"http://127.0.0.1:{port}"
        with tempfile.TemporaryDirectory() as tmpdir:
            impersonate_proxy._init_ca(tmpdir)
            ca_cert = os.path.join(tmpdir, "ca.crt")
            server = ThreadingHTTPServer(("127.0.0.1", port), impersonate_proxy.ProxyHandler)
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
                    "https://tls.peet.ws/api/all",
                    proxies={"http": proxy_url, "https": proxy_url},
                    timeout=30,
                    verify=ca_cert,
                )
                assert resp.status_code == 200
                data = resp.json()
            finally:
                server.shutdown()

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
