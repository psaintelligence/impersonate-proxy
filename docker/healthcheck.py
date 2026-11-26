"""Container healthcheck: verify local /healthz liveness and end-to-end proxying.

1. Probes the proxy's local loopback ``/healthz`` endpoint to confirm the
   listener and handler threads are responsive.
2. Issues one plain-HTTP request through the proxy to a lightweight utility
   endpoint (default: ``http://edge-http.microsoft.com/captiveportal/generate_204``,
   Microsoft Edge's purpose-built connectivity probe). Override via
   ``IMPERSONATE_PROXY_HEALTHCHECK_URL`` or set it to empty (``""``) for
   air-gapped environments to run the local ``/healthz`` check only.
"""

import base64
import http.client
import os
import sys

DEFAULT_HEALTHCHECK_URL = "http://edge-http.microsoft.com/captiveportal/generate_204"


def _target_host() -> str:
    bind_host = os.environ.get("IMPERSONATE_PROXY_HOST", "127.0.0.1").strip()
    if bind_host in ("", "0.0.0.0"):
        return "127.0.0.1"
    if bind_host == "::":
        return "::1"
    return bind_host


def _check_local_healthz(host: str, port: int) -> None:
    conn = http.client.HTTPConnection(host, port, timeout=5)
    try:
        conn.request("GET", "/healthz")
        resp = conn.getresponse()
        body = resp.read()
        if resp.status != 200 or body.strip() != b"ok":
            raise RuntimeError(f"/healthz unexpected response {resp.status} {body!r}")
    finally:
        conn.close()


def _check_proxied_url(host: str, port: int, url: str) -> None:
    headers: dict[str, str] = {}
    proxy_auth = os.environ.get("IMPERSONATE_PROXY_PROXY_AUTH", "").strip()
    if proxy_auth:
        token = base64.b64encode(proxy_auth.encode()).decode()
        headers["Proxy-Authorization"] = f"Basic {token}"

    conn = http.client.HTTPConnection(host, port, timeout=10)
    try:
        conn.request("GET", url, headers=headers)
        resp = conn.getresponse()
        resp.read()
        # 502 indicates upstream forwarding failed; 2xx/3xx/4xx (e.g. 204 from
        # generate_204 or 403 when --allow-from excludes loopback) confirms the
        # proxy request pipeline is healthy.
        if resp.status >= 500:
            raise RuntimeError(f"proxied probe {url} returned HTTP {resp.status}")
    finally:
        conn.close()


def main() -> int:
    host = _target_host()
    port = int(os.environ.get("IMPERSONATE_PROXY_PORT", "8899"))
    probe_url = os.environ.get("IMPERSONATE_PROXY_HEALTHCHECK_URL", DEFAULT_HEALTHCHECK_URL).strip()
    try:
        _check_local_healthz(host, port)
        if probe_url:
            _check_proxied_url(host, port, probe_url)
    except Exception as exc:
        print(f"healthcheck failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
