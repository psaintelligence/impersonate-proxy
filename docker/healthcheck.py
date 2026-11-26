"""Container healthcheck: probe the proxy's local /healthz endpoint.

Verifies the proxy listener is accepting connections and its handler threads
are actively serving HTTP requests without making any external network calls.
Works regardless of --proxy-auth, --allow-from, --block-host, --upstream-proxy,
or air-gapped egress policies.
"""

import http.client
import os
import sys


def main() -> int:
    bind_host = os.environ.get("IMPERSONATE_PROXY_HOST", "127.0.0.1").strip()
    if bind_host in ("", "0.0.0.0"):
        target_host = "127.0.0.1"
    elif bind_host == "::":
        target_host = "::1"
    else:
        target_host = bind_host

    port = int(os.environ.get("IMPERSONATE_PROXY_PORT", "8899"))
    conn = http.client.HTTPConnection(target_host, port, timeout=5)
    try:
        conn.request("GET", "/healthz")
        resp = conn.getresponse()
        body = resp.read()
        if resp.status != 200 or body.strip() != b"ok":
            print(f"healthcheck failed: unexpected response {resp.status} {body!r}", file=sys.stderr)
            return 1
        return 0
    except Exception as exc:
        print(f"healthcheck failed: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
