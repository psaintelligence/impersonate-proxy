"""Container healthcheck: issue one plain-HTTP request through the local proxy.

Any HTTP response (even 4xx/5xx from the upstream) proves the proxy is serving
requests; only connection-level failures mark the container unhealthy.
"""

import os
import sys
import urllib.error
import urllib.request

port = os.environ.get("IMPERSONATE_PROXY_PORT", "8899")
proxy_url = f"http://127.0.0.1:{port}"
opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
)
try:
    opener.open("http://example.com/", timeout=10)
except urllib.error.HTTPError:
    pass
except Exception as exc:
    print(f"healthcheck failed: {exc}", file=sys.stderr)
    sys.exit(1)
