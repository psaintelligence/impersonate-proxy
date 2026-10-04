# Installation & CLI Guide

`impersonate-proxy` can be run either as a local Python application or containerized using Docker.

---

## Local Installation

### Prerequisites
- Python 3.12 or newer
- `pip` or `uv` package manager

```bash
# Install via pipx from pypi
pipx install impersonate-proxy

# Or install via uv from source
uv pip install git+https://github.com/psaintelligence/impersonate-proxy.git

# Start the proxy (default: 127.0.0.1:8899)
impersonate-proxy
```

---

## Docker Installation (Recommended)

Running the proxy via Docker is recommended for isolated operation and to persist certificate states easily.

```bash
docker run --rm -p 8899:8899 \
  -v /tmp/impersonate-certs:/root/.config/impersonate-proxy \
  ghcr.io/psaintelligence/impersonate-proxy:latest
```

### Docker Compose
You can spin up the service in the background using docker-compose:
```yaml
services:
  proxy:
    image: ghcr.io/psaintelligence/impersonate-proxy:latest
    ports:
      - "8899:8899"
    environment:
      - IMPERSONATE_PROXY_IMPERSONATE=chrome
      - IMPERSONATE_PROXY_DEBUG=false
    volumes:
      - impersonate-proxy-ca-certs:/root/.config/impersonate-proxy

volumes:
  impersonate-proxy-ca-certs:
```

---

## Command Line Interface (CLI)

Run `impersonate-proxy --help` to view all available parameters:

```text
usage: impersonate-proxy [-h] [--port PORT] [--host HOST]
                         [--impersonate IMPERSONATE] [--cffi-defaults |
                         --passthrough-headers] [--strip-client-leak-headers]
                         [--upstream-proxy UPSTREAM_PROXY]
                         [--no-fingerprint-real]
                         [--session-pool-max SESSION_POOL_MAX]
                         [--connect-timeout CONNECT_TIMEOUT]
                         [--read-timeout READ_TIMEOUT]
                         [--max-body-size MAX_BODY_SIZE]
                         [--tunnel-idle-timeout TUNNEL_IDLE_TIMEOUT]
                         [--block-host BLOCK_HOST] [--ca-dir CA_DIR] [--debug]
                         [--quiet]

HTTP/HTTPS proxy that impersonates browser TLS fingerprints

options:
  -h, --help            show this help message and exit
  --port, -p PORT       Port to listen on (default: 8899 or
                        IMPERSONATE_PROXY_PORT)
  --host, -H HOST       Host to bind to (default: 127.0.0.1 or
                        IMPERSONATE_PROXY_HOST)
  --impersonate, -i IMPERSONATE
                        Browser to impersonate (chrome, firefox, etc. Default:
                        chrome or IMPERSONATE_PROXY_IMPERSONATE)
  --cffi-defaults       Strip browser-shape headers (User-Agent, Sec-Ch-Ua-*,
                        Accept-Encoding, Priority, TE, Upgrade-Insecure-
                        Requests, Sec-Fetch-User) from the client and drop
                        bot-tell headers (Cache-Control, DNT, Connection) so
                        curl_cffi injects the correct current browser values
                        from its impersonation profile. [DEFAULT]
  --passthrough-headers
                        Forward client headers untouched; curl_cffi only sets
                        TLS-impersonation headers. For advanced users.
  --strip-client-leak-headers
                        Drop middlebox-chain / tracing leak headers
                        (X-Forwarded-*, Forwarded, Via, X-Request-ID,
                        X-Correlation-ID). CDN-ingress headers (X-Real-IP,
                        True-Client-IP, etc.) are forwarded with a warning
                        when present. Combinable with any header mode. Or
                        IMPERSONATE_PROXY_STRIP_CLIENT_LEAK_HEADERS=true
  --upstream-proxy UPSTREAM_PROXY
                        Upstream egress proxy URL (e.g. http://127.0.0.1:8080
                        or IMPERSONATE_PROXY_UPSTREAM_PROXY)
  --no-fingerprint-real
                        Disable injection of platform-coherent full-build UA +
                        complete Sec-CH-UA family on top of curl_cffi's TLS
                        impersonation. On by default in cffi-defaults mode. Or
                        IMPERSONATE_PROXY_FINGERPRINT_REAL=false
  --session-pool-max SESSION_POOL_MAX
                        Maximum reusable curl_cffi sessions in pool (default:
                        32 or IMPERSONATE_PROXY_SESSION_POOL_MAX)
  --connect-timeout CONNECT_TIMEOUT
                        Upstream TCP/TLS connect timeout in seconds (default:
                        10.0 or IMPERSONATE_PROXY_CONNECT_TIMEOUT)
  --read-timeout READ_TIMEOUT
                        Upstream HTTP read timeout in seconds (default: 300.0
                        or IMPERSONATE_PROXY_READ_TIMEOUT)
  --max-body-size MAX_BODY_SIZE
                        Maximum client request body accepted per request, in
                        bytes (default: 536870912 = 512 MiB or
                        IMPERSONATE_PROXY_MAX_BODY_SIZE). Larger bodies are
                        rejected with 413
  --tunnel-idle-timeout TUNNEL_IDLE_TIMEOUT
                        Idle seconds allowed on tunnel sockets before closing:
                        the raw-tunnel select loop and the MITM keep-alive
                        loop between requests (default: 30.0 or
                        IMPERSONATE_PROXY_TUNNEL_IDLE_TIMEOUT)
  --block-host BLOCK_HOST
                        Comma-separated target hostnames to refuse with 403
                        (exact or suffix match: example.com also blocks
                        *.example.com). Or IMPERSONATE_PROXY_BLOCK_HOST
  --ca-dir, -c CA_DIR   Directory to store/load CA certificate and key
                        (default: ~/.config/impersonate-proxy or
                        IMPERSONATE_PROXY_CA_DIR)
  --debug, -d           Enable verbose debug logging (unredacts URLs/hosts in
                        logs) or IMPERSONATE_PROXY_DEBUG=true
  --quiet, -q           Disable logging of request traffic or
                        IMPERSONATE_PROXY_QUIET=true
```

The two header-mode flags are mutually exclusive. The default mode is
`--cffi-defaults`. Equivalent environment variables are
`IMPERSONATE_PROXY_HEADER_MODE` (one of `passthrough`, `cffi-defaults`),
`IMPERSONATE_PROXY_STRIP_CLIENT_LEAK_HEADERS`, `IMPERSONATE_PROXY_UPSTREAM_PROXY`,
`IMPERSONATE_PROXY_SESSION_POOL_MAX`, `IMPERSONATE_PROXY_CONNECT_TIMEOUT`,
`IMPERSONATE_PROXY_READ_TIMEOUT`, `IMPERSONATE_PROXY_MAX_BODY_SIZE`,
`IMPERSONATE_PROXY_TUNNEL_IDLE_TIMEOUT`, and `IMPERSONATE_PROXY_BLOCK_HOST`.

An unknown `--impersonate` target is rejected at startup (exit code 2) with a
list of valid `curl_cffi` targets — it would otherwise fail lazily on the first
request with a 502 and no actionable hint.

---

## Trusting the Root CA

To allow client applications to perform HTTPS requests through the proxy without throwing SSL verification errors:

1. **Locate the Certificate**: By default, the root certificate is created at `~/.config/impersonate-proxy/ca.crt`.
2. **Set Environment Variables**: Many tools (like `curl`, `wget`, `python-requests`, `httpx`) respect specific environment variables for trust stores:

```bash
# Set CA trust path for curl
export SSL_CERT_FILE=~/.config/impersonate-proxy/ca.crt

# Set CA trust path for python-requests
export REQUESTS_CA_BUNDLE=~/.config/impersonate-proxy/ca.crt

# Test HTTPS request through the proxy
curl -x http://127.0.0.1:8899 https://example.com
```
