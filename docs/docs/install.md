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
  -v /tmp/impersonate-certs:/home/impersonate/.config/impersonate-proxy \
  ghcr.io/psaintelligence/impersonate-proxy:latest
```

The container runs as a dedicated non-root user (`impersonate`) and ships a
`HEALTHCHECK` that probes both the local loopback `/healthz` endpoint and an
end-to-end proxied request to Microsoft's lightweight connectivity probe
(`http://edge-http.microsoft.com/captiveportal/generate_204`). Override the
target with `IMPERSONATE_PROXY_HEALTHCHECK_URL` (or set it to `""` for
air-gapped deployments to run `/healthz` only).

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
      - impersonate-proxy-ca-certs:/home/impersonate/.config/impersonate-proxy

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
                         [--upstream-proxy UPSTREAM_PROXY] [--dns DNS]
                         [--no-fingerprint-real]
                         [--session-pool-max SESSION_POOL_MAX]
                         [--connect-timeout CONNECT_TIMEOUT]
                         [--read-timeout READ_TIMEOUT]
                         [--max-body-size MAX_BODY_SIZE]
                         [--tunnel-idle-timeout TUNNEL_IDLE_TIMEOUT]
                         [--block-host BLOCK_HOST]
                         [--raw-tunnel-host RAW_TUNNEL_HOST]
                         [--block-private-ips] [--proxy-auth PROXY_AUTH]
                         [--allow-from ALLOW_FROM] [--stats-port STATS_PORT]
                         [--max-threads MAX_THREADS]
                         [--log-format {text,json}] [--ca-dir CA_DIR]
                         [--debug] [--quiet]

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
  --dns DNS             Custom upstream DNS server IP(s) (comma-separated,
                        e.g. 1.1.1.1,8.8.8.8) or DNS-over-HTTPS URL (e.g.
                        https://1.1.1.1/dns-query). Or IMPERSONATE_PROXY_DNS
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
                        *.example.com; prefix @/path/to/file for SIGHUP-
                        reloadable lists). Or IMPERSONATE_PROXY_BLOCK_HOST
  --raw-tunnel-host RAW_TUNNEL_HOST
                        Comma-separated target hostnames to bypass MITM and
                        relay via raw TCP tunnel on CONNECT (exact or suffix
                        match; supports @/path/to/file and SIGHUP reload). Or
                        IMPERSONATE_PROXY_RAW_TUNNEL_HOST
  --block-private-ips   Refuse requests targeting private, loopback, link-
                        local (cloud metadata), CGNAT, ULA, or multicast IP
                        addresses with 403 (SSRF protection). Or
                        IMPERSONATE_PROXY_BLOCK_PRIVATE_IPS=true
  --proxy-auth PROXY_AUTH
                        Require Proxy-Authorization: Basic auth with these
                        user:password credentials on every request; reply 407
                        otherwise (e.g. --proxy-auth alice:s3cret or
                        IMPERSONATE_PROXY_PROXY_AUTH)
  --allow-from ALLOW_FROM
                        Comma-separated client allowlist: bare IPs (matched
                        via the /24 or /64 auto-netblock, e.g. 192.168.1.7) or
                        explicit CIDRs (e.g. 10.0.0.0/8; supports
                        @/path/to/file and SIGHUP reload); other clients are
                        refused with 403. Or IMPERSONATE_PROXY_ALLOW_FROM
  --stats-port STATS_PORT
                        Serve Prometheus metrics at /metrics on this port (off
                        by default, or IMPERSONATE_PROXY_STATS_PORT)
  --max-threads MAX_THREADS
                        Maximum concurrent handler threads; excess connections
                        wait in the listen backlog (default: 0 = unlimited, or
                        IMPERSONATE_PROXY_MAX_THREADS)
  --log-format {text,json}
                        Log output format: 'text' (default) or 'json'. Or
                        IMPERSONATE_PROXY_LOG_FORMAT
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
`IMPERSONATE_PROXY_DNS`, `IMPERSONATE_PROXY_SESSION_POOL_MAX`,
`IMPERSONATE_PROXY_CONNECT_TIMEOUT`, `IMPERSONATE_PROXY_READ_TIMEOUT`,
`IMPERSONATE_PROXY_MAX_BODY_SIZE`, `IMPERSONATE_PROXY_TUNNEL_IDLE_TIMEOUT`,
`IMPERSONATE_PROXY_BLOCK_HOST`, `IMPERSONATE_PROXY_RAW_TUNNEL_HOST`,
`IMPERSONATE_PROXY_BLOCK_PRIVATE_IPS`, `IMPERSONATE_PROXY_PROXY_AUTH`,
`IMPERSONATE_PROXY_ALLOW_FROM`, `IMPERSONATE_PROXY_STATS_PORT`,
`IMPERSONATE_PROXY_MAX_THREADS`, and `IMPERSONATE_PROXY_LOG_FORMAT`.

`--block-host`, `--allow-from`, and `--raw-tunnel-host` also accept `@/path/to/file`
entries (one item per line, `#` comments ignored) and reload live on `SIGHUP`
without interrupting active connections.

An unknown `--impersonate` target is rejected at startup (exit code 2) with a
list of valid `curl_cffi` targets — it would otherwise fail lazily on the first
request with a 502 and no actionable hint.

---

## Access Control & Routing (shared deployments)

The default bind is `127.0.0.1` (local only). When binding to a broader
interface (`--host 0.0.0.0`, Docker), orthogonal guardrails keep the proxy from
acting as an unauthenticated open relay or SSRF pivot:

```bash
# Require Basic proxy authentication (client: curl -x http://alice:s3cret@127.0.0.1:8899)
impersonate-proxy --host 0.0.0.0 --proxy-auth alice:s3cret

# Restrict clients, block SSRF targets, bypass MITM for pinned hosts, and reload lists on SIGHUP
impersonate-proxy --host 0.0.0.0 \
  --allow-from @/etc/impersonate-proxy/allow.txt \
  --block-host @/etc/impersonate-proxy/block.txt \
  --raw-tunnel-host @/etc/impersonate-proxy/pinned.txt \
  --block-private-ips \
  --dns https://1.1.1.1/dns-query \
  --log-format json
```

- `--proxy-auth` checks `Proxy-Authorization: Basic` on both CONNECT and
  plain-HTTP requests in constant time; unauthorized clients receive
  `407 Proxy Authentication Required` with a `Proxy-Authenticate` challenge.
- `--allow-from` refuses clients outside the listed netblocks with `403`.
- `--block-private-ips` blocks requests targeting private, loopback, link-local
  (`169.254.169.254`), CGNAT, ULA, or multicast IP addresses with `403`.
- `--raw-tunnel-host` relays matched `CONNECT` hosts as raw TCP tunnels without
  MITM decryption (useful for certificate-pinned apps or WebSockets).
- `--block-host`, `--allow-from`, and `--raw-tunnel-host` accept `@/path/to/file`
  lists and reload atomically on `SIGHUP`.
- All guardrails are off by default; local usage and existing Docker flows are
  unchanged.

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

---

## Development

The repository ships a `Makefile` wrapping the common development tasks
(all commands run through `uv` with an isolated virtualenv and cache):

```bash
make help            # List all available targets
make setup           # Create the isolated virtualenv and sync dependencies
make sync            # Sync python dependencies (dev environment)
make test            # Run offline unit and integration tests
make test-verbose    # Run offline tests with verbose output
make test-live       # Run basic live tests (hit real URLs)
make test-extended   # Run extended fingerprint/bot-detection live tests
make benchmark       # Run the concurrency performance benchmark
make lint            # Run linting checks (ruff)
make format          # Format code (ruff)
make lint-fix        # Auto-fix linting and formatting issues
make typecheck       # Run type checking (basedpyright)
make build           # Build wheel and source distributions
make bump-patch      # Bump the patch version number (e.g. 0.1.0 -> 0.1.1)
make bump-minor      # Bump the minor version number (e.g. 0.1.0 -> 0.2.0)
make clean           # Clean build and cache artifacts
make docs-sync       # Sync documentation dependencies
make docs-build      # Build documentation site
make docs-serve      # Serve documentation locally
```

Tests marked `live` / `live_extended` are deselected by default and require
internet access; run them explicitly with `make test-live` / `make test-extended`.
