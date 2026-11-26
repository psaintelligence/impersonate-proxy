# Design: impersonate-proxy

Welcome to the `impersonate-proxy` design document. This document outlines the core stack, architecture, design decisions, and coding standards.

---

## 🛠 Core Stack

- **Runtime**: Python 3.12+
- **Key Dependencies**:
  - `curl_cffi`: Used to make request calls that impersonate browser TLS signatures (JA3/JA4).
  - `cryptography`: Used to generate self-signed Root CA and dynamically issue site-specific certs for MITM decryption.
  - `pytest`: For unit and integration tests.
  - `basedpyright` and `ruff`: For type checking, formatting, and linting.
- **Package & Env Management**: Managed using `uv`.

---

## 🏗 Architecture & Design Decisions

The proxy operates in two primary modes depending on whether it receives plain HTTP requests or an HTTPS `CONNECT` tunnel request:

1. **HTTP Proxy Mode**:
   - Acts as a standard HTTP proxy forwarding requested HTTP traffic.
   - Re-issues requests via `curl_cffi` to mimic browser TLS fingerprints.

2. **HTTPS Proxy Mode (MITM)**:
   - On startup, a root CA is loaded or generated in `--ca-dir` (default `~/.config/impersonate-proxy`; clients trust `ca.crt` via `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE`).
   - Upon receiving a `CONNECT` request, the proxy accepts the tunnel, dynamically generates a fake certificate signed by the Root CA for the requested domain (e.g. `example.com`), and performs a TLS handshake with the client.
   - The decrypted requests inside the secure tunnel are read, and the proxy forwards them using `curl_cffi` with browser TLS fingerprinting to the upstream server.
   - If the root CA fails to initialize or trust store installation fails, the proxy falls back to a raw TCP tunnel (relaying raw bytes back and forth) without TLS impersonation.

3. **Header Delegation Philosophy**:
   - Rather than manually replicating browser headers in Python, the proxy delegates header generation directly to `curl-impersonate` / `curl_cffi`.
   - In `cffi-defaults` mode, the proxy acts as a thin adapter: it strips client-supplied headers that would override `curl_cffi` defaults (`User-Agent`, the full `Sec-Ch-Ua*` family, `Accept-Encoding`, `Priority`, `TE`, `Upgrade-Insecure-Requests`, `Sec-Fetch-User`), drops bot-tells (`DNT`, `Cache-Control`, `Connection`), suppresses profile-default `Cache-Control` via `"Cache-Control": None`, strips `Accept-Language` only when it is the literal `*` (a bot tell), and preserves request payload/auth semantics (`Cookie`, `Authorization`, `Host`, `Sec-Fetch-*` for XHR, real `Accept-Language`).
   - Pooled `curl_cffi` sessions are created with `discard_cookies=True` and `trust_env=False` (no cross-client cookie bleed or ambient proxy-env loops); upstream response headers are forwarded via `multi_items()` so repeated `Set-Cookie` headers are preserved individually.
   - `--strip-client-leak-headers` (orthogonal flag) drops middlebox-chain/tracing headers (`X-Forwarded-*`, `Forwarded`, `Via`, `X-Request-ID`, `X-Correlation-ID`); CDN-ingress headers (`X-Real-IP`, `True-Client-IP`, etc.) are forwarded with a warning, not dropped.

4. **Realistic Client-Hint Fingerprint Override (`fingerprint_real`, default on)**:
   - curl_cffi's profiles emit two residual tells: a scrubbed UA build (`Chrome/152.0.0.0`) and an incomplete `Sec-CH-UA` family.
   - `fingerprint.py` curates platform-coherent header sets (full-build UA + complete `Sec-CH-UA-*` family) keyed by curl_cffi target, injected on top in `cffi-defaults` mode.
   - Canonical HTTP/2 header order is enforced via `extra_fp={"header_order": ...}` on every request (HTTP/2 only).
   - Curated builds must track real-world Chrome stable releases (see `.agents/workflows/fingerprint-verification.md`); disable with `--no-fingerprint-real` / `IMPERSONATE_PROXY_FINGERPRINT_REAL=false`.

5. **Concurrency**:
   - The server uses `ThreadingMixIn` combined with `HTTPServer` to handle multiple client connections concurrently.
   - Certificate caching is synchronized with threading locks to optimize TLS handshake speed for repeated hosts.

6. **Tunnel hardening (keep-alive + limits)**:
   - CONNECT tunnels are client-driven keep-alive: HTTP/1.1 persists unless `Connection: close`; HTTP/1.0 requires an explicit keep-alive token. Capped by `--tunnel-idle-timeout` (default 30s, shared with the raw-tunnel select loop) and a hard per-tunnel request cap (1000).
   - Request bodies are capped by `--max-body-size` (default 512 MiB); oversized → 413 inside the tunnel or on the plain-HTTP path, invalid/negative Content-Length → 400. Applies to Content-Length and de-chunked chunked bodies.
   - `--block-host a.com,b.com` (exact or suffix match) refuses CONNECT/plain-HTTP targets with 403 before any tunnel or upstream request.
   - Unknown `--impersonate` targets are rejected at startup (exit 2) via `_impersonate_error_message()` in `main.py`.
   - Hop-by-hop header stripping is a single shared `_HOP_BY_HOP_HEADERS` frozenset in `server.py` used by both the MITM and plain-HTTP paths.
   - Open-proxy guardrails (off by default): `--proxy-auth user:password` (constant-time Basic check on CONNECT before `200`, 407 otherwise) and `--allow-from` (bare-IP auto-netblock or CIDR, 403 for foreign clients). Deny-list responses flow through `_reject_client()` which also feeds the stats counters.
   - Optional `--stats-port` exposes Prometheus metrics at `/metrics` (`stats.py`): requests per mode, upstream failures, 4xx/5xx classes, session-pool high-water, cert-cache size. Counters live on `ctx.stats` (always on), endpoint gated.
   - CA generation is concurrency-safe: an exclusive `.generate-claim` file elects one generator (reclaiming stale claims >30s after crashes) that publishes `ca.key`/`ca.crt` via atomic `os.replace`; losers wait for a consistent pair (`cert_manager._load_ca_files` verifies key↔cert match on load).
   - Leaf certs load from a single combined PEM temp file (cert+key) and live in a true LRU cache (`ctx.host_cert_cache`) with 29-day TTL refresh for 30-day leaf certs.
   - Local loopback-only `GET`/`HEAD /healthz` provides zero-egress container liveness (`docker/healthcheck.py`) without polluting stats/logs or exposing any external fingerprint surface.
   - `--max-threads N` (0 = unlimited) caps concurrent handler threads via a `BoundedSemaphore` in `ThreadingHTTPServer.process_request`; the accept loop blocks at the cap (backlog absorbs excess).
   - Firefox fingerprints (`fingerprint_for("firefox155")`, alias `firefox`) are UA-only (`browser="firefox"` → `to_headers()` emits just the User-Agent) with empty `header_order` — never impose Chrome's order or CH family on Firefox targets; `session_pool` only sends `extra_fp={"header_order": ...}` when the fingerprint has a non-empty order.

---

## 🧪 Testing Guidelines

Always run the tests using isolated virtual environment prefixes to prevent `.venv` directory creation in the repository:

```bash
UV_PROJECT_ENVIRONMENT=${HOME}/.local/venvs/impersonate-proxy \
UV_CACHE_DIR=/tmp/.uv-cache-impersonate-proxy \
UV_LINK_MODE=copy \
uv run --extra dev pytest
```
