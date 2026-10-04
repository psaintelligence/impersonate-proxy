# Project Context: impersonate-proxy

Welcome to the `impersonate-proxy` codebase context. This document outlines the core stack, architecture, design decisions, and coding standards.

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
   - On startup, a root CA is initialized (via in-memory generation, with the CA certificate stored in `/tmp` and registered in the system trust store).
   - Upon receiving a `CONNECT` request, the proxy accepts the tunnel, dynamically generates a fake certificate signed by the Root CA for the requested domain (e.g. `example.com`), and performs a TLS handshake with the client.
   - The decrypted requests inside the secure tunnel are read, and the proxy forwards them using `curl_cffi` with browser TLS fingerprinting to the upstream server.
   - If the root CA fails to initialize or trust store installation fails, the proxy falls back to a raw TCP tunnel (relaying raw bytes back and forth) without TLS impersonation.

3. **Header Delegation Philosophy**:
   - Rather than manually replicating browser headers in Python, the proxy delegates header generation directly to `curl-impersonate` / `curl_cffi`.
   - In `cffi-defaults` mode, the proxy acts as a thin adapter: it strips client-supplied headers that would override `curl_cffi` defaults (`User-Agent`, `Sec-Ch-Ua-*`, `Accept-Encoding`, `Priority`, `TE`, `Upgrade-Insecure-Requests`, `Sec-Fetch-User`), drops bot-tells (`DNT`, `Cache-Control`, `Connection`), strips `Accept-Language` only when it is the literal `*` (a bot tell), and preserves request payload/auth semantics (`Cookie`, `Authorization`, `Host`, `Sec-Fetch-*` for XHR, real `Accept-Language`).
   - `--strip-client-leak-headers` (orthogonal flag) drops middlebox-chain/tracing headers (`X-Forwarded-*`, `Forwarded`, `Via`, `X-Request-ID`, `X-Correlation-ID`); CDN-ingress headers (`X-Real-IP`, `True-Client-IP`, etc.) are forwarded with a warning, not dropped.

4. **Realistic Client-Hint Fingerprint Override (`fingerprint_real`, default on)**:
   - curl_cffi's profiles emit two residual tells: a scrubbed UA build (`Chrome/150.0.0.0`) and an incomplete `Sec-CH-UA` family.
   - `fingerprint.py` curates platform-coherent header sets (full-build UA + complete `Sec-CH-UA-*` family) keyed by curl_cffi target, injected on top in `cffi-defaults` mode.
   - Canonical HTTP/2 header order is enforced via `extra_fp={"header_order": ...}` on every request (HTTP/2 only).
   - Curated builds must track real-world Chrome stable releases (see `.agents/workflows/fingerprint-verification.md`); disable with `--no-fingerprint-real` / `IMPERSONATE_PROXY_FINGERPRINT_REAL=false`.

5. **Concurrency**:
   - The server uses `ThreadingMixIn` combined with `HTTPServer` to handle multiple client connections concurrently.
   - Certificate caching is synchronized with threading locks to optimize TLS handshake speed for repeated hosts.

---

## 🧪 Testing Guidelines

Always run the tests using isolated virtual environment prefixes to prevent `.venv` directory creation in the repository:

```bash
UV_PROJECT_ENVIRONMENT=${HOME}/.local/venvs/impersonate-proxy \
UV_CACHE_DIR=/tmp/.uv-cache-impersonate-proxy \
UV_LINK_MODE=copy \
uv run --extra dev pytest
```
