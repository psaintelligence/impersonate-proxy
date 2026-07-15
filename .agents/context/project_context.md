# Project Context: tls-impersonate-proxy

Welcome to the `tls-impersonate-proxy` codebase context. This document outlines the core stack, architecture, design decisions, and coding standards.

---

## 🛠 Core Stack

- **Runtime**: Python 3.11+
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

3. **Concurrency**:
   - The server uses `ThreadingMixIn` combined with `HTTPServer` to handle multiple client connections concurrently.
   - Certificate caching is synchronized with threading locks to optimize TLS handshake speed for repeated hosts.

---

## 🧪 Testing Guidelines

Always run the tests using isolated virtual environment prefixes to prevent `.venv` directory creation in the repository:

```bash
UV_PROJECT_ENVIRONMENT=${HOME}/.local/venvs/tls-impersonate-proxy \
UV_CACHE_DIR=/tmp/.uv-cache-tls-impersonate-proxy \
UV_LINK_MODE=copy \
uv run --extra dev pytest
```
