# PSA Intelligence Impersonate Proxy

[![pypi](https://img.shields.io/pypi/v/impersonate-proxy.svg)](https://pypi.org/project/impersonate-proxy/)
[![python](https://img.shields.io/badge/python-3.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://github.com/psaintelligence/impersonate-proxy/)
[![build tests](https://github.com/psaintelligence/impersonate-proxy/actions/workflows/project-tests.yml/badge.svg)](https://github.com/psaintelligence/impersonate-proxy/actions/workflows/project-tests.yml)
[![license](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/psaintelligence/impersonate-proxy/blob/main/LICENSE)
<img src="assets/img/logo.jpg" align="right" width="140" style="margin-left: 20px; margin-bottom: 20px;" alt="impersonate-proxy logo">

HTTP/HTTPS proxy that impersonates browser TLS fingerprints using [curl_cffi](https://github.com/lexiforest/curl_cffi) that can be effective in avoiding blocks against non-browser clients.

!!! note "Attribution"
    This project started as a fork of [hauxir/tls-impersonate-proxy](https://github.com/hauxir/tls-impersonate-proxy) and has now evolved beyond a pull request to merge.  This **impersonate-proxy** project is maintained at [psaintelligence/impersonate-proxy](https://github.com/psaintelligence/impersonate-proxy).

Pypi: [pypi.org/project/impersonate-proxy](https://pypi.org/project/impersonate-proxy/)

GHCR: [github.com/psaintelligence/impersonate-proxy/pkgs/container](https://github.com/psaintelligence/impersonate-proxy/pkgs/container/impersonate-proxy)

---

## Quick Start (Docker)

Spin up the proxy container:

```bash
docker run --rm -p 8899:8899 \
  -v /tmp/impersonate-certs:/home/impersonate/.config/impersonate-proxy \
  ghcr.io/psaintelligence/impersonate-proxy:latest
```

Once started, configure your client to trust the CA and use the proxy:

```bash
# Export the generated CA cert to trust the proxy
export SSL_CERT_FILE=/tmp/impersonate-certs/ca.crt

# Issue request through the proxy
curl --silent -x http://127.0.0.1:8899 https://tls.browserleaks.com/json
```

---

## Quick Start (pip / uv)

Install and start the proxy locally:

```bash
# Install via pipx from pypi
pipx install impersonate-proxy

# Or install via uv from source
uv pip install git+https://github.com/psaintelligence/impersonate-proxy.git

# Start the proxy (default: 127.0.0.1:8899)
impersonate-proxy
```

---

## Features

- **TLS Impersonation**: Disguises client TLS fingerprints as standard browsers (Chrome or Firefox).
- **Header Adapter & Delegation**: Strips conflicting non-browser client headers (e.g. `User-Agent: python-httpx`) so native `curl-impersonate` profile defaults shine through, while preserving payload and auth semantics.
- **Realistic Fingerprinting**: Injects a platform-coherent full-build User-Agent with the complete `Sec-CH-UA` family and canonical HTTP/2 header order for Chrome targets, and a UA-only full-build User-Agent for Firefox targets, on top of curl_cffi's TLS impersonation (on by default, `--no-fingerprint-real` to disable).
- **Open-Proxy Guardrails**: Optional Basic proxy authentication (`--proxy-auth`), client allowlist (`--allow-from`), and target deny list (`--block-host`) to run the proxy as a controlled egress point.
- **Connection Keep-Alive & Session Pooling**: Reuses TLS sessions and upstream TCP connections to optimize latency and handle high-concurrency requests, with an optional `--max-threads` handler cap and a `--stats-port` Prometheus endpoint.
- **Fast Dynamic Cert Generation**: Dynamic certificate generation using fast Elliptic Curve (ECDSA P-256) cryptography with leaf key reuse.

---

## Capabilities

| Capability | What it does | Benefit |
|---|---|---|
| **TLS Fingerprinting** | Matches JA3/JA4/HTTP2 fingerprints with real browsers | Defeats Cloudflare, Akamai, and Imperva WAF blocks |
| **MITM CONNECT Decryption** | Decrypts and re-signs HTTPS traffic using local CA | Allows inspection, header filtering, and proxying of TLS streams |
| **Header Delegation** | Strips non-browser headers and delegates to `curl-impersonate` | Ensures User-Agent and TLS fingerprint profiles align natively without duplication |
| **Client-Hint Coherence** | Full-build UA + complete `Sec-CH-UA` family in canonical HTTP/2 header order (Chrome); UA-only curation for Firefox | Removes the scrubbed-UA / partial-client-hint tells that fingerprint services flag |
| **Open-Proxy Guardrails** | Optional `--proxy-auth`, `--allow-from` client allowlist, and `--block-host` deny list | Runs the proxy as a controlled, multi-user-safe egress point |
| **Session Pooling** | Maintains queue-based reusable `curl_cffi` sessions | Boosts performance for concurrent request bursts to ~70+ RPS |
| **P-256 Cryptography** | Reuses a static leaf private key for ECDSA cert creation | Reduces leaf certificate dynamic issuance time to `<1ms` |
| **Observability & Limits** | Prometheus `/metrics` (`--stats-port`) and `--max-threads` handler cap | Monitors traffic live and prevents resource exhaustion under load |

---

## Guided Tour

- **[Installation Guide](install.md)**: System setup, CLI parameters, and Docker integrations.
- **[How It Works](workflow.md)**: Deep dive into the interception pipeline, session pool, and header delegation mechanism.
