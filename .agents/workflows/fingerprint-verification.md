---
description: How to verify browser-fingerprint integrity after a curl_cffi/impersonate upgrade.
---

# Fingerprint Verification Workflow

Use this workflow whenever upgrading `curl_cffi` (or otherwise changing the
browser impersonation target) to ensure the proxy still emits a *realistic,
platform-coherent* browser fingerprint and does not regress into the
"scrubbed/reconstructed" tells.

## Background: why this exists

The proxy delegates TLS impersonation to `curl_cffi` but must override the
**header layer**. curl_cffi's impersonation profiles ship two tells that a
fingerprint service (Cloudflare, browserleaks, etc.) can detect:

1. **Scrubbed UA build** — e.g. `Chrome/150.0.0.0`. Real browsers send a full
   build like `Chrome/150.0.6585.24`. The `.0.0.0` suffix is the classic
   placeholder value proxy tools emit.
2. **Incomplete Sec-CH-UA family** — only the basic triplets
   (`Sec-CH-UA`, `Sec-CH-UA-Mobile`, `Sec-CH-UA-Platform`). A real desktop
   Chrome over HTTPS also sends `Sec-CH-UA-Full-Version-List`,
   `Sec-CH-UA-Platform-Version`, `Sec-CH-UA-Arch`, `Sec-CH-UA-Bitness`,
   `Sec-CH-UA-Model`.

The proxy fixes these by injecting a curated fingerprint (`fingerprint.py`)
on top of curl_cffi's TLS profile. **Never delete or "simplify" that override —
it is the whole point of the impersonation.**

The single most decisive signal is the combination of a `Chrome/X.0.0.0` UA **and**
partial client hints — no genuine browser sends that. Both must be coherent.

## Coherence rules (non-negotiable)

A real browser is internally consistent. These must ALL agree, or it's a tell:

- `User-Agent` build (e.g. `150.0.6585.24`) must match the version in
  `Sec-CH-UA-Full-Version-List` ("Chromium" and "Google Chrome" entries).
- `User-Agent` major (e.g. `150`) must match the major in base `Sec-CH-UA`
  (the src-ch-ua triplet). A mismatch here (146-vs-150) is an instant tell.
- `User-Agent` platform token (e.g. `Windows NT 10.0; Win64; x64`) must match
  `Sec-CH-UA-Platform` (`"Windows"`) and `Sec-CH-UA-Platform-Version`
  (`"10.0.0"`). A Windows UA with `Sec-CH-UA-Platform: "macOS"` is a bot tell.
- No brand-list skew: `"Not/A)Brand"` short version must use the same
  major-8 pattern as the full list.

## How to verify

### 1. Automated tests (fast, always run)

```bash
UV_PROJECT_ENVIRONMENT=${HOME}/.local/venvs/impersonate-proxy UV_CACHE_DIR=/tmp/.uv-cache-impersonate-proxy UV_LINK_MODE=copy uv run --extra dev pytest tests/test_fingerprint.py -q
```

Check `tests/test_fingerprint.py` — it asserts:
- `Chrome/X.0.0.0` never appears (`test_ua_build_not_scrubbed`).
- UA version == Full-Version-List version (`test_ua_and_full_version_list_agree`).
- base `Sec-CH-UA` major == UA major (`test_base_sec_ch_ua_major_matches_ua`).
- platform coherence (`test_platform_coherent`).
- the full CH family is present (`test_headers_include_full_family`).
- HTTP/2 header order is canonical (`test_header_order_canonical`).

### 1b. HTTP/2 header order

A real Chrome sends its headers in a canonical order (CH family grouped
`sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, sec-ch-ua-arch,
sec-ch-ua-bitness, sec-ch-ua-full-version-list, sec-ch-ua-model,
sec-ch-ua-platform-version`, then `user-agent` before `accept`, then the
`sec-fetch-*` cluster). curl_cffi's impersonation profile sets an *empty*
`header_order`, so any extra headers you inject (the full CH family) would be
appended in non-canonical order — a tell.

The proxy fixes this by passing `extra_fp={"header_order": fp.header_order}`
on every request when `--fingerprint-real` is active. The order lives on the
`BrowserFingerprint` dataclass. If a service reflects non-canonical order, the
`header_order` string is out of sync — update it and the test will catch it.

### 2. Live end-to-end (real proxy, real reflection service)

```bash
# Marker-gated; hits the live network.
UV_PROJECT_ENVIRONMENT=${HOME}/.local/venvs/impersonate-proxy UV_CACHE_DIR=/tmp/.uv-cache-impersonate-proxy UV_LINK_MODE=copy uv run --extra dev pytest -m live tests/test_fingerprint.py -q
```

This starts a real proxy instance and sends requests through it:
- `https://whoami.projects.psaintelligence.com/` — asserts the reflected
  headers carry the full build + complete CH family.
- `https://tls.peet.ws/api/all` — reads the true on-the-wire HTTP/2 HEADERS
  frame and asserts the canonical order
  (`test_http2_header_order_canonical`).

Note: use `tls.peet.ws` (not whoami) for order checks — whoami serves
HTTP/1.1, which reflects header *list* order, not the HTTP/2 compression frame
order that fingerprint services inspect.

### 3. Manual TLS fingerprint (browserleaks)

To verify the low-level TLS/HTTP2 fingerprint (JA3/JA4/Akamai) matches a real
Chrome — header-order and TLS details that the whoami service does not show:

```bash
# Throwaway env; does NOT touch the project venv.
cd /tmp && UV_CACHE_DIR=/tmp/.uv-cache-impersonate-proxy UV_LINK_MODE=copy \
  uv run --no-project --with "curl_cffi==<VERSION>" python - <<'PY'
from curl_cffi import requests as cffi_requests
s = cffi_requests.Session(impersonate="chrome150")
r = s.get("https://tls.browserleaks.com/json")
import json
d = r.json()
for k in ["ja4", "ja4_o", "ja4_r", "ja4_ro", "akamai_text", "user_agent"]:
    print(k, "=", d.get(k))
PY
```

For the header-layer check via browserleaks, GET the same URL but assert the
reflected `user_agent` and that the UA build is not `.0.0.0`.

## After an upgrade, verify these specific regressions

When bumping `curl_cffi` (especially to a new major target like `chrome1xx`):

1. **Does the new target still ship the scrubbed UA?** Almost certainly yes —
   this is a curl-impersonate design choice, not a version bug. The override in
   `fingerprint.py` exists precisely for this. Extend `_FINGERPRINTS` with the
   new target and a real (non-scrubbed) build number.
2. **Does bare `chrome` now resolve to the new target?** `resolve_latest_browser_type("chrome")`
   returns the newest. If it moved (e.g. `chrome146` -> `chrome150`), update
   `_ALIASES` and `DEFAULT_MAJOR`/`DEFAULT_BUILD` so the default fingerprint
   stays in sync with the TLS signature.
3. **Is the base `Sec-CH-UA` triplet emitted by the new profile already
   aligned with the UA major?** When using the native newest target (e.g.
   `chrome150` on curl_cffi 0.16.1b1) the base triplet is already correct, so
   you do **not** need to override it — but the fingerprint module overrides it
   defensively anyway to prevent major-skew. Keep that behavior.
4. **Run all three verification steps above.** Step 1 catches header coherence;
   step 2 proves the full pipeline; step 3 confirms the TLS layer.
5. **Header order.** New chrome targets may set their own (possibly empty)
   `header_order` or change the header names curl_cffi emits. Ensure the
   `header_order` on the `BrowserFingerprint` matches the real target's order
   and that `test_http2_header_order_canonical` still passes. Remember the
   order is enforced via `extra_fp={"header_order": ...}`, which is HTTP/2-only.

## Current version facts (as of last verification)

- `curl_cffi` pinned at `>=0.16.1b1` (prerelease required — `chrome150` only
  exists there; `0.16.0` tops out at `chrome146` and raises `ImpersonateError`
  for `chrome150`).
- Bare `chrome` resolves to `chrome150`, default fingerprint = Chrome 150
  `150.0.6585.24`, Windows / x64 / bitness 64 / `10.0.0`.
- Header order fixed via `extra_fp={"header_order": ...}` on every
  `fingerprint_real` request; verified canonical on the wire via
  `tls.peet.ws/api/all`.
- Verified coherent through the proxy against `whoami...`,
  `tls.browserleaks.com/json`, and `tls.peet.ws/api/all`.
