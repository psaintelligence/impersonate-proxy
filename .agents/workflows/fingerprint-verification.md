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

1. **Scrubbed UA build** — e.g. `Chrome/152.0.0.0`. Real browsers send a full
   build like `Chrome/152.0.7977.83`. The `.0.0.0` suffix is the classic
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

- `User-Agent` build (e.g. `152.0.7977.83`) must match the version in
  `Sec-CH-UA-Full-Version-List` ("Chromium" and "Google Chrome" entries).
- `User-Agent` major (e.g. `152`) must match the major in base `Sec-CH-UA`
  (the src-ch-ua triplet). A mismatch here (150-vs-152) is an instant tell.
- `User-Agent` platform token (e.g. `Windows NT 10.0; Win64; x64`) must match
  `Sec-CH-UA-Platform` (`"Windows"`) and `Sec-CH-UA-Platform-Version`
  (`"10.0.0"`). A Windows UA with `Sec-CH-UA-Platform: "macOS"` is a bot tell.
- No brand-list skew: the GREASE brand string, brand ordering, and GREASE
  version (always one of Chrome's authentic `8`/`24`/`99`) must match between
  `Sec-CH-UA` and `Sec-CH-UA-Full-Version-List` (`<ver>.0.0.0`), mirroring
  `curl_cffi`'s captured signature for that major.

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

The extended live suite (`pytest -m live_extended`) now automates the
TLS-layer checks against two independent observers, so the manual snippet
below is only needed for ad-hoc inspection during an upgrade:

- `tests/.../test_tls_api_ja3_check` — tls.peet.ws: JA3 not in the known-bot
  set, JA4 format `t13d<4 digits>h2_<hash>_<hash>`, non-empty HTTP/2 Akamai
  fingerprint hash.
- `tests/.../test_tls_browserleaks_fingerprint` — tls.browserleaks.com/json:
  same JA4 format, non-empty `ja3n_hash`/`akamai_hash`, Akamai settings text
  shaped `1:65536;...|<fp>|0|m,a,s,p`, and the reflected UA is the curated
  profile UA (`_assert_profile_user_agent`).
- `tests/.../test_cloudflare_trace_coherence` — cloudflare.com/cdn-cgi/trace:
  reflected UA matches the curated profile UA, `http=http/2` (end-to-end
  HTTP/2), `tls=TLSv1.3`.

For ad-hoc manual inspection of the low-level TLS/HTTP2 fingerprint (JA3/JA4/Akamai):

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

### Known live-endpoint instability

`tls.peet.ws` intermittently resets the connection **mid-response** (after the
response headers have been forwarded; observed as curl 56 on the proxy and
`ChunkedEncodingError: Response ended prematurely` on the client). This is
endpoint-side — verified NOT rate-based (fails at 2s spacing), not
profile-specific across chrome/firefox, and never reproduced against
`tls.browserleaks.com` with the identical proxied profile. Consequences:

- Live tests route peet.ws requests through `_get_with_retry` (2 retries,
  1s backoff) — keep that wrapper on any new peet.ws-based test.
- The proxy logs these as `WARNING: MITM upstream reset mid-response`
  (curl 56/18), not handler errors; they are unreplayable at the proxy layer.
- Prefer `tls.browserleaks.com/json` as the stable fallback for TLS-layer
  verification when peet.ws is flapping.

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
   `chrome150` on curl_cffi 0.16.4b1) the base triplet is already correct, so
   you do **not** need to override it — but the fingerprint module overrides it
   defensively anyway to prevent major-skew. Keep that behavior.
4. **Run all three verification steps above.** Step 1 catches header coherence;
   step 2 proves the full pipeline; step 3 confirms the TLS layer.
5. **Header order.** New chrome targets may set their own (possibly empty)
   `header_order` or change the header names curl_cffi emits. Ensure the
   `header_order` on the `BrowserFingerprint` matches the real target's order
   and that `test_http2_header_order_canonical` still passes. Remember the
   order is enforced via `extra_fp={"header_order": ...}`, which is HTTP/2-only.

## Firefox curation rules (non-negotiable)

Firefox targets (`firefox155`, `firefox154`, `firefox153`, `firefox147`, alias `firefox` -> `firefox155`) are curated **UA-only**:

- Firefox sends **no** client hints — `to_headers()` must emit **only**
  `User-Agent` (checked by `test_headers_are_ua_only`). Never add
  `Sec-CH-UA-*` to a Firefox fingerprint.
- Firefox UAs carry no scrubbed-build tell (`rv:` always equals the
  `Firefox/` version), so the curation pins a full platform-coherent UA:
  `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:<major>.0) Gecko/20100101
  Firefox/<major>.0` — Windows/Win64/x64, consistent with the Chrome family
  default platform.
- `header_order` must stay **empty** for Firefox: curl_cffi's firefox
  profiles already ship the authentic captured HTTP/2 order (verified on the
  wire via tls.peet.ws). `session_pool` skips
  `extra_fp={"header_order": ...}` when the order is empty — never "fix" this
  by inventing a Firefox order.
- Extending to a newer Firefox target: add a `_firefox(<major>, ...)` entry to
  `_FINGERPRINTS`, move `_ALIASES["firefox"]` to the new target (mirror
  curl_cffi's `DEFAULT_FIREFOX`), and keep `rv`/`Firefox/` coherence in
  `test_ua_coherent`.

## Current version facts (as of last verification)

- `curl_cffi` pinned at `>=0.17.0` (ships `chrome151`/`chrome152` + `_macos`
  variants and `firefox153`/`firefox154`/`firefox155`).
- Bare `chrome` resolves to `chrome152`, default fingerprint = Chrome 152
  `152.0.7977.83`, Windows / x64 / bitness 64 / `10.0.0`, with authentic
  Chromium GREASE brand list (`"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"`).
- `chrome152` in `curl_cffi 0.17.0` ships a reload capture artifact
  (`cache-control: max-age=0` at the end of its default header list);
  `session_pool._issue_request` passes `"Cache-Control": None` in
  `cffi-defaults` mode to suppress profile-default `Cache-Control`.
- Header order fixed via `extra_fp={"header_order": ...}` on every
  `fingerprint_real` request for Chrome; verified canonical on the wire via
  `tls.peet.ws/api/all`. Firefox targets send no `header_order` override
  (curl_cffi's captured order is already authentic).
- Firefox curation: `fingerprint_for("firefox155")` / alias `firefox` →
  UA-only fingerprint (`rv:155.0` == `Firefox/155.0`, Windows/Win64/x64);
  verified through the proxy on `tls.peet.ws/api/all` (UA reflects the pinned
  Windows Firefox UA, no `sec-ch-ua` family present). Note that `firefox155`
  in `curl_cffi 0.17.0` was captured from a fetch request (`priority: u=4`,
  no `upgrade-insecure-requests`).
- Verified coherent through the proxy against `whoami...`,
  `tls.browserleaks.com/json`, `tls.peet.ws/api/all`, and
  `cloudflare.com/cdn-cgi/trace` — the latter three automated in the
  `live_extended` suite (JA4 format, Akamai HTTP/2 fingerprint, h2/TLS1.3
  protocol coherence, curated-UA reflection).
