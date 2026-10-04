"""Session pool management for upstream curl_cffi requests."""

import contextlib
import logging
import queue
import warnings
from typing import Any

from curl_cffi import requests as cffi_requests
from curl_cffi.utils import CurlCffiWarning

from impersonate_proxy.context import ProxyContext
from impersonate_proxy.fingerprint import fingerprint_for
from impersonate_proxy.header_filter import (
    cffi_defaults_headers,
    sanitize_headers,
    strip_leak_headers,
)

logger: logging.Logger = logging.getLogger("impersonate-proxy")

# Safe methods retried once on a fresh session after transport-level failures:
# no bytes reached the application layer, and repeated execution is harmless.
_RETRYABLE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})

# fingerprint-real deliberately overrides the HTTP/2 header order on top of an
# impersonation profile (extra_fp={"header_order": ...}), so curl_cffi's
# "Extra fingerprints were altered after impersonated version was set" notice
# is expected on every such request. curl_cffi ignores its own warnings at
# runtime (config_warnings(on=False) in its __init__); this filter keeps that
# suppression stable if that default ever changes or a -W override re-enables
# them. Under pytest the filter stack is reset, so pyproject.toml carries the
# equivalent filterwarnings entry. Registered once at import: filter state is
# process-global, and per-call catch_warnings() blocks are not thread-safe.
warnings.filterwarnings("ignore", category=CurlCffiWarning, message="Extra fingerprints were altered")


def get_session(ctx: ProxyContext) -> cffi_requests.Session[Any]:
    """Get a reused curl_cffi session from the pool or create a new one."""
    ctx.stats.record_session_leased()
    try:
        return ctx.session_pool.get_nowait()
    except queue.Empty:
        return cffi_requests.Session(impersonate=ctx.config.impersonate)


def release_session(ctx: ProxyContext, session: cffi_requests.Session[Any], *, healthy: bool = True) -> None:
    """Release a session back to the pool if healthy; otherwise close and discard."""
    ctx.stats.record_session_released()
    if healthy and not ctx.session_pool.full():
        ctx.session_pool.put_nowait(session)
    else:
        with contextlib.suppress(Exception):
            session.close()


def _issue_request(
    ctx: ProxyContext,
    session: cffi_requests.Session[Any],
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None,
    allow_redirects: bool,
) -> cffi_requests.Response:
    """Issue one request on the given session and wire its close() to the pool."""
    fp = fingerprint_for(ctx.config.impersonate) if ctx.config.fingerprint_real else None
    if ctx.config.header_mode == "passthrough":
        out_headers = dict(headers)
    else:
        out_headers = cffi_defaults_headers(headers)
        if fp is not None:
            out_headers.update(fp.to_headers())
    extra_fp = {"header_order": fp.header_order} if fp is not None and fp.header_order else None
    if ctx.config.strip_client_leak_headers:
        out_headers = strip_leak_headers(out_headers)
    logger.debug(
        f"Issuing request: {method} {ctx.show_identifying(url)} "
        f"(header_mode={ctx.config.header_mode}, strip_leak={ctx.config.strip_client_leak_headers}, "
        f"headers={sanitize_headers(out_headers)})"
    )
    proxies = (
        {"http": ctx.config.upstream_proxy, "https": ctx.config.upstream_proxy} if ctx.config.upstream_proxy else None
    )
    timeout = (ctx.config.connect_timeout, ctx.config.read_timeout)
    # curl_cffi's stubs leave Session.request's return type unannotated; pin it
    # so the rest of this module is fully typed.
    resp: cffi_requests.Response = session.request(  # pyright: ignore[reportUnknownMemberType]
        method=method,  # pyright: ignore[reportArgumentType]  # curl_cffi's HttpMethod literal is narrower than the HTTP method grammar it accepts at runtime
        url=url,
        headers=out_headers,
        data=body,
        timeout=timeout,
        proxies=proxies,  # pyright: ignore[reportArgumentType]  # curl_cffi's ProxySpec TypedDict stub rejects the runtime-accepted scheme-keyed dict
        allow_redirects=allow_redirects,
        stream=True,
        extra_fp=extra_fp,  # pyright: ignore[reportArgumentType]  # curl_cffi's ExtraFpDict stub keys are stricter than the documented runtime dict
    )
    orig_close = resp.close
    session_released = False

    def custom_close() -> None:
        nonlocal session_released
        orig_close()
        if not session_released:
            release_session(ctx, session)
            session_released = True

    resp.close = custom_close
    return resp


def do_request(
    ctx: ProxyContext,
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None,
    allow_redirects: bool = False,
) -> cffi_requests.Response | None:
    """Issue a request via curl_cffi with TLS impersonation using ProxyContext.

    Transport-level failures are retried once on a fresh session for safe
    methods (GET/HEAD/OPTIONS): a pooled session can be left unusable by a
    raced prior close inside curl_cffi (libcurl error 43 under concurrent
    load), and the failed attempt never produced a response.
    """
    attempts = 2 if method.upper() in _RETRYABLE_METHODS else 1
    for attempt in range(attempts):
        session = get_session(ctx)
        try:
            return _issue_request(ctx, session, method, url, headers, body, allow_redirects)
        except Exception as e:
            logger.error(f"Upstream request failed for {ctx.show_identifying(url)}: {e}")
            release_session(ctx, session, healthy=False)
            if attempt + 1 < attempts:
                logger.debug(f"Retrying {method} {ctx.show_identifying(url)} on a fresh session")
    return None
