#!/usr/bin/env python3
"""HTTP/HTTPS proxy that impersonates browser TLS fingerprints.

Uses curl_cffi to re-issue every request with a browser TLS fingerprint
(JA3/JA4), defeating CDN fingerprint-based blocking of non-browser clients.

Supports both plain HTTP proxy requests and HTTPS CONNECT tunnels via
MITM with an auto-generated CA certificate stored in --ca-dir
(default: ~/.config/impersonate-proxy).

Usage:
    impersonate-proxy [--port PORT] [--host HOST] [--impersonate BROWSER]

    # As an HTTP proxy for curl:
    curl -x http://127.0.0.1:8899 https://example.com

    # As an HTTP proxy for ffmpeg:
    ffmpeg -http_proxy http://127.0.0.1:8899 -i https://stream.example.com/live.m3u8 output.mp4

Environment variables:
    IMPERSONATE_PROXY_PORT          Port to listen on (default: 8899)
    IMPERSONATE_PROXY_HOST          Host to bind to (default: 127.0.0.1)
    IMPERSONATE_PROXY_IMPERSONATE   Browser to impersonate (default: chrome)
"""

import argparse
import importlib.metadata
import logging
import os
import signal
import sys

from impersonate_proxy import cert_manager
from impersonate_proxy.context import ProxyConfig, ProxyContext
from impersonate_proxy.server import ThreadingHTTPServer, create_handler_class

logger: logging.Logger = logging.getLogger("impersonate-proxy")


def _sigterm_handler(signum: int, frame: object) -> None:
    del signum, frame
    sys.exit(0)


def _impersonate_error_message(target: str) -> str | None:
    """Return an actionable error message when target is not a valid curl_cffi target, else None.

    curl_cffi only raises ImpersonateError lazily on the first request, so an
    invalid target would otherwise turn every request into a 502 with no hint
    about the cause.
    """
    from typing import get_args

    from curl_cffi.requests.impersonate import BrowserTypeLiteral

    targets: tuple[str, ...] = get_args(BrowserTypeLiteral)
    if target in targets:
        return None
    by_family: dict[str, list[str]] = {}
    for t in targets:
        by_family.setdefault(t.rstrip("0123456789"), []).append(t)
    listing = "\n".join(f"  {family}: {', '.join(sorted(names))}" for family, names in sorted(by_family.items()))
    return f"--impersonate {target!r} is not a valid curl_cffi target. Valid targets:\n{listing}"


def run(
    host: str = "127.0.0.1",
    port: int = 8899,
    impersonate: str = "chrome",
    ca_dir: str | None = None,
    header_mode: str = "cffi-defaults",
    strip_client_leak_headers: bool = False,
    debug: bool = False,
    quiet: bool = False,
    upstream_proxy: str | None = None,
    session_pool_max: int = 32,
    connect_timeout: float = 10.0,
    read_timeout: float = 300.0,
    fingerprint_real: bool = True,
    max_body_size: int = 512 * 1024 * 1024,
    tunnel_idle_timeout: float = 30.0,
    block_hosts: tuple[str, ...] = (),
    proxy_auth: str | None = None,
    allow_from: tuple[str, ...] = (),
    stats_port: int | None = None,
    max_threads: int = 0,
    ctx: ProxyContext | None = None,
) -> None:
    """Run the proxy server with the given configuration until interrupted."""
    target_ctx = ctx or ProxyContext()
    target_ctx.config = ProxyConfig(
        host=host,
        port=port,
        impersonate=impersonate,
        ca_dir=ca_dir,
        header_mode=header_mode,
        strip_client_leak_headers=strip_client_leak_headers,
        debug=debug,
        quiet=quiet,
        upstream_proxy=upstream_proxy,
        session_pool_max=session_pool_max,
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
        fingerprint_real=fingerprint_real,
        max_body_size=max_body_size,
        tunnel_idle_timeout=tunnel_idle_timeout,
        block_hosts=block_hosts,
        proxy_auth=proxy_auth,
        allow_from=allow_from,
        max_threads=max_threads,
    )
    target_ctx.session_pool_max = session_pool_max

    cert_manager.init_ca(target_ctx, ca_dir)

    handler_cls = create_handler_class(target_ctx)
    server = ThreadingHTTPServer((host, port), handler_cls, target_ctx)
    stats_server = None
    if stats_port:
        from impersonate_proxy.stats import start_stats_server

        stats_server = start_stats_server(target_ctx, host, stats_port)
    try:
        curl_cffi_version = importlib.metadata.version("curl_cffi")
    except importlib.metadata.PackageNotFoundError:
        curl_cffi_version = "unknown"

    logger.info(
        f"impersonate-proxy listening on {host}:{port} "
        f"(impersonating {impersonate}, header_mode={header_mode}, "
        f"strip_client_leak_headers={strip_client_leak_headers}, debug={debug}, "
        f"curl_cffi={curl_cffi_version})"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received, shutting down...")
    finally:
        logger.info("Shutting down proxy server and clearing session pool...")
        server.server_close()
        if stats_server is not None:
            stats_server.server_close()
            stats_server.shutdown()
        target_ctx.clear_session_pool()


def main() -> None:
    signal.signal(signal.SIGTERM, _sigterm_handler)
    parser = argparse.ArgumentParser(description="HTTP/HTTPS proxy that impersonates browser TLS fingerprints")
    parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=int(os.environ.get("IMPERSONATE_PROXY_PORT", "8899")),
        help="Port to listen on (default: 8899 or IMPERSONATE_PROXY_PORT)",
    )
    parser.add_argument(
        "--host",
        "-H",
        default=os.environ.get("IMPERSONATE_PROXY_HOST", "127.0.0.1"),
        help="Host to bind to (default: 127.0.0.1 or IMPERSONATE_PROXY_HOST)",
    )
    parser.add_argument(
        "--impersonate",
        "-i",
        default=os.environ.get("IMPERSONATE_PROXY_IMPERSONATE", "chrome"),
        help="Browser to impersonate (chrome, firefox, etc. Default: chrome or IMPERSONATE_PROXY_IMPERSONATE)",
    )
    header_mode_group = parser.add_mutually_exclusive_group()
    header_mode_group.add_argument(
        "--cffi-defaults",
        action="store_const",
        dest="header_mode",
        const="cffi-defaults",
        default=os.environ.get("IMPERSONATE_PROXY_HEADER_MODE", "cffi-defaults").lower(),
        help="Strip browser-shape headers (User-Agent, Sec-Ch-Ua-*, Accept-Encoding, "
        "Priority, TE, Upgrade-Insecure-Requests, Sec-Fetch-User) from the client and "
        "drop bot-tell headers (Cache-Control, DNT, Connection) so curl_cffi injects "
        "the correct current browser values from its impersonation profile. [DEFAULT]",
    )
    header_mode_group.add_argument(
        "--passthrough-headers",
        action="store_const",
        dest="header_mode",
        const="passthrough",
        help="Forward client headers untouched; curl_cffi only sets TLS-impersonation headers. For advanced users.",
    )
    parser.add_argument(
        "--strip-client-leak-headers",
        action="store_true",
        default=os.environ.get("IMPERSONATE_PROXY_STRIP_CLIENT_LEAK_HEADERS", "false").lower() in ("true", "1", "yes"),
        help="Drop middlebox-chain / tracing leak headers (X-Forwarded-*, "
        "Forwarded, Via, X-Request-ID, X-Correlation-ID). CDN-ingress headers "
        "(X-Real-IP, True-Client-IP, etc.) are forwarded with a warning when "
        "present. Combinable with any header mode. Or "
        "IMPERSONATE_PROXY_STRIP_CLIENT_LEAK_HEADERS=true",
    )
    parser.add_argument(
        "--upstream-proxy",
        default=os.environ.get("IMPERSONATE_PROXY_UPSTREAM_PROXY"),
        help="Upstream egress proxy URL (e.g. http://127.0.0.1:8080 or IMPERSONATE_PROXY_UPSTREAM_PROXY)",
    )
    parser.add_argument(
        "--no-fingerprint-real",
        action="store_false",
        dest="fingerprint_real",
        default=os.environ.get("IMPERSONATE_PROXY_FINGERPRINT_REAL", "true").lower() in ("true", "1", "yes"),
        help="Disable injection of platform-coherent full-build UA + complete Sec-CH-UA "
        "family on top of curl_cffi's TLS impersonation. On by default in cffi-defaults "
        "mode. Or IMPERSONATE_PROXY_FINGERPRINT_REAL=false",
    )
    parser.add_argument(
        "--session-pool-max",
        type=int,
        default=int(os.environ.get("IMPERSONATE_PROXY_SESSION_POOL_MAX", "32")),
        help="Maximum reusable curl_cffi sessions in pool (default: 32 or IMPERSONATE_PROXY_SESSION_POOL_MAX)",
    )
    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=float(os.environ.get("IMPERSONATE_PROXY_CONNECT_TIMEOUT", "10.0")),
        help="Upstream TCP/TLS connect timeout in seconds (default: 10.0 or IMPERSONATE_PROXY_CONNECT_TIMEOUT)",
    )
    parser.add_argument(
        "--read-timeout",
        type=float,
        default=float(os.environ.get("IMPERSONATE_PROXY_READ_TIMEOUT", "300.0")),
        help="Upstream HTTP read timeout in seconds (default: 300.0 or IMPERSONATE_PROXY_READ_TIMEOUT)",
    )
    parser.add_argument(
        "--max-body-size",
        type=int,
        default=int(os.environ.get("IMPERSONATE_PROXY_MAX_BODY_SIZE", str(512 * 1024 * 1024))),
        help="Maximum client request body accepted per request, in bytes "
        "(default: 536870912 = 512 MiB or IMPERSONATE_PROXY_MAX_BODY_SIZE). "
        "Larger bodies are rejected with 413",
    )
    parser.add_argument(
        "--tunnel-idle-timeout",
        type=float,
        default=float(os.environ.get("IMPERSONATE_PROXY_TUNNEL_IDLE_TIMEOUT", "30.0")),
        help="Idle seconds allowed on tunnel sockets before closing: the raw-tunnel "
        "select loop and the MITM keep-alive loop between requests "
        "(default: 30.0 or IMPERSONATE_PROXY_TUNNEL_IDLE_TIMEOUT)",
    )
    parser.add_argument(
        "--block-host",
        default=os.environ.get("IMPERSONATE_PROXY_BLOCK_HOST", ""),
        help="Comma-separated target hostnames to refuse with 403 (exact or suffix "
        "match: example.com also blocks *.example.com). Or IMPERSONATE_PROXY_BLOCK_HOST",
    )
    parser.add_argument(
        "--proxy-auth",
        default=os.environ.get("IMPERSONATE_PROXY_PROXY_AUTH"),
        help="Require Proxy-Authorization: Basic auth with these user:password "
        "credentials on every request; reply 407 otherwise "
        "(e.g. --proxy-auth alice:s3cret or IMPERSONATE_PROXY_PROXY_AUTH)",
    )
    parser.add_argument(
        "--allow-from",
        default=os.environ.get("IMPERSONATE_PROXY_ALLOW_FROM", ""),
        help="Comma-separated client allowlist: bare IPs (matched via the /24 or /64 "
        "auto-netblock, e.g. 192.168.1.7) or explicit CIDRs (e.g. 10.0.0.0/8); "
        "other clients are refused with 403. Or IMPERSONATE_PROXY_ALLOW_FROM",
    )
    parser.add_argument(
        "--stats-port",
        type=int,
        default=os.environ.get("IMPERSONATE_PROXY_STATS_PORT"),
        help="Serve Prometheus metrics at /metrics on this port (off by default, or IMPERSONATE_PROXY_STATS_PORT)",
    )
    parser.add_argument(
        "--max-threads",
        type=int,
        default=int(os.environ.get("IMPERSONATE_PROXY_MAX_THREADS", "0")),
        help="Maximum concurrent handler threads; excess connections wait in the "
        "listen backlog (default: 0 = unlimited, or IMPERSONATE_PROXY_MAX_THREADS)",
    )
    parser.add_argument(
        "--ca-dir",
        "-c",
        default=os.environ.get("IMPERSONATE_PROXY_CA_DIR"),
        help="Directory to store/load CA certificate and key (default: ~/.config/impersonate-proxy or IMPERSONATE_PROXY_CA_DIR)",
    )
    parser.add_argument(
        "--debug",
        "-d",
        action="store_true",
        default=os.environ.get("IMPERSONATE_PROXY_DEBUG", "").lower() in ("true", "1", "yes"),
        help="Enable verbose debug logging (unredacts URLs/hosts in logs) or IMPERSONATE_PROXY_DEBUG=true",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        default=os.environ.get("IMPERSONATE_PROXY_QUIET", "false").lower() in ("true", "1", "yes"),
        help="Disable logging of request traffic or IMPERSONATE_PROXY_QUIET=true",
    )
    args = parser.parse_args()
    header_mode = args.header_mode if args.header_mode in ("passthrough", "cffi-defaults") else "cffi-defaults"
    error_message = _impersonate_error_message(args.impersonate)
    if error_message:
        parser.error(error_message)
    block_hosts = tuple(h.strip().lower() for h in args.block_host.split(",") if h.strip())
    allow_from = tuple(e.strip() for e in args.allow_from.split(",") if e.strip())
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,
    )
    run(
        host=args.host,
        port=args.port,
        impersonate=args.impersonate,
        ca_dir=args.ca_dir,
        header_mode=header_mode,
        strip_client_leak_headers=args.strip_client_leak_headers,
        debug=args.debug,
        quiet=args.quiet,
        upstream_proxy=args.upstream_proxy,
        session_pool_max=args.session_pool_max,
        connect_timeout=args.connect_timeout,
        read_timeout=args.read_timeout,
        fingerprint_real=args.fingerprint_real,
        max_body_size=args.max_body_size,
        tunnel_idle_timeout=args.tunnel_idle_timeout,
        block_hosts=block_hosts,
        proxy_auth=args.proxy_auth,
        allow_from=allow_from,
        stats_port=args.stats_port,
        max_threads=args.max_threads,
    )


if __name__ == "__main__":
    main()
