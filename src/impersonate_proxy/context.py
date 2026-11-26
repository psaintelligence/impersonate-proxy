"""Configuration dataclass and operational state container for impersonate-proxy."""

import contextlib
import logging
import queue
import ssl
import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from curl_cffi import CurlShare

from impersonate_proxy.stats import ProxyStats

if TYPE_CHECKING:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec
    from curl_cffi import requests as cffi_requests

logger: logging.Logger = logging.getLogger("impersonate-proxy")


@dataclass
class ProxyConfig:
    """Holds proxy configuration settings."""

    host: str = "127.0.0.1"
    port: int = 8899
    impersonate: str = "chrome"
    ca_dir: str | None = None
    header_mode: str = "cffi-defaults"
    strip_client_leak_headers: bool = False
    fingerprint_real: bool = True
    debug: bool = False
    quiet: bool = False
    upstream_proxy: str | None = None
    session_pool_max: int = 32
    connect_timeout: float = 10.0
    read_timeout: float = 300.0
    # Maximum client request body accepted per request (Content-Length or
    # de-chunked chunked body). Larger bodies are rejected with 413.
    max_body_size: int = 512 * 1024 * 1024
    # Idle seconds allowed on tunnel sockets before they are closed: both the
    # raw-tunnel select loop and the MITM keep-alive read loop between requests.
    tunnel_idle_timeout: float = 30.0
    # Target hostnames to refuse (exact or suffix match). Empty allows all.
    block_hosts: tuple[str, ...] = ()
    # Target hostnames to bypass MITM and relay via raw TCP tunnel (exact or suffix match).
    raw_tunnel_hosts: tuple[str, ...] = ()
    # Block egress to private/loopback/link-local/non-global IPs (SSRF protection).
    block_private_ips: bool = False
    # Custom upstream DNS server IP(s) (comma-separated) or DoH URL (https://...).
    dns: str | None = None
    # Log format: 'text' (default) or 'json'.
    log_format: str = "text"
    # user:password required in Proxy-Authorization: Basic (None disables auth).
    proxy_auth: str | None = None
    # Client allowlist entries: bare IP (auto /24|/64 netblock) or explicit CIDR.
    # Empty allows all clients.
    allow_from: tuple[str, ...] = ()
    # Maximum concurrent handler threads; 0 = unlimited (thread per connection).
    max_threads: int = 0

    def __post_init__(self) -> None:
        if self.header_mode not in ("passthrough", "cffi-defaults"):
            logger.warning(
                "Unknown header_mode=%r; falling back to 'cffi-defaults'.",
                self.header_mode,
            )
            self.header_mode = "cffi-defaults"
        if self.log_format not in ("text", "json"):
            logger.warning("Unknown log_format=%r; falling back to 'text'.", self.log_format)
            self.log_format = "text"


class ProxyContext:
    """Encapsulates runtime state and resources for a proxy server instance."""

    def __init__(
        self,
        config: ProxyConfig | None = None,
        host_cert_max: int = 256,
        session_pool_max: int | None = None,
    ) -> None:
        self.config: ProxyConfig = config or ProxyConfig()
        self.stats: ProxyStats = ProxyStats()
        self.ca_key: ec.EllipticCurvePrivateKey | None = None
        self.ca_cert: x509.Certificate | None = None
        self.leaf_key: ec.EllipticCurvePrivateKey | None = None

        self.host_cert_max: int = host_cert_max
        self.host_cert_cache: OrderedDict[str, tuple[ssl.SSLContext, float]] = OrderedDict()
        self.host_cert_lock: threading.Lock = threading.Lock()

        effective_pool_max = session_pool_max if session_pool_max is not None else self.config.session_pool_max
        self.session_pool_max: int = effective_pool_max
        self.session_pool: queue.Queue[cffi_requests.Session[Any]] = queue.Queue(maxsize=effective_pool_max)
        self._curl_share_lock: threading.Lock = threading.Lock()
        self._curl_share: CurlShare | None = None

    def get_curl_share(self) -> CurlShare:
        """Return the context's shared DNS + TLS-session CurlShare (never shares cookies)."""
        with self._curl_share_lock:
            if self._curl_share is None:
                self._curl_share = CurlShare(connect=False, dns=True, ssl_session=True)
            return self._curl_share

    def show_identifying(self, val: str) -> str:
        """Return val if debug mode is active, otherwise '[redacted]'."""
        return val if self.config.debug else "[redacted]"

    def clear_session_pool(self) -> None:
        """Close and clear all idle sessions in the pool, then release CurlShare if unused."""
        while not self.session_pool.empty():
            try:
                sess = self.session_pool.get_nowait()
                sess.close()
            except queue.Empty:
                break
        with self._curl_share_lock:
            if self._curl_share is not None:
                with contextlib.suppress(Exception):
                    self._curl_share.close()
                self._curl_share = None
