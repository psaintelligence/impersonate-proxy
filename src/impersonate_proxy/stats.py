"""Thread-safe request statistics and the optional Prometheus metrics endpoint.

Counters are always active (negligible overhead); the metrics HTTP server is
only started when ``--stats-port`` is given.
"""

import logging
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from impersonate_proxy.context import ProxyContext

logger: logging.Logger = logging.getLogger("impersonate-proxy")


class ProxyStats:
    """Thread-safe counters for proxied traffic, exposed via the optional stats endpoint."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests: Counter[str] = Counter()
        self._status_classes: Counter[str] = Counter()
        self._upstream_failures = 0
        self._sessions_leased = 0
        self._pool_high_water = 0

    def record_request(self, mode: str) -> None:
        """Count one client request forwarded upstream for the given mode."""
        with self._lock:
            self._requests[mode] += 1

    def record_status(self, status_code: int) -> None:
        """Count one client-facing response with status >= 400 by class."""
        if status_code < 400:
            return
        status_class = "4xx" if status_code < 500 else "5xx"
        with self._lock:
            self._status_classes[status_class] += 1

    def record_upstream_failure(self) -> None:
        """Count one upstream request that failed before producing a response."""
        with self._lock:
            self._upstream_failures += 1

    def record_session_leased(self) -> None:
        """Count one session lease and track the pool high-water mark."""
        with self._lock:
            self._sessions_leased += 1
            self._pool_high_water = max(self._pool_high_water, self._sessions_leased)

    def record_session_released(self) -> None:
        """Count one session release back to the pool (or discard)."""
        with self._lock:
            self._sessions_leased = max(0, self._sessions_leased - 1)

    def snapshot(self, cert_cache_size: int) -> dict[str, object]:
        """Return a consistent copy of all counters plus the given gauge."""
        with self._lock:
            return {
                "requests": dict(self._requests),
                "status_classes": dict(self._status_classes),
                "upstream_failures": self._upstream_failures,
                "pool_high_water": self._pool_high_water,
                "cert_cache_size": cert_cache_size,
            }


def render_metrics(snapshot: dict[str, object]) -> str:
    """Render a stats snapshot in Prometheus text format."""
    requests: dict[str, int] = snapshot["requests"]  # type: ignore[assignment]
    status_classes: dict[str, int] = snapshot["status_classes"]  # type: ignore[assignment]
    lines = [
        "# HELP impersonate_proxy_requests_total Total client requests forwarded upstream by mode.",
        "# TYPE impersonate_proxy_requests_total counter",
    ]
    for mode in sorted(requests):
        lines.append(f'impersonate_proxy_requests_total{{mode="{mode}"}} {requests[mode]}')
    lines.extend(
        [
            "# HELP impersonate_proxy_upstream_failures_total Upstream requests that failed before producing a response.",
            "# TYPE impersonate_proxy_upstream_failures_total counter",
            f"impersonate_proxy_upstream_failures_total {snapshot['upstream_failures']}",
            "# HELP impersonate_proxy_client_status_total Client-facing responses with status >= 400 by class,",
            "# including early rejects (403/407/413) and 502 upstream failures.",
            "# TYPE impersonate_proxy_client_status_total counter",
        ]
    )
    for status_class in sorted(status_classes):
        lines.append(
            f'impersonate_proxy_client_status_total{{status_class="{status_class}"}} {status_classes[status_class]}'
        )
    lines.extend(
        [
            "# HELP impersonate_proxy_session_pool_high_water Maximum concurrently leased curl_cffi sessions.",
            "# TYPE impersonate_proxy_session_pool_high_water gauge",
            f"impersonate_proxy_session_pool_high_water {snapshot['pool_high_water']}",
            "# HELP impersonate_proxy_cert_cache_size Number of host SSL contexts currently cached.",
            "# TYPE impersonate_proxy_cert_cache_size gauge",
            f"impersonate_proxy_cert_cache_size {snapshot['cert_cache_size']}",
        ]
    )
    return "\n".join(lines) + "\n"


class _ThreadingMetricsServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def start_stats_server(ctx: "ProxyContext", host: str, port: int) -> HTTPServer:
    """Start a tiny HTTP server exposing Prometheus metrics at /metrics."""
    logger.info(f"Stats endpoint serving Prometheus metrics on {host}:{port}/metrics")

    class MetricsHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_GET(self) -> None:
            if self.path != "/metrics":
                self.send_error(404, "Not Found")
                return
            with ctx.host_cert_lock:
                cert_cache_size = len(ctx.host_cert_cache)
            body = render_metrics(ctx.stats.snapshot(cert_cache_size)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = _ThreadingMetricsServer((host, port), MetricsHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server
