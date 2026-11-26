"""Thread-safe request statistics and the optional Prometheus metrics endpoint.

Counters are always active (negligible overhead); the metrics HTTP server is
only started when ``--stats-port`` is given.
"""

import logging
import threading
from collections import Counter
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from impersonate_proxy.context import ProxyContext

logger: logging.Logger = logging.getLogger("impersonate-proxy")

# Upper bounds (in seconds) for the upstream request duration histogram.
_DURATION_BUCKETS: tuple[float, ...] = (0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)


@dataclass(frozen=True)
class MetricsSnapshot:
    """A consistent copy of all stats counters plus gauges supplied at scrape time."""

    requests: dict[str, int]
    status_classes: dict[str, int]
    upstream_failures: int
    pool_high_water: int
    active_threads: int
    duration_buckets: tuple[tuple[float, int], ...]
    duration_count: int
    duration_sum: float
    cert_cache_size: int


class ProxyStats:
    """Thread-safe counters for proxied traffic, exposed via the optional stats endpoint."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests: Counter[str] = Counter()
        self._status_classes: Counter[str] = Counter()
        self._upstream_failures = 0
        self._sessions_leased = 0
        self._pool_high_water = 0
        self._active_threads = 0
        self._duration_buckets: list[int] = [0] * len(_DURATION_BUCKETS)
        self._duration_count = 0
        self._duration_sum = 0.0

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

    def record_thread_started(self) -> None:
        """Increment the currently active handler thread count."""
        with self._lock:
            self._active_threads += 1

    def record_thread_finished(self) -> None:
        """Decrement the currently active handler thread count."""
        with self._lock:
            self._active_threads = max(0, self._active_threads - 1)

    def record_request_duration(self, duration_seconds: float) -> None:
        """Observe one upstream request duration in seconds."""
        elapsed = max(0.0, duration_seconds)
        with self._lock:
            self._duration_count += 1
            self._duration_sum += elapsed
            for i, bound in enumerate(_DURATION_BUCKETS):
                if elapsed <= bound:
                    self._duration_buckets[i] += 1

    def snapshot(self, cert_cache_size: int) -> MetricsSnapshot:
        """Return a consistent copy of all counters plus the given gauge."""
        with self._lock:
            return MetricsSnapshot(
                requests=dict(self._requests),
                status_classes=dict(self._status_classes),
                upstream_failures=self._upstream_failures,
                pool_high_water=self._pool_high_water,
                active_threads=self._active_threads,
                duration_buckets=tuple(zip(_DURATION_BUCKETS, self._duration_buckets, strict=True)),
                duration_count=self._duration_count,
                duration_sum=self._duration_sum,
                cert_cache_size=cert_cache_size,
            )


def render_metrics(snapshot: MetricsSnapshot) -> str:
    """Render a stats snapshot in Prometheus text format."""
    lines = [
        "# HELP impersonate_proxy_requests_total Total client requests forwarded upstream by mode.",
        "# TYPE impersonate_proxy_requests_total counter",
    ]
    for mode in sorted(snapshot.requests):
        lines.append(f'impersonate_proxy_requests_total{{mode="{mode}"}} {snapshot.requests[mode]}')
    lines.extend(
        [
            "# HELP impersonate_proxy_upstream_failures_total Upstream requests that failed before producing a response.",
            "# TYPE impersonate_proxy_upstream_failures_total counter",
            f"impersonate_proxy_upstream_failures_total {snapshot.upstream_failures}",
            "# HELP impersonate_proxy_client_status_total Client-facing responses with status >= 400 by class (including early rejects and 502 upstream failures).",
            "# TYPE impersonate_proxy_client_status_total counter",
        ]
    )
    for status_class in sorted(snapshot.status_classes):
        lines.append(
            f'impersonate_proxy_client_status_total{{status_class="{status_class}"}} {snapshot.status_classes[status_class]}'
        )
    lines.extend(
        [
            "# HELP impersonate_proxy_session_pool_high_water Maximum concurrently leased curl_cffi sessions.",
            "# TYPE impersonate_proxy_session_pool_high_water gauge",
            f"impersonate_proxy_session_pool_high_water {snapshot.pool_high_water}",
            "# HELP impersonate_proxy_active_threads Number of handler threads currently serving client connections.",
            "# TYPE impersonate_proxy_active_threads gauge",
            f"impersonate_proxy_active_threads {snapshot.active_threads}",
            "# HELP impersonate_proxy_request_duration_seconds Upstream request handling duration in seconds.",
            "# TYPE impersonate_proxy_request_duration_seconds histogram",
        ]
    )
    for bound, count in snapshot.duration_buckets:
        lines.append(f'impersonate_proxy_request_duration_seconds_bucket{{le="{bound}"}} {count}')
    lines.extend(
        [
            f'impersonate_proxy_request_duration_seconds_bucket{{le="+Inf"}} {snapshot.duration_count}',
            f"impersonate_proxy_request_duration_seconds_sum {snapshot.duration_sum:.6f}",
            f"impersonate_proxy_request_duration_seconds_count {snapshot.duration_count}",
            "# HELP impersonate_proxy_cert_cache_size Number of host SSL contexts currently cached.",
            "# TYPE impersonate_proxy_cert_cache_size gauge",
            f"impersonate_proxy_cert_cache_size {snapshot.cert_cache_size}",
        ]
    )
    return "\n".join(lines) + "\n"


class _ThreadingMetricsServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


def start_stats_server(ctx: "ProxyContext", host: str, port: int) -> HTTPServer:
    """Start a tiny HTTP server exposing Prometheus metrics at /metrics."""
    logger.info(f"Stats endpoint serving Prometheus metrics on {host}:{port}/metrics")

    class MetricsHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
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
