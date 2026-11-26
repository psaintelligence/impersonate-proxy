"""Proxy request handler and multithreaded HTTP server."""

import base64
import contextlib
import hmac
import http.client
import ipaddress
import logging
import select
import socket
import threading
import urllib.parse
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import IO, TYPE_CHECKING, Any

from curl_cffi import CurlError

from impersonate_proxy.cert_manager import get_cert_for_host
from impersonate_proxy.context import ProxyContext
from impersonate_proxy.header_filter import sanitize_headers
from impersonate_proxy.session_pool import do_request

if TYPE_CHECKING:
    from curl_cffi import requests as cffi_requests

CHUNK_SIZE: int = 65536
# Safety cap on requests served per CONNECT tunnel (not a browser-relevant limit;
# browsers reuse tunnels for tens of requests at most).
MAX_TUNNEL_REQUESTS: int = 1000
# Hop-by-hop headers are consumed by the connection itself and must never be
# forwarded upstream (shared by the MITM and plain-HTTP paths).
_HOP_BY_HOP_HEADERS: frozenset[str] = frozenset(
    {
        "host",
        "proxy-connection",
        "connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "proxy-authorization",
        "proxy-authenticate",
    }
)
logger: logging.Logger = logging.getLogger("impersonate-proxy")


class _BodyTooLargeError(Exception):
    """Raised when a client request body exceeds ProxyConfig.max_body_size."""


def is_host_blocked(ctx: ProxyContext, host: str) -> bool:
    """Return True when host matches a ProxyConfig.block_hosts entry.

    Matching is case-insensitive and supports exact entries plus suffix
    matching: an entry ``example.com`` blocks both ``example.com`` and any
    ``*.example.com`` subdomain, but not ``notexample.com``.
    """
    host = host.lower().rstrip(".")
    for entry in ctx.config.block_hosts:
        entry = entry.lower().rstrip(".")
        if host == entry or host.endswith(f".{entry}"):
            return True
    return False


def is_client_allowed(ctx: ProxyContext, client_ip: str) -> bool:
    """Return True when client_ip passes ProxyConfig.allow_from (empty allows all).

    Entries may be a bare IP — matched via the same /24 (IPv4) or /64 (IPv6)
    auto-netblock used for logging — or an explicit CIDR netblock matched via
    :mod:`ipaddress`. An unverifiable client IP is denied while an allowlist is
    active.
    """
    allow_from = ctx.config.allow_from
    if not allow_from:
        return True
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    for entry in allow_from:
        entry = entry.strip()
        if not entry:
            continue
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            elif get_client_netblock(str(addr)) == get_client_netblock(entry):
                return True
        except ValueError:
            continue
    return False


def proxy_auth_ok(ctx: ProxyContext, auth_header: str | None) -> bool:
    """Return True when the client's Proxy-Authorization header is acceptable.

    ``ProxyConfig.proxy_auth`` holds ``user:password`` credentials; the expected
    ``Basic`` token is derived from it and compared in constant time. When no
    credentials are configured, every request passes.
    """
    credentials = ctx.config.proxy_auth
    if not credentials:
        return True
    scheme, _, token = (auth_header or "").partition(" ")
    if scheme.strip().lower() != "basic":
        return False
    expected = base64.b64encode(credentials.encode()).decode()
    return hmac.compare_digest(token.strip(), expected)


def _wants_keep_alive(headers: dict[str, str], version: str) -> bool:
    """Return whether the client expects the connection to persist after this request.

    HTTP/1.1 is persistent by default unless ``Connection: close`` is sent;
    HTTP/1.0 requires an explicit keep-alive token on ``Connection`` or
    ``Proxy-Connection``.
    """
    tokens: set[str] = set()
    for name in ("Connection", "Proxy-Connection"):
        tokens.update(t.strip().lower() for t in headers.get(name, "").split(",") if t.strip())
    if version.upper() >= "HTTP/1.1":
        return "close" not in tokens
    return "keep-alive" in tokens


def _iter_content_bytes(resp: "cffi_requests.Response") -> Iterator[bytes]:
    """Return an upstream response's body as an iterator of byte chunks.

    curl_cffi leaves ``iter_content``'s parameters and yielded type unannotated
    upstream, so the iterator must be pinned at this single boundary.
    """
    return resp.iter_content()  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]


def _iter_response_headers(resp: "cffi_requests.Response") -> list[tuple[str, str | None]]:
    """Return all upstream response headers, preserving repeated keys like Set-Cookie.

    ``curl_cffi``'s ``Headers.items()`` comma-joins repeated headers (which
    corrupts multiple ``Set-Cookie`` headers per RFC 6265), whereas
    ``multi_items()`` preserves every wire header individually. Falls back to
    ``items()`` for dict-backed test doubles.
    """
    headers = resp.headers
    if hasattr(headers, "multi_items"):
        return headers.multi_items()
    return list(headers.items())


def get_client_netblock(ip_str: str) -> str:
    """Return the /24 netblock for IPv4 or /64 netblock for IPv6."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.version == 4:
            return str(ipaddress.ip_network(f"{ip_str}/24", strict=False))
        else:
            return str(ipaddress.ip_network(f"{ip_str}/64", strict=False))
    except Exception:
        return ip_str


def raw_tunnel(ctx: ProxyContext, client_sock: socket.socket, host: str, port: int) -> None:
    """Relay bytes between client and upstream without inspection."""
    logger.info(f"Establishing raw tunnel to: {ctx.show_identifying(f'{host}:{port}')}")
    try:
        upstream = socket.create_connection((host, port), timeout=10)
    except Exception as e:
        logger.error(f"Raw tunnel connect failed for {ctx.show_identifying(f'{host}:{port}')}: {e}")
        return
    ctx.stats.record_request("raw_tunnel")
    try:
        while True:
            readable, _, _ = select.select([client_sock, upstream], [], [], ctx.config.tunnel_idle_timeout)
            if not readable:
                logger.debug("Raw tunnel idle timeout reached; closing tunnel")
                break
            for sock in readable:
                data = sock.recv(CHUNK_SIZE)
                if not data:
                    raise ConnectionError("closed")
                if sock is client_sock:
                    upstream.sendall(data)
                else:
                    client_sock.sendall(data)
    except Exception as e:
        logger.debug(f"Raw tunnel ended: {type(e).__name__}: {e}")
    finally:
        with contextlib.suppress(Exception):
            upstream.shutdown(socket.SHUT_RDWR)
        upstream.close()


class ProxyRequestHandler(BaseHTTPRequestHandler):
    """HTTP/HTTPS proxy request handler using a ProxyContext."""

    ctx: ProxyContext

    def log_message(self, format: str, *args: object) -> None:
        pass

    def _reject_client(self, code: int, reason: str) -> None:
        """Send an error response to the client, close the connection, and record it."""
        if code == 407:
            self.send_response(code, reason)
            self.send_header("Proxy-Authenticate", 'Basic realm="impersonate-proxy"')
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_error(code, reason)
        self.close_connection = True
        self.ctx.stats.record_status(code)

    def do_CONNECT(self) -> None:
        host, _, port_str = self.path.rpartition(":")
        host = host.strip("[]")
        try:
            port = int(port_str) if port_str else 443
        except ValueError:
            logger.warning(f"CONNECT bad host:port: {self.ctx.show_identifying(self.path[:120])}")
            self.send_error(400, "Bad host:port")
            return

        client_ip = self.client_address[0]

        if not is_client_allowed(self.ctx, client_ip):
            logger.warning(f"CONNECT from disallowed client: {get_client_netblock(client_ip)}")
            self._reject_client(403, "Forbidden client")
            return
        if not proxy_auth_ok(self.ctx, self.headers.get("Proxy-Authorization")):
            logger.warning(f"CONNECT with missing/invalid proxy auth from {get_client_netblock(client_ip)}")
            self._reject_client(407, "Proxy Authentication Required")
            return
        if is_host_blocked(self.ctx, host):
            logger.warning(f"CONNECT to blocked host: {self.ctx.show_identifying(host)}")
            self._reject_client(403, "Forbidden host")
            return

        netblock = get_client_netblock(client_ip)
        if not self.ctx.config.quiet:
            logger.info(f"CONNECT request from {netblock} to {host}")

        self.send_response(200, "Connection established")
        self.end_headers()

        if self.ctx.ca_key is None:
            if not self.ctx.config.quiet:
                logger.info(f"CONNECT {self.ctx.show_identifying(f'{host}:{port}')} (raw tunnel, no impersonation)")
            raw_tunnel(self.ctx, self.connection, host, port)
            self.close_connection = True
            return

        try:
            ssl_ctx = get_cert_for_host(self.ctx, host)
            client_tls = ssl_ctx.wrap_socket(self.connection, server_side=True)
        except Exception as e:
            logger.error(f"MITM TLS wrap error for {self.ctx.show_identifying(host)}: {e}")
            self.close_connection = True
            return

        rfile = wfile = None
        try:
            rfile = client_tls.makefile("rb")
            wfile = client_tls.makefile("wb")
            # Keep-alive idle cap: a persistent client may idle between requests;
            # drop the tunnel when the next request does not arrive in time.
            client_tls.settimeout(self.ctx.config.tunnel_idle_timeout)

            for requests_left in range(MAX_TUNNEL_REQUESTS, 0, -1):
                try:
                    parsed = self._parse_mitm_request(rfile)
                except _BodyTooLargeError:
                    logger.warning("CONNECT-MITM: request body exceeds max_body_size; sending 413")
                    self._write_mitm_error(wfile, 413, "Payload Too Large")
                    break
                except ValueError as e:
                    logger.warning(f"CONNECT-MITM: malformed request ({e}); sending 400")
                    self._write_mitm_error(wfile, 400, "Bad Request")
                    break
                if parsed is None:
                    break
                method, path, version, headers, body = parsed

                url = f"https://{host}{path}" if port == 443 else f"https://{host}:{port}{path}"
                fwd_headers = {k: v for k, v in headers.items() if k.lower() not in _HOP_BY_HOP_HEADERS}
                keep_alive = _wants_keep_alive(headers, version) and requests_left > 1

                status = self._forward_mitm_request(method, url, fwd_headers, body, wfile, keep_alive)
                if status is None or not keep_alive:
                    break

        except Exception as e:
            err_msg = str(e)
            # curl 56/18 mid-stream = the upstream reset or closed the transfer
            # after response headers were already forwarded; unreplayable here.
            # Log as a clear warning rather than a handler-crash error.
            if isinstance(e, CurlError) and e.code in (56, 18):
                logger.warning(f"MITM upstream reset mid-response: {e}")
            elif isinstance(e, (TimeoutError, BrokenPipeError, ConnectionResetError)) or "curl: (23)" in err_msg:
                logger.debug(f"MITM tunnel closed: {e}")
            else:
                logger.error(f"MITM handler error: {e}")
        finally:
            if rfile:
                with contextlib.suppress(Exception):
                    rfile.close()
            if wfile:
                with contextlib.suppress(Exception):
                    wfile.close()
            with contextlib.suppress(Exception):
                client_tls.shutdown(socket.SHUT_RDWR)
            client_tls.close()

        self.close_connection = True

    def _parse_mitm_request(self, rfile: IO[bytes]) -> tuple[str, str, str, dict[str, str], bytes | None] | None:
        """Read one request from the decrypted client stream.

        Returns ``(method, path, version, headers, body)`` or ``None`` when the
        client closed the connection or sent an empty line. Raises
        ``_BodyTooLargeError`` when the body exceeds ``max_body_size`` and
        ``ValueError`` for malformed framing (invalid/negative Content-Length,
        malformed chunked encoding); the caller must answer inside the tunnel
        before closing it.
        """
        req_line = rfile.readline(8193)
        if not req_line or req_line.strip() == b"":
            return None

        parts = req_line.decode("latin-1").strip().split(" ", 2)
        if len(parts) < 2:
            return None
        method = parts[0]
        path = parts[1]
        version = parts[2] if len(parts) > 2 else "HTTP/1.0"

        headers: dict[str, str] = {}
        while True:
            hline = rfile.readline(8193)
            if hline in (b"\r\n", b"\n", b""):
                break
            if b":" in hline:
                k, v = hline.decode("latin-1").split(":", 1)
                headers[k.strip()] = v.strip()

        body = self._read_mitm_body(rfile, headers)
        return method, path, version, headers, body

    def _read_mitm_body(self, rfile: IO[bytes], headers: dict[str, str]) -> bytes | None:
        """Read the request body, honoring ``max_body_size`` (Content-Length or chunked)."""
        max_size = self.ctx.config.max_body_size
        if "chunked" in headers.get("Transfer-Encoding", "").lower():
            chunks: list[bytes] = []
            total = 0
            while True:
                size_line = rfile.readline(8193)
                if not size_line:
                    raise ConnectionError("client closed during chunked body")
                try:
                    size = int(size_line.split(b";", 1)[0].strip() or b"", 16)
                except ValueError as e:
                    raise ValueError("malformed chunked body") from e
                if size == 0:
                    while True:  # consume optional trailers up to the blank line
                        trailer = rfile.readline(8193)
                        if trailer in (b"\r\n", b"\n", b""):
                            break
                    return b"".join(chunks)
                total += size
                if total > max_size:
                    raise _BodyTooLargeError
                data = rfile.read(size)
                if len(data) < size:
                    raise ConnectionError("client closed during chunked body")
                chunks.append(data)
                rfile.readline(8193)  # CRLF after each chunk's data

        cl = headers.get("Content-Length")
        if not cl:
            return None
        try:
            length = int(cl)
        except ValueError as e:
            raise ValueError(f"invalid Content-Length: {cl[:64]}") from e
        if length < 0:
            raise ValueError(f"negative Content-Length: {length}")
        if length > max_size:
            raise _BodyTooLargeError
        body = rfile.read(length)
        if len(body) < length:
            raise ConnectionError("client closed during body read")
        return body

    def _write_mitm_error(self, wfile: IO[bytes], code: int, reason: str) -> None:
        """Write a minimal error response inside the decrypted tunnel (closes the tunnel)."""
        wfile.write(f"HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode())
        wfile.flush()
        self.ctx.stats.record_status(code)

    def _write_chunked_response(self, wfile: IO[bytes], resp: "cffi_requests.Response", keep_alive: bool) -> None:
        """Stream an upstream response to the client as a chunked HTTP/1.1 message."""
        skip_resp = {"transfer-encoding", "content-encoding", "content-length", "connection", "keep-alive"}
        status_code = resp.status_code
        reason = http.client.responses.get(status_code, "Unknown")
        wfile.write(f"HTTP/1.1 {status_code} {reason}\r\n".encode())
        for k, v in _iter_response_headers(resp):
            if k.lower() in skip_resp:
                continue
            wfile.write(f"{k}: {v or ''}\r\n".encode())
        wfile.write(b"Transfer-Encoding: chunked\r\n")
        wfile.write(b"Connection: keep-alive\r\n" if keep_alive else b"Connection: close\r\n")
        wfile.write(b"\r\n")
        for chunk in _iter_content_bytes(resp):
            if chunk:
                wfile.write(f"{len(chunk):x}\r\n".encode())
                wfile.write(chunk)
                wfile.write(b"\r\n")
        wfile.write(b"0\r\n\r\n")
        wfile.flush()

    def _forward_mitm_request(
        self,
        method: str,
        url: str,
        fwd_headers: dict[str, str],
        body: bytes | None,
        wfile: IO[bytes],
        keep_alive: bool,
    ) -> int | None:
        """Forward one decrypted request upstream and stream the response back.

        Returns the upstream status code, or ``None`` when the upstream request
        failed (a 502 has already been written to the client).
        """
        logger.debug(
            f"CONNECT-MITM proxying request: {method} {self.ctx.show_identifying(url)} "
            f"(headers={sanitize_headers(fwd_headers)})"
        )
        self.ctx.stats.record_request("mitm")
        r = do_request(self.ctx, method, url, fwd_headers, body, allow_redirects=False)
        if r is None:
            self.ctx.stats.record_upstream_failure()
            self.ctx.stats.record_status(502)
            wfile.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            wfile.flush()
            return None
        try:
            self._write_chunked_response(wfile, r, keep_alive)
            self.ctx.stats.record_status(r.status_code)
            if (r.status_code >= 400 or self.ctx.config.debug) and not self.ctx.config.quiet:
                logger.info(f"CONNECT-MITM {method} {self.ctx.show_identifying(url)} -> {r.status_code}")
            return r.status_code
        finally:
            r.close()

    def _proxy(self) -> None:
        client_ip = self.client_address[0]
        netblock = get_client_netblock(client_ip)
        if not is_client_allowed(self.ctx, client_ip):
            logger.warning(f"HTTP Proxy request from disallowed client: {netblock}")
            self._reject_client(403, "Forbidden client")
            return

        url = self.path
        if not url.startswith("http"):
            logger.warning(f"HTTP Proxy bad request: {self.ctx.show_identifying(url)}")
            self._reject_client(400, "Absolute URL required")
            return

        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        if not proxy_auth_ok(self.ctx, self.headers.get("Proxy-Authorization")):
            logger.warning(f"HTTP Proxy request with missing/invalid proxy auth from {netblock}")
            self._reject_client(407, "Proxy Authentication Required")
            return
        if is_host_blocked(self.ctx, host):
            logger.warning(f"HTTP Proxy request to blocked host: {self.ctx.show_identifying(host)}")
            self._reject_client(403, "Forbidden host")
            return
        if not self.ctx.config.quiet:
            logger.info(f"{self.command} request from {netblock} to {host}")

        headers = {k: v for k, v in self.headers.items() if k.lower() not in _HOP_BY_HOP_HEADERS}

        body: bytes | None = None
        content_length = self.headers.get("Content-Length")
        if content_length:
            try:
                length = int(content_length)
            except ValueError:
                length = -1
            if length < 0:
                self._reject_client(400, "Invalid Content-Length")
                return
            if length > self.ctx.config.max_body_size:
                logger.warning(f"HTTP Proxy: request body of {length} bytes exceeds max_body_size; sending 413")
                self._reject_client(413, "Payload Too Large")
                return
            body = self.rfile.read(length)

        logger.debug(
            f"HTTP Proxy proxying request: {self.command} {self.ctx.show_identifying(url)} (headers={sanitize_headers(headers)})"
        )

        self.ctx.stats.record_request("plain_http")
        resp = do_request(self.ctx, self.command, url, headers, body)
        if resp is None:
            logger.error(f"HTTP Proxy upstream request failed for: {self.ctx.show_identifying(url)}")
            self.ctx.stats.record_upstream_failure()
            self.ctx.stats.record_status(502)
            self.send_error(502, "Upstream request failed")
            return
        self.ctx.stats.record_status(resp.status_code)

        try:
            is_head = self.command == "HEAD"
            skip_resp = {"transfer-encoding", "content-encoding", "content-length"}
            resp_headers = [(k, v or "") for k, v in _iter_response_headers(resp) if k.lower() not in skip_resp]
            if is_head:
                self.send_response(resp.status_code)
                for key, val in resp_headers:
                    self.send_header(key, val)
                cl = resp.headers.get("content-length")
                if cl:
                    self.send_header("Content-Length", cl)
                self.end_headers()
            else:
                self.send_response(resp.status_code)
                for key, val in resp_headers:
                    self.send_header(key, val)
                self.send_header("Transfer-Encoding", "chunked")
                self.send_header("Connection", "close")
                self.end_headers()
                for chunk in _iter_content_bytes(resp):
                    if chunk:
                        self.wfile.write(f"{len(chunk):x}\r\n".encode())
                        self.wfile.write(chunk)
                        self.wfile.write(b"\r\n")
                self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
            if not self.ctx.config.quiet:
                logger.info(f"HTTP Proxy {self.command} {self.ctx.show_identifying(url)} -> {resp.status_code}")
        except Exception as e:
            err_msg = str(e)
            if isinstance(e, (BrokenPipeError, ConnectionResetError)) or "curl: (23)" in err_msg:
                logger.debug(f"HTTP Proxy client disconnected mid-stream: {e}")
            else:
                logger.error(f"HTTP Proxy handler error for {self.ctx.show_identifying(url)}: {e}")
        finally:
            resp.close()

    do_GET = _proxy
    do_POST = _proxy
    do_PUT = _proxy
    do_HEAD = _proxy
    do_OPTIONS = _proxy


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Multithreaded HTTP server bound to a ProxyContext.

    Optionally caps concurrent handler threads with a bounded semaphore
    (``ProxyConfig.max_threads``); the accept loop blocks at the cap so excess
    connections wait in the TCP listen backlog.
    """

    daemon_threads = True

    def __init__(
        self, server_address: tuple[str, int], RequestHandlerClass: type[BaseHTTPRequestHandler], ctx: ProxyContext
    ):
        self.ctx = ctx
        self._thread_slots: threading.BoundedSemaphore | None = (
            threading.BoundedSemaphore(ctx.config.max_threads) if ctx.config.max_threads > 0 else None
        )
        super().__init__(server_address, RequestHandlerClass)

    def process_request(self, request: Any, client_address: Any) -> None:
        """Acquire a thread slot before spawning the handler thread."""
        if self._thread_slots is None:
            super().process_request(request, client_address)
            return
        self._thread_slots.acquire()
        try:
            super().process_request(request, client_address)
        except Exception:
            self._thread_slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        """Run the handler and release the thread slot afterwards."""
        try:
            super().process_request_thread(request, client_address)
        finally:
            if self._thread_slots is not None:
                self._thread_slots.release()


def create_handler_class(ctx: ProxyContext) -> type[ProxyRequestHandler]:
    """Return a ProxyRequestHandler subclass bound to the given ProxyContext."""

    class BoundProxyHandler(ProxyRequestHandler):
        pass

    BoundProxyHandler.ctx = ctx
    return BoundProxyHandler
