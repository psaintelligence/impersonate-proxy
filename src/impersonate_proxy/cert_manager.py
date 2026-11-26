"""Certificate Authority initialization and dynamic host SSLContext caching."""

import contextlib
import datetime
import ipaddress
import logging
import os
import ssl
import tempfile
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from impersonate_proxy.context import ProxyContext

logger: logging.Logger = logging.getLogger("impersonate-proxy")

# How long a losing concurrent initializer waits for the winner to publish
# its CA files before giving up (MITM then falls back to raw tunnels).
_CA_PUBLISH_TIMEOUT: float = 10.0
# Age after which a leftover .generate-claim file (e.g. from a SIGKILL crash)
# is considered stale and safe to reclaim.
_CA_CLAIM_STALE_SECONDS: float = 30.0
# Leaf certificates are valid for 30 days; refresh cached SSLContexts 1 day
# before expiry so long-running proxies never serve expired certs.
_LEAF_CERT_LIFETIME_DAYS: int = 30
_LEAF_CERT_CACHE_TTL: float = (_LEAF_CERT_LIFETIME_DAYS - 1) * 86400.0


def _load_ca_files(ctx: ProxyContext, key_path: str, cert_path: str) -> bool:
    """Load key+cert files into ctx; return False when they are absent or torn."""
    try:
        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)  # type: ignore
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
    except (OSError, ValueError):
        return False
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        logger.warning("CA key on disk is not an EC private key; regenerating")
        return False
    # A torn interleaved write from an older version can pair a key with a
    # foreign certificate; such a pair cannot sign consistent leaf certs.
    if cert.public_key() != key.public_key():
        logger.warning("CA key/cert pair mismatch on disk; regenerating")
        return False
    ctx.ca_key = key
    ctx.ca_cert = cert
    return True


def _publish_atomic(path: str, payload: bytes, mode: int) -> None:
    """Write payload to a temp file in the same directory, then os.replace it."""
    tmp_path = f"{path}.tmp.{os.getpid()}.{threading.get_ident()}"
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
        os.replace(tmp_path, path)
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


def init_ca(ctx: ProxyContext, ca_dir: str | None = None) -> None:
    """Load or generate self-signed CA files in ca_dir for MITM CONNECT handling.

    Concurrent first starts are safe: an exclusive ``.generate-claim`` file
    elects a single generator that publishes key and certificate via atomic
    ``os.replace``; losers wait for a consistent pair to appear and load it.
    """
    with ctx.host_cert_lock:
        ctx.host_cert_cache.clear()
    ctx.clear_session_pool()

    if ca_dir is None:
        ca_dir = (
            ctx.config.ca_dir
            or os.environ.get("IMPERSONATE_PROXY_CA_DIR")
            or os.path.expanduser("~/.config/impersonate-proxy")
        )
    ctx.config.ca_dir = ca_dir

    try:
        os.makedirs(ca_dir, exist_ok=True)

        key_path = os.path.join(ca_dir, "ca.key")
        cert_path = os.path.join(ca_dir, "ca.crt")
        claim_path = os.path.join(ca_dir, ".generate-claim")

        if os.path.exists(key_path) and os.path.exists(cert_path) and _load_ca_files(ctx, key_path, cert_path):
            logger.info(f"Loaded existing CA key and certificate from {ctx.show_identifying(ca_dir)}")
            return
        # Torn or mismatched pair on disk: fall through and regenerate.

        # Elect a single generator for this ca_dir, reclaiming a stale claim
        # left behind if a previous process crashed mid-generation.
        claim_fd: int | None = None
        for attempt in range(2):
            try:
                claim_fd = os.open(claim_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                break
            except FileExistsError:
                claim_fd = None
                if attempt == 0:
                    try:
                        age = time.time() - os.stat(claim_path).st_mtime
                    except OSError:
                        continue
                    if age > _CA_CLAIM_STALE_SECONDS:
                        logger.warning(
                            "Reclaiming stale CA generation claim in %s (age=%.1fs)",
                            ctx.show_identifying(ca_dir),
                            age,
                        )
                        with contextlib.suppress(OSError):
                            os.unlink(claim_path)
                        continue
                break

        if claim_fd is not None:
            try:
                _generate_and_publish_ca(ctx, key_path, cert_path)
            finally:
                os.close(claim_fd)
                with contextlib.suppress(OSError):
                    os.unlink(claim_path)
            logger.info(f"Generated and saved new CA key and certificate in {ctx.show_identifying(ca_dir)}")
            return

        # Losing initializer: wait for the winner to publish a consistent pair.
        deadline = time.monotonic() + _CA_PUBLISH_TIMEOUT
        while time.monotonic() < deadline:
            if _load_ca_files(ctx, key_path, cert_path):
                logger.info(f"Loaded CA generated by a concurrent start from {ctx.show_identifying(ca_dir)}")
                return
            time.sleep(0.05)
        logger.warning(
            f"Timed out waiting for concurrent CA generation in {ctx.show_identifying(ca_dir)} "
            "— CONNECT will fall back to raw tunnel"
        )

    except Exception as e:
        logger.warning(f"MITM CA init failed ({e}) — CONNECT will fall back to raw tunnel")


def _generate_and_publish_ca(ctx: ProxyContext, key_path: str, cert_path: str) -> None:
    """Generate a fresh CA pair and publish both files atomically."""
    ctx.ca_key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Impersonate Proxy CA"),
        ]
    )
    subject_key_id = x509.SubjectKeyIdentifier.from_public_key(ctx.ca_key.public_key())
    ctx.ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ctx.ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(subject_key_id, critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ctx.ca_key, hashes.SHA256())
    )

    key_bytes = ctx.ca_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_bytes = ctx.ca_cert.public_bytes(serialization.Encoding.PEM)

    _publish_atomic(key_path, key_bytes, 0o600)
    _publish_atomic(cert_path, cert_bytes, 0o644)


def get_cert_for_host(ctx: ProxyContext, hostname: str) -> ssl.SSLContext:
    """Get or create a cached SSL context for the given hostname (LRU with expiry)."""
    now = time.monotonic()
    with ctx.host_cert_lock:
        entry = ctx.host_cert_cache.get(hostname)
        if entry is not None:
            ssl_ctx, expires_at = entry
            if now < expires_at:
                ctx.host_cert_cache.move_to_end(hostname)
                logger.debug(f"SSLContext cache hit for: {ctx.show_identifying(hostname)}")
                return ssl_ctx
            del ctx.host_cert_cache[hostname]
            logger.debug(f"SSLContext cache entry expired for: {ctx.show_identifying(hostname)}")
        if ctx.leaf_key is None:
            ctx.leaf_key = ec.generate_private_key(ec.SECP256R1())
        key = ctx.leaf_key

    try:
        san = x509.IPAddress(ipaddress.ip_address(hostname))
    except ValueError:
        san = x509.DNSName(hostname)

    logger.debug(f"Generating dynamic host certificate for: {ctx.show_identifying(hostname)}")
    cn = hostname[:64] if len(hostname) > 64 else hostname
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ctx.ca_cert.subject)  # type: ignore
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=_LEAF_CERT_LIFETIME_DAYS))
        .add_extension(
            x509.SubjectAlternativeName([san]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ctx.ca_key.public_key()),  # type: ignore
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ctx.ca_key, hashes.SHA256())  # type: ignore
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # One combined PEM (cert + key) halves the temp-file roundtrip; stdlib
    # SSLContext has no in-memory cert loading, so one file is the minimum.
    pem_file = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            f.write(cert_pem + b"\n" + key_pem)
            pem_file = f.name
        ssl_ctx.load_cert_chain(pem_file)
    finally:
        if pem_file:
            with contextlib.suppress(OSError):
                os.unlink(pem_file)

    store_now = time.monotonic()
    with ctx.host_cert_lock:
        existing = ctx.host_cert_cache.get(hostname)
        if existing is not None and store_now < existing[1]:
            ctx.host_cert_cache.move_to_end(hostname)
            return existing[0]
        ctx.host_cert_cache[hostname] = (ssl_ctx, store_now + _LEAF_CERT_CACHE_TTL)
        ctx.host_cert_cache.move_to_end(hostname)
        while len(ctx.host_cert_cache) > ctx.host_cert_max:
            evicted, _ = ctx.host_cert_cache.popitem(last=False)
            logger.debug(f"Evicted host from certificate cache: {ctx.show_identifying(evicted)}")
    return ssl_ctx
