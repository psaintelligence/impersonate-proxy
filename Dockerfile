# --- Stage 1: Build virtual environment ---
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS builder

WORKDIR /app

# Enable bytecode compilation
ENV UV_COMPILE_BYTECODE=1

# Copy files required to install dependencies
COPY pyproject.toml uv.lock README.md ./

# Copy source code
COPY src/ ./src

# Install dependencies and the project
RUN uv sync --no-dev --no-editable


# --- Stage 2: Final minimal runtime ---
FROM python:3.13-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="impersonate-proxy" \
      org.opencontainers.image.description="HTTP/HTTPS proxy that impersonates browser TLS fingerprints using curl_cffi" \
      org.opencontainers.image.source="https://github.com/psaintelligence/impersonate-proxy" \
      org.opencontainers.image.documentation="https://psaintelligence.github.io/impersonate-proxy/" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Copy the compiled virtual environment from the builder
COPY --from=builder /app/.venv /app/.venv

# Healthcheck script (local loopback /healthz probe, no external traffic)
COPY --chmod=0644 docker/healthcheck.py /app/healthcheck.py

# Add virtual environment bin directory to PATH
ENV PATH="/app/.venv/bin:${PATH}"

# Define default configuration environments
ENV IMPERSONATE_PROXY_HOST="0.0.0.0"
ENV IMPERSONATE_PROXY_PORT="8899"
ENV IMPERSONATE_PROXY_CA_DIR="/home/impersonate/.config/impersonate-proxy"
ENV IMPERSONATE_PROXY_IMPERSONATE="chrome"
ENV IMPERSONATE_PROXY_DEBUG="false"

# Run as a dedicated non-root user; pre-create the CA dirs the image and
# docker-compose.yml may mount volumes on so they stay writable.
RUN useradd --create-home --shell /usr/sbin/nologin impersonate \
    && mkdir -p /home/impersonate/.config/impersonate-proxy /certs \
    && chown -R impersonate:impersonate /home/impersonate /certs

# Expose proxy port
EXPOSE 8899

# Persistent volume for CA files
VOLUME ["/home/impersonate/.config/impersonate-proxy"]

# Verify the proxy listener and handler threads are serving local /healthz probes
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD ["python", "/app/healthcheck.py"]

USER impersonate

# Run the proxy CLI
ENTRYPOINT ["impersonate-proxy"]
