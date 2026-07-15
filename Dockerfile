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

WORKDIR /app

# Copy the compiled virtual environment from the builder
COPY --from=builder /app/.venv /app/.venv

# Add virtual environment bin directory to PATH
ENV PATH="/app/.venv/bin:${PATH}"

# Define default configuration environments
ENV TLS_PROXY_HOST="0.0.0.0"
ENV TLS_PROXY_PORT="8899"
ENV TLS_PROXY_CA_DIR="/root/.config/tls-impersonate-proxy"
ENV TLS_PROXY_IMPERSONATE="chrome"
ENV TLS_PROXY_DEBUG="false"

# Expose proxy port
EXPOSE 8899

# Persistent volume for CA files
VOLUME ["/root/.config/tls-impersonate-proxy"]

# Run the proxy CLI
ENTRYPOINT ["tls-impersonate-proxy"]
