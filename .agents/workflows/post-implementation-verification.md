# Post-Implementation Verification Checklist

Before submitting any code changes, complete the following verification steps:

---

## 1. Code Formatting & Linting

Run `ruff` to ensure compliance with the repository's code style rules:

```bash
UV_PROJECT_ENVIRONMENT=${HOME}/.local/venvs/impersonate-proxy \
UV_CACHE_DIR=/tmp/.uv-cache-impersonate-proxy \
UV_LINK_MODE=copy \
uv run --extra dev ruff check .
```

To automatically fix auto-correctable issues, run:

```bash
UV_PROJECT_ENVIRONMENT=${HOME}/.local/venvs/impersonate-proxy \
UV_CACHE_DIR=/tmp/.uv-cache-impersonate-proxy \
UV_LINK_MODE=copy \
uv run --extra dev ruff check --fix .
```

---

## 2. Type Checking

Validate type hints and structures using `basedpyright`:

```bash
UV_PROJECT_ENVIRONMENT=${HOME}/.local/venvs/impersonate-proxy \
UV_CACHE_DIR=/tmp/.uv-cache-impersonate-proxy \
UV_LINK_MODE=copy \
uv run --extra dev basedpyright
```

---

## 3. Automated Testing

Execute the test suite to ensure all unit and integration tests are passing:

```bash
UV_PROJECT_ENVIRONMENT=${HOME}/.local/venvs/impersonate-proxy \
UV_CACHE_DIR=/tmp/.uv-cache-impersonate-proxy \
UV_LINK_MODE=copy \
uv run --extra dev pytest
```

---

## 4. Manual Verification

Test the proxy manually using `curl`:

1. Start the proxy in one terminal:
   ```bash
   UV_PROJECT_ENVIRONMENT=${HOME}/.local/venvs/impersonate-proxy \
   UV_CACHE_DIR=/tmp/.uv-cache-impersonate-proxy \
   UV_LINK_MODE=copy \
   uv run --extra dev impersonate-proxy --port 8899
   ```
2. In another terminal, make a request using the proxy:
   ```bash
   curl -x http://127.0.0.1:8899 https://httpbin.org/get
   ```
3. Confirm that the request succeeds and the response contains the expected information.
