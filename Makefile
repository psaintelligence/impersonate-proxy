# Makefile for impersonate-proxy
# Enforces isolated Python virtual environments using uv to prevent local .venv leakage.

.PHONY: help setup sync test test-verbose test-live test-extended benchmark lint format lint-fix typecheck build clean bump-patch bump-minor docs-sync docs-build docs-serve

.DEFAULT_GOAL := help

# UV execution prefix with environment isolation
UV := UV_PROJECT_ENVIRONMENT=$(HOME)/.local/venvs/impersonate-proxy UV_CACHE_DIR=/tmp/.uv-cache-impersonate-proxy UV_LINK_MODE=copy uv

# Show help menu of available commands
help:
	@echo "Available commands:"
	@echo "  make setup        - Create virtual environment and sync dependencies"
	@echo "  make sync         - Sync python dependencies (dev environment)"
	@echo "  make test          - Run offline unit and integration tests"
	@echo "  make test-verbose  - Run offline tests with verbose output"
	@echo "  make test-live     - Run basic live tests (hit real URLs)"
	@echo "  make test-extended - Run extended fingerprint/bot-detection live tests"
	@echo "  make benchmark     - Run concurrency performance benchmark"
	@echo "  make lint         - Run linting checks (ruff)"
	@echo "  make format       - Format code (ruff)"
	@echo "  make lint-fix     - Auto-fix linting and formatting issues"
	@echo "  make typecheck    - Run type checking (basedpyright)"
	@echo "  make build        - Build wheel and source distributions"
	@echo "  make bump-patch   - Bump the patch version number (e.g. 0.1.0 -> 0.1.1)"
	@echo "  make bump-minor   - Bump the minor version number (e.g. 0.1.0 -> 0.2.0)"
	@echo "  make clean        - Clean build and cache artifacts"
	@echo "  make docs-sync    - Sync documentation dependencies"
	@echo "  make docs-build   - Build documentation site"
	@echo "  make docs-serve   - Serve documentation locally"

# Create virtual environment and sync dependencies
setup:
	@echo "Initializing isolated virtual environment..."
	$(UV) venv --clear $(HOME)/.local/venvs/impersonate-proxy
	@echo "Syncing dependencies..."
	$(UV) sync --extra dev

# Sync Python dependencies
sync:
	$(UV) sync --extra dev

# Run tests
test:
	$(UV) run --extra dev pytest

# Run tests with verbose output
test-verbose:
	$(UV) run --extra dev pytest -v

# Run basic live tests (hit real URLs)
test-live:
	$(UV) run --extra dev pytest -m live -v

# Run extended fingerprint/bot-detection live tests
test-extended:
	$(UV) run --extra dev pytest -m live_extended -v

# Run concurrency performance benchmark
benchmark:
	$(UV) run python tests/benchmark.py

# Run linting checks
lint:
	$(UV) run --extra dev ruff check src tests

# Format code
format:
	$(UV) run --extra dev ruff format src tests

# Auto-fix linting and formatting issues
lint-fix:
	$(UV) run --extra dev ruff check --fix src tests
	$(UV) run --extra dev ruff format src tests

# Run type checking
typecheck:
	$(UV) run --extra dev basedpyright

# Build distribution packages
build:
	$(UV) build

# Clean build/test/cache artifacts
clean:
	rm -rf dist build *.egg-info src/*.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
	find . -type d -name .ruff_cache -exec rm -rf {} +

# Bump the patch version number (e.g. 0.1.0 -> 0.1.1)
bump-patch:
	@$(UV) run python -c 'import re; from pathlib import Path; p = Path("src/impersonate_proxy/__init__.py"); c = p.read_text(); m = re.search(r"^__version__\s*=\s*\"([^\"]+)\"", c, re.MULTILINE); v = m.group(1); parts = v.split("."); n = f"{parts[0]}.{parts[1]}.{int(parts[2])+1}"; p.write_text(re.sub(r"^__version__\s*=\s*\"[^\"]+\"", f"__version__ = \"{n}\"", c, flags=re.MULTILINE)); print(f"Bumped patch version: {v} -> {n}")'

# Bump the minor version number (e.g. 0.1.0 -> 0.2.0)
bump-minor:
	@$(UV) run python -c 'import re; from pathlib import Path; p = Path("src/impersonate_proxy/__init__.py"); c = p.read_text(); m = re.search(r"^__version__\s*=\s*\"([^\"]+)\"", c, re.MULTILINE); v = m.group(1); parts = v.split("."); n = f"{parts[0]}.{int(parts[1])+1}.0"; p.write_text(re.sub(r"^__version__\s*=\s*\"[^\"]+\"", f"__version__ = \"{n}\"", c, flags=re.MULTILINE)); print(f"Bumped minor version: {v} -> {n}")'

# UV configuration for documentation (isolated to prevent package dev conflict)
DOCS_UV = UV_PROJECT_ENVIRONMENT=$(HOME)/.local/venvs/impersonate-proxy-docs UV_CACHE_DIR=/tmp/.uv-cache-impersonate-proxy-docs UV_LINK_MODE=copy uv

# Sync documentation dependencies
docs-sync:
	cd docs && $(DOCS_UV) sync

# Build documentation site
docs-build:
	cd docs && $(DOCS_UV) run mkdocs build

# Serve documentation locally
docs-serve:
	cd docs && $(DOCS_UV) run mkdocs serve
