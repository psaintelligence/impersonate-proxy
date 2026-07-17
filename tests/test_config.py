"""Unit tests for command line arguments and environment variables configuration parsing."""

import os
from unittest.mock import patch

import pytest

from impersonate_proxy import main as impersonate_proxy


def test_config_defaults():
    """Test defaults when no CLI args or env vars are set."""
    with (
        patch("sys.argv", ["impersonate-proxy"]),
        patch.dict(os.environ, {}, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        mock_run.assert_called_once_with(
            host="127.0.0.1",
            port=8899,
            impersonate="chrome",
            ca_dir=None,
            enrich_headers=True,
            debug=False,
            quiet=False,
        )


def test_config_env_vars():
    """Test that environment variables are correctly parsed when no CLI args are present."""
    env = {
        "IMPERSONATE_PROXY_PORT": "9999",
        "IMPERSONATE_PROXY_HOST": "10.0.0.2",
        "IMPERSONATE_PROXY_IMPERSONATE": "firefox",
        "IMPERSONATE_PROXY_CA_DIR": "/env/ca",
        "IMPERSONATE_PROXY_ENRICH_HEADERS": "false",
        "IMPERSONATE_PROXY_DEBUG": "true",
    }
    with (
        patch("sys.argv", ["impersonate-proxy"]),
        patch.dict(os.environ, env, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        mock_run.assert_called_once_with(
            host="10.0.0.2",
            port=9999,
            impersonate="firefox",
            ca_dir="/env/ca",
            enrich_headers=False,
            debug=True,
            quiet=False,
        )


def test_config_cli_args():
    """Test that CLI arguments are correctly parsed when no env vars are present."""
    argv = [
        "impersonate-proxy",
        "--host",
        "192.168.1.50",
        "--port",
        "7777",
        "--impersonate",
        "safari",
        "--ca-dir",
        "/cli/ca",
        "--no-enrich-headers",
        "--debug",
    ]
    with (
        patch("sys.argv", argv),
        patch.dict(os.environ, {}, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        mock_run.assert_called_once_with(
            host="192.168.1.50",
            port=7777,
            impersonate="safari",
            ca_dir="/cli/ca",
            enrich_headers=False,
            debug=True,
            quiet=False,
        )


def test_config_cli_overrides_env():
    """Test that CLI arguments take precedence over environment variables."""
    env = {
        "IMPERSONATE_PROXY_PORT": "9999",
        "IMPERSONATE_PROXY_HOST": "10.0.0.2",
        "IMPERSONATE_PROXY_IMPERSONATE": "firefox",
        "IMPERSONATE_PROXY_CA_DIR": "/env/ca",
        "IMPERSONATE_PROXY_ENRICH_HEADERS": "true",
        "IMPERSONATE_PROXY_DEBUG": "false",
    }
    argv = [
        "impersonate-proxy",
        "--host",
        "192.168.1.50",
        "--port",
        "7777",
        "--impersonate",
        "safari",
        "--ca-dir",
        "/cli/ca",
        "--no-enrich-headers",
        "--debug",
    ]
    with (
        patch("sys.argv", argv),
        patch.dict(os.environ, env, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        mock_run.assert_called_once_with(
            host="192.168.1.50",
            port=7777,
            impersonate="safari",
            ca_dir="/cli/ca",
            enrich_headers=False,
            debug=True,
            quiet=False,
        )


@pytest.mark.parametrize(
    "env_val,expected_enrich",
    [
        ("true", True),
        ("1", True),
        ("yes", True),
        ("false", False),
        ("0", False),
        ("no", False),
    ],
)
def test_config_enrich_headers_env_variants(env_val, expected_enrich):
    """Test different boolean-like environment variable values for header enrichment."""
    env = {"IMPERSONATE_PROXY_ENRICH_HEADERS": env_val}
    with (
        patch("sys.argv", ["impersonate-proxy"]),
        patch.dict(os.environ, env, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        mock_run.assert_called_once()
        assert mock_run.call_args[1]["enrich_headers"] is expected_enrich


@pytest.mark.parametrize(
    "env_val,expected_debug",
    [
        ("true", True),
        ("1", True),
        ("yes", True),
        ("false", False),
        ("0", False),
        ("no", False),
        ("", False),
    ],
)
def test_config_debug_env_variants(env_val, expected_debug):
    """Test different boolean-like environment variable values for debug mode."""
    env = {"IMPERSONATE_PROXY_DEBUG": env_val}
    with (
        patch("sys.argv", ["impersonate-proxy"]),
        patch.dict(os.environ, env, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        mock_run.assert_called_once()
        assert mock_run.call_args[1]["debug"] is expected_debug


def test_run_keyboard_interrupt():
    """Test that run() catches KeyboardInterrupt, logs it, and closes the server."""
    from unittest.mock import patch

    with (
        patch("socketserver.BaseServer.serve_forever", side_effect=KeyboardInterrupt),
        patch("socketserver.TCPServer.server_close") as mock_close,
        patch("impersonate_proxy.main._init_ca"),
        patch.dict(os.environ, {}, clear=True),
        patch.object(impersonate_proxy.logger, "info") as mock_info,
    ):
        impersonate_proxy.run(port=0)

    # Verify server_close was called in finally block
    mock_close.assert_called_once()
    # Verify expected log message was recorded
    log_messages = [call.args[0] for call in mock_info.call_args_list]
    log_found = any("Keyboard interrupt received, shutting down..." in msg for msg in log_messages)
    assert log_found, f"Expected KeyboardInterrupt log not found. Logs: {log_messages}"


def test_config_quiet_via_env():
    """Test that quiet mode is enabled when IMPERSONATE_PROXY_QUIET env var is true."""
    env = {"IMPERSONATE_PROXY_QUIET": "true"}
    with (
        patch("sys.argv", ["impersonate-proxy"]),
        patch.dict(os.environ, env, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        mock_run.assert_called_once_with(
            host="127.0.0.1",
            port=8899,
            impersonate="chrome",
            ca_dir=None,
            enrich_headers=True,
            debug=False,
            quiet=True,
        )


def test_config_quiet_via_cli():
    """Test that quiet mode is enabled when --quiet is passed via CLI."""
    with (
        patch("sys.argv", ["impersonate-proxy", "--quiet"]),
        patch.dict(os.environ, {}, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        mock_run.assert_called_once_with(
            host="127.0.0.1",
            port=8899,
            impersonate="chrome",
            ca_dir=None,
            enrich_headers=True,
            debug=False,
            quiet=True,
        )


def test_config_quiet_cli_overrides_env():
    """Test that CLI --quiet overrides IMPERSONATE_PROXY_QUIET=false env var."""
    env = {"IMPERSONATE_PROXY_QUIET": "false"}
    with (
        patch("sys.argv", ["impersonate-proxy", "-q"]),
        patch.dict(os.environ, env, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        mock_run.assert_called_once_with(
            host="127.0.0.1",
            port=8899,
            impersonate="chrome",
            ca_dir=None,
            enrich_headers=True,
            debug=False,
            quiet=True,
        )


@pytest.mark.parametrize(
    "env_val,expected_quiet",
    [
        ("true", True),
        ("1", True),
        ("yes", True),
        ("false", False),
        ("0", False),
        ("no", False),
    ],
)
def test_config_quiet_env_variants(env_val, expected_quiet):
    """Test different boolean-like environment variable values for quiet mode."""
    env = {"IMPERSONATE_PROXY_QUIET": env_val}
    with (
        patch("sys.argv", ["impersonate-proxy"]),
        patch.dict(os.environ, env, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        mock_run.assert_called_once()
        assert mock_run.call_args[1]["quiet"] is expected_quiet
