"""Unit tests for command line arguments and environment variables configuration parsing."""

import os
from unittest.mock import patch

import pytest

from impersonate_proxy import main as impersonate_proxy

_DEFAULT_RUN_CALL: dict[str, object] = {
    "host": "127.0.0.1",
    "port": 8899,
    "impersonate": "chrome",
    "ca_dir": None,
    "header_mode": "cffi-defaults",
    "strip_client_leak_headers": False,
    "debug": False,
    "quiet": False,
    "upstream_proxy": None,
    "session_pool_max": 32,
    "connect_timeout": 10.0,
    "read_timeout": 300.0,
    "fingerprint_real": True,
    "max_body_size": 512 * 1024 * 1024,
    "tunnel_idle_timeout": 30.0,
    "block_hosts": (),
    "proxy_auth": None,
    "allow_from": (),
    "stats_port": None,
}


def test_config_defaults():
    """Test defaults when no CLI args or env vars are set."""
    with (
        patch("sys.argv", ["impersonate-proxy"]),
        patch.dict(os.environ, {}, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        mock_run.assert_called_once_with(**_DEFAULT_RUN_CALL)


def test_config_env_vars():
    """Test that environment variables are correctly parsed when no CLI args are present."""
    env = {
        "IMPERSONATE_PROXY_PORT": "9999",
        "IMPERSONATE_PROXY_HOST": "10.0.0.2",
        "IMPERSONATE_PROXY_IMPERSONATE": "firefox",
        "IMPERSONATE_PROXY_CA_DIR": "/env/ca",
        "IMPERSONATE_PROXY_HEADER_MODE": "cffi-defaults",
        "IMPERSONATE_PROXY_STRIP_CLIENT_LEAK_HEADERS": "true",
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
            header_mode="cffi-defaults",
            strip_client_leak_headers=True,
            debug=True,
            quiet=False,
            upstream_proxy=None,
            session_pool_max=32,
            connect_timeout=10.0,
            read_timeout=300.0,
            fingerprint_real=True,
            max_body_size=512 * 1024 * 1024,
            tunnel_idle_timeout=30.0,
            block_hosts=(),
            proxy_auth=None,
            allow_from=(),
            stats_port=None,
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
        "--passthrough-headers",
        "--strip-client-leak-headers",
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
            header_mode="passthrough",
            strip_client_leak_headers=True,
            debug=True,
            quiet=False,
            upstream_proxy=None,
            session_pool_max=32,
            connect_timeout=10.0,
            read_timeout=300.0,
            fingerprint_real=True,
            max_body_size=512 * 1024 * 1024,
            tunnel_idle_timeout=30.0,
            block_hosts=(),
            proxy_auth=None,
            allow_from=(),
            stats_port=None,
        )


def test_config_cli_overrides_env():
    """Test that CLI arguments take precedence over environment variables."""
    env = {
        "IMPERSONATE_PROXY_PORT": "9999",
        "IMPERSONATE_PROXY_HOST": "10.0.0.2",
        "IMPERSONATE_PROXY_IMPERSONATE": "firefox",
        "IMPERSONATE_PROXY_CA_DIR": "/env/ca",
        "IMPERSONATE_PROXY_HEADER_MODE": "cffi-defaults",
        "IMPERSONATE_PROXY_STRIP_CLIENT_LEAK_HEADERS": "false",
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
        "--passthrough-headers",
        "--strip-client-leak-headers",
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
            header_mode="passthrough",
            strip_client_leak_headers=True,
            debug=True,
            quiet=False,
            upstream_proxy=None,
            session_pool_max=32,
            connect_timeout=10.0,
            read_timeout=300.0,
            fingerprint_real=True,
            max_body_size=512 * 1024 * 1024,
            tunnel_idle_timeout=30.0,
            block_hosts=(),
            proxy_auth=None,
            allow_from=(),
            stats_port=None,
        )


@pytest.mark.parametrize(
    "env_val,expected_mode",
    [
        ("passthrough", "passthrough"),
        ("cffi-defaults", "cffi-defaults"),
        ("", "cffi-defaults"),
        ("invalid", "cffi-defaults"),
        ("PASSTHROUGH", "passthrough"),
        ("CFFI-DEFAULTS", "cffi-defaults"),
        ("Cffi-Defaults", "cffi-defaults"),
    ],
)
def test_config_header_mode_env_variants(env_val, expected_mode):
    """Test IMPERSONATE_PROXY_HEADER_MODE parsing and fallback to cffi-defaults."""
    env = {"IMPERSONATE_PROXY_HEADER_MODE": env_val} if env_val else {}
    with (
        patch("sys.argv", ["impersonate-proxy"]),
        patch.dict(os.environ, env, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        mock_run.assert_called_once()
        assert mock_run.call_args[1]["header_mode"] == expected_mode


@pytest.mark.parametrize(
    "env_val,expected_strip",
    [
        ("true", True),
        ("1", True),
        ("yes", True),
        ("false", False),
        ("0", False),
        ("no", False),
    ],
)
def test_config_strip_leak_env_variants(env_val, expected_strip):
    """Test IMPERSONATE_PROXY_STRIP_CLIENT_LEAK_HEADERS boolean parsing."""
    env = {"IMPERSONATE_PROXY_STRIP_CLIENT_LEAK_HEADERS": env_val}
    with (
        patch("sys.argv", ["impersonate-proxy"]),
        patch.dict(os.environ, env, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        mock_run.assert_called_once()
        assert mock_run.call_args[1]["strip_client_leak_headers"] is expected_strip


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
        patch("impersonate_proxy.cert_manager.init_ca"),
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
        expected = dict(_DEFAULT_RUN_CALL)
        expected["quiet"] = True
        mock_run.assert_called_once_with(**expected)


def test_config_quiet_via_cli():
    """Test that quiet mode is enabled when --quiet is passed via CLI."""
    with (
        patch("sys.argv", ["impersonate-proxy", "--quiet"]),
        patch.dict(os.environ, {}, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        expected = dict(_DEFAULT_RUN_CALL)
        expected["quiet"] = True
        mock_run.assert_called_once_with(**expected)


def test_config_quiet_cli_overrides_env():
    """Test that CLI --quiet overrides IMPERSONATE_PROXY_QUIET=false env var."""
    env = {"IMPERSONATE_PROXY_QUIET": "false"}
    with (
        patch("sys.argv", ["impersonate-proxy", "-q"]),
        patch.dict(os.environ, env, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        expected = dict(_DEFAULT_RUN_CALL)
        expected["quiet"] = True
        mock_run.assert_called_once_with(**expected)


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


def test_config_header_modes_mutually_exclusive():
    """Test that passing two header-mode flags triggers argparse error."""
    argv = ["impersonate-proxy", "--passthrough-headers", "--cffi-defaults"]
    with (
        patch("sys.argv", argv),
        patch.dict(os.environ, {}, clear=True),
        patch("argparse.ArgumentParser.error", side_effect=SystemExit(2)) as mock_error,
    ):
        with pytest.raises(SystemExit):
            impersonate_proxy.main()
        mock_error.assert_called_once()


def test_config_new_features_cli():
    """Test parsing of upstream proxy, pool max, and timeout CLI arguments."""
    argv = [
        "impersonate-proxy",
        "--upstream-proxy",
        "http://127.0.0.1:8080",
        "--session-pool-max",
        "64",
        "--connect-timeout",
        "5.0",
        "--read-timeout",
        "120.0",
    ]
    with (
        patch("sys.argv", argv),
        patch.dict(os.environ, {}, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        mock_run.assert_called_once()
        kwargs = mock_run.call_args[1]
        assert kwargs["upstream_proxy"] == "http://127.0.0.1:8080"
        assert kwargs["session_pool_max"] == 64
        assert kwargs["connect_timeout"] == 5.0
        assert kwargs["read_timeout"] == 120.0


def test_config_new_features_env():
    """Test parsing of upstream proxy, pool max, and timeout environment variables."""
    env = {
        "IMPERSONATE_PROXY_UPSTREAM_PROXY": "http://proxy.internal:3128",
        "IMPERSONATE_PROXY_SESSION_POOL_MAX": "128",
        "IMPERSONATE_PROXY_CONNECT_TIMEOUT": "2.5",
        "IMPERSONATE_PROXY_READ_TIMEOUT": "60.0",
    }
    with (
        patch("sys.argv", ["impersonate-proxy"]),
        patch.dict(os.environ, env, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        mock_run.assert_called_once()
        kwargs = mock_run.call_args[1]
        assert kwargs["upstream_proxy"] == "http://proxy.internal:3128"
        assert kwargs["session_pool_max"] == 128
        assert kwargs["connect_timeout"] == 2.5
        assert kwargs["read_timeout"] == 60.0


def test_config_new_hardening_flags_cli():
    """Test parsing of max-body-size, tunnel-idle-timeout, and block-host CLI arguments."""
    argv = [
        "impersonate-proxy",
        "--max-body-size",
        "1024",
        "--tunnel-idle-timeout",
        "5.5",
        "--block-host",
        "evil.com, ads.example.net",
    ]
    with (
        patch("sys.argv", argv),
        patch.dict(os.environ, {}, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        mock_run.assert_called_once()
        kwargs = mock_run.call_args[1]
        assert kwargs["max_body_size"] == 1024
        assert kwargs["tunnel_idle_timeout"] == 5.5
        assert kwargs["block_hosts"] == ("evil.com", "ads.example.net")


def test_config_new_hardening_flags_env():
    """Test parsing of max-body-size, tunnel-idle-timeout, and block-host environment variables."""
    env = {
        "IMPERSONATE_PROXY_MAX_BODY_SIZE": "2048",
        "IMPERSONATE_PROXY_TUNNEL_IDLE_TIMEOUT": "12.5",
        "IMPERSONATE_PROXY_BLOCK_HOST": "evil.com",
    }
    with (
        patch("sys.argv", ["impersonate-proxy"]),
        patch.dict(os.environ, env, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        mock_run.assert_called_once()
        kwargs = mock_run.call_args[1]
        assert kwargs["max_body_size"] == 2048
        assert kwargs["tunnel_idle_timeout"] == 12.5
        assert kwargs["block_hosts"] == ("evil.com",)


def test_config_access_control_and_stats_flags():
    """Test parsing of proxy-auth, allow-from, and stats-port CLI arguments and env vars."""
    argv = [
        "impersonate-proxy",
        "--proxy-auth",
        "alice:s3cret",
        "--allow-from",
        "10.0.0.0/8, 192.168.1.7",
        "--stats-port",
        "9100",
    ]
    with (
        patch("sys.argv", argv),
        patch.dict(os.environ, {}, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        mock_run.assert_called_once()
        kwargs = mock_run.call_args[1]
        assert kwargs["proxy_auth"] == "alice:s3cret"
        assert kwargs["allow_from"] == ("10.0.0.0/8", "192.168.1.7")
        assert kwargs["stats_port"] == 9100

    env = {
        "IMPERSONATE_PROXY_PROXY_AUTH": "bob:hunter2",
        "IMPERSONATE_PROXY_ALLOW_FROM": "172.16.0.0/12",
        "IMPERSONATE_PROXY_STATS_PORT": "9200",
    }
    with (
        patch("sys.argv", ["impersonate-proxy"]),
        patch.dict(os.environ, env, clear=True),
        patch("impersonate_proxy.main.run") as mock_run,
    ):
        impersonate_proxy.main()
        mock_run.assert_called_once()
        kwargs = mock_run.call_args[1]
        assert kwargs["proxy_auth"] == "bob:hunter2"
        assert kwargs["allow_from"] == ("172.16.0.0/12",)
        assert kwargs["stats_port"] == 9200


def test_config_invalid_impersonate_target():
    """An unknown --impersonate target must fail fast at startup with exit code 2."""
    argv = ["impersonate-proxy", "--impersonate", "bogus"]
    with (
        patch("sys.argv", argv),
        patch.dict(os.environ, {}, clear=True),
        pytest.raises(SystemExit) as exc,
    ):
        impersonate_proxy.main()
    assert exc.value.code == 2


def test_config_invalid_impersonate_target_lists_alternatives(capsys):
    """The error message must list the valid curl_cffi targets."""
    argv = ["impersonate-proxy", "--impersonate", "bogus"]
    with (
        patch("sys.argv", argv),
        patch.dict(os.environ, {}, clear=True),
        pytest.raises(SystemExit),
    ):
        impersonate_proxy.main()
    err = capsys.readouterr().err
    assert "bogus" in err
    assert "chrome" in err
    assert "firefox" in err


@pytest.mark.parametrize(
    "browser_profile",
    ["chrome", "firefox", "safari", "edge", "chrome120", "chrome146", "firefox147"],
)
def test_impersonate_profiles_valid_in_curl_cffi(browser_profile: str):
    """Ensure standard browser profiles are supported by curl_cffi without runtime latency."""
    from curl_cffi import requests as cffi_requests

    sess = cffi_requests.Session(impersonate=browser_profile)
    try:
        assert sess is not None
    finally:
        sess.close()
