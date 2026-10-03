"""Tests for flowhound.vulnerabilities.exploits.langflow.cve_2026_19295."""

import json as _json
from unittest.mock import MagicMock, patch

from flowhound.vulnerabilities.exploits.langflow.cve_2026_19295 import Exploit

_BASE_URL = "http://localhost:7860"
_AUTH_HEADERS = {
    "Authorization": "Bearer test-token",
    "Content-Type": "application/json",
}


def _mock_resp(status: int = 200, json_data=None, text: str = "ok"):
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    if json_data is not None:
        resp.json.return_value = json_data
    return resp


def _mock_auth_post(status: int = 200):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = {"access_token": "test-token"}
    return resp


def _mock_auto_login_disabled():
    resp = MagicMock()
    resp.status_code = 403
    resp.json.return_value = {}
    return resp


def _stream_ctx(*events):
    """Build a mock context-manager whose iter_lines yields JSON-encoded events."""
    ctx = MagicMock()
    ctx.__enter__ = MagicMock(return_value=ctx)
    ctx.__exit__ = MagicMock(return_value=False)
    ctx.iter_lines.return_value = iter([_json.dumps(e) for e in events])
    return ctx


def _empty_stream_ctx():
    ctx = MagicMock()
    ctx.__enter__ = MagicMock(return_value=ctx)
    ctx.__exit__ = MagicMock(return_value=False)
    ctx.iter_lines.return_value = iter([])
    return ctx


# ---------------------------------------------------------------------------
# _build_flow_payload
# ---------------------------------------------------------------------------


class TestBuildFlowPayload:
    def test_non_blocking_appends_boilerplate(self):
        exploit = Exploit()
        result = exploit._build_flow_payload("x = 1", blocking=False)
        code_val = result["data"]["nodes"][0]["data"]["node"]["template"]["code"][
            "value"
        ]
        assert "x = 1" in code_val
        assert "CVE-2026-19295-Probe" in code_val

    def test_blocking_uses_blocking_boilerplate(self):
        exploit = Exploit()
        result = exploit._build_flow_payload("x = 1", blocking=True)
        code_val = result["data"]["nodes"][0]["data"]["node"]["template"]["code"][
            "value"
        ]
        assert "        x = 1" in code_val

    def test_has_required_top_level_keys(self):
        exploit = Exploit()
        result = exploit._build_flow_payload("x=1")
        assert "name" in result
        assert "description" in result
        assert "data" in result
        assert "nodes" in result["data"]


# ---------------------------------------------------------------------------
# _poll_events
# ---------------------------------------------------------------------------


class TestPollEvents:
    def test_returns_output_on_end_vertex(self):
        event = {
            "event": "end_vertex",
            "data": {
                "build_data": {
                    "data": {"outputs": {"out": {"message": {"output": "uid=0(root)"}}}}
                }
            },
        }
        exploit = Exploit()
        with (
            patch("flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.sleep"),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.get",
                return_value=_stream_ctx(event),
            ),
        ):
            assert (
                exploit._poll_events(
                    base_url=_BASE_URL, auth=_AUTH_HEADERS, job_id="job-1"
                )
                == "uid=0(root)"
            )

    def test_returns_error_text_on_error_event(self):
        exploit = Exploit()
        with (
            patch("flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.sleep"),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.get",
                return_value=_stream_ctx(
                    {"event": "error", "data": {"text": "failed"}}
                ),
            ),
        ):
            assert (
                exploit._poll_events(
                    base_url=_BASE_URL, auth=_AUTH_HEADERS, job_id="job-1"
                )
                == "failed"
            )

    def test_blocking_returns_sentinel_when_no_output(self):
        exploit = Exploit()
        with (
            patch("flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.sleep"),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.get",
                return_value=_empty_stream_ctx(),
            ),
        ):
            assert (
                exploit._poll_events(
                    base_url=_BASE_URL,
                    auth=_AUTH_HEADERS,
                    job_id="job-1",
                    blocking=True,
                )
                == "shell dispatched"
            )

    def test_non_blocking_returns_none_when_no_output(self):
        exploit = Exploit()
        with (
            patch("flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.sleep"),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.get",
                return_value=_empty_stream_ctx(),
            ),
        ):
            assert (
                exploit._poll_events(
                    base_url=_BASE_URL,
                    auth=_AUTH_HEADERS,
                    job_id="job-1",
                    blocking=False,
                )
                is None
            )

    def test_skips_empty_lines_in_stream(self):
        """Empty lines in the SSE stream are silently skipped."""
        import json as _json

        event = {
            "event": "end_vertex",
            "data": {
                "build_data": {
                    "data": {"outputs": {"out": {"message": {"output": "uid=0"}}}}
                }
            },
        }
        ctx = MagicMock()
        ctx.__enter__ = MagicMock(return_value=ctx)
        ctx.__exit__ = MagicMock(return_value=False)
        # Mix empty strings (skipped) with a valid event line
        ctx.iter_lines.return_value = iter(["", "   ", _json.dumps(event)])
        exploit = Exploit()
        with (
            patch("flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.sleep"),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.get",
                return_value=ctx,
            ),
        ):
            assert (
                exploit._poll_events(
                    base_url=_BASE_URL, auth=_AUTH_HEADERS, job_id="job-1"
                )
                == "uid=0"
            )

    def test_skips_non_json_lines_in_stream(self):
        """Lines that cannot be decoded as JSON are silently skipped."""
        import json as _json

        event = {
            "event": "end_vertex",
            "data": {
                "build_data": {
                    "data": {"outputs": {"out": {"message": {"output": "uid=0"}}}}
                }
            },
        }
        ctx = MagicMock()
        ctx.__enter__ = MagicMock(return_value=ctx)
        ctx.__exit__ = MagicMock(return_value=False)
        ctx.iter_lines.return_value = iter(["not json at all", _json.dumps(event)])
        exploit = Exploit()
        with (
            patch("flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.sleep"),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.get",
                return_value=ctx,
            ),
        ):
            assert (
                exploit._poll_events(
                    base_url=_BASE_URL, auth=_AUTH_HEADERS, job_id="job-1"
                )
                == "uid=0"
            )

    def test_skips_event_with_non_dict_data(self):
        """Events whose 'data' field is not a dict are silently skipped."""
        import json as _json

        events = [
            {"event": "some_event", "data": "a plain string"},
            {"event": "end", "data": {}},
        ]
        ctx = MagicMock()
        ctx.__enter__ = MagicMock(return_value=ctx)
        ctx.__exit__ = MagicMock(return_value=False)
        ctx.iter_lines.return_value = iter([_json.dumps(e) for e in events])
        exploit = Exploit()
        with (
            patch("flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.sleep"),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.get",
                return_value=ctx,
            ),
        ):
            # No output found, non-blocking → returns None
            assert (
                exploit._poll_events(
                    base_url=_BASE_URL,
                    auth=_AUTH_HEADERS,
                    job_id="job-1",
                    blocking=False,
                )
                is None
            )

    def test_end_vertex_with_missing_keys_does_not_raise(self):
        """KeyError inside end_vertex output parsing is silently swallowed."""
        import json as _json

        # end_vertex with no 'build_data' key — triggers the KeyError/TypeError pass
        events = [
            {"event": "end_vertex", "data": {}},
            {"event": "end", "data": {}},
        ]
        ctx = MagicMock()
        ctx.__enter__ = MagicMock(return_value=ctx)
        ctx.__exit__ = MagicMock(return_value=False)
        ctx.iter_lines.return_value = iter([_json.dumps(e) for e in events])
        exploit = Exploit()
        with (
            patch("flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.sleep"),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.get",
                return_value=ctx,
            ),
        ):
            assert (
                exploit._poll_events(
                    base_url=_BASE_URL,
                    auth=_AUTH_HEADERS,
                    job_id="job-1",
                    blocking=False,
                )
                is None
            )

    def test_stream_exception_does_not_raise(self):
        """An exception raised during streaming is silently swallowed."""
        exploit = Exploit()
        with (
            patch("flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.sleep"),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.get",
                side_effect=ConnectionError("refused"),
            ),
        ):
            # Non-blocking with no output → None
            assert (
                exploit._poll_events(
                    base_url=_BASE_URL,
                    auth=_AUTH_HEADERS,
                    job_id="job-1",
                    blocking=False,
                )
                is None
            )


# ---------------------------------------------------------------------------
# save_flow
# ---------------------------------------------------------------------------


class TestSaveFlow:
    def test_returns_id_on_201(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.post",
            return_value=_mock_resp(201, {"id": "flow-1"}),
        ):
            assert (
                exploit.save_flow(base_url=_BASE_URL, auth=_AUTH_HEADERS, code="x=1")
                == "flow-1"
            )

    def test_returns_none_on_bad_status(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.post",
            return_value=_mock_resp(400, {"error": "bad"}),
        ):
            assert (
                exploit.save_flow(base_url=_BASE_URL, auth=_AUTH_HEADERS, code="x=1")
                is None
            )

    def test_network_error_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.post",
            side_effect=ConnectionError("refused"),
        ):
            assert (
                exploit.save_flow(base_url=_BASE_URL, auth=_AUTH_HEADERS, code="x=1")
                is None
            )


# ---------------------------------------------------------------------------
# trigger_vuln
# ---------------------------------------------------------------------------


class TestTriggerVuln:
    def test_non_200_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.post",
            return_value=_mock_resp(403, {}),
        ):
            assert (
                exploit.trigger_vuln(
                    base_url=_BASE_URL, auth=_AUTH_HEADERS, flow_id="flow-1"
                )
                is None
            )

    def test_network_error_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.post",
            side_effect=ConnectionError("refused"),
        ):
            assert (
                exploit.trigger_vuln(
                    base_url=_BASE_URL, auth=_AUTH_HEADERS, flow_id="flow-1"
                )
                is None
            )


# ---------------------------------------------------------------------------
# delete_flow
# ---------------------------------------------------------------------------


class TestDeleteFlow:
    def test_success(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.delete",
            return_value=_mock_resp(200),
        ):
            exploit.delete_flow(
                base_url=_BASE_URL, auth=_AUTH_HEADERS, flow_id="flow-1"
            )

    def test_network_error_does_not_raise(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.delete",
            side_effect=ConnectionError("refused"),
        ):
            exploit.delete_flow(
                base_url=_BASE_URL, auth=_AUTH_HEADERS, flow_id="flow-1"
            )


# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------


class TestExploit:
    def test_auth_failure_returns_false(self):
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get",
                return_value=_mock_auto_login_disabled(),
            ),
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(401),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="wrong")
                is False
            )

    def test_save_flow_failure_returns_false(self):
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get",
                return_value=_mock_auto_login_disabled(),
            ),
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(),
            ),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.post",
                return_value=_mock_resp(400, {"error": "bad"}),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is False
            )

    def test_no_rce_output_returns_false(self):
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get",
                return_value=_mock_auto_login_disabled(),
            ),
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(),
            ),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.post",
                side_effect=[_mock_resp(201, {"id": "flow-1"}), _mock_resp(403, {})],
            ),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.delete",
                return_value=_mock_resp(200),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is False
            )

    def test_successful_rce(self):
        event = {
            "event": "end_vertex",
            "data": {
                "build_data": {
                    "data": {"outputs": {"out": {"message": {"output": "uid=0"}}}}
                }
            },
        }
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get",
                return_value=_mock_auto_login_disabled(),
            ),
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(),
            ),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.post",
                side_effect=[
                    _mock_resp(201, {"id": "flow-1"}),
                    _mock_resp(200, {"job_id": "job-1"}),
                ],
            ),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.get",
                return_value=_stream_ctx(event),
            ),
            patch("flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.sleep"),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_19295.delete",
                return_value=_mock_resp(200),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is True
            )
