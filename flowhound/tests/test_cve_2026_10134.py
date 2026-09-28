"""Tests for flowhound.vulnerabilities.exploits.cve_2026_10134."""

import json as _json
from unittest.mock import MagicMock, patch

import pytest

from flowhound.vulnerabilities.exploits.cve_2026_10134 import Exploit

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


def _iter_resp(*events):
    """Return a mock streaming response whose iter_lines yields JSON-encoded events."""
    resp = MagicMock()
    resp.iter_lines.return_value = iter([_json.dumps(e) for e in events])
    return resp


# ---------------------------------------------------------------------------
# _poll_events
# ---------------------------------------------------------------------------


class TestPollEvents:
    def test_returns_true_on_end_event(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_10134.get",
            return_value=_iter_resp({"event": "end"}),
        ):
            assert exploit._poll_events(base_url=_BASE_URL, job_id="job-1") is True

    def test_returns_false_on_error_event(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_10134.get",
            return_value=_iter_resp({"event": "error"}),
        ):
            assert exploit._poll_events(base_url=_BASE_URL, job_id="job-1") is False

    def test_skips_empty_lines(self):
        mock_resp = MagicMock()
        mock_resp.iter_lines.return_value = iter(
            ["", "   ", _json.dumps({"event": "end"})]
        )
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_10134.get",
            return_value=mock_resp,
        ):
            assert exploit._poll_events(base_url=_BASE_URL, job_id="job-1") is True

    def test_skips_invalid_json_lines(self):
        mock_resp = MagicMock()
        mock_resp.iter_lines.return_value = iter(
            ["not-json", _json.dumps({"event": "end"})]
        )
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_10134.get",
            return_value=mock_resp,
        ):
            assert exploit._poll_events(base_url=_BASE_URL, job_id="job-1") is True

    def test_network_error_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_10134.get",
            side_effect=ConnectionError("refused"),
        ):
            assert exploit._poll_events(base_url=_BASE_URL, job_id="job-1") is None

    def test_no_matching_event_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_10134.get",
            return_value=_iter_resp({"event": "progress"}),
        ):
            assert exploit._poll_events(base_url=_BASE_URL, job_id="job-1") is None


# ---------------------------------------------------------------------------
# create_flow
# ---------------------------------------------------------------------------


class TestCreateFlow:
    def test_returns_flow_id_on_success(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_10134.post",
            return_value=_mock_resp(201, {"id": "flow-abc"}),
        ):
            result = exploit.create_flow(
                base_url=_BASE_URL,
                auth=_AUTH_HEADERS,
                code="x = 1",
                component_code="stub",
            )
        assert result == "flow-abc"

    def test_returns_none_on_bad_status(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_10134.post",
            return_value=_mock_resp(400, {"error": "bad"}),
        ):
            assert (
                exploit.create_flow(
                    base_url=_BASE_URL,
                    auth=_AUTH_HEADERS,
                    code="x=1",
                    component_code="stub",
                )
                is None
            )

    def test_returns_none_when_id_missing(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_10134.post",
            return_value=_mock_resp(200, {"name": "flow"}),
        ):
            assert (
                exploit.create_flow(
                    base_url=_BASE_URL,
                    auth=_AUTH_HEADERS,
                    code="x=1",
                    component_code="stub",
                )
                is None
            )

    def test_network_error_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_10134.post",
            side_effect=ConnectionError("refused"),
        ):
            assert (
                exploit.create_flow(
                    base_url=_BASE_URL,
                    auth=_AUTH_HEADERS,
                    code="x=1",
                    component_code="stub",
                )
                is None
            )


# ---------------------------------------------------------------------------
# cleanup
# ---------------------------------------------------------------------------


class TestCleanup:
    def test_succeeds_on_200(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_10134.delete",
            return_value=_mock_resp(200),
        ):
            exploit.cleanup(base_url=_BASE_URL, auth=_AUTH_HEADERS, flow_id="flow-1")

    def test_succeeds_on_404(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_10134.delete",
            return_value=_mock_resp(404),
        ):
            exploit.cleanup(base_url=_BASE_URL, auth=_AUTH_HEADERS, flow_id="flow-1")

    def test_logs_warning_on_unexpected_status(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_10134.delete",
            return_value=_mock_resp(500),
        ):
            exploit.cleanup(base_url=_BASE_URL, auth=_AUTH_HEADERS, flow_id="flow-1")

    def test_network_error_does_not_raise(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_10134.delete",
            side_effect=ConnectionError("refused"),
        ):
            exploit.cleanup(base_url=_BASE_URL, auth=_AUTH_HEADERS, flow_id="flow-1")


# ---------------------------------------------------------------------------
# trigger_vuln
# ---------------------------------------------------------------------------


class TestTriggerVuln:
    def test_returns_job_id(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_10134.post",
            return_value=_mock_resp(200, {"job_id": "job-99"}),
        ):
            assert (
                exploit.trigger_vuln(base_url=_BASE_URL, flow_id="flow-1") == "job-99"
            )

    def test_raises_on_non_200(self):
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_10134.post",
                return_value=_mock_resp(403, {"error": "denied"}),
            ),
            pytest.raises(RuntimeError, match="Exploit failed"),
        ):
            exploit.trigger_vuln(base_url=_BASE_URL, flow_id="flow-1")

    def test_network_error_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_10134.post",
            side_effect=ConnectionError("refused"),
        ):
            assert exploit.trigger_vuln(base_url=_BASE_URL, flow_id="flow-1") is None


# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------


class TestExploit:
    def test_auth_failure_returns_false(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.clients.langflow.post",
            return_value=_mock_auth_post(401),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="wrong")
                is False
            )

    def test_create_flow_failure_returns_false(self):
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(),
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_10134.post",
                return_value=_mock_resp(400, {"error": "bad"}),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is False
            )

    def test_full_success(self):
        poll_resp = MagicMock()
        poll_resp.iter_lines.return_value = iter([_json.dumps({"event": "end"})])
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(),
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_10134.post",
                side_effect=[
                    _mock_resp(201, {"id": "flow-1"}),
                    _mock_resp(200, {"job_id": "job-1"}),
                ],
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_10134.get",
                return_value=poll_resp,
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_10134.delete",
                return_value=_mock_resp(200),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is True
            )

    def test_no_poll_events_still_returns_true(self):
        """exploit() always returns True after cleanup regardless of poll result."""
        poll_resp = MagicMock()
        poll_resp.iter_lines.return_value = iter([])
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(),
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_10134.post",
                side_effect=[
                    _mock_resp(201, {"id": "flow-1"}),
                    _mock_resp(200, {"job_id": "job-1"}),
                ],
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_10134.get",
                return_value=poll_resp,
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_10134.delete",
                return_value=_mock_resp(200),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is True
            )
