"""Tests for flowhound.vulnerabilities.exploits.cve_2026_18729."""

from unittest.mock import MagicMock, patch

from flowhound.vulnerabilities.exploits.cve_2026_18729 import Exploit

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


# ---------------------------------------------------------------------------
# _parse_response
# ---------------------------------------------------------------------------


class TestParseResponse:
    def test_returns_true_on_zero_division(self):
        resp_json = {"detail": {"error": "ZeroDivisionError(division by zero)"}}
        assert Exploit()._parse_response(resp_json) is True

    def test_returns_false_when_no_detail(self):
        exploit = Exploit()
        assert exploit._parse_response({}) is False
        assert exploit._parse_response({"detail": {}}) is False
        assert exploit._parse_response({"detail": {"error": ""}}) is False

    def test_returns_false_for_different_error(self):
        assert (
            Exploit()._parse_response({"detail": {"error": "SomeOtherError"}}) is False
        )

    def test_returns_false_when_no_error_key(self):
        assert Exploit()._parse_response({"detail": {"message": "something"}}) is False


# ---------------------------------------------------------------------------
# _blocking_boilerplate (static)
# ---------------------------------------------------------------------------


class TestBlockingBoilerplate:
    def test_indents_code(self):
        result = Exploit._blocking_boilerplate("x = 1\ny = 2")
        assert "        x = 1" in result
        assert "        y = 2" in result
        assert "CVE-2026-18729-Probe" in result

    def test_single_line(self):
        assert "        x = 1" in Exploit._blocking_boilerplate("x = 1")


# ---------------------------------------------------------------------------
# trigger_vuln
# ---------------------------------------------------------------------------


class TestTriggerVuln:
    def test_non_blocking_returns_response(self):
        mock_resp = _mock_resp(200, {"result": "ok"})
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_18729.post",
            return_value=mock_resp,
        ):
            assert (
                exploit.trigger_vuln(
                    base_url=_BASE_URL, auth=_AUTH_HEADERS, code="x = 1"
                )
                is mock_resp
            )

    def test_blocking_uses_blocking_boilerplate(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_18729.post",
            return_value=_mock_resp(200),
        ) as mock_post:
            exploit.trigger_vuln(
                base_url=_BASE_URL, auth=_AUTH_HEADERS, code="x = 1", blocking=True
            )
        assert "        x = 1" in mock_post.call_args.kwargs["json"]["code"]

    def test_network_error_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_18729.post",
            side_effect=ConnectionError("refused"),
        ):
            assert (
                exploit.trigger_vuln(base_url=_BASE_URL, auth=_AUTH_HEADERS, code="x=1")
                is None
            )


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

    def test_200_returns_true(self):
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(),
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_18729.post",
                return_value=_mock_resp(200, {"result": "ok"}),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is True
            )

    def test_400_with_zero_division_returns_true(self):
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(),
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_18729.post",
                return_value=_mock_resp(
                    400, {"detail": {"error": "ZeroDivisionError(division by zero)"}}
                ),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is True
            )

    def test_trigger_none_returns_false(self):
        """trigger_vuln returning None (network error) → exploit returns False."""
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(),
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_18729.post",
                side_effect=ConnectionError("refused"),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is False
            )

    def test_custom_payload_with_blocking(self):
        payload = MagicMock()
        payload.load_payload.return_value = "x = 99"
        payload.blocking = True
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(),
            ),
            patch.object(
                exploit,
                "_upload_flow",
                return_value="flow-abc123",
            ) as mock_upload,
            patch.object(exploit, "_trigger_flow"),
            patch.object(exploit, "_delete_flow"),
        ):
            result = exploit.exploit(
                base_url=_BASE_URL, username="admin", password="secret", payload=payload
            )
        assert result is True
        uploaded_code = mock_upload.call_args.kwargs["component_code"]
        assert "        x = 99" in uploaded_code
