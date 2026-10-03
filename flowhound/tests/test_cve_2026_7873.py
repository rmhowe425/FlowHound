"""Tests for flowhound.vulnerabilities.exploits.cve_2026_7873."""

from unittest.mock import MagicMock, patch

from flowhound.vulnerabilities.exploits.cve_2026_7873 import Exploit

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


# ---------------------------------------------------------------------------
# trigger_vuln
# ---------------------------------------------------------------------------


class TestTriggerVuln:
    def test_returns_response_on_success(self):
        mock_resp = _mock_resp(200, {"detail": "ok"})
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_7873.post",
            return_value=mock_resp,
        ):
            result = exploit.trigger_vuln(
                base_url=_BASE_URL, auth=_AUTH_HEADERS, code="x = 1"
            )
        assert result is mock_resp

    def test_network_error_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_7873.post",
            side_effect=ConnectionError("refused"),
        ):
            result = exploit.trigger_vuln(
                base_url=_BASE_URL, auth=_AUTH_HEADERS, code="x=1"
            )
        assert result is None

    def test_embeds_code_in_exfil_function(self):
        mock_resp = _mock_resp(200)
        code = "import os\nos.system('id')"
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_7873.post",
            return_value=mock_resp,
        ) as mock_post:
            exploit.trigger_vuln(base_url=_BASE_URL, auth=_AUTH_HEADERS, code=code)
        body = mock_post.call_args.kwargs["json"]["code"]
        # code is repr()-quoted into the exfil wrapper
        assert repr(code) in body
        assert "exploit" in body


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

    def test_returns_true_on_200(self):
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
                "flowhound.vulnerabilities.exploits.cve_2026_7873.post",
                return_value=_mock_resp(200, {"result": "uid=0"}),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is True
            )

    def test_trigger_none_returns_true(self):
        """trigger_vuln returning None (connection held open / timed out) → success."""
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
                "flowhound.vulnerabilities.exploits.cve_2026_7873.post",
                side_effect=ConnectionError("timeout"),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is True
            )

    def test_returns_false_on_non_200_non_none(self):
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
                "flowhound.vulnerabilities.exploits.cve_2026_7873.post",
                return_value=_mock_resp(403, {"detail": "forbidden"}),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is False
            )

    def test_uses_custom_payload(self):
        payload = MagicMock()
        payload.load_payload.return_value = "x = 99"
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
                "flowhound.vulnerabilities.exploits.cve_2026_7873.post",
                return_value=_mock_resp(200, {"result": "custom"}),
            ) as mock_post,
        ):
            exploit.exploit(
                base_url=_BASE_URL, username="admin", password="secret", payload=payload
            )
        assert "x = 99" in mock_post.call_args.kwargs["json"]["code"]

    def test_uses_default_code_when_no_payload(self):
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
                "flowhound.vulnerabilities.exploits.cve_2026_7873.post",
                return_value=_mock_resp(200, {"result": "uid=0"}),
            ) as mock_post,
        ):
            exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
        assert "subprocess" in mock_post.call_args.kwargs["json"]["code"]
