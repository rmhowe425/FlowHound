"""Tests for flowhound.vulnerabilities.exploits.cve_2026_5027."""

from unittest.mock import MagicMock, patch

from flowhound.vulnerabilities.exploits.cve_2026_5027 import Exploit

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
# get_uuid
# ---------------------------------------------------------------------------


class TestGetUuid:
    def test_success(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_5027.get",
            return_value=_mock_resp(200, {"id": "abc-123"}),
        ):
            assert exploit.get_uuid(base_url=_BASE_URL, auth=_AUTH_HEADERS) == "abc-123"

    def test_non_200_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_5027.get",
            return_value=_mock_resp(401, {"detail": "unauthorized"}),
        ):
            assert exploit.get_uuid(base_url=_BASE_URL, auth=_AUTH_HEADERS) is None

    def test_missing_id_field_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_5027.get",
            return_value=_mock_resp(200, {"user": "admin"}),
        ):
            assert exploit.get_uuid(base_url=_BASE_URL, auth=_AUTH_HEADERS) is None

    def test_network_error_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_5027.get",
            side_effect=ConnectionError("refused"),
        ):
            assert exploit.get_uuid(base_url=_BASE_URL, auth=_AUTH_HEADERS) is None


# ---------------------------------------------------------------------------
# upload_file
# ---------------------------------------------------------------------------


class TestUploadFile:
    def test_returns_json_on_success(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_5027.post",
            return_value=_mock_resp(200, {"path": "/uploads/file.json"}),
        ):
            result = exploit.upload_file(
                auth=_AUTH_HEADERS,
                url=_BASE_URL,
                uuid="uuid-1",
                command="python3 -c 'x = 1'",
            )
        assert result == {"path": "/uploads/file.json"}

    def test_network_error_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_5027.post",
            side_effect=ConnectionError("refused"),
        ):
            assert (
                exploit.upload_file(
                    auth=_AUTH_HEADERS, url=_BASE_URL, uuid="uuid-1", command="id"
                )
                is None
            )


# ---------------------------------------------------------------------------
# trigger_vuln
# ---------------------------------------------------------------------------


class TestTriggerVuln:
    def test_returns_true_on_200(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_5027.get",
            return_value=_mock_resp(200),
        ):
            assert exploit.trigger_vuln(base_url=_BASE_URL, auth=_AUTH_HEADERS) is True

    def test_returns_false_on_non_200(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_5027.get",
            return_value=_mock_resp(403),
        ):
            assert exploit.trigger_vuln(base_url=_BASE_URL, auth=_AUTH_HEADERS) is False

    def test_network_error_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_5027.get",
            side_effect=ConnectionError("refused"),
        ):
            assert exploit.trigger_vuln(base_url=_BASE_URL, auth=_AUTH_HEADERS) is None


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

    def test_uuid_failure_returns_false(self):
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(),
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_5027.get",
                return_value=_mock_resp(401, {"detail": "unauth"}),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is False
            )

    def test_upload_failure_returns_false(self):
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(),
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_5027.get",
                return_value=_mock_resp(200, {"id": "uid-123"}),
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_5027.post",
                side_effect=ConnectionError("refused"),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is False
            )

    def test_trigger_failure_returns_false(self):
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(),
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_5027.get",
                side_effect=[_mock_resp(200, {"id": "uid-123"}), _mock_resp(403)],
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_5027.post",
                return_value=_mock_resp(200, {"path": "file.json"}),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is False
            )

    def test_full_success(self):
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(),
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_5027.get",
                side_effect=[_mock_resp(200, {"id": "uid-123"}), _mock_resp(200)],
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_5027.post",
                return_value=_mock_resp(200, {"path": "file.json"}),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is True
            )

    def test_uses_custom_payload(self):
        payload = MagicMock()
        payload.load_payload.return_value = "import os; os.system('id')"
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(),
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_5027.get",
                side_effect=[_mock_resp(200, {"id": "uid-123"}), _mock_resp(200)],
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_5027.post",
                return_value=_mock_resp(200, {"path": "file.json"}),
            ),
        ):
            assert (
                exploit.exploit(
                    base_url=_BASE_URL,
                    username="admin",
                    password="secret",
                    payload=payload,
                )
                is True
            )
        payload.load_payload.assert_called_once()
