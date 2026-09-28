"""Tests for flowhound.vulnerabilities.exploits.cve_2023_1177."""

from unittest.mock import MagicMock, patch

from flowhound.vulnerabilities.exploits.cve_2023_1177 import Exploit

_BASE_URL = "http://localhost:5000"
_AUTH_HEADERS = {
    "Authorization": "Basic YWRtaW46c2VjcmV0",
    "Content-Type": "application/json",
}


def _mock_auth_get(status: int = 200):
    """Return a mock GET response used by MLflowClient.authenticate."""
    resp = MagicMock()
    resp.status_code = status
    return resp


# ---------------------------------------------------------------------------
# trigger_vuln
# ---------------------------------------------------------------------------


class TestTriggerVuln:
    def test_returns_status_and_body(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "file content"

        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2023_1177.get",
            return_value=mock_resp,
        ):
            result = exploit.trigger_vuln(
                base_url=_BASE_URL, path="../../../../etc/passwd"
            )

        assert result == (200, "file content")

    def test_network_error_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2023_1177.get",
            side_effect=ConnectionError("refused"),
        ):
            result = exploit.trigger_vuln(
                base_url=_BASE_URL, path="../../../../etc/passwd"
            )

        assert result is None


# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------


class TestExploit:
    def test_successful_traversal(self):
        """A 200 response with body signals a successful file read."""
        auth_resp = _mock_auth_get(200)
        traversal_resp = MagicMock()
        traversal_resp.status_code = 200
        traversal_resp.text = "root:x:0:0:root:/root:/bin/bash\n"

        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.mlflow.get", return_value=auth_resp
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2023_1177.get",
                return_value=traversal_resp,
            ),
        ):
            result = exploit.exploit(
                base_url=_BASE_URL, username="admin", password="secret"
            )

        assert result is True

    def test_patched_server_returns_false(self):
        """All 404 responses (patched server) result in False."""
        not_found = MagicMock()
        not_found.status_code = 404
        not_found.text = ""

        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2023_1177.get",
            return_value=not_found,
        ):
            result = exploit.exploit(base_url=_BASE_URL, username="", password="")

        assert result is False

    def test_network_error_skips_target(self):
        """A network error on every probe returns False without raising."""
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2023_1177.get",
            side_effect=ConnectionError("refused"),
        ):
            result = exploit.exploit(base_url=_BASE_URL, username="", password="")

        assert result is False

    def test_uses_custom_payload(self):
        """When a payload is provided its load_payload() value is used as the sole target."""
        auth_resp = _mock_auth_get(200)
        traversal_resp = MagicMock()
        traversal_resp.status_code = 200
        traversal_resp.text = "SECRET_KEY=abc123"

        payload = MagicMock()
        payload.load_payload.return_value = "../../../../app/.env"

        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.mlflow.get", return_value=auth_resp
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2023_1177.get",
                return_value=traversal_resp,
            ) as mock_get,
        ):
            result = exploit.exploit(
                base_url=_BASE_URL, username="", password="", payload=payload
            )

        assert result is True
        called_params = mock_get.call_args_list
        assert len(called_params) == 1
        assert (
            called_params[0].kwargs["params"]["artifact_uri"] == "../../../../app/.env"
        )
