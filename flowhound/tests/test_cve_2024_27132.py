"""Tests for flowhound.vulnerabilities.auxiliary.mlflow.cve_2024_27132."""

from unittest.mock import MagicMock, patch

from flowhound.vulnerabilities.auxiliary.mlflow.cve_2024_27132 import Auxiliary

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
        mock_resp.text = "response body"

        exploit = Auxiliary()
        with patch(
            "flowhound.vulnerabilities.auxiliary.mlflow.cve_2024_27132.get",
            return_value=mock_resp,
        ):
            result = exploit.trigger_vuln(
                base_url=_BASE_URL,
                headers=_AUTH_HEADERS,
                artifact_uri="http://169.254.169.254/latest/meta-data/",
            )

        assert result == (200, "response body")

    def test_network_error_returns_none(self):
        exploit = Auxiliary()
        with patch(
            "flowhound.vulnerabilities.auxiliary.mlflow.cve_2024_27132.get",
            side_effect=ConnectionError("refused"),
        ):
            result = exploit.trigger_vuln(
                base_url=_BASE_URL,
                headers=_AUTH_HEADERS,
                artifact_uri="http://169.254.169.254/latest/meta-data/",
            )

        assert result is None


# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------


class TestRun:
    def test_ssrf_200_success(self):
        """A 200 from the artifact endpoint confirms SSRF."""
        auth_resp = _mock_auth_get(200)
        ssrf_resp = MagicMock()
        ssrf_resp.status_code = 200
        ssrf_resp.text = "ami-id\nami-launch-index\n"

        exploit = Auxiliary()
        with (
            patch(
                "flowhound.vulnerabilities.clients.mlflow.get", return_value=auth_resp
            ),
            patch(
                "flowhound.vulnerabilities.auxiliary.mlflow.cve_2024_27132.get",
                return_value=ssrf_resp,
            ),
        ):
            result = exploit.run(
                base_url=_BASE_URL, username="admin", password="secret"
            )

        assert result is True

    def test_ssrf_error_body_confirms_request(self):
        """A 500 response body that echoes the target URL also confirms SSRF."""
        auth_resp = _mock_auth_get(200)
        ssrf_target = "http://169.254.169.254/latest/meta-data/"
        error_resp = MagicMock()
        error_resp.status_code = 500
        error_resp.text = f"Connection refused to {ssrf_target}"

        exploit = Auxiliary()
        with (
            patch(
                "flowhound.vulnerabilities.clients.mlflow.get", return_value=auth_resp
            ),
            patch(
                "flowhound.vulnerabilities.auxiliary.mlflow.cve_2024_27132.get",
                return_value=error_resp,
            ),
        ):
            result = exploit.run(
                base_url=_BASE_URL, username="admin", password="secret"
            )

        assert result is True

    def test_patched_server_returns_false(self):
        """All 403 responses → False."""
        auth_resp = _mock_auth_get(200)
        denied = MagicMock()
        denied.status_code = 403
        denied.text = "Forbidden"

        exploit = Auxiliary()
        with (
            patch(
                "flowhound.vulnerabilities.clients.mlflow.get", return_value=auth_resp
            ),
            patch(
                "flowhound.vulnerabilities.auxiliary.mlflow.cve_2024_27132.get",
                return_value=denied,
            ),
        ):
            result = exploit.run(
                base_url=_BASE_URL, username="admin", password="secret"
            )

        assert result is False

    def test_auth_failure_returns_false(self):
        exploit = Auxiliary()
        with patch(
            "flowhound.vulnerabilities.clients.mlflow.get",
            return_value=_mock_auth_get(401),
        ):
            result = exploit.run(
                base_url=_BASE_URL, username="admin", password="wrongpass"
            )

        assert result is False

    def test_network_error_skips_target(self):
        """Network errors on all probes yield False without raising."""
        auth_resp = _mock_auth_get(200)

        exploit = Auxiliary()
        with (
            patch(
                "flowhound.vulnerabilities.clients.mlflow.get", return_value=auth_resp
            ),
            patch(
                "flowhound.vulnerabilities.auxiliary.mlflow.cve_2024_27132.get",
                side_effect=ConnectionError("refused"),
            ),
        ):
            result = exploit.run(
                base_url=_BASE_URL, username="admin", password="secret"
            )

        assert result is False

    def test_uses_custom_f_path(self):
        """Custom f_path replaces the default SSRF target list."""
        auth_resp = _mock_auth_get(200)
        ssrf_resp = MagicMock()
        ssrf_resp.status_code = 200
        ssrf_resp.text = "internal response"

        custom_target = "http://internal.corp/api/secret"

        exploit = Auxiliary()
        with (
            patch(
                "flowhound.vulnerabilities.clients.mlflow.get", return_value=auth_resp
            ),
            patch(
                "flowhound.vulnerabilities.auxiliary.mlflow.cve_2024_27132.get",
                return_value=ssrf_resp,
            ) as mock_get,
        ):
            result = exploit.run(
                base_url=_BASE_URL,
                username="admin",
                password="secret",
                f_path=custom_target,
            )

        assert result is True
        called_params = mock_get.call_args_list
        assert len(called_params) == 1
        assert called_params[0].kwargs["params"]["artifact_uri"] == custom_target
