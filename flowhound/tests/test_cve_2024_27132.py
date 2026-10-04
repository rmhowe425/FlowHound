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


def _make_experiment_resp(experiment_id: str = "exp123"):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"experiment_id": experiment_id}
    return resp


def _make_run_resp(run_id: str = "run456"):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"run": {"info": {"run_id": run_id}}}
    return resp


def _make_delete_resp():
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {}
    return resp


def _make_artifact_list_resp(status: int = 200, text: str = "{}"):
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
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
                run_id="run456",
            )

        assert result == (200, "response body")

    def test_uses_artifacts_list_endpoint(self):
        """trigger_vuln must call /api/2.0/mlflow/artifacts/list with run_id."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "{}"

        exploit = Auxiliary()
        with patch(
            "flowhound.vulnerabilities.auxiliary.mlflow.cve_2024_27132.get",
            return_value=mock_resp,
        ) as mock_get:
            exploit.trigger_vuln(
                base_url=_BASE_URL,
                headers=_AUTH_HEADERS,
                run_id="run456",
            )

        call = mock_get.call_args
        assert "/api/2.0/mlflow/artifacts/list" in call[0][0]
        assert call.kwargs["params"]["run_id"] == "run456"

    def test_network_error_returns_none(self):
        exploit = Auxiliary()
        with patch(
            "flowhound.vulnerabilities.auxiliary.mlflow.cve_2024_27132.get",
            side_effect=ConnectionError("refused"),
        ):
            result = exploit.trigger_vuln(
                base_url=_BASE_URL,
                headers=_AUTH_HEADERS,
                run_id="run456",
            )

        assert result is None


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


class TestRun:
    def test_ssrf_200_success(self):
        """A 200 from the artifact list endpoint confirms SSRF."""
        auth_resp = _mock_auth_get(200)
        exp_resp = _make_experiment_resp()
        run_resp = _make_run_resp()
        delete_resp = _make_delete_resp()
        artifact_resp = _make_artifact_list_resp(200, '{"files": []}')

        exploit = Auxiliary()
        with (
            patch(
                "flowhound.vulnerabilities.clients.mlflow.get", return_value=auth_resp
            ),
            patch(
                "flowhound.vulnerabilities.auxiliary.mlflow.cve_2024_27132.post",
                side_effect=[exp_resp, run_resp, delete_resp],
            ),
            patch(
                "flowhound.vulnerabilities.auxiliary.mlflow.cve_2024_27132.get",
                return_value=artifact_resp,
            ),
        ):
            result = exploit.run(
                base_url=_BASE_URL, username="admin", password="secret"
            )

        assert result is True

    def test_ssrf_500_confirms_request(self):
        """Any 500 from the artifact list endpoint confirms the server made an outbound
        connection to the HTTP artifact URI — body content does not matter."""
        auth_resp = _mock_auth_get(200)
        exp_resp = _make_experiment_resp()
        run_resp = _make_run_resp()
        delete_resp = _make_delete_resp()
        error_resp = _make_artifact_list_resp(500, "Internal Server Error")

        exploit = Auxiliary()
        with (
            patch(
                "flowhound.vulnerabilities.clients.mlflow.get", return_value=auth_resp
            ),
            patch(
                "flowhound.vulnerabilities.auxiliary.mlflow.cve_2024_27132.post",
                side_effect=[exp_resp, run_resp, delete_resp],
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

    def test_experiment_creation_failure_skips_target(self):
        """If experiment creation fails, that target is skipped and False returned."""
        auth_resp = _mock_auth_get(200)
        failed_exp = MagicMock()
        failed_exp.status_code = 500
        failed_exp.json.return_value = {}

        exploit = Auxiliary()
        with (
            patch(
                "flowhound.vulnerabilities.clients.mlflow.get", return_value=auth_resp
            ),
            patch(
                "flowhound.vulnerabilities.auxiliary.mlflow.cve_2024_27132.post",
                return_value=failed_exp,
            ),
        ):
            result = exploit.run(
                base_url=_BASE_URL, username="admin", password="secret"
            )

        assert result is False

    def test_patched_server_returns_false(self):
        """403 on the artifact list endpoint for every target → False."""
        auth_resp = _mock_auth_get(200)
        exp_resp = _make_experiment_resp()
        run_resp = _make_run_resp()
        delete_resp = _make_delete_resp()
        denied = _make_artifact_list_resp(403, "Forbidden")

        exploit = Auxiliary()
        with (
            patch(
                "flowhound.vulnerabilities.clients.mlflow.get", return_value=auth_resp
            ),
            patch(
                "flowhound.vulnerabilities.auxiliary.mlflow.cve_2024_27132.post",
                side_effect=[exp_resp, run_resp, delete_resp] * 10,
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

    def test_uses_custom_f_path(self):
        """Custom f_path is used as the experiment artifact_location."""
        auth_resp = _mock_auth_get(200)
        exp_resp = _make_experiment_resp()
        run_resp = _make_run_resp()
        delete_resp = _make_delete_resp()
        artifact_resp = _make_artifact_list_resp(200, "{}")
        custom_target = "http://internal.corp/api/secret"

        exploit = Auxiliary()
        with (
            patch(
                "flowhound.vulnerabilities.clients.mlflow.get", return_value=auth_resp
            ),
            patch(
                "flowhound.vulnerabilities.auxiliary.mlflow.cve_2024_27132.post",
                side_effect=[exp_resp, run_resp, delete_resp],
            ) as mock_post,
            patch(
                "flowhound.vulnerabilities.auxiliary.mlflow.cve_2024_27132.get",
                return_value=artifact_resp,
            ),
        ):
            result = exploit.run(
                base_url=_BASE_URL,
                username="admin",
                password="secret",
                f_path=custom_target,
            )

        assert result is True
        # First post call creates the experiment with the custom target as artifact_location
        create_exp_call = mock_post.call_args_list[0]
        assert create_exp_call.kwargs["json"]["artifact_location"] == custom_target
