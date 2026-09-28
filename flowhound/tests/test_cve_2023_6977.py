"""Tests for flowhound.vulnerabilities.exploits.cve_2023_6977."""

from unittest.mock import MagicMock, patch

from flowhound.vulnerabilities.exploits.cve_2023_6977 import Exploit

_BASE_URL = "http://localhost:5000"
_AUTH_HEADERS = {
    "Authorization": "Basic YWRtaW46c2VjcmV0",
    "Content-Type": "application/json",
}


def _mock_auth_get(status: int = 200):
    resp = MagicMock()
    resp.status_code = status
    return resp


# ---------------------------------------------------------------------------
# Shared response factories
# ---------------------------------------------------------------------------


def _make_auth_resp():
    resp = MagicMock()
    resp.status_code = 200
    return resp


def _make_models_resp(model_name: str = "my_model"):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"registered_models": [{"name": model_name}]}
    return resp


def _make_versions_resp(version: str = "1"):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"model_versions": [{"version": version}]}
    return resp


def _make_traversal_resp(status: int = 200, text: str = "root:x:0:0"):
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    return resp


# ---------------------------------------------------------------------------
# trigger_vuln
# ---------------------------------------------------------------------------


class TestTriggerVuln:
    def test_returns_tuple(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "file body"

        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2023_6977.get",
            return_value=mock_resp,
        ):
            result = exploit.trigger_vuln(
                base_url=_BASE_URL,
                headers=_AUTH_HEADERS,
                model_name="my_model",
                version="1",
                path="../../../../etc/passwd",
            )

        assert result == (200, "file body")

    def test_network_error_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2023_6977.get",
            side_effect=ConnectionError("refused"),
        ):
            result = exploit.trigger_vuln(
                base_url=_BASE_URL,
                headers=_AUTH_HEADERS,
                model_name="my_model",
                version="1",
                path="../../../../etc/passwd",
            )

        assert result is None


# ---------------------------------------------------------------------------
# _list_registered_models
# ---------------------------------------------------------------------------


class TestListRegisteredModels:
    def test_network_error_returns_empty(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2023_6977.get",
            side_effect=ConnectionError("refused"),
        ):
            assert (
                exploit._list_registered_models(
                    base_url=_BASE_URL, headers=_AUTH_HEADERS
                )
                == []
            )

    def test_non_200_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 403
        resp.json.return_value = {"error": "forbidden"}
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2023_6977.get",
            return_value=resp,
        ):
            assert (
                exploit._list_registered_models(
                    base_url=_BASE_URL, headers=_AUTH_HEADERS
                )
                == []
            )

    def test_filters_unnamed_entries(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "registered_models": [{"name": "valid"}, {}, {"name": ""}]
        }
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2023_6977.get",
            return_value=resp,
        ):
            assert exploit._list_registered_models(
                base_url=_BASE_URL, headers=_AUTH_HEADERS
            ) == ["valid"]


# ---------------------------------------------------------------------------
# _list_model_versions
# ---------------------------------------------------------------------------


class TestListModelVersions:
    def test_network_error_returns_empty(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2023_6977.get",
            side_effect=ConnectionError("refused"),
        ):
            assert (
                exploit._list_model_versions(
                    base_url=_BASE_URL, headers=_AUTH_HEADERS, model_name="my_model"
                )
                == []
            )

    def test_non_200_returns_empty(self):
        resp = MagicMock()
        resp.status_code = 404
        resp.json.return_value = {"error": "not found"}
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2023_6977.get",
            return_value=resp,
        ):
            assert (
                exploit._list_model_versions(
                    base_url=_BASE_URL, headers=_AUTH_HEADERS, model_name="my_model"
                )
                == []
            )

    def test_filters_versionless_entries(self):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "model_versions": [{"version": "1"}, {}, {"version": ""}]
        }
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2023_6977.get",
            return_value=resp,
        ):
            assert exploit._list_model_versions(
                base_url=_BASE_URL, headers=_AUTH_HEADERS, model_name="my_model"
            ) == ["1"]


# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------


class TestExploit:
    def test_successful_traversal(self):
        auth_resp = _make_auth_resp()
        models_resp = _make_models_resp()
        versions_resp = _make_versions_resp()
        traversal_resp = _make_traversal_resp(200, "root:x:0:0:root:/root:/bin/bash")

        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.mlflow.get",
                side_effect=[auth_resp, models_resp, versions_resp, traversal_resp],
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2023_6977.get",
                side_effect=[models_resp, versions_resp, traversal_resp],
            ),
        ):
            result = exploit.exploit(
                base_url=_BASE_URL, username="admin", password="secret"
            )

        assert result is True

    def test_no_registered_models_returns_false(self):
        auth_resp = _make_auth_resp()
        no_models_resp = MagicMock()
        no_models_resp.status_code = 200
        no_models_resp.json.return_value = {"registered_models": []}

        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.mlflow.get", return_value=auth_resp
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2023_6977.get",
                return_value=no_models_resp,
            ),
        ):
            result = exploit.exploit(
                base_url=_BASE_URL, username="admin", password="secret"
            )

        assert result is False

    def test_auth_failure_returns_false(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.clients.mlflow.get",
            return_value=_mock_auth_get(401),
        ):
            result = exploit.exploit(
                base_url=_BASE_URL, username="admin", password="wrongpass"
            )

        assert result is False

    def test_patched_server_returns_false(self):
        """403 on every traversal attempt → False."""
        auth_resp = _make_auth_resp()
        models_resp = _make_models_resp()
        versions_resp = _make_versions_resp()
        denied = _make_traversal_resp(status=403, text="")

        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.mlflow.get", return_value=auth_resp
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2023_6977.get",
                side_effect=[models_resp, versions_resp] + [denied] * 10,
            ),
        ):
            result = exploit.exploit(
                base_url=_BASE_URL, username="admin", password="secret"
            )

        assert result is False

    def test_skips_model_with_no_versions(self):
        """When a model has no versions the loop continues to the next model."""
        auth_resp = _make_auth_resp()
        models_resp = MagicMock()
        models_resp.status_code = 200
        models_resp.json.return_value = {
            "registered_models": [{"name": "no_ver"}, {"name": "has_ver"}]
        }
        no_ver_resp = MagicMock()
        no_ver_resp.status_code = 200
        no_ver_resp.json.return_value = {"model_versions": []}
        ver_resp = MagicMock()
        ver_resp.status_code = 200
        ver_resp.json.return_value = {"model_versions": [{"version": "2"}]}
        traversal_resp = MagicMock()
        traversal_resp.status_code = 200
        traversal_resp.text = "root:x:0:0"

        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.mlflow.get", return_value=auth_resp
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2023_6977.get",
                side_effect=[models_resp, no_ver_resp, ver_resp, traversal_resp],
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is True
            )

    def test_trigger_none_continues_to_next_target(self):
        """trigger_vuln returning None (network error) skips to the next path."""
        auth_resp = _make_auth_resp()
        models_resp = MagicMock()
        models_resp.status_code = 200
        models_resp.json.return_value = {"registered_models": [{"name": "m"}]}
        ver_resp = MagicMock()
        ver_resp.status_code = 200
        ver_resp.json.return_value = {"model_versions": [{"version": "1"}]}
        traversal_ok = MagicMock()
        traversal_ok.status_code = 200
        traversal_ok.text = "uid=0"

        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.mlflow.get", return_value=auth_resp
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2023_6977.get",
                side_effect=[
                    models_resp,
                    ver_resp,
                    ConnectionError("refused"),
                    traversal_ok,
                ],
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is True
            )
