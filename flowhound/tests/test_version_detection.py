from unittest.mock import MagicMock, patch

import pytest

from flowhound.vulnerabilities.io.version_detection import (
    convert_tuple_to_version,
    convert_version_to_tuple,
    detect_target,
    get_langflow_target_version,
    get_mlflow_target_version,
)

convert_version_to_tuple_valid = [
    ("1.0.0", (1, 0, 0)),
    ("1.8.4", (1, 8, 4)),
    ("1.10.0", (1, 10, 0)),
    ("0.0.0", (0, 0, 0)),
    ("1.1000.0", (1, 1000, 0)),
]

convert_version_to_tuple_invalid = [
    (None, ValueError, "`target_version` must be a non-empty string."),
    ("", ValueError, "`target_version` must be a non-empty string."),
    ("1.10", ValueError, "`target_version` must take the form: `x.x.x`."),
    ("1.10.0.1", ValueError, "`target_version` must take the form: `x.x.x`."),
]

convert_tuple_to_version_valid = [
    ((1, 0, 0), "1.0.0"),
    ((1, 8, 4), "1.8.4"),
    ((1, 10, 0), "1.10.0"),
    ((0, 0, 0), "0.0.0"),
    ((1, 1000, 0), "1.1000.0"),
]

convert_tuple_to_version_invalid = [
    ("1.0.0", ValueError, "Invalid version tuple."),
    (1000000, ValueError, "Invalid version tuple."),
    ((1, 2), ValueError, "Invalid version tuple."),
    (None, ValueError, "Invalid version tuple."),
    ((1, "2", 3), ValueError, "Invalid version tuple."),
]


@pytest.mark.parametrize("target_version, result", convert_version_to_tuple_valid)
def test_convert_version_to_tuple_valid(target_version, result):
    conversion = convert_version_to_tuple(target_version=target_version)
    assert conversion == result


@pytest.mark.parametrize(
    "target_version, error, error_msg", convert_version_to_tuple_invalid
)
def test_convert_version_to_tuple_invalid(target_version, error, error_msg):
    with pytest.raises(error, match=error_msg):
        convert_version_to_tuple(target_version=target_version)


@pytest.mark.parametrize("target_version, result", convert_tuple_to_version_valid)
def test_convert_tuple_to_version_valid(target_version, result):
    conversion = convert_tuple_to_version(target_version=target_version)
    assert conversion == result


@pytest.mark.parametrize(
    "target_version, error, error_msg", convert_tuple_to_version_invalid
)
def test_convert_tuple_to_version_invalid(target_version, error, error_msg):
    with pytest.raises(error, match=error_msg):
        convert_tuple_to_version(target_version=target_version)


# ---------------------------------------------------------------------------
# get_langflow_target_version
# ---------------------------------------------------------------------------


def test_get_langflow_target_version_success():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"version": "1.5.0", "package": "Langflow"}

    with patch(
        "flowhound.vulnerabilities.io.version_detection.get", return_value=mock_resp
    ):
        result = get_langflow_target_version(base_url="http://localhost:7860")

    assert result == "1.5.0"


def test_get_langflow_target_version_non_200_raises_runtime_error():
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.json.return_value = {}

    with (
        patch(
            "flowhound.vulnerabilities.io.version_detection.get", return_value=mock_resp
        ),
        pytest.raises(RuntimeError, match="Unable to retrieve Langflow version"),
    ):
        get_langflow_target_version(base_url="http://localhost:7860")


def test_get_langflow_target_version_missing_version_key_raises_runtime_error():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"other_key": "value"}

    with (
        patch(
            "flowhound.vulnerabilities.io.version_detection.get", return_value=mock_resp
        ),
        pytest.raises(RuntimeError, match="Unable to retrieve Langflow version"),
    ):
        get_langflow_target_version(base_url="http://localhost:7860")


def test_get_langflow_target_version_network_error_raises_runtime_error():
    with (
        patch(
            "flowhound.vulnerabilities.io.version_detection.get",
            side_effect=ConnectionError("refused"),
        ),
        pytest.raises(RuntimeError, match="Error retrieving target Langflow version"),
    ):
        get_langflow_target_version(base_url="http://localhost:7860")


# ---------------------------------------------------------------------------
# get_mlflow_target_version
# ---------------------------------------------------------------------------


def test_get_mlflow_target_version_success():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "3.1.0"

    with patch(
        "flowhound.vulnerabilities.io.version_detection.get", return_value=mock_resp
    ):
        result = get_mlflow_target_version(base_url="http://localhost:5000")

    assert result == "3.1.0"


def test_get_mlflow_target_version_non_200_raises_runtime_error():
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.text = ""

    with (
        patch(
            "flowhound.vulnerabilities.io.version_detection.get", return_value=mock_resp
        ),
        pytest.raises(RuntimeError, match="Unable to retrieve MLflow version"),
    ):
        get_mlflow_target_version(base_url="http://localhost:5000")


def test_get_mlflow_target_version_non_semver_raises_runtime_error():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "not-a-version"

    with (
        patch(
            "flowhound.vulnerabilities.io.version_detection.get", return_value=mock_resp
        ),
        pytest.raises(RuntimeError, match="Unable to retrieve MLflow version"),
    ):
        get_mlflow_target_version(base_url="http://localhost:5000")


def test_get_mlflow_target_version_network_error_raises_runtime_error():
    with (
        patch(
            "flowhound.vulnerabilities.io.version_detection.get",
            side_effect=ConnectionError("refused"),
        ),
        pytest.raises(RuntimeError, match="Error retrieving target MLflow version"),
    ):
        get_mlflow_target_version(base_url="http://localhost:5000")


# ---------------------------------------------------------------------------
# detect_target
# ---------------------------------------------------------------------------


def test_detect_target_identifies_langflow():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"version": "1.5.0", "package": "Langflow"}

    with patch(
        "flowhound.vulnerabilities.io.version_detection.get", return_value=mock_resp
    ):
        application, version = detect_target(base_url="http://localhost:7860")

    assert application == "langflow"
    assert version == "1.5.0"


def test_detect_target_identifies_mlflow_after_langflow_fails():
    langflow_resp = MagicMock()
    langflow_resp.status_code = 404
    langflow_resp.json.return_value = {}

    mlflow_resp = MagicMock()
    mlflow_resp.status_code = 200
    mlflow_resp.text = "3.1.0"

    with patch(
        "flowhound.vulnerabilities.io.version_detection.get",
        side_effect=[langflow_resp, mlflow_resp],
    ):
        application, version = detect_target(base_url="http://localhost:5000")

    assert application == "mlflow"
    assert version == "3.1.0"


def test_detect_target_raises_when_no_product_matched():
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.json.return_value = {}
    mock_resp.text = "not-a-version"

    with (
        patch(
            "flowhound.vulnerabilities.io.version_detection.get", return_value=mock_resp
        ),
        pytest.raises(RuntimeError, match="Could not identify a supported application"),
    ):
        detect_target(base_url="http://localhost:9999")


def test_detect_target_raises_on_network_error():
    with (
        patch(
            "flowhound.vulnerabilities.io.version_detection.get",
            side_effect=ConnectionError("refused"),
        ),
        pytest.raises(RuntimeError, match="Could not identify a supported application"),
    ):
        detect_target(base_url="http://localhost:9999")


def test_detect_target_with_application_skips_other_detectors():
    """When application is supplied only that detector is called."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "3.1.0"

    with patch(
        "flowhound.vulnerabilities.io.version_detection.get", return_value=mock_resp
    ) as mock_get:
        application, version = detect_target(
            base_url="http://localhost:5000", application="mlflow"
        )

    assert application == "mlflow"
    assert version == "3.1.0"
    # Only one HTTP call was made — straight to the MLflow endpoint
    assert mock_get.call_count == 1


def test_detect_target_application_is_case_insensitive():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"version": "1.5.0", "package": "Langflow"}

    with patch(
        "flowhound.vulnerabilities.io.version_detection.get", return_value=mock_resp
    ):
        application, version = detect_target(
            base_url="http://localhost:7860", application="Langflow"
        )

    assert application == "langflow"
    assert version == "1.5.0"


def test_detect_target_unknown_application_raises_value_error():
    with pytest.raises(ValueError, match="Unrecognised application"):
        detect_target(base_url="http://localhost:7860", application="notaproduct")
