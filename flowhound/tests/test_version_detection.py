from unittest.mock import MagicMock, patch

import pytest

from flowhound.vulnerabilities.io.version_detection import (
    convert_tuple_to_version,
    convert_version_to_tuple,
    get_target_version,
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
# get_target_version
# ---------------------------------------------------------------------------


def test_get_target_version_success():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"version": "1.5.0"}

    with patch(
        "flowhound.vulnerabilities.io.version_detection.get", return_value=mock_resp
    ):
        result = get_target_version(base_url="http://localhost:7860")

    assert result == "1.5.0"


def test_get_target_version_non_200_raises_runtime_error():
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.json.return_value = {}

    with (
        patch(
            "flowhound.vulnerabilities.io.version_detection.get", return_value=mock_resp
        ),
        pytest.raises(RuntimeError, match="Unable to retrieve Langflow version"),
    ):
        get_target_version(base_url="http://localhost:7860")


def test_get_target_version_missing_version_key_raises_runtime_error():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"other_key": "value"}

    with (
        patch(
            "flowhound.vulnerabilities.io.version_detection.get", return_value=mock_resp
        ),
        pytest.raises(RuntimeError, match="Unable to retrieve Langflow version"),
    ):
        get_target_version(base_url="http://localhost:7860")


def test_get_target_version_network_error_raises_runtime_error():
    with (
        patch(
            "flowhound.vulnerabilities.io.version_detection.get",
            side_effect=ConnectionError("refused"),
        ),
        pytest.raises(RuntimeError, match="Error retrieving target Langflow version"),
    ):
        get_target_version(base_url="http://localhost:7860")
