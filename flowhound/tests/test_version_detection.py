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


# ===========================================================================
# Hypothesis — property-based tests
# ===========================================================================

from hypothesis import given, settings
from hypothesis import strategies as st

# ---------------------------------------------------------------------------
# Round-trip: tuple → string → tuple must be identity
# ---------------------------------------------------------------------------

_version_component = st.integers(min_value=0, max_value=9999)


@given(major=_version_component, minor=_version_component, patch=_version_component)
def test_version_round_trip_tuple_to_str_to_tuple(major, minor, patch):
    """convert_tuple_to_version followed by convert_version_to_tuple is identity."""
    tup = (major, minor, patch)
    assert convert_version_to_tuple(convert_tuple_to_version(tup)) == tup


@given(major=_version_component, minor=_version_component, patch=_version_component)
def test_version_round_trip_str_to_tuple_to_str(major, minor, patch):
    """convert_version_to_tuple followed by convert_tuple_to_version is identity."""
    version_str = f"{major}.{minor}.{patch}"
    assert (
        convert_tuple_to_version(convert_version_to_tuple(version_str)) == version_str
    )


# ---------------------------------------------------------------------------
# convert_version_to_tuple: valid inputs always produce 3-int tuples
# ---------------------------------------------------------------------------


@given(major=_version_component, minor=_version_component, patch=_version_component)
def test_convert_version_to_tuple_output_shape(major, minor, patch):
    """Any well-formed semver string produces a 3-element all-int tuple."""
    result = convert_version_to_tuple(f"{major}.{minor}.{patch}")
    assert isinstance(result, tuple)
    assert len(result) == 3
    assert all(isinstance(v, int) for v in result)


@given(major=_version_component, minor=_version_component, patch=_version_component)
def test_convert_version_to_tuple_values_match(major, minor, patch):
    """The parsed integers match the original components exactly."""
    result = convert_version_to_tuple(f"{major}.{minor}.{patch}")
    assert result == (major, minor, patch)


# ---------------------------------------------------------------------------
# convert_version_to_tuple: invalid inputs always raise ValueError
# ---------------------------------------------------------------------------


@given(st.text().filter(lambda s: s.count(".") != 2 and s != ""))
@settings(max_examples=200)
def test_convert_version_to_tuple_non_semver_raises(value):
    """Any non-empty string that does not contain exactly 2 dots raises ValueError."""
    import pytest as _pytest

    with _pytest.raises(ValueError):
        convert_version_to_tuple(value)


# ---------------------------------------------------------------------------
# convert_tuple_to_version: valid inputs always produce "X.Y.Z" strings
# ---------------------------------------------------------------------------


@given(major=_version_component, minor=_version_component, patch=_version_component)
def test_convert_tuple_to_version_output_format(major, minor, patch):
    """Output is always a string of the form 'X.Y.Z'."""
    result = convert_tuple_to_version((major, minor, patch))
    assert isinstance(result, str)
    assert result.count(".") == 2
    parts = result.split(".")
    assert len(parts) == 3
    assert all(p.isdigit() for p in parts)


# ---------------------------------------------------------------------------
# convert_tuple_to_version: non-3-int-tuples always raise ValueError
# ---------------------------------------------------------------------------


@given(
    st.one_of(
        st.integers(),
        st.text(),
        st.none(),
        st.tuples(st.integers(), st.integers()),  # 2-element
        st.tuples(
            st.integers(), st.integers(), st.integers(), st.integers()
        ),  # 4-element
        st.tuples(st.text(), st.text(), st.text()),  # wrong element types
    )
)
def test_convert_tuple_to_version_invalid_input_raises(value):
    """Anything that is not a 3-int tuple raises ValueError."""
    import pytest as _pytest

    with _pytest.raises(ValueError):
        convert_tuple_to_version(value)


# ---------------------------------------------------------------------------
# get_langflow_target_version — wrong package name branch (line 45)
# ---------------------------------------------------------------------------


def test_get_langflow_target_version_wrong_package_raises_runtime_error():
    """A 200 response with a valid version but wrong package name is rejected."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"version": "1.5.0", "package": "NotLangflow"}

    with (
        patch(
            "flowhound.vulnerabilities.io.version_detection.get", return_value=mock_resp
        ),
        pytest.raises(RuntimeError, match="does not appear to be a Langflow instance"),
    ):
        get_langflow_target_version(base_url="http://localhost:7860")


# ---------------------------------------------------------------------------
# get_mlflow_target_version — non-numeric semver parts branch (line 81)
# ---------------------------------------------------------------------------


def test_get_mlflow_target_version_non_numeric_parts_raises_runtime_error():
    """A version with two dots but non-digit segments raises RuntimeError."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "3.1.alpha"

    with (
        patch(
            "flowhound.vulnerabilities.io.version_detection.get", return_value=mock_resp
        ),
        pytest.raises(RuntimeError, match="unexpected format"),
    ):
        get_mlflow_target_version(base_url="http://localhost:5000")


# ---------------------------------------------------------------------------
# convert_version_to_tuple: two-dot strings with non-numeric segments always raise
# ---------------------------------------------------------------------------


@given(st.from_regex(r"[a-z][a-z0-9]*\.[a-z][a-z0-9]*\.[a-z][a-z0-9]*", fullmatch=True))
@settings(max_examples=200)
def test_convert_version_to_tuple_non_numeric_semver_raises(value):
    """A string with exactly two dots but non-digit segments always raises ValueError."""
    import pytest as _pytest

    with _pytest.raises(ValueError):
        convert_version_to_tuple(value)
