from unittest.mock import patch

import click
import pytest

from flowhound.cli.validators import validate_cve, validate_proxy, validate_url

# ---------------------------------------------------------------------------
# validate_url
# ---------------------------------------------------------------------------

validate_url_valid = [
    "http://localhost:7860",
    "https://example.com",
    "http://192.168.1.10:8080",
    "https://langflow.example.com/app",
]

validate_url_invalid = [
    "ftp://example.com",
    "not-a-url",
    "//example.com",
    "",
    "http://",
]


@pytest.mark.parametrize("value", validate_url_valid)
def test_validate_url_valid(value):
    result = validate_url(ctx=None, param=None, value=value)
    assert result == value


@pytest.mark.parametrize("value", validate_url_invalid)
def test_validate_url_invalid(value):
    with pytest.raises(click.BadParameter):
        validate_url(ctx=None, param=None, value=value)


# ---------------------------------------------------------------------------
# validate_proxy
# ---------------------------------------------------------------------------

validate_proxy_valid = [
    (
        "http://127.0.0.1:8080",
        {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"},
    ),
    (
        "https://proxy.example.com:3128",
        {
            "http": "https://proxy.example.com:3128",
            "https": "https://proxy.example.com:3128",
        },
    ),
]

validate_proxy_invalid = [
    "ftp://proxy.example.com",
    "not-a-url",
    "http://",
]


def test_validate_proxy_none():
    result = validate_proxy(ctx=None, param=None, value=None)
    assert result is None


@pytest.mark.parametrize("value, expected", validate_proxy_valid)
def test_validate_proxy_valid(value, expected):
    result = validate_proxy(ctx=None, param=None, value=value)
    assert result == expected


@pytest.mark.parametrize("value", validate_proxy_invalid)
def test_validate_proxy_invalid(value):
    with pytest.raises(click.BadParameter):
        validate_proxy(ctx=None, param=None, value=value)


# ---------------------------------------------------------------------------
# validate_cve
# ---------------------------------------------------------------------------

validate_cve_valid = [
    ("CVE-2026-9198", "cve-2026-9198"),
    ("cve-2021-44228", "cve-2021-44228"),
    ("CVE-2023-1234567", "cve-2023-1234567"),
]

validate_cve_invalid = [
    "CVE-26-9198",
    "NOTACVE-2026-9198",
    "CVE-20261-9198",
]


@pytest.mark.parametrize("value, expected", validate_cve_valid)
def test_validate_cve_valid(value, expected):
    result = validate_cve(ctx=None, param=None, value=value)
    assert result == expected


@pytest.mark.parametrize("value", validate_cve_invalid)
def test_validate_cve_invalid(value):
    with pytest.raises(click.BadParameter):
        validate_cve(ctx=None, param=None, value=value)


# ---------------------------------------------------------------------------
# validate_authentication
# ---------------------------------------------------------------------------


def test_validate_authentication_both_present():
    from flowhound.cli.validators import validate_authentication

    assert validate_authentication("admin", "secret") is True


def test_validate_authentication_neither_present():
    from flowhound.cli.validators import validate_authentication

    assert validate_authentication("", "") is False
    assert validate_authentication(None, None) is False


def test_validate_authentication_only_username_raises():
    from flowhound.cli.validators import validate_authentication

    with pytest.raises(click.BadParameter):
        validate_authentication("admin", "")
    with pytest.raises(click.BadParameter):
        validate_authentication("admin", None)


def test_validate_authentication_only_password_raises():
    from flowhound.cli.validators import validate_authentication

    with pytest.raises(click.BadParameter):
        validate_authentication("", "secret")
    with pytest.raises(click.BadParameter):
        validate_authentication(None, "secret")


# ---------------------------------------------------------------------------
# validate_payload_args
# ---------------------------------------------------------------------------


def test_validate_payload_args_none():
    from flowhound.cli.validators import validate_payload_args

    assert validate_payload_args(None, None) is None


def test_validate_payload_args_cmd():
    from flowhound.cli.validators import validate_payload_args

    assert validate_payload_args("id", None) is None


def test_validate_payload_args_reverse_shell_valid():
    from flowhound.cli.validators import validate_payload_args

    assert validate_payload_args(None, "192.168.1.10:4444") == ("192.168.1.10", 4444)


def test_validate_payload_args_mutually_exclusive():
    from flowhound.cli.validators import validate_payload_args

    with pytest.raises(click.UsageError):
        validate_payload_args("id", "192.168.1.10:4444")


def test_validate_payload_args_invalid_format():
    from flowhound.cli.validators import validate_payload_args

    with pytest.raises(click.BadParameter):
        validate_payload_args(None, "invalid-format")


def test_validate_payload_args_invalid_port():
    from flowhound.cli.validators import validate_payload_args

    with pytest.raises(click.BadParameter):
        validate_payload_args(None, "192.168.1.10:99999")
    with pytest.raises(click.BadParameter):
        validate_payload_args(None, "192.168.1.10:0")


# ===========================================================================
# urlparse exception branches (lines 12-13, 27-28)
# ===========================================================================


def test_validate_url_urlparse_exception_raises_bad_parameter():
    """Lines 12-13: when urlparse itself raises, BadParameter is re-raised."""
    with (
        patch(
            "flowhound.cli.validators.urlparse",
            side_effect=ValueError("boom"),
        ),
        pytest.raises(click.BadParameter, match="Malformed URL"),
    ):
        validate_url(ctx=None, param=None, value="http://example.com")


def test_validate_proxy_urlparse_exception_raises_bad_parameter():
    """Lines 27-28: same for proxy."""
    with (
        patch(
            "flowhound.cli.validators.urlparse",
            side_effect=ValueError("boom"),
        ),
        pytest.raises(click.BadParameter, match="Malformed URL"),
    ):
        validate_proxy(ctx=None, param=None, value="http://127.0.0.1:8080")


# ===========================================================================
# Hypothesis — property-based tests
# ===========================================================================

from hypothesis import given, settings
from hypothesis import strategies as st

# ---------------------------------------------------------------------------
# validate_cve: regex contract
# ---------------------------------------------------------------------------

# Strategy producing strings that must always match the CVE pattern
_valid_cve_years = st.integers(min_value=1000, max_value=9999).map(str)
_valid_cve_ids = st.integers(min_value=1000, max_value=9999999).map(str)


@given(year=_valid_cve_years, cve_id=_valid_cve_ids)
def test_validate_cve_accepts_all_valid_formats(year, cve_id):
    """validate_cve accepts any CVE-YYYY-NNNNN... with a 4-digit year and 4-7 digit id."""
    value = f"CVE-{year}-{cve_id}"
    result = validate_cve(ctx=None, param=None, value=value)
    assert result == value.lower()


@given(year=_valid_cve_years, cve_id=_valid_cve_ids)
def test_validate_cve_always_lowercases(year, cve_id):
    """validate_cve always returns a lowercase string."""
    value = f"CVE-{year}-{cve_id}"
    result = validate_cve(ctx=None, param=None, value=value)
    assert result == result.lower()


@given(
    st.text(min_size=1).filter(
        lambda s: not __import__("re").match(r"^cve-\d{4}-\d{4,7}$", s.lower())
    )
)
@settings(max_examples=300)
def test_validate_cve_rejects_all_malformed_strings(value):
    """validate_cve raises click.BadParameter for any string that doesn't match the pattern."""
    with pytest.raises(click.BadParameter):
        validate_cve(ctx=None, param=None, value=value)


# ---------------------------------------------------------------------------
# validate_url: never crashes; only raises click.BadParameter
# ---------------------------------------------------------------------------


@given(st.text())
@settings(max_examples=300)
def test_validate_url_never_raises_unexpected_exception(value):
    """validate_url raises only click.BadParameter (or nothing) for any string input."""
    try:
        validate_url(ctx=None, param=None, value=value)
    except click.BadParameter:
        pass  # expected
    except Exception as exc:
        raise AssertionError(
            f"validate_url raised unexpected {type(exc).__name__} for input {value!r}"
        ) from exc


# ---------------------------------------------------------------------------
# validate_proxy: never crashes; only raises click.BadParameter
# ---------------------------------------------------------------------------


@given(st.text())
@settings(max_examples=300)
def test_validate_proxy_never_raises_unexpected_exception(value):
    """validate_proxy raises only click.BadParameter (or nothing) for any string input."""
    try:
        validate_proxy(ctx=None, param=None, value=value)
    except click.BadParameter:
        pass  # expected
    except Exception as exc:
        raise AssertionError(
            f"validate_proxy raised unexpected {type(exc).__name__} for input {value!r}"
        ) from exc


# ---------------------------------------------------------------------------
# validate_proxy: valid http/https URLs always return a two-key dict
# ---------------------------------------------------------------------------

_valid_hosts = st.from_regex(r"[a-z0-9]{1,20}\.[a-z]{2,4}", fullmatch=True)
_valid_ports = st.integers(min_value=1, max_value=65535).map(str)


@given(scheme=st.sampled_from(["http", "https"]), host=_valid_hosts, port=_valid_ports)
def test_validate_proxy_valid_url_returns_dict(scheme, host, port):
    """validate_proxy returns {'http': url, 'https': url} for any valid http/https URL."""
    url = f"{scheme}://{host}:{port}"
    result = validate_proxy(ctx=None, param=None, value=url)
    assert isinstance(result, dict)
    assert result["http"] == url
    assert result["https"] == url
