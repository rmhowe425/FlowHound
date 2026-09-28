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
