import pytest

from flowhound.vulnerabilities.cve.cve import CVE
from flowhound.vulnerabilities.exploits.cve_2026_9198 import Exploit

_CVE_BASE = {
    "application": "langflow",
    "cve_id": "CVE-2026-44221",
    "cve_description": "this is a CVE",
    "cvss_severity": 1.0,
    "min_impacted_version": "1.0.0",
    "max_impacted_version": "1.10.0",
    "exploit_module": "flowhound.vulnerabilities.exploits.cve_2026_44221",
    "exploit_class": "Exploit",
    "auth_required": False,
}

cve_creation = [
    pytest.param(
        {
            "application": "langflow",
            "cve_id": "CVE-2026-44221",
            "cve_description": "this is a CVE",
            "cvss_severity": 9.8,
            "min_impacted_version": "1.0.0",
            "max_impacted_version": "1.10.0",
            "exploit_module": "flowhound.vulnerabilities.exploits.cve_2026_44221",
            "exploit_class": "Exploit",
            "auth_required": True,
        },
        id="auth_required",
    ),
    pytest.param(
        {
            "application": "langflow",
            "cve_id": "CVE-2026-44221",
            "cve_description": "this is a CVE",
            "cvss_severity": 1.0,
            "min_impacted_version": "1.0.0",
            "max_impacted_version": "1.10.0",
            "exploit_module": "flowhound.vulnerabilities.exploits.cve_2026_44221",
            "exploit_class": "Exploit",
            "auth_required": False,
        },
        id="no_auth",
    ),
]

set_impacted_version_invalid = [
    ("", ValueError, "`version` must be a non-empty string."),
    (None, ValueError, "`version` must be a non-empty string."),
    ("1.10", ValueError, "`version` must take the form of `x.x.x`."),
    (10, ValueError, "`version` must be a non-empty string."),
    ("10", ValueError, "`version` must take the form of `x.x.x`."),
    ({}, ValueError, "`version` must be a non-empty string."),
    ([], ValueError, "`version` must be a non-empty string."),
    ([], ValueError, "`version` must be a non-empty string."),
    (1.10, ValueError, "`version` must be a non-empty string."),
]


@pytest.mark.parametrize("input", cve_creation)
def test_cve_creation(input):
    CVE(**input)


def test_cve_accepts_any_non_empty_application():
    """Removing CVE.apps allowlist means any non-empty string is now valid."""
    cve = CVE(**{**_CVE_BASE, "application": "future_product"})
    assert cve.application == "future_product"


def test_cve_application_empty_string_still_raises():
    with pytest.raises(ValueError, match="`application` must be a non-empty string."):
        CVE(**{**_CVE_BASE, "application": ""})


def test_cve_application_non_string_still_raises():
    with pytest.raises(ValueError, match="`application` must be a non-empty string."):
        CVE(**{**_CVE_BASE, "application": None})


@pytest.mark.parametrize("input", cve_creation)
def test_set_impacted_version_valid(input):
    cve_inst = CVE(**input)
    cve_inst.max_impacted_version = "1.10.0"


@pytest.mark.parametrize("input, error, error_msg", set_impacted_version_invalid)
def test_set_max_impacted_version_invalid(input, error, error_msg):
    cve_dict = {
        "application": "langflow",
        "cve_id": "CVE-2026-44221",
        "cve_description": "this is a CVE",
        "cvss_severity": 1.0,
        "min_impacted_version": "1.0.0",
        "max_impacted_version": "1.10.0",
        "exploit_module": "flowhound.vulnerabilities.exploits.cve_2026_44221",
        "exploit_class": "Exploit",
        "auth_required": False,
    }

    cve_inst = CVE(**cve_dict)
    with pytest.raises(error, match=error_msg):
        cve_inst.max_impacted_version = input


@pytest.mark.parametrize("input, error, error_msg", set_impacted_version_invalid)
def test_set_min_impacted_version_invalid(input, error, error_msg):
    cve_dict = {
        "application": "langflow",
        "cve_id": "CVE-2026-44221",
        "cve_description": "this is a CVE",
        "cvss_severity": 1.0,
        "min_impacted_version": "1.0.0",
        "max_impacted_version": "1.10.0",
        "exploit_module": "flowhound.vulnerabilities.exploits.cve_2026_44221",
        "exploit_class": "Exploit",
        "auth_required": False,
    }

    cve_inst = CVE(**cve_dict)
    with pytest.raises(error, match=error_msg):
        cve_inst.min_impacted_version = input


def test_get_exploit_instance():
    cve_dict = {
        "application": "langflow",
        "cve_id": "CVE-2026-44221",
        "cve_description": "this is a CVE",
        "cvss_severity": 1.0,
        "min_impacted_version": "1.0.0",
        "max_impacted_version": "1.10.0",
        "exploit_module": "flowhound.vulnerabilities.exploits.cve_2026_9198",
        "exploit_class": "Exploit",
        "auth_required": False,
    }

    cve_inst = CVE(**cve_dict)
    inst = cve_inst.get_exploit_instance()

    assert isinstance(inst, Exploit)


def test_get_exploit_instance_bad_module_raises_runtime_error():
    cve_dict = {
        "application": "langflow",
        "cve_id": "CVE-2026-44221",
        "cve_description": "this is a CVE",
        "cvss_severity": 1.0,
        "min_impacted_version": "1.0.0",
        "max_impacted_version": "1.10.0",
        "exploit_module": "flowhound.vulnerabilities.exploits.does_not_exist",
        "exploit_class": "Exploit",
        "auth_required": False,
    }

    cve_inst = CVE(**cve_dict)
    with pytest.raises(RuntimeError, match="Error importing exploit module"):
        cve_inst.get_exploit_instance()


# ===========================================================================
# CVE.min/max_impacted_version — tuple and list setter branches
# ===========================================================================

_CVE_TUPLE_BASE = {
    "application": "langflow",
    "cve_id": "CVE-2026-9198",
    "cve_description": "Test CVE",
    "cvss_severity": 7.5,
    "min_impacted_version": "1.0.0",
    "max_impacted_version": "1.10.0",
    "exploit_module": "flowhound.vulnerabilities.exploits.cve_2026_9198",
    "exploit_class": "Exploit",
    "auth_required": False,
}


class TestVersionSetterTupleBranch:
    def test_min_version_accepts_tuple(self):
        cve = CVE(**_CVE_TUPLE_BASE)
        cve.min_impacted_version = (2, 0, 0)
        assert cve.min_impacted_version == "2.0.0"

    def test_min_version_accepts_list(self):
        cve = CVE(**_CVE_TUPLE_BASE)
        cve.min_impacted_version = [3, 1, 4]
        assert cve.min_impacted_version == "3.1.4"

    def test_max_version_accepts_tuple(self):
        cve = CVE(**_CVE_TUPLE_BASE)
        cve.max_impacted_version = (9, 9, 9)
        assert cve.max_impacted_version == "9.9.9"

    def test_max_version_accepts_list(self):
        cve = CVE(**_CVE_TUPLE_BASE)
        cve.max_impacted_version = [0, 1, 2]
        assert cve.max_impacted_version == "0.1.2"

    def test_empty_list_raises_for_min(self):
        cve = CVE(**_CVE_TUPLE_BASE)
        with pytest.raises(ValueError, match="non-empty string"):
            cve.min_impacted_version = []

    def test_empty_list_raises_for_max(self):
        cve = CVE(**_CVE_TUPLE_BASE)
        with pytest.raises(ValueError, match="non-empty string"):
            cve.max_impacted_version = []

    def test_integer_raises(self):
        cve = CVE(**_CVE_TUPLE_BASE)
        with pytest.raises(ValueError):
            cve.min_impacted_version = 100

    def test_version_getters_return_correct_values(self):
        cve = CVE(**_CVE_TUPLE_BASE)
        assert cve.min_impacted_version == "1.0.0"
        assert cve.max_impacted_version == "1.10.0"


# ===========================================================================
# Hypothesis — property-based tests
# ===========================================================================

from hypothesis import given, settings
from hypothesis import strategies as st

# Strategy for a valid semver string
_version_component = st.integers(min_value=0, max_value=9999)
_valid_version = st.builds(
    lambda a, b, c: f"{a}.{b}.{c}",
    _version_component,
    _version_component,
    _version_component,
)

_CVE_HYPOTHESIS_BASE = {
    "application": "langflow",
    "cve_id": "CVE-2026-44221",
    "cve_description": "hypothesis test CVE",
    "cvss_severity": 7.5,
    "min_impacted_version": "1.0.0",
    "max_impacted_version": "9.9.9",
    "exploit_module": "flowhound.vulnerabilities.exploits.cve_2026_9198",
    "exploit_class": "Exploit",
    "auth_required": False,
}


# ---------------------------------------------------------------------------
# Version setter: any valid "X.Y.Z" string is accepted
# ---------------------------------------------------------------------------


@given(version=_valid_version)
def test_cve_min_version_setter_accepts_any_valid_semver(version):
    """min_impacted_version setter accepts any well-formed X.Y.Z string."""
    cve = CVE(**_CVE_HYPOTHESIS_BASE)
    cve.min_impacted_version = version
    assert cve.min_impacted_version == version


@given(version=_valid_version)
def test_cve_max_version_setter_accepts_any_valid_semver(version):
    """max_impacted_version setter accepts any well-formed X.Y.Z string."""
    cve = CVE(**_CVE_HYPOTHESIS_BASE)
    cve.max_impacted_version = version
    assert cve.max_impacted_version == version


# ---------------------------------------------------------------------------
# Version setter: tuple and list inputs are coerced to a string correctly
# ---------------------------------------------------------------------------


@given(
    major=_version_component,
    minor=_version_component,
    patch=_version_component,
)
def test_cve_min_version_setter_coerces_tuple(major, minor, patch):
    """min_impacted_version setter converts a (major, minor, patch) tuple to X.Y.Z."""
    cve = CVE(**_CVE_HYPOTHESIS_BASE)
    cve.min_impacted_version = (major, minor, patch)
    assert cve.min_impacted_version == f"{major}.{minor}.{patch}"


@given(
    major=_version_component,
    minor=_version_component,
    patch=_version_component,
)
def test_cve_max_version_setter_coerces_list(major, minor, patch):
    """max_impacted_version setter converts a [major, minor, patch] list to X.Y.Z."""
    cve = CVE(**_CVE_HYPOTHESIS_BASE)
    cve.max_impacted_version = [major, minor, patch]
    assert cve.max_impacted_version == f"{major}.{minor}.{patch}"


# ---------------------------------------------------------------------------
# Version setter: non-semver strings always raise ValueError
# ---------------------------------------------------------------------------


@given(st.text().filter(lambda s: s.count(".") != 2 and len(s) > 0))
@settings(max_examples=200)
def test_cve_min_version_setter_rejects_non_semver(bad_version):
    """min_impacted_version setter raises ValueError for any non-semver string."""
    cve = CVE(**_CVE_HYPOTHESIS_BASE)
    with pytest.raises(ValueError):
        cve.min_impacted_version = bad_version


@given(st.text().filter(lambda s: s.count(".") != 2 and len(s) > 0))
@settings(max_examples=200)
def test_cve_max_version_setter_rejects_non_semver(bad_version):
    """max_impacted_version setter raises ValueError for any non-semver string."""
    cve = CVE(**_CVE_HYPOTHESIS_BASE)
    with pytest.raises(ValueError):
        cve.max_impacted_version = bad_version


# ---------------------------------------------------------------------------
# application setter: any non-empty string is accepted; empty/non-str raises
# ---------------------------------------------------------------------------


@given(st.text(min_size=1))
def test_cve_application_setter_accepts_any_non_empty_string(app_name):
    """application setter accepts any non-empty string."""
    cve = CVE(**_CVE_HYPOTHESIS_BASE)
    cve.application = app_name
    assert cve.application == app_name
