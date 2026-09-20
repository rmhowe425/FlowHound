import pytest

from flowhound.vulnerabilities.cve.cve import CVE
from flowhound.vulnerabilities.exploits.cve_2026_9198 import Exploit

cve_creation = [
    pytest.param(
        {
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


@pytest.mark.parametrize("input", cve_creation)
def test_set_impacted_version_valid(input):
    cve_inst = CVE(**input)
    cve_inst.max_impacted_version = "1.10.0"


@pytest.mark.parametrize("input, error, error_msg", set_impacted_version_invalid)
def test_set_max_impacted_version_invalid(input, error, error_msg):
    cve_dict = {
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
