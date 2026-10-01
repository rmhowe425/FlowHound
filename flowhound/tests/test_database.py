import json

import pytest

from flowhound.vulnerabilities.cve.cve import CVE
from flowhound.vulnerabilities.io.database import Database

retrieve_vulnerabilities = [
    pytest.param("langflow", "1.0.0", False, id="langflow_unauth"),
    pytest.param("langflow", "1.0.0", True, id="langflow_auth"),
]


def test_constructor():
    db_inst = Database()
    assert isinstance(db_inst, Database)
    assert isinstance(db_inst.records, list)


@pytest.mark.parametrize("application, version, is_auth", retrieve_vulnerabilities)
def test_retrieve_vulnerabilities(application, version, is_auth):
    db_inst = Database()
    vulns = db_inst.retrieve_vulnerabilities(
        application=application, target_version=version, is_auth=is_auth
    )
    assert len(vulns) > 0
    assert all(isinstance(cve, CVE) for cve in vulns)
    assert all(cve.application.lower() == application.lower() for cve in vulns)


def test_retrieve_vulnerabilities_with_auth():
    db_inst = Database()
    vulns = db_inst.retrieve_vulnerabilities(
        application="langflow", target_version="1.0.0", is_auth=True
    )
    assert all(isinstance(cve, CVE) for cve in vulns)


def test_retrieve_vulnerabilities_no_match_returns_empty():
    db_inst = Database()
    # Use a version far outside any known range
    vulns = db_inst.retrieve_vulnerabilities(
        application="langflow", target_version="0.0.1", is_auth=True
    )
    assert isinstance(vulns, list)
    assert len(vulns) == 0


def test_retrieve_vulnerabilities_filters_by_application():
    db_inst = Database()
    # langflow version 1.0.0 has known CVEs; querying for an unknown application
    # must return nothing even for a version that would otherwise match.
    vulns = db_inst.retrieve_vulnerabilities(
        application="unknownapp", target_version="1.0.0", is_auth=True
    )
    assert isinstance(vulns, list)
    assert len(vulns) == 0


def test_retrieve_vulnerabilities_returns_only_matching_application():
    db_inst = Database()
    vulns = db_inst.retrieve_vulnerabilities(
        application="langflow", target_version="1.0.0", is_auth=True
    )
    assert all(cve.application.lower() == "langflow" for cve in vulns)


def test_load_raises_file_not_found(tmp_path):
    db_inst = Database()
    db_inst.db_path = tmp_path / "nonexistent.json"
    with pytest.raises(FileNotFoundError, match="Data store not found"):
        db_inst._load()


def test_load_raises_value_error_on_missing_fields(tmp_path):
    bad_record = [{"cve_id": "CVE-2026-9999"}]  # missing most required fields
    bad_json = tmp_path / "vulnerabilities.json"
    bad_json.write_text(json.dumps(bad_record), encoding="utf-8")

    db_inst = Database()
    db_inst.db_path = bad_json
    with pytest.raises(ValueError, match="missing required field"):
        db_inst._load()


def test_load_raises_value_error_on_null_max_version(tmp_path):
    null_max_record = [
        {
            "application": "langflow",
            "cve_id": "CVE-2026-9999",
            "cve_description": "Test CVE",
            "cvss_severity": 9.0,
            "min_impacted_version": [1, 0, 0],
            "max_impacted_version": None,
            "exploit_module": "flowhound.vulnerabilities.exploits.cve_2026_9999",
            "exploit_class": "Exploit",
            "auth_required": False,
        }
    ]
    bad_json = tmp_path / "vulnerabilities.json"
    bad_json.write_text(json.dumps(null_max_record), encoding="utf-8")

    db_inst = Database()
    db_inst.db_path = bad_json
    with pytest.raises(ValueError, match="null value for 'max_impacted_version'"):
        db_inst._load()


def test_search_vulnerabilities_no_filter_returns_all():
    db_inst = Database()
    all_vulns = db_inst.search_vulnerabilities(cve="")
    assert isinstance(all_vulns, list)
    assert len(all_vulns) == len(db_inst.records)
    assert all(isinstance(v, CVE) for v in all_vulns)


def test_search_vulnerabilities_by_cve_id():
    db_inst = Database()
    if not db_inst.records:
        pytest.skip("No records in database to search.")

    existing_id = db_inst.records[0]["cve_id"]
    results = db_inst.search_vulnerabilities(cve=existing_id)

    assert len(results) > 0
    assert all(v.cve_id.lower() == existing_id.lower() for v in results)


def test_search_vulnerabilities_unknown_id_returns_empty():
    db_inst = Database()
    results = db_inst.search_vulnerabilities(cve="CVE-9999-00000")
    assert isinstance(results, list)
    assert len(results) == 0


# ===========================================================================
# Hypothesis — property-based tests
# ===========================================================================

from hypothesis import given, settings
from hypothesis import strategies as st

_version_component = st.integers(min_value=0, max_value=9999)
_valid_version = st.builds(
    lambda a, b, c: f"{a}.{b}.{c}",
    _version_component,
    _version_component,
    _version_component,
)


# ---------------------------------------------------------------------------
# retrieve_vulnerabilities: every returned CVE satisfies the filter invariants
# ---------------------------------------------------------------------------


@given(target_version=_valid_version, is_auth=st.booleans())
@settings(max_examples=200)
def test_retrieve_vulnerabilities_results_satisfy_version_bounds(
    target_version, is_auth
):
    """Every CVE returned must have min_version <= target <= max_version."""
    from flowhound.vulnerabilities.io.version_detection import convert_version_to_tuple

    db = Database()
    results = db.retrieve_vulnerabilities(
        application="langflow", target_version=target_version, is_auth=is_auth
    )
    target_tuple = convert_version_to_tuple(target_version)
    for cve in results:
        assert convert_version_to_tuple(cve.min_impacted_version) <= target_tuple
        assert convert_version_to_tuple(cve.max_impacted_version) >= target_tuple


@given(target_version=_valid_version, is_auth=st.booleans())
@settings(max_examples=200)
def test_retrieve_vulnerabilities_results_match_requested_application(
    target_version, is_auth
):
    """Every CVE returned must belong to the requested application."""
    db = Database()
    for app in ("langflow", "mlflow"):
        results = db.retrieve_vulnerabilities(
            application=app, target_version=target_version, is_auth=is_auth
        )
        assert all(cve.application.lower() == app for cve in results)


@given(target_version=_valid_version, is_auth=st.booleans())
@settings(max_examples=200)
def test_retrieve_vulnerabilities_auth_filter_respected(target_version, is_auth):
    """When is_auth=False, no returned CVE should require authentication."""
    db = Database()
    results = db.retrieve_vulnerabilities(
        application="langflow", target_version=target_version, is_auth=False
    )
    assert all(not cve.auth_required for cve in results)


# ---------------------------------------------------------------------------
# search_vulnerabilities: result CVE IDs always match the search term
# ---------------------------------------------------------------------------


@given(st.text(min_size=1))
@settings(max_examples=200)
def test_search_vulnerabilities_results_always_match_query(cve_id):
    """Every result from search_vulnerabilities must have cve_id matching the query."""
    db = Database()
    results = db.search_vulnerabilities(cve=cve_id)
    assert all(r.cve_id.lower() == cve_id.lower() for r in results)


@given(
    st.text(min_size=1).filter(
        lambda s: s not in {r["cve_id"] for r in Database().records}
    )
)
@settings(max_examples=100)
def test_search_vulnerabilities_unknown_id_always_empty(cve_id):
    """Searching for a CVE ID that does not exist always returns an empty list."""
    db = Database()
    assert db.search_vulnerabilities(cve=cve_id) == []
