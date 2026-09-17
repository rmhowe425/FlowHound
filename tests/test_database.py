import pytest
from flowhound.vulnerabilities.cve.cve import CVE
from flowhound.vulnerabilities.io.database import Database

retrieve_vulnerabilities = [('1.0.0', 0)]

def test_constructor():
    try:
        db_inst = Database()
    except Exception as e:
        pytest.fail(str(e))
        return
    
    if not isinstance(db_inst, Database) or not isinstance(db_inst.records, list):
        pytest.fail("`Database` instantiation failed.")


def test_close():
    db_inst = Database()

    try:
        db_inst.close()
    except Exception as e:
        pytest.fail(str(e))
    
    assert db_inst.records is None


@pytest.mark.parametrize("version, is_auth", retrieve_vulnerabilities)
def test_retrieve_vulnerabilities(version, is_auth):
    db_inst = Database()

    try:
        vulns = db_inst.retrieve_vulnerabilities(target_version=version, is_auth=is_auth)
    except Exception as e:
        pytest.fail(str(e))

    assert len(vulns) > 0
    assert all(
        isinstance(cve, CVE) for cve in vulns
    )
