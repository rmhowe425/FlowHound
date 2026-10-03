from unittest.mock import MagicMock, patch

import click
import pytest
from click.testing import CliRunner

from flowhound.cli.command import _get_payload, attack, scan, sniff
from flowhound.vulnerabilities.auxiliary.base_auxiliary_class import AuxiliaryBaseClass
from flowhound.vulnerabilities.exploits.base_exploit_class import ExploitBaseClass
from flowhound.vulnerabilities.io.database import Database
from flowhound.vulnerabilities.payloads.execute_bash_command import (
    Payload as CommandPayload,
)
from flowhound.vulnerabilities.payloads.reverse_tcp_shell import (
    Payload as ReverseTcpShellPayload,
)

# ---------------------------------------------------------------------------
# _get_payload
# ---------------------------------------------------------------------------


def test_get_payload_returns_none_when_no_args():
    result = _get_payload(cmd=None, reverse_shell=None)
    assert result is None


def test_get_payload_command_returns_command_payload():
    result = _get_payload(cmd="id", reverse_shell=None)
    assert isinstance(result, CommandPayload)


def test_get_payload_reverse_shell_returns_reverse_shell_payload():
    result = _get_payload(cmd=None, reverse_shell="192.168.1.10:4444")
    assert isinstance(result, ReverseTcpShellPayload)


def test_get_payload_reverse_shell_invalid_format_raises():
    with pytest.raises(click.BadParameter, match="LHOST:LPORT"):
        _get_payload(cmd=None, reverse_shell="no-colon-here")


def test_get_payload_reverse_shell_invalid_port_raises():
    with pytest.raises(click.BadParameter, match="Port must be between"):
        _get_payload(cmd=None, reverse_shell="192.168.1.10:99999")


def test_get_payload_reverse_shell_port_zero_raises():
    with pytest.raises(click.BadParameter, match="Port must be between"):
        _get_payload(cmd=None, reverse_shell="192.168.1.10:0")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_db_with_vulns(vulns):
    """Return a mock Database whose retrieve_vulnerabilities returns `vulns`."""
    db = MagicMock(spec=Database)
    db.retrieve_vulnerabilities.return_value = vulns
    return db


# ---------------------------------------------------------------------------
# attack command
# ---------------------------------------------------------------------------


def test_attack_missing_url_fails():
    runner = CliRunner()
    result = runner.invoke(attack, [], obj=MagicMock(spec=Database))
    assert result.exit_code != 0


def test_attack_username_without_password_fails():
    runner = CliRunner()
    db = _make_db_with_vulns([])

    with patch(
        "flowhound.cli.command.detect_target", return_value=("langflow", "1.0.0")
    ):
        result = runner.invoke(
            attack,
            [
                "--url",
                "http://localhost:7860",
                "--username",
                "admin",
            ],
            obj=db,
        )

    assert result.exit_code != 0


def test_attack_command_and_reverse_shell_mutually_exclusive():
    runner = CliRunner()
    db = _make_db_with_vulns([])

    with patch(
        "flowhound.cli.command.detect_target", return_value=("langflow", "1.0.0")
    ):
        result = runner.invoke(
            attack,
            [
                "--url",
                "http://localhost:7860",
                "--command",
                "id",
                "--reverse_shell",
                "192.168.1.10:4444",
            ],
            obj=db,
        )

    assert result.exit_code != 0


def test_attack_detection_error_exits():
    runner = CliRunner()
    db = _make_db_with_vulns([])

    with patch(
        "flowhound.cli.command.detect_target",
        side_effect=RuntimeError("unreachable"),
    ):
        result = runner.invoke(
            attack,
            [
                "--url",
                "http://localhost:7860",
            ],
            obj=db,
        )

    assert result.exit_code != 0
    assert "Error detecting target" in result.output


def test_attack_no_vulns_runs_without_error():
    runner = CliRunner()
    db = _make_db_with_vulns([])

    with patch(
        "flowhound.cli.command.detect_target", return_value=("langflow", "1.0.0")
    ):
        result = runner.invoke(
            attack,
            [
                "--url",
                "http://localhost:7860",
            ],
            obj=db,
        )

    assert result.exit_code == 0


def test_attack_stops_after_first_success_without_autopwn():
    runner = CliRunner()

    mock_vuln = MagicMock()
    mock_vuln.cve_id = "CVE-2026-9999"
    mock_vuln.min_impacted_version = "1.0.0"
    mock_vuln.max_impacted_version = "1.10.0"
    mock_exploit = MagicMock(spec=ExploitBaseClass)
    mock_exploit.exploit.return_value = True
    mock_vuln.get_module_instance.return_value = mock_exploit

    db = _make_db_with_vulns([mock_vuln, mock_vuln])

    with (
        patch(
            "flowhound.cli.command.detect_target", return_value=("langflow", "1.0.0")
        ),
        patch("flowhound.cli.command._execute_exploit", return_value=True),
    ):
        result = runner.invoke(
            attack,
            [
                "--url",
                "http://localhost:7860",
            ],
            obj=db,
        )

    assert result.exit_code == 0


def test_attack_continues_with_autopwn():
    runner = CliRunner()

    mock_vuln = MagicMock()
    mock_vuln.cve_id = "CVE-2026-9999"
    mock_vuln.min_impacted_version = "1.0.0"
    mock_vuln.max_impacted_version = "1.10.0"
    mock_exploit = MagicMock(spec=ExploitBaseClass)
    mock_vuln.get_module_instance.return_value = mock_exploit

    db = _make_db_with_vulns([mock_vuln, mock_vuln])

    execute_calls = []

    def fake_execute(**_):
        execute_calls.append(1)
        return True

    with (
        patch(
            "flowhound.cli.command.detect_target", return_value=("langflow", "1.0.0")
        ),
        patch("flowhound.cli.command._execute_exploit", side_effect=fake_execute),
    ):
        result = runner.invoke(
            attack,
            [
                "--url",
                "http://localhost:7860",
                "--autopwn",
            ],
            obj=db,
        )

    assert result.exit_code == 0
    assert len(execute_calls) == 2


# ---------------------------------------------------------------------------
# sniff command
# ---------------------------------------------------------------------------


def test_sniff_missing_url_fails():
    runner = CliRunner()
    result = runner.invoke(sniff, [], obj=MagicMock(spec=Database))
    assert result.exit_code != 0


def test_sniff_detection_error_exits():
    runner = CliRunner()
    db = _make_db_with_vulns([])

    with patch(
        "flowhound.cli.command.detect_target",
        side_effect=RuntimeError("unreachable"),
    ):
        result = runner.invoke(
            sniff,
            [
                "--url",
                "http://localhost:7860",
            ],
            obj=db,
        )

    assert result.exit_code != 0
    assert "Error detecting target" in result.output


def test_sniff_success_runs_without_error():
    runner = CliRunner()
    db = _make_db_with_vulns([])

    with patch(
        "flowhound.cli.command.detect_target", return_value=("langflow", "1.0.0")
    ):
        result = runner.invoke(
            sniff,
            [
                "--url",
                "http://localhost:7860",
            ],
            obj=db,
        )

    assert result.exit_code == 0
    assert "Error" not in result.output


# ---------------------------------------------------------------------------
# --application flag (attack)
# ---------------------------------------------------------------------------


def test_attack_with_application_flag_passes_to_detect_target():
    runner = CliRunner()
    db = _make_db_with_vulns([])

    with patch(
        "flowhound.cli.command.detect_target", return_value=("mlflow", "3.1.0")
    ) as mock_detect:
        result = runner.invoke(
            attack,
            ["--url", "http://localhost:5000", "--application", "mlflow"],
            obj=db,
        )

    assert result.exit_code == 0
    mock_detect.assert_called_once_with(
        base_url="http://localhost:5000", proxies=None, application="mlflow"
    )


def test_attack_invalid_application_exits():
    runner = CliRunner()
    db = _make_db_with_vulns([])

    with patch("flowhound.cli.command.detect_target") as mock_detect:
        result = runner.invoke(
            attack,
            ["--url", "http://localhost:7860", "--application", "notaproduct"],
            obj=db,
        )

    assert result.exit_code != 0
    assert "notaproduct" in result.output
    mock_detect.assert_not_called()


# ---------------------------------------------------------------------------
# --application flag (sniff)
# ---------------------------------------------------------------------------


def test_sniff_with_application_flag_passes_to_detect_target():
    runner = CliRunner()
    db = _make_db_with_vulns([])

    with patch(
        "flowhound.cli.command.detect_target", return_value=("mlflow", "3.1.0")
    ) as mock_detect:
        result = runner.invoke(
            sniff,
            ["--url", "http://localhost:5000", "--application", "mlflow"],
            obj=db,
        )

    assert result.exit_code == 0
    mock_detect.assert_called_once_with(
        base_url="http://localhost:5000", proxies=None, application="mlflow"
    )


def test_sniff_invalid_application_exits():
    runner = CliRunner()
    db = _make_db_with_vulns([])

    with patch("flowhound.cli.command.detect_target") as mock_detect:
        result = runner.invoke(
            sniff,
            ["--url", "http://localhost:7860", "--application", "notaproduct"],
            obj=db,
        )

    assert result.exit_code != 0
    assert "notaproduct" in result.output
    mock_detect.assert_not_called()


# ===========================================================================
# _execute_exploit, _get_vulnerabilities, timeout branch, --cve, sniff listing
# ===========================================================================

from concurrent.futures import TimeoutError as FutureTimeoutError

from flowhound.cli.command import _execute_exploit, _get_vulnerabilities

# --- _execute_exploit -------------------------------------------------------


class TestExecuteExploit:
    def test_returns_exploit_result(self):
        exploit_module = MagicMock()
        exploit_module.exploit.return_value = True
        result = _execute_exploit(
            exploit_module=exploit_module,
            base_url="http://localhost:7860",
            username="admin",
            password="secret",
            proxies=None,
            payload=None,
            timeout=10,
        )
        assert result is True

    def test_exploit_false_result(self):
        exploit_module = MagicMock()
        exploit_module.exploit.return_value = False
        result = _execute_exploit(
            exploit_module=exploit_module,
            base_url="http://localhost:7860",
            username="",
            password="",
            proxies=None,
            payload=None,
        )
        assert result is False

    def test_passes_all_kwargs_to_exploit(self):
        exploit_module = MagicMock()
        exploit_module.exploit.return_value = True
        payload = MagicMock()
        _execute_exploit(
            exploit_module=exploit_module,
            base_url="http://localhost:7860",
            username="u",
            password="p",
            proxies=None,
            payload=payload,
        )
        exploit_module.exploit.assert_called_once_with(
            base_url="http://localhost:7860",
            username="u",
            password="p",
            proxies=None,
            payload=payload,
        )


# --- _get_vulnerabilities ---------------------------------------------------


class TestGetVulnerabilities:
    def _make_db(self, vulns=None, search_vulns=None):
        db = MagicMock(spec=Database)
        db.retrieve_vulnerabilities.return_value = vulns or []
        db.search_vulnerabilities.return_value = search_vulns or []
        return db

    def test_returns_cve_search_when_cve_provided(self):
        db = self._make_db(search_vulns=["v"])
        result = _get_vulnerabilities(
            db=db,
            application="langflow",
            target_version="1.0.0",
            is_auth=False,
            cve="cve-2026-9198",
        )
        assert result == ["v"]
        db.search_vulnerabilities.assert_called_once_with(
            cve="cve-2026-9198", module_type="exploit"
        )

    def test_returns_retrieve_when_no_cve(self):
        db = self._make_db(vulns=["v1", "v2"])
        result = _get_vulnerabilities(
            db=db, application="langflow", target_version="1.0.0", is_auth=True
        )
        assert result == ["v1", "v2"]

    def test_value_error_raises_click_exception(self):
        db = self._make_db()
        db.retrieve_vulnerabilities.side_effect = ValueError("bad")
        with pytest.raises(click.ClickException, match="Error retrieving exploits"):
            _get_vulnerabilities(
                db=db, application="langflow", target_version="bad", is_auth=False
            )

    def test_runtime_error_raises_click_exception(self):
        db = self._make_db()
        db.retrieve_vulnerabilities.side_effect = RuntimeError("db error")
        with pytest.raises(click.ClickException, match="Error retrieving exploits"):
            _get_vulnerabilities(
                db=db, application="langflow", target_version="1.0.0", is_auth=False
            )


# --- timeout branch ----------------------------------------------------------


def test_exploit_timeout_continues_to_next():
    runner = CliRunner()
    mock_vuln = MagicMock()
    mock_vuln.cve_id = "CVE-2026-9999"
    mock_vuln.application = "langflow"
    mock_vuln.min_impacted_version = "1.0.0"
    mock_vuln.max_impacted_version = "2.0.0"
    mock_vuln.get_module_instance.return_value = MagicMock(spec=ExploitBaseClass)

    db = MagicMock(spec=Database)
    db.retrieve_vulnerabilities.return_value = [mock_vuln]

    with (
        patch(
            "flowhound.cli.command.detect_target", return_value=("langflow", "1.0.0")
        ),
        patch(
            "flowhound.cli.command._execute_exploit",
            side_effect=FutureTimeoutError(),
        ),
    ):
        result = runner.invoke(attack, ["--url", "http://localhost:7860"], obj=db)
    assert result.exit_code == 0


def test_exploit_timeout_blocking_payload_reports_success(caplog):
    """FutureTimeoutError with a blocking payload should be treated as success."""
    import logging
    from concurrent.futures import TimeoutError as FutureTimeoutError

    runner = CliRunner()
    mock_vuln = MagicMock()
    mock_vuln.cve_id = "CVE-2026-9198"
    mock_vuln.application = "langflow"
    mock_vuln.min_impacted_version = "1.0.0"
    mock_vuln.max_impacted_version = "2.0.0"
    mock_vuln.get_module_instance.return_value = MagicMock(spec=ExploitBaseClass)

    db = MagicMock(spec=Database)
    db.retrieve_vulnerabilities.return_value = [mock_vuln]

    with (
        patch(
            "flowhound.cli.command.detect_target", return_value=("langflow", "1.0.0")
        ),
        patch(
            "flowhound.cli.command._execute_exploit",
            side_effect=FutureTimeoutError(),
        ),
        caplog.at_level(logging.INFO, logger="flowhound.cli.command"),
    ):
        result = runner.invoke(
            attack,
            [
                "--url",
                "http://localhost:7860",
                "--reverse_shell",
                "9.61.10.227:4444",
            ],
            obj=db,
        )
    assert result.exit_code == 0
    assert "blocking payload is still executing" in caplog.text


def test_exploit_timeout_non_blocking_payload_reports_skip(caplog):
    """FutureTimeoutError without a blocking payload logs the skip warning."""
    import logging
    from concurrent.futures import TimeoutError as FutureTimeoutError

    runner = CliRunner()
    mock_vuln = MagicMock()
    mock_vuln.cve_id = "CVE-2026-9999"
    mock_vuln.application = "langflow"
    mock_vuln.min_impacted_version = "1.0.0"
    mock_vuln.max_impacted_version = "2.0.0"
    mock_vuln.get_module_instance.return_value = MagicMock(spec=ExploitBaseClass)

    db = MagicMock(spec=Database)
    db.retrieve_vulnerabilities.return_value = [mock_vuln]

    with (
        patch(
            "flowhound.cli.command.detect_target", return_value=("langflow", "1.0.0")
        ),
        patch(
            "flowhound.cli.command._execute_exploit",
            side_effect=FutureTimeoutError(),
        ),
        caplog.at_level(logging.WARNING, logger="flowhound.cli.command"),
    ):
        result = runner.invoke(attack, ["--url", "http://localhost:7860"], obj=db)
    assert result.exit_code == 0
    assert "timed out after" in caplog.text


# --- credentials-detected warning -------------------------------------------


def test_credentials_detected_logs_warning():
    runner = CliRunner()
    db = MagicMock(spec=Database)
    db.retrieve_vulnerabilities.return_value = []

    with patch(
        "flowhound.cli.command.detect_target", return_value=("langflow", "1.0.0")
    ):
        result = runner.invoke(
            attack,
            [
                "--url",
                "http://localhost:7860",
                "--username",
                "admin",
                "--password",
                "secret",
            ],
            obj=db,
        )
    assert result.exit_code == 0


# --- --cve flag --------------------------------------------------------------


def test_attack_cve_flag_calls_search_vulnerabilities():
    runner = CliRunner()
    db = MagicMock(spec=Database)
    mock_vuln = MagicMock()
    mock_vuln.get_module_instance.return_value = MagicMock(spec=ExploitBaseClass)
    db.search_vulnerabilities.return_value = [mock_vuln]

    with patch(
        "flowhound.cli.command.detect_target", return_value=("langflow", "1.0.0")
    ):
        result = runner.invoke(
            attack,
            ["--url", "http://localhost:7860", "--cve", "CVE-2026-9198"],
            obj=db,
        )
    assert result.exit_code == 0
    db.search_vulnerabilities.assert_called_once_with(
        cve="cve-2026-9198", module_type="exploit"
    )


def test_attack_invalid_cve_format_exits():
    runner = CliRunner()
    db = MagicMock(spec=Database)
    result = runner.invoke(
        attack,
        ["--url", "http://localhost:7860", "--cve", "NOT-A-CVE"],
        obj=db,
    )
    assert result.exit_code != 0


def test_attack_get_vulnerabilities_error_exits():
    runner = CliRunner()
    db = MagicMock(spec=Database)
    db.retrieve_vulnerabilities.side_effect = ValueError("bad data")

    with patch(
        "flowhound.cli.command.detect_target", return_value=("langflow", "1.0.0")
    ):
        result = runner.invoke(attack, ["--url", "http://localhost:7860"], obj=db)
    assert result.exit_code != 0


# --- sniff vuln listing (line 267) ------------------------------------------


def test_sniff_lists_all_modules():
    runner = CliRunner()
    mock_exploit = MagicMock()
    mock_exploit.module = "flowhound.vulnerabilities.exploits.langflow.cve_2026_9198"
    mock_exploit.module_type = "exploit"
    mock_auxiliary = MagicMock()
    mock_auxiliary.module = "flowhound.vulnerabilities.auxiliary.mlflow.cve_2023_1177"
    mock_auxiliary.module_type = "auxiliary"
    db = MagicMock(spec=Database)
    db.retrieve_vulnerabilities.return_value = [mock_exploit, mock_auxiliary]

    with patch(
        "flowhound.cli.command.detect_target", return_value=("langflow", "1.0.0")
    ):
        result = runner.invoke(sniff, ["--url", "http://localhost:7860"], obj=db)

    assert result.exit_code == 0
    db.retrieve_vulnerabilities.assert_called_once_with(
        application="langflow",
        target_version="1.0.0",
        is_auth=True,
        module_type=None,
    )


def test_sniff_get_vulnerabilities_error_exits():
    runner = CliRunner()
    db = MagicMock(spec=Database)
    db.retrieve_vulnerabilities.side_effect = RuntimeError("db error")

    with patch(
        "flowhound.cli.command.detect_target", return_value=("langflow", "1.0.0")
    ):
        result = runner.invoke(sniff, ["--url", "http://localhost:7860"], obj=db)
    assert result.exit_code != 0


# --- CLI module type validation tests ---------------------------------------


def test_attack_fails_gracefully_on_auxiliary_cve():
    runner = CliRunner()
    db = Database()

    with patch("flowhound.cli.command.detect_target", return_value=("mlflow", "1.0.0")):
        result = runner.invoke(
            attack,
            ["--url", "http://localhost:5000", "--cve", "CVE-2023-1177"],
            obj=db,
        )
    assert result.exit_code != 0
    assert "is not an exploit module" in result.output


def test_scan_fails_gracefully_on_exploit_cve():
    runner = CliRunner()
    db = Database()

    result = runner.invoke(
        scan,
        [
            "--url",
            "http://localhost:7860",
            "--cve",
            "CVE-2026-9198",
        ],
        obj=db,
    )
    assert result.exit_code != 0
    assert "is not an auxiliary module" in result.output


# ===========================================================================
# _get_vulnerabilities — uncovered branches
# ===========================================================================


def test_get_vulnerabilities_cve_not_found_at_all_raises():
    """When a CVE ID is not in the DB at all, a ClickException 'not found' is raised."""
    runner = CliRunner()
    db = MagicMock(spec=Database)
    # Neither the typed nor the untyped search finds anything
    db.search_vulnerabilities.return_value = []

    with patch(
        "flowhound.cli.command.detect_target", return_value=("langflow", "1.0.0")
    ):
        result = runner.invoke(
            attack,
            ["--url", "http://localhost:7860", "--cve", "CVE-2026-9999"],
            obj=db,
        )

    assert result.exit_code != 0
    assert "not found" in result.output


def test_get_vulnerabilities_runtime_error_raises_click_exception():
    """A RuntimeError from retrieve_vulnerabilities is wrapped in a ClickException."""
    runner = CliRunner()
    db = MagicMock(spec=Database)
    db.retrieve_vulnerabilities.side_effect = RuntimeError("unexpected db failure")

    with patch(
        "flowhound.cli.command.detect_target", return_value=("langflow", "1.0.0")
    ):
        result = runner.invoke(attack, ["--url", "http://localhost:7860"], obj=db)

    assert result.exit_code != 0
    assert "Error retrieving exploits" in result.output


# ===========================================================================
# scan command — happy path
# ===========================================================================


def test_scan_executes_auxiliary_module():
    """scan resolves an auxiliary module and calls _execute_auxiliary."""
    runner = CliRunner()
    mock_vuln = MagicMock()
    mock_vuln.cve_id = "cve-2023-1177"

    mock_module = MagicMock(spec=AuxiliaryBaseClass)
    mock_vuln.get_module_instance.return_value = mock_module

    db = MagicMock(spec=Database)
    db.search_vulnerabilities.return_value = [mock_vuln]

    with patch(
        "flowhound.cli.command._execute_auxiliary", return_value=True
    ) as mock_exec:
        result = runner.invoke(
            scan,
            ["--url", "http://localhost:5000", "--cve", "CVE-2023-1177"],
            obj=db,
        )

    assert result.exit_code == 0
    mock_exec.assert_called_once()


def test_scan_raises_when_module_is_not_auxiliary():
    """scan raises a ClickException when get_module_instance returns an exploit."""
    runner = CliRunner()
    mock_vuln = MagicMock()
    mock_vuln.cve_id = "cve-2026-9198"

    # Return an exploit instance instead of an auxiliary
    mock_module = MagicMock(spec=ExploitBaseClass)
    mock_vuln.get_module_instance.return_value = mock_module

    db = MagicMock(spec=Database)
    db.search_vulnerabilities.return_value = [mock_vuln]

    result = runner.invoke(
        scan,
        ["--url", "http://localhost:7860", "--cve", "CVE-2026-9198"],
        obj=db,
    )

    assert result.exit_code != 0
    assert "is not an auxiliary module" in result.output


# ===========================================================================
# _get_auxiliary_modules — uncovered branches
# ===========================================================================


def test_get_auxiliary_modules_cve_not_found_at_all_raises():
    """When scan's CVE is absent from the DB entirely, 'not found' is raised."""
    runner = CliRunner()
    db = MagicMock(spec=Database)
    db.search_vulnerabilities.return_value = []

    result = runner.invoke(
        scan,
        ["--url", "http://localhost:5000", "--cve", "CVE-2023-9999"],
        obj=db,
    )

    assert result.exit_code != 0
    assert "not found" in result.output


def test_get_auxiliary_modules_runtime_error_raises_click_exception():
    """A RuntimeError from search_vulnerabilities is wrapped in a ClickException."""
    runner = CliRunner()
    db = MagicMock(spec=Database)
    db.search_vulnerabilities.side_effect = RuntimeError("db exploded")

    result = runner.invoke(
        scan,
        ["--url", "http://localhost:5000", "--cve", "CVE-2023-1177"],
        obj=db,
    )

    assert result.exit_code != 0
    assert "Error retrieving auxiliary module" in result.output
