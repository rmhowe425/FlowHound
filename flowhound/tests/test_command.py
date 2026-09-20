import pytest
import click
from unittest.mock import patch, MagicMock
from click.testing import CliRunner
from flowhound.cli.command import _get_payload, attack, sniff
from flowhound.vulnerabilities.io.database import Database
from flowhound.vulnerabilities.payloads.execute_bash_command import Payload as CommandPayload
from flowhound.vulnerabilities.payloads.reverse_tcp_shell import Payload as ReverseTcpShellPayload


# ---------------------------------------------------------------------------
# _get_payload
# ---------------------------------------------------------------------------

def test_get_payload_returns_none_when_no_args():
    result = _get_payload(cmd=None, reverse_shell=None)
    assert result is None


def test_get_payload_command_returns_command_payload():
    result = _get_payload(cmd='id', reverse_shell=None)
    assert isinstance(result, CommandPayload)


def test_get_payload_reverse_shell_returns_reverse_shell_payload():
    result = _get_payload(cmd=None, reverse_shell='192.168.1.10:4444')
    assert isinstance(result, ReverseTcpShellPayload)


def test_get_payload_reverse_shell_invalid_format_raises():
    with pytest.raises(click.BadParameter, match='LHOST:LPORT'):
        _get_payload(cmd=None, reverse_shell='no-colon-here')


def test_get_payload_reverse_shell_invalid_port_raises():
    with pytest.raises(click.BadParameter, match='Port must be between'):
        _get_payload(cmd=None, reverse_shell='192.168.1.10:99999')


def test_get_payload_reverse_shell_port_zero_raises():
    with pytest.raises(click.BadParameter, match='Port must be between'):
        _get_payload(cmd=None, reverse_shell='192.168.1.10:0')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_db_with_vulns(vulns):
    """Return a mock Database whose retrieve_vulnerabilities returns `vulns`."""
    db = MagicMock(spec=Database)
    db.retrieve_vulnerabilities.return_value = vulns
    return db


def _make_runner_with_db(db):
    runner = CliRunner()
    return runner, db


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

    with patch('flowhound.cli.command.get_target_version', return_value='1.0.0'):
        result = runner.invoke(attack, [
            '--url', 'http://localhost:7860',
            '--username', 'admin',
        ], obj=db)

    assert result.exit_code != 0


def test_attack_command_and_reverse_shell_mutually_exclusive():
    runner = CliRunner()
    db = _make_db_with_vulns([])

    with patch('flowhound.cli.command.get_target_version', return_value='1.0.0'):
        result = runner.invoke(attack, [
            '--url', 'http://localhost:7860',
            '--command', 'id',
            '--reverse_shell', '192.168.1.10:4444',
        ], obj=db)

    assert result.exit_code != 0


def test_attack_version_error_exits():
    runner = CliRunner()
    db = _make_db_with_vulns([])

    with patch('flowhound.cli.command.get_target_version', side_effect=RuntimeError('unreachable')):
        result = runner.invoke(attack, [
            '--url', 'http://localhost:7860',
        ], obj=db)

    assert result.exit_code != 0
    assert 'Error retrieving target Langflow version' in result.output


def test_attack_no_vulns_runs_without_error():
    runner = CliRunner()
    db = _make_db_with_vulns([])

    with patch('flowhound.cli.command.get_target_version', return_value='1.0.0'):
        result = runner.invoke(attack, [
            '--url', 'http://localhost:7860',
        ], obj=db)

    assert result.exit_code == 0


def test_attack_stops_after_first_success_without_autopwn():
    runner = CliRunner()

    mock_vuln = MagicMock()
    mock_vuln.cve_id = 'CVE-2026-9999'
    mock_vuln.min_impacted_version = '1.0.0'
    mock_vuln.max_impacted_version = '1.10.0'
    mock_exploit = MagicMock()
    mock_exploit.exploit.return_value = True
    mock_vuln.get_exploit_instance.return_value = mock_exploit

    db = _make_db_with_vulns([mock_vuln, mock_vuln])

    with patch('flowhound.cli.command.get_target_version', return_value='1.0.0'):
        with patch('flowhound.cli.command._execute_exploit', return_value=True):
            result = runner.invoke(attack, [
                '--url', 'http://localhost:7860',
            ], obj=db)

    assert result.exit_code == 0


def test_attack_continues_with_autopwn():
    runner = CliRunner()

    mock_vuln = MagicMock()
    mock_vuln.cve_id = 'CVE-2026-9999'
    mock_vuln.min_impacted_version = '1.0.0'
    mock_vuln.max_impacted_version = '1.10.0'

    db = _make_db_with_vulns([mock_vuln, mock_vuln])

    execute_calls = []

    def fake_execute(**kwargs):
        execute_calls.append(1)
        return True

    with patch('flowhound.cli.command.get_target_version', return_value='1.0.0'):
        with patch('flowhound.cli.command._execute_exploit', side_effect=fake_execute):
            result = runner.invoke(attack, [
                '--url', 'http://localhost:7860',
                '--autopwn',
            ], obj=db)

    assert result.exit_code == 0
    assert len(execute_calls) == 2


# ---------------------------------------------------------------------------
# sniff command
# ---------------------------------------------------------------------------

def test_sniff_missing_url_fails():
    runner = CliRunner()
    result = runner.invoke(sniff, [], obj=MagicMock(spec=Database))
    assert result.exit_code != 0


def test_sniff_version_error_exits():
    runner = CliRunner()
    db = _make_db_with_vulns([])

    with patch('flowhound.cli.command.get_target_version', side_effect=RuntimeError('unreachable')):
        result = runner.invoke(sniff, [
            '--url', 'http://localhost:7860',
        ], obj=db)

    assert result.exit_code != 0
    assert 'Error retrieving target Langflow version' in result.output


def test_sniff_success_runs_without_error():
    runner = CliRunner()
    db = _make_db_with_vulns([])

    with patch('flowhound.cli.command.get_target_version', return_value='1.0.0'):
        result = runner.invoke(sniff, [
            '--url', 'http://localhost:7860',
        ], obj=db)

    assert result.exit_code == 0
    assert 'Error' not in result.output
