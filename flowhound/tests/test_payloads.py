import pytest
from flowhound.vulnerabilities.payloads.execute_bash_command import Payload as CommandPayload
from flowhound.vulnerabilities.payloads.reverse_tcp_shell import Payload as ReverseTcpShellPayload


# ---------------------------------------------------------------------------
# execute_bash_command.Payload
# ---------------------------------------------------------------------------

command_payload_cases = [
    'id',
    'whoami',
    'cat /etc/passwd',
    'ls -la /tmp',
]


@pytest.mark.parametrize("cmd", command_payload_cases)
def test_command_payload_creation(cmd):
    p = CommandPayload(cmd=cmd)
    assert isinstance(p, CommandPayload)


@pytest.mark.parametrize("cmd", command_payload_cases)
def test_command_payload_contains_cmd(cmd):
    p = CommandPayload(cmd=cmd)
    result = p.load_payload()
    assert cmd in result


@pytest.mark.parametrize("cmd", command_payload_cases)
def test_command_payload_load_payload_returns_string(cmd):
    p = CommandPayload(cmd=cmd)
    assert isinstance(p.load_payload(), str)


def test_command_payload_not_blocking():
    p = CommandPayload(cmd='id')
    assert p.blocking is False


def test_command_payload_generate_payload_contains_subprocess():
    p = CommandPayload(cmd='whoami')
    assert 'subprocess' in p.load_payload()


# ---------------------------------------------------------------------------
# reverse_tcp_shell.Payload
# ---------------------------------------------------------------------------

reverse_shell_payload_cases = [
    ('192.168.1.10', 4444),
    ('10.0.0.1', 1337),
    ('127.0.0.1', 9001),
]


@pytest.mark.parametrize("lhost, lport", reverse_shell_payload_cases)
def test_reverse_shell_payload_creation(lhost, lport):
    p = ReverseTcpShellPayload(lhost=lhost, lport=lport)
    assert isinstance(p, ReverseTcpShellPayload)


@pytest.mark.parametrize("lhost, lport", reverse_shell_payload_cases)
def test_reverse_shell_payload_contains_lhost_and_lport(lhost, lport):
    p = ReverseTcpShellPayload(lhost=lhost, lport=lport)
    result = p.load_payload()
    assert lhost in result
    assert str(lport) in result


@pytest.mark.parametrize("lhost, lport", reverse_shell_payload_cases)
def test_reverse_shell_payload_load_payload_returns_string(lhost, lport):
    p = ReverseTcpShellPayload(lhost=lhost, lport=lport)
    assert isinstance(p.load_payload(), str)


def test_reverse_shell_payload_is_blocking():
    p = ReverseTcpShellPayload(lhost='192.168.1.10', lport=4444)
    assert p.blocking is True


def test_reverse_shell_payload_contains_socket():
    p = ReverseTcpShellPayload(lhost='192.168.1.10', lport=4444)
    assert 'socket' in p.load_payload()
