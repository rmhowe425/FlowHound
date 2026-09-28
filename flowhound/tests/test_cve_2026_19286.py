"""Tests for flowhound.vulnerabilities.exploits.cve_2026_19286."""

from unittest.mock import MagicMock, patch

from flowhound.vulnerabilities.exploits.cve_2026_19286 import Exploit

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
