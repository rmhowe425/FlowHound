"""Tests for flowhound.vulnerabilities.exploits.langflow.cve_2026_18729."""

from unittest.mock import MagicMock, patch

from flowhound.vulnerabilities.exploits.langflow.cve_2026_18729 import Exploit

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
# _parse_response
# ---------------------------------------------------------------------------


class TestParseResponse:
    def test_returns_true_on_zero_division(self):
        resp_json = {"detail": {"error": "ZeroDivisionError(division by zero)"}}
        assert Exploit()._parse_response(resp_json) is True

    def test_returns_false_when_no_detail(self):
        exploit = Exploit()
        assert exploit._parse_response({}) is False
        assert exploit._parse_response({"detail": {}}) is False
        assert exploit._parse_response({"detail": {"error": ""}}) is False

    def test_returns_false_for_different_error(self):
        assert (
            Exploit()._parse_response({"detail": {"error": "SomeOtherError"}}) is False
        )

    def test_returns_false_when_no_error_key(self):
        assert Exploit()._parse_response({"detail": {"message": "something"}}) is False


# ---------------------------------------------------------------------------
# _blocking_boilerplate (static)
# ---------------------------------------------------------------------------


class TestBlockingBoilerplate:
    def test_indents_code(self):
        component_code, _ = Exploit._blocking_boilerplate("x = 1\ny = 2")
        assert "        x = 1" in component_code
        assert "        y = 2" in component_code

    def test_single_line(self):
        component_code, _ = Exploit._blocking_boilerplate("x = 1")
        assert "        x = 1" in component_code

    def test_returns_matching_method_name(self):
        """The method name in the source code must match the returned method_name."""
        component_code, method_name = Exploit._blocking_boilerplate("pass")
        assert f"def {method_name}" in component_code
        assert f"method='{method_name}'" in component_code

    def test_identifiers_are_randomized(self):
        """Each call must produce a different method name."""
        _, method_a = Exploit._blocking_boilerplate("pass")
        _, method_b = Exploit._blocking_boilerplate("pass")
        assert method_a != method_b


# ---------------------------------------------------------------------------
# trigger_vuln
# ---------------------------------------------------------------------------


class TestTriggerVuln:
    def test_non_blocking_returns_response(self):
        mock_resp = _mock_resp(200, {"result": "ok"})
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_18729.post",
            return_value=mock_resp,
        ):
            assert (
                exploit.trigger_vuln(
                    base_url=_BASE_URL, auth=_AUTH_HEADERS, code="x = 1"
                )
                is mock_resp
            )

    def test_network_error_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_18729.post",
            side_effect=ConnectionError("refused"),
        ):
            assert (
                exploit.trigger_vuln(base_url=_BASE_URL, auth=_AUTH_HEADERS, code="x=1")
                is None
            )


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

    def test_200_returns_true(self):
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
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_18729.post",
                return_value=_mock_resp(200, {"result": "ok"}),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is True
            )

    def test_400_with_zero_division_returns_true(self):
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
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_18729.post",
                return_value=_mock_resp(
                    400, {"detail": {"error": "ZeroDivisionError(division by zero)"}}
                ),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is True
            )

    def test_trigger_none_returns_false(self):
        """trigger_vuln returning None (network error) → exploit returns False."""
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
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_18729.post",
                side_effect=ConnectionError("refused"),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is False
            )

    def test_custom_payload_with_blocking(self):
        payload = MagicMock()
        payload.load_payload.return_value = "x = 99"
        payload.blocking = True
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
            patch.object(
                exploit,
                "_upload_flow",
                return_value="flow-abc123",
            ) as mock_upload,
            patch.object(exploit, "_trigger_flow"),
            patch.object(exploit, "_delete_flow"),
        ):
            result = exploit.exploit(
                base_url=_BASE_URL, username="admin", password="secret", payload=payload
            )
        assert result is True
        uploaded_code = mock_upload.call_args.kwargs["component_code"]
        assert "        x = 99" in uploaded_code


# ---------------------------------------------------------------------------
# _upload_flow
# ---------------------------------------------------------------------------


class TestUploadFlow:
    def test_returns_flow_id_on_200(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_18729.post",
            return_value=_mock_resp(200, {"id": "flow-abc"}),
        ):
            assert (
                exploit._upload_flow(
                    base_url=_BASE_URL,
                    auth=_AUTH_HEADERS,
                    component_code="x = 1",
                    method_name="run",
                )
                == "flow-abc"
            )

    def test_returns_flow_id_on_201(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_18729.post",
            return_value=_mock_resp(201, {"id": "flow-xyz"}),
        ):
            assert (
                exploit._upload_flow(
                    base_url=_BASE_URL,
                    auth=_AUTH_HEADERS,
                    component_code="x = 1",
                    method_name="run",
                )
                == "flow-xyz"
            )

    def test_non_200_201_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_18729.post",
            return_value=_mock_resp(400, {"error": "bad request"}),
        ):
            assert (
                exploit._upload_flow(
                    base_url=_BASE_URL,
                    auth=_AUTH_HEADERS,
                    component_code="x = 1",
                    method_name="run",
                )
                is None
            )

    def test_network_error_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_18729.post",
            side_effect=ConnectionError("refused"),
        ):
            assert (
                exploit._upload_flow(
                    base_url=_BASE_URL,
                    auth=_AUTH_HEADERS,
                    component_code="x = 1",
                    method_name="run",
                )
                is None
            )

    def test_embeds_component_code_in_payload(self):
        """The component_code value must appear in the flow JSON sent to the server."""
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_18729.post",
            return_value=_mock_resp(201, {"id": "flow-1"}),
        ) as mock_post:
            exploit._upload_flow(
                base_url=_BASE_URL,
                auth=_AUTH_HEADERS,
                component_code="SENTINEL_CODE",
                method_name="run",
            )
        sent_json = mock_post.call_args.kwargs["json"]
        code_value = sent_json["data"]["nodes"][0]["data"]["node"]["template"]["code"][
            "value"
        ]
        assert "SENTINEL_CODE" in code_value

    def test_method_name_appears_in_flow_manifest(self):
        """The method_name passed to _upload_flow must appear in the outputs manifest."""
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_18729.post",
            return_value=_mock_resp(201, {"id": "flow-1"}),
        ) as mock_post:
            exploit._upload_flow(
                base_url=_BASE_URL,
                auth=_AUTH_HEADERS,
                component_code="x = 1",
                method_name="my_sentinel_method",
            )
        sent_json = mock_post.call_args.kwargs["json"]
        output_method = sent_json["data"]["nodes"][0]["data"]["node"]["outputs"][0][
            "method"
        ]
        assert output_method == "my_sentinel_method"


# ---------------------------------------------------------------------------
# _trigger_flow
# ---------------------------------------------------------------------------


class TestTriggerFlow:
    def test_returns_true_on_success(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_18729.post",
            return_value=_mock_resp(200),
        ):
            assert (
                exploit._trigger_flow(
                    base_url=_BASE_URL, auth=_AUTH_HEADERS, flow_id="flow-1"
                )
                is True
            )

    def test_network_error_still_returns_true(self):
        """A network error on trigger is the expected reverse-shell success signal."""
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_18729.post",
            side_effect=ConnectionError("refused"),
        ):
            assert (
                exploit._trigger_flow(
                    base_url=_BASE_URL, auth=_AUTH_HEADERS, flow_id="flow-1"
                )
                is True
            )


# ---------------------------------------------------------------------------
# _delete_flow
# ---------------------------------------------------------------------------


class TestDeleteFlow:
    def test_success_does_not_raise(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_18729.delete",
            return_value=_mock_resp(200),
        ):
            exploit._delete_flow(
                base_url=_BASE_URL, auth=_AUTH_HEADERS, flow_id="flow-1"
            )

    def test_network_error_does_not_raise(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_18729.delete",
            side_effect=ConnectionError("refused"),
        ):
            exploit._delete_flow(
                base_url=_BASE_URL, auth=_AUTH_HEADERS, flow_id="flow-1"
            )


# ---------------------------------------------------------------------------
# exploit — blocking path with real _upload_flow / _trigger_flow / _delete_flow
# ---------------------------------------------------------------------------


class TestExploitBlockingPath:
    def test_upload_failure_returns_false(self):
        """If _upload_flow returns None the exploit halts and returns False."""
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
            patch.object(exploit, "_upload_flow", return_value=None),
        ):
            payload = MagicMock()
            payload.load_payload.return_value = "x = 1"
            payload.blocking = True
            assert (
                exploit.exploit(
                    base_url=_BASE_URL,
                    username="admin",
                    password="secret",
                    payload=payload,
                )
                is False
            )

    def test_full_blocking_path_calls_all_three_methods(self):
        """exploit() must call _upload_flow, _trigger_flow, and _delete_flow in order."""
        exploit = Exploit()
        call_order = []

        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get",
                return_value=_mock_auto_login_disabled(),
            ),
            patch(
                "flowhound.vulnerabilities.clients.langflow.post",
                return_value=_mock_auth_post(),
            ),
            patch.object(
                exploit,
                "_upload_flow",
                side_effect=lambda **_: call_order.append("upload") or "flow-1",
            ),
            patch.object(
                exploit,
                "_trigger_flow",
                side_effect=lambda **_: call_order.append("trigger"),
            ),
            patch.object(
                exploit,
                "_delete_flow",
                side_effect=lambda **_: call_order.append("delete"),
            ),
        ):
            payload = MagicMock()
            payload.load_payload.return_value = "x = 1"
            payload.blocking = True
            result = exploit.exploit(
                base_url=_BASE_URL,
                username="admin",
                password="secret",
                payload=payload,
            )

        assert result is True
        assert call_order == ["upload", "trigger", "delete"]


# ---------------------------------------------------------------------------
# exploit — non-200/non-400 terminal path (lines 287-288)
# ---------------------------------------------------------------------------


class TestExploitTerminalPath:
    def test_unexpected_status_returns_false(self):
        """A non-200, non-400 response from trigger_vuln returns False."""
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
                return_value=_mock_resp(500),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="admin", password="secret")
                is False
            )
