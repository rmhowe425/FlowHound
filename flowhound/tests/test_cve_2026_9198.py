"""Tests for flowhound.vulnerabilities.exploits.cve_2026_9198."""

from unittest.mock import MagicMock, patch

import pytest

from flowhound.vulnerabilities.exploits.cve_2026_9198 import Exploit

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
# trigger_vuln
# ---------------------------------------------------------------------------


class TestTriggerVuln:
    def test_returns_response_on_success(self):
        mock_resp = _mock_resp(200, {"detail": "ok"})
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_9198.post",
            return_value=mock_resp,
        ):
            result = exploit.trigger_vuln(
                base_url=_BASE_URL, headers=_AUTH_HEADERS, code="x = 1"
            )
        assert result is mock_resp

    def test_network_error_raises_runtime_error(self):
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_9198.post",
                side_effect=ConnectionError("refused"),
            ),
            pytest.raises(RuntimeError, match="Error querying API"),
        ):
            exploit.trigger_vuln(
                base_url=_BASE_URL, headers=_AUTH_HEADERS, code="x = 1"
            )

    def test_passes_proxies(self):
        mock_resp = _mock_resp(200)
        proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_9198.post",
            return_value=mock_resp,
        ) as mock_post:
            exploit.trigger_vuln(
                base_url=_BASE_URL,
                headers=_AUTH_HEADERS,
                code="x = 1",
                proxies=proxies,
            )
        assert mock_post.call_args.kwargs["proxies"] == proxies

    def test_empty_code_string(self):
        mock_resp = _mock_resp(200)
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_9198.post",
            return_value=mock_resp,
        ):
            result = exploit.trigger_vuln(base_url=_BASE_URL, headers={}, code="")
        assert result is mock_resp

    def test_malicious_code_injection_does_not_raise_locally(self):
        mock_resp = _mock_resp(200)
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_9198.post",
            return_value=mock_resp,
        ):
            result = exploit.trigger_vuln(
                base_url=_BASE_URL, headers={}, code="'; DROP TABLE users; --"
            )
        assert result is mock_resp


# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------


class TestExploit:
    def test_returns_true_on_200(self):
        # cve_2026_9198 uses auto_login() which calls langflow.get
        auth_resp = _mock_resp(200, {"access_token": "test-token"})
        vuln_resp = _mock_resp(200, {"result": "uid=0(root)"})
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get", return_value=auth_resp
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_9198.post",
                return_value=vuln_resp,
            ),
        ):
            result = exploit.exploit(
                base_url=_BASE_URL, username="admin", password="secret"
            )
        assert result is True

    def test_returns_false_on_non_200(self):
        auth_resp = _mock_resp(200, {"access_token": "test-token"})
        vuln_resp = _mock_resp(400, {"detail": "error"})
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get", return_value=auth_resp
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_9198.post",
                return_value=vuln_resp,
            ),
        ):
            result = exploit.exploit(
                base_url=_BASE_URL, username="admin", password="secret"
            )
        assert result is False

    def test_auth_failure_returns_false(self):
        auth_resp = _mock_resp(401, {})
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.clients.langflow.get", return_value=auth_resp
        ):
            result = exploit.exploit(
                base_url=_BASE_URL, username="admin", password="wrong"
            )
        assert result is False

    def test_uses_custom_payload(self):
        auth_resp = _mock_resp(200, {"access_token": "test-token"})
        vuln_resp = _mock_resp(200, {"result": "custom_output"})
        payload = MagicMock()
        payload.load_payload.return_value = "x = 99"
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get", return_value=auth_resp
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_9198.post",
                return_value=vuln_resp,
            ) as mock_post,
        ):
            result = exploit.exploit(
                base_url=_BASE_URL, username="admin", password="secret", payload=payload
            )
        assert result is True
        payload.load_payload.assert_called_once()
        assert "x = 99" in mock_post.call_args.kwargs["json"]["code"]

    def test_uses_default_code_when_no_payload(self):
        auth_resp = _mock_resp(200, {"access_token": "test-token"})
        vuln_resp = _mock_resp(200, {"result": "uid=0"})
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get", return_value=auth_resp
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_9198.post",
                return_value=vuln_resp,
            ) as mock_post,
        ):
            exploit.exploit(base_url=_BASE_URL, username="", password="")
        assert "subprocess" in mock_post.call_args.kwargs["json"]["code"]

    def test_with_proxies(self):
        auth_resp = _mock_resp(200, {"access_token": "test-token"})
        vuln_resp = _mock_resp(200, {"r": "ok"})
        proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
        exploit = Exploit()
        with (
            patch(
                "flowhound.vulnerabilities.clients.langflow.get", return_value=auth_resp
            ),
            patch(
                "flowhound.vulnerabilities.exploits.cve_2026_9198.post",
                return_value=vuln_resp,
            ),
        ):
            result = exploit.exploit(
                base_url=_BASE_URL, username="admin", password="secret", proxies=proxies
            )
        assert result is True
