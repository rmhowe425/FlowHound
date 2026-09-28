"""Tests for flowhound.vulnerabilities.exploits.cve_2026_0768."""

from unittest.mock import MagicMock, patch

from flowhound.vulnerabilities.exploits.cve_2026_0768 import Exploit

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
        assert "PwnComponent" in result
        assert "CVE-2026-0768-Probe" in result

    def test_empty_code(self):
        result = Exploit._blocking_boilerplate("")
        assert "PwnComponent" in result
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
# trigger_vuln
# ---------------------------------------------------------------------------


class TestTriggerVuln:
    def test_non_blocking_appends_boilerplate(self):
        mock_resp = _mock_resp(200)
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_0768.post",
            return_value=mock_resp,
        ) as mock_post:
            result = exploit.trigger_vuln(
                base_url=_BASE_URL, code="x = 1", blocking=False
            )
        assert result is mock_resp
        body = mock_post.call_args.kwargs["json"]["code"]
        assert "x = 1" in body
        assert "PwnComponent" in body

    def test_blocking_uses_blocking_boilerplate(self):
        mock_resp = _mock_resp(200)
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_0768.post",
            return_value=mock_resp,
        ) as mock_post:
            result = exploit.trigger_vuln(
                base_url=_BASE_URL, code="x = 1", blocking=True
            )
        assert result is mock_resp
        assert "        x = 1" in mock_post.call_args.kwargs["json"]["code"]

    def test_network_error_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_0768.post",
            side_effect=ConnectionError("refused"),
        ):
            result = exploit.trigger_vuln(base_url=_BASE_URL, code="x=1")
        assert result is None

    def test_passes_proxies(self):
        proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_0768.post",
            return_value=_mock_resp(200),
        ) as mock_post:
            exploit.trigger_vuln(base_url=_BASE_URL, code="x=1", proxies=proxies)
        assert mock_post.call_args.kwargs["proxies"] == proxies


# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------


class TestExploit:
    def test_returns_true_on_200(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_0768.post",
            return_value=_mock_resp(200, {"result": "uid=0"}),
        ):
            assert exploit.exploit(base_url=_BASE_URL, username="", password="") is True

    def test_returns_false_on_non_200(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_0768.post",
            return_value=_mock_resp(403, {"detail": "forbidden"}),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="", password="") is False
            )

    def test_returns_false_when_trigger_vuln_returns_none(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_0768.post",
            side_effect=ConnectionError("refused"),
        ):
            assert (
                exploit.exploit(base_url=_BASE_URL, username="", password="") is False
            )

    def test_custom_payload_blocking(self):
        payload = MagicMock()
        payload.load_payload.return_value = "import os; os.system('id')"
        payload.blocking = True
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_0768.post",
            return_value=_mock_resp(200, {"result": "ok"}),
        ) as mock_post:
            assert (
                exploit.exploit(
                    base_url=_BASE_URL, username="", password="", payload=payload
                )
                is True
            )
        assert (
            "        import os; os.system('id')"
            in mock_post.call_args.kwargs["json"]["code"]
        )

    def test_custom_payload_non_blocking(self):
        payload = MagicMock()
        payload.load_payload.return_value = "x = 42"
        payload.blocking = False
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_0768.post",
            return_value=_mock_resp(200, {"result": "ok"}),
        ) as mock_post:
            exploit.exploit(
                base_url=_BASE_URL, username="", password="", payload=payload
            )
        assert "x = 42" in mock_post.call_args.kwargs["json"]["code"]

    def test_default_code_non_blocking(self):
        exploit = Exploit()
        with patch(
            "flowhound.vulnerabilities.exploits.cve_2026_0768.post",
            return_value=_mock_resp(200, {"result": "ok"}),
        ) as mock_post:
            exploit.exploit(base_url=_BASE_URL, username="", password="")
        body = mock_post.call_args.kwargs["json"]["code"]
        assert "subprocess" in body
        assert "PwnComponent" in body
