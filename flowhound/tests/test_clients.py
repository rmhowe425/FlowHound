from unittest.mock import MagicMock, patch

import pytest

from flowhound.vulnerabilities.clients.base import TargetClient
from flowhound.vulnerabilities.clients.langflow import LangflowClient
from flowhound.vulnerabilities.clients.mlflow import MLflowClient

# ---------------------------------------------------------------------------
# TargetClient (Base class)
# ---------------------------------------------------------------------------


class ConcreteClient(TargetClient):
    def authenticate(self, username: str, password: str) -> dict[str, str] | None:
        return {"Authorization": f"User {username}:{password}"}


def test_target_client_initialization():
    client = ConcreteClient(
        base_url="http://localhost:7860/", proxies={"http": "http://127.0.0.1:8080"}
    )
    assert client.base_url == "http://localhost:7860"
    assert client.proxies == {"http": "http://127.0.0.1:8080"}
    assert client.timeout == 20
    assert client.auto_login() is None
    assert client.logger.name == ConcreteClient.__module__


# ---------------------------------------------------------------------------
# LangflowClient
# ---------------------------------------------------------------------------


def test_langflow_auto_login_success():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"access_token": "test-token-abc"}

    with patch(
        "flowhound.vulnerabilities.clients.langflow.get",
        return_value=mock_resp,
    ):
        client = LangflowClient(base_url="http://localhost:7860")
        headers = client.auto_login()

    assert headers is not None
    assert headers["Authorization"] == "Bearer test-token-abc"
    assert headers["Content-Type"] == "application/json"


def test_langflow_auto_login_non_200_returns_none():
    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.json.return_value = {}

    with patch(
        "flowhound.vulnerabilities.clients.langflow.get",
        return_value=mock_resp,
    ):
        client = LangflowClient(base_url="http://localhost:7860")
        result = client.auto_login()

    assert result is None


def test_langflow_auto_login_network_error_raises_runtime_error():
    with patch(
        "flowhound.vulnerabilities.clients.langflow.get",
        side_effect=ConnectionError("refused"),
    ):
        client = LangflowClient(base_url="http://localhost:7860")
        with pytest.raises(RuntimeError, match="Error querying API"):
            client.auto_login()


def test_langflow_authenticate_success():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"access_token": "user-token-xyz"}

    with patch(
        "flowhound.vulnerabilities.clients.langflow.post",
        return_value=mock_resp,
    ):
        client = LangflowClient(base_url="http://localhost:7860")
        headers = client.authenticate(username="admin", password="secret")

    assert headers is not None
    assert headers["Authorization"] == "Bearer user-token-xyz"
    assert "Content-Type" not in headers


def test_langflow_authenticate_non_200_returns_none():
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.json.return_value = {"detail": "Unauthorized"}

    with patch(
        "flowhound.vulnerabilities.clients.langflow.post",
        return_value=mock_resp,
    ):
        client = LangflowClient(base_url="http://localhost:7860")
        result = client.authenticate(username="admin", password="wrongpass")

    assert result is None


def test_langflow_authenticate_network_error_raises_runtime_error():
    with patch(
        "flowhound.vulnerabilities.clients.langflow.post",
        side_effect=ConnectionError("refused"),
    ):
        client = LangflowClient(base_url="http://localhost:7860")
        with pytest.raises(RuntimeError, match="Unable to authenticate with Langflow"):
            client.authenticate(username="admin", password="secret")


# ---------------------------------------------------------------------------
# MLflowClient
# ---------------------------------------------------------------------------


def test_mlflow_authenticate_success():
    mock_resp = MagicMock()
    mock_resp.status_code = 200

    with patch(
        "flowhound.vulnerabilities.clients.mlflow.get",
        return_value=mock_resp,
    ):
        client = MLflowClient(base_url="http://localhost:5000")
        headers = client.authenticate(username="admin", password="secret")

    assert headers is not None
    assert headers["Authorization"].startswith("Basic ")
    assert headers["Content-Type"] == "application/json"


def test_mlflow_authenticate_non_200_returns_none():
    mock_resp = MagicMock()
    mock_resp.status_code = 401

    with patch(
        "flowhound.vulnerabilities.clients.mlflow.get",
        return_value=mock_resp,
    ):
        client = MLflowClient(base_url="http://localhost:5000")
        result = client.authenticate(username="admin", password="wrongpass")

    assert result is None


def test_mlflow_authenticate_network_error_raises_runtime_error():
    with patch(
        "flowhound.vulnerabilities.clients.mlflow.get",
        side_effect=ConnectionError("refused"),
    ):
        client = MLflowClient(base_url="http://localhost:5000")
        with pytest.raises(RuntimeError, match="Unable to authenticate with MLflow"):
            client.authenticate(username="admin", password="secret")
