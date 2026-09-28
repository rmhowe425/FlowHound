import base64

from requests import get

from flowhound.vulnerabilities.clients.base import TargetClient


class MLflowClient(TargetClient):
    """
    Client adapter for interacting and authenticating with MLflow instances.
    """

    def authenticate(self, username: str, password: str) -> dict[str, str] | None:
        """
        Authenticate with MLflow using HTTP Basic Authentication or token headers.

        Parameters
        ----------
        username : str
            Username to authenticate with.
        password : str
            Password to authenticate with.

        Returns
        -------
        dict[str, str] | None
            HTTP authentication header or None.
        """
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers = {
            "Authorization": f"Basic {token}",
            "Content-Type": "application/json",
        }

        try:
            resp = get(
                f"{self.base_url}/api/2.0/mlflow/experiments/search",
                headers=headers,
                timeout=self.timeout,
                proxies=self.proxies,
            )
        except Exception as e:
            raise RuntimeError(f"Unable to authenticate with MLflow: {e!s}") from e

        if resp.status_code == 200:
            return headers

        self.logger.warning(
            f"Unable to authenticate with MLflow, returned status code: {resp.status_code}"
        )
        return None
