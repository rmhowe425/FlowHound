from requests import get, post

from flowhound.vulnerabilities.clients.base import TargetClient


class LangflowClient(TargetClient):
    """
    Client adapter for interacting and authenticating with Langflow instances.
    """

    def auto_login(self) -> dict[str, str] | None:
        """
        Authenticate with Langflow using the Langflow auto_login endpoint.

        Returns
        -------
        dict[str, str] | None
            HTTP authentication header or None.
        """
        endpoint = "/api/v1/auto_login"
        headers = {"Content-Type": "application/json"}

        try:
            resp = get(
                f"{self.base_url}{endpoint}",
                headers=headers,
                timeout=self.timeout,
                proxies=self.proxies,
            )
        except Exception as e:
            raise RuntimeError(f"Error querying API.\n{e!s}") from e

        if resp.status_code == 200:
            resp_json = resp.json()
            headers["Authorization"] = f"Bearer {resp_json['access_token']}"
            return headers

        self.logger.warning(
            f"Unable to authenticate, `{endpoint}` returned with {resp.status_code}. "
            "Verify that auto login is enabled."
        )
        return None

    def authenticate(self, username: str, password: str) -> dict[str, str] | None:
        """
        Authenticate with Langflow using the /api/v1/login endpoint.

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
        endpoint = "/api/v1/login"
        headers = {"Content-Type": "application/json"}

        try:
            resp = post(
                f"{self.base_url}{endpoint}",
                data={"username": username, "password": password},
                timeout=self.timeout,
                proxies=self.proxies,
            )
            resp_json = resp.json()
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(f"Unable to authenticate with Langflow: {e!s}")

        if resp.status_code == 200:
            headers["Authorization"] = f"Bearer {resp_json['access_token']}"
            return headers

        self.logger.warning(
            f"Unable to authenticate, `{endpoint}` returned with {resp.status_code}"
        )
        return None
