from collections.abc import Callable

from requests import get
from requests.exceptions import RequestException

# Re-exported for callers that import these from this module directly
# (e.g. flowhound.vulnerabilities.io.database). The canonical definitions
# live in flowhound.vulnerabilities.utils to avoid cross-layer coupling.
from flowhound.vulnerabilities.utils import (  # noqa: F401
    convert_tuple_to_version,
    convert_version_to_tuple,
)


def get_langflow_target_version(
    base_url: str, proxies: dict[str, str] | None = None
) -> str:
    """
    Retrieves package version of targeted
    Langflow instance.

    Parameters
    ----------
    base_url : str
        URL of target Langflow instance.
    proxies: dict[str, str] | None
        HTTP(s) proxy to use for network I/O operations

    Returns
    -------
    Langflow version string.
    """
    endpoint = "/api/v1/version"
    package_name = "Langflow"

    try:
        resp = get(base_url + endpoint, timeout=20, proxies=proxies)
        resp_json = resp.json()
    except (RequestException, OSError) as e:
        raise RuntimeError(f"Error retrieving target Langflow version: {e!s}")

    if resp.status_code != 200 or not resp_json.get("version"):
        raise RuntimeError("Unable to retrieve Langflow version.")
    elif resp_json.get("package") != package_name:
        raise RuntimeError("target does not appear to be a Langflow instance.")

    return resp_json["version"]


def get_mlflow_target_version(
    base_url: str, proxies: dict[str, str] | None = None
) -> str:
    """
    Retrieves package version of targeted
    MLFlow instance.

    Parameters
    ----------
    base_url : str
        URL of target MLFlow instance.
    proxies: dict[str, str] | None
        HTTP(s) proxy to use for network I/O operations

    Returns
    -------
    MLFlow version string.
    """
    endpoint = "/version"

    try:
        resp = get(base_url + endpoint, timeout=20, proxies=proxies)
        version = resp.text.strip()
    except (RequestException, OSError) as e:
        raise RuntimeError(f"Error retrieving target MLflow version: {e}")

    if resp.status_code != 200 or not version or version.count(".") != 2:
        raise RuntimeError("Unable to retrieve MLflow version.")

    parts = version.split(".")
    if not all(part.isdigit() for part in parts):
        raise RuntimeError(
            f"Unable to retrieve MLflow version: unexpected format {version!r}."
        )

    return version


_DETECTORS: dict[str, Callable] = {
    "langflow": get_langflow_target_version,
    "mlflow": get_mlflow_target_version,
}


def supported_applications() -> frozenset[str]:
    """Return the set of canonical application names recognised by FlowHound."""
    return frozenset(_DETECTORS)


def detect_target(
    base_url: str,
    proxies: dict[str, str] | None = None,
    application: str | None = None,
) -> tuple[str, str]:
    """
    Identify the target application and retrieve its version.

    When ``application`` is provided the corresponding detector is called
    directly, skipping all other probes.  When omitted every registered
    detector is tried in sequence and the first successful match is returned.

    Parameters
    ----------
    base_url : str
        URL of the target instance.
    proxies : dict[str, str] | None
        HTTP(s) proxy to use for network I/O operations.
    application : str | None
        Optional canonical application name (e.g. "langflow", "mlflow").
        When supplied, auto-detection is skipped entirely.

    Returns
    -------
    A (application, version) tuple where application is the canonical
    lowercase product name (e.g. "langflow", "mlflow") and version is
    the semver string (e.g. "1.10.0").

    Raises
    ------
    RuntimeError
        If no supported product is detected at the target URL.
    """
    if application is not None:
        app_key = application.lower()
        version = _DETECTORS[app_key](base_url=base_url, proxies=proxies)
        return (app_key, version)

    for app_key, detector_fn in _DETECTORS.items():
        try:
            version = detector_fn(base_url=base_url, proxies=proxies)
            return (app_key, version)
        except RuntimeError:
            continue

    raise RuntimeError(
        f"Could not identify a supported application at {base_url}. "
        "Target may not be a supported product, or may be unreachable."
    )
