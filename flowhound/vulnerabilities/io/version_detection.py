from collections.abc import Callable

from requests import get
from requests.exceptions import RequestException


def convert_version_to_tuple(target_version: str) -> tuple[int, int, int]:
    """
    Convert a semantic version string into a comparable tuple.

    Parameters
    ----------
    target_version : str
        Application version of a running target instance.

    Returns
    -------
    Tuple of (major, minor, patch) integers.

    Examples
    --------
    '1.0.0'  -> (1, 0, 0)
    '1.8.4'  -> (1, 8, 4)
    '1.10.0' -> (1, 10, 0)
    """
    if not isinstance(target_version, str) or not target_version:
        raise ValueError("`target_version` must be a non-empty string.")
    elif target_version.count(".") != 2:
        raise ValueError("`target_version` must take the form: `x.x.x`.")

    major, minor, patch = target_version.split(".")
    return (int(major), int(minor), int(patch))


def convert_tuple_to_version(target_version: tuple) -> str:
    """
    Convert a (major, minor, patch) tuple into a semantic version string.

    Parameters
    ----------
    target_version : tuple
        (major, minor, patch) representation of the running
        application instance version.

    Returns
    -------
    Human-readable string representation of the running
    target instance version.
    """
    if (
        not isinstance(target_version, (tuple, list))
        or len(target_version) != 3
        or not all(isinstance(v, int) for v in target_version)
    ):
        raise ValueError(
            "Invalid version tuple. `target_version` must be a (major, minor, patch) tuple of ints."
        )

    major, minor, patch = target_version
    return f"{major}.{minor}.{patch}"


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
        version = resp.text
    except (RequestException, OSError) as e:
        raise RuntimeError(f"Error retrieving target MLflow version: {e}")

    if resp.status_code != 200 or not version or version.count(".") != 2:
        raise RuntimeError("Unable to retrieve MLflow version.")

    return version


_DETECTORS: dict[str, Callable] = {
    "langflow": get_langflow_target_version,
    "mlflow": get_mlflow_target_version,
}


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
    ValueError
        If ``application`` is supplied but is not a recognised product.
    RuntimeError
        If no supported product is detected at the target URL.
    """
    if application is not None:
        app_key = application.lower()
        if app_key not in _DETECTORS:
            raise ValueError(
                f"Unrecognised application {application!r}. "
                f"Supported values: {', '.join(sorted(_DETECTORS))}."
            )
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
