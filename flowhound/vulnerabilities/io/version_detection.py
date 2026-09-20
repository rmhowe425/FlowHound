from requests import get


def convert_version_to_tuple(target_version: str) -> tuple[int, int, int]:
    """
    Convert a semantic version string into a comparable tuple.

    Parameters
    ----------
    target_version : str
        Version of a running Langflow instance.

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
        raise ValueError('`target_version` must be a non-empty string.')
    elif target_version.count('.') != 2:
        raise ValueError('`target_version` must take the form: `x.x.x`.')

    major, minor, patch = target_version.split(".")
    return (int(major), int(minor), int(patch))


def convert_tuple_to_version(target_version: tuple) -> str:
    """
    Convert a (major, minor, patch) tuple into a semantic version string.

    Parameters
    ----------
    target_version : tuple
        (major, minor, patch) representation of the running
        Langflow instance version.

    Returns
    -------
    Human-readable string representation of the running
    Langflow instance version.
    """
    if (
        not isinstance(target_version, (tuple, list))
        or len(target_version) != 3
        or not all(isinstance(v, int) for v in target_version)
    ):
        raise ValueError("Invalid version tuple. `target_version` must be a (major, minor, patch) tuple of ints.")

    major, minor, patch = target_version
    return f"{major}.{minor}.{patch}"


def get_target_version(base_url: str, proxies: dict[str, str] | None = None) -> str:
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
    endpoint = '/api/v1/version'

    try:
        resp = get(base_url + endpoint, timeout=20, proxies=proxies)
        resp_json = resp.json()
    except Exception as e:
        raise RuntimeError(f"Error retrieving target Langflow version: {str(e)}")

    if resp.status_code != 200 or not resp_json.get('version'):
        raise RuntimeError("Unable to retrieve Langflow version.")

    return resp_json['version']
