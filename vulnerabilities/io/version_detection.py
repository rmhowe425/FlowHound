from requests import get


def convert_version_to_int(target_version: str) -> int:
    """
    Convert a semantic version string into a comparable integer.

    Parameters
    ----------
    target_version : str
        Version of a running Langflow instance.

    Returns
    -------
    Integer representation of a Langflow version.

    Examples
    --------
    1.0.0  -> 1000000
    1.8.4  -> 1008004
    1.10.0 -> 1010000
    """
    if not isinstance(target_version, str) or not target_version:
        raise ValueError('`target_version` must be a non-empty string.')
    elif target_version.count('.') != 2:
        raise ValueError('`target_version` must take the form: `x.x.x`.')

    major, minor, patch = target_version.split(".")
    return (int(major) * 1_000_000 + int(minor) * 1_000 + int(patch))


def convert_int_to_version(target_version: int) -> str:
    """
    Convert a comparable integer into a semantic version string.

    Parameters
    ----------
    version : int
        Integer representation of the running
        Langflow instance version.

    Returns
    -------
    Human-readable string representation of the running
    Langflow instance version.
    """
    if not isinstance(target_version, int) or target_version <= 0:
        raise ValueError("Invalid version integer. `target_version` Must be a integer > 0.")

    major = target_version // 1_000_000
    minor = (target_version % 1_000_000) // 1_000
    patch = target_version % 1_000

    return f"{major}.{minor}.{patch}"


def get_target_version(base_url: str) -> str:
    """
    Retrieves package version of targeted
    Langflow instance.

    Parameters
    ----------
    base_url : str
        URL of target Langflow instance.

    Returns
    -------
    Langflow version string.
    """
    try:
        r = get(f"{base_url}/api/v1/version")
        r_json = r.json()
    except Exception as e:
        raise RuntimeError(f"Error retrieving target Langflow version: {str(e)}") from e

    if r.status_code != 200 or not r_json.get('version'):
        raise RuntimeError("Unable to retrieve Langflow version.")

    return r_json['version']
