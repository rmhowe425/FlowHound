import re
from urllib.parse import urlparse

import click

from flowhound.vulnerabilities.io.version_detection import supported_applications


def validate_url(ctx, param, value) -> str:
    try:
        result = urlparse(value)
    except Exception:  # noqa: BLE001
        raise click.BadParameter(f"Malformed URL: {value}")

    if result.scheme not in ("http", "https") or not bool(result.netloc):
        raise click.BadParameter(f"Malformed URL: {value}")

    return value


def validate_file_path(ctx, param, value) -> str | None:
    if value is None:
        return None

    if not value.strip():
        raise click.BadParameter("File path cannot be empty.")

    return value


def validate_proxy(ctx, param, value) -> dict[str, str] | None:
    if value is None:
        return value

    try:
        result = urlparse(value)
    except Exception:  # noqa: BLE001
        raise click.BadParameter(f"Malformed URL: {value}")

    if result.scheme not in ("http", "https") or not bool(result.netloc):
        raise click.BadParameter(f"Malformed URL: {value}")

    return {"http": value, "https": value}


def validate_application(ctx, param, value) -> str | None:
    if value is None:
        return value

    app_key = value.lower()
    apps = supported_applications()
    if app_key not in apps:
        raise click.BadParameter(
            f"Unsupported application {value!r}. "
            f"Supported values: {', '.join(sorted(apps))}."
        )

    return app_key


def validate_cve(ctx, param, value) -> str | None:
    if value is None:
        return None

    val_lowered = value.lower()
    if not re.match(r"^cve-\d{4}-\d{4,7}$", val_lowered):
        raise click.BadParameter("Must provide a correctly formatted CVE code.")

    return val_lowered


def validate_authentication(username: str | None, password: str | None) -> bool:
    """Validate username and password pair.

    Returns True if both are provided, False if neither is provided.
    Raises click.BadParameter if only one is provided.
    """
    if username and password:
        return True
    if username or password:
        raise click.BadParameter(
            "`--username` and `--password` must be provided together."
        )

    return False


def validate_payload_args(
    cmd: str | None,
    reverse_shell: str | None,
    bind_shell: str | None,
    bind_langflow_http: str | None = None,
) -> tuple[str, int] | None:
    """Validate command, reverse_shell, bind_shell, and bind_langflow_http arguments.

    Returns:
        tuple[str, int]: (host, port) if a shell option is valid.
        None: if cmd is provided or no shell option is provided.

    Raises:
        click.UsageError: If mutually exclusive options are combined.
        click.BadParameter: If the shell option has an invalid format or port range.
    """
    shell_flags = {
        "--command": cmd,
        "--reverse_shell": reverse_shell,
        "--bind_shell": bind_shell,
        "--bind_langflow_http": bind_langflow_http,
    }
    active = [name for name, val in shell_flags.items() if val]
    if len(active) > 1:
        raise click.UsageError(f"{' and '.join(active)} are mutually exclusive.")

    shell_value, flag_name = (
        (reverse_shell, "--reverse_shell")
        if reverse_shell
        else (bind_shell, "--bind_shell")
        if bind_shell
        else (bind_langflow_http, "--bind_langflow_http")
        if bind_langflow_http
        else (None, None)
    )

    if shell_value is None:
        return None

    try:
        host, port_str = shell_value.rsplit(":", 1)
        port = int(port_str)
    except ValueError:
        raise click.BadParameter(
            f"{flag_name} must be formatted as HOST:PORT (e.g. 192.168.1.10:4444)."
        )

    if not (1 <= port <= 65535):
        raise click.BadParameter("Port must be between 1 and 65535.")

    if flag_name in ("--bind_shell", "--bind_langflow_http") and host in (
        "0.0.0.0",
        "",
    ):
        raise click.BadParameter(
            f"{flag_name} HOST must be the victim's reachable IP address, not a wildcard. "
            f"Example: {flag_name} 192.168.1.30:7860"
        )

    return host, port
