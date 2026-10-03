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

    if not value.startswith("/"):
        raise click.BadParameter(
            f"File path must be an absolute path (e.g. /etc/passwd): {value!r}"
        )

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
    cmd: str | None, reverse_shell: str | None
) -> tuple[str, int] | None:
    """Validate command and reverse_shell arguments.

    Returns:
        tuple[str, int]: (lhost, lport) if reverse_shell is valid.
        None: if cmd is provided or neither is provided.

    Raises:
        click.UsageError: If both cmd and reverse_shell are provided.
        click.BadParameter: If reverse_shell has invalid format or port range.
    """
    if cmd and reverse_shell:
        raise click.UsageError("--command and --reverse_shell are mutually exclusive.")

    if reverse_shell:
        try:
            lhost, lport_str = reverse_shell.rsplit(":", 1)
            lport = int(lport_str)
        except ValueError:
            raise click.BadParameter(
                "--reverse_shell must be formatted as LHOST:LPORT (e.g. 192.168.1.10:4444)."
            )

        if not (1 <= lport <= 65535):
            raise click.BadParameter("Port must be between 1 and 65535.")

        return lhost, lport

    return None
