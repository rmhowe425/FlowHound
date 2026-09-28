import re
from urllib.parse import urlparse

import click

from flowhound.vulnerabilities.io.version_detection import supported_applications


def validate_url(ctx, param, value) -> str:
    try:
        result = urlparse(value)
    except Exception:  # noqa: BLE001
        raise click.BadParameter(f"Malformed URL: {value}")

    if not result.scheme in ("http", "https") or not bool(result.netloc):
        raise click.BadParameter(f"Malformed URL: {value}")

    return value


def validate_proxy(ctx, param, value) -> dict | None:
    if value is None:
        return value

    try:
        result = urlparse(value)
    except Exception:  # noqa: BLE001
        raise click.BadParameter(f"Malformed URL: {value}")

    if not result.scheme in ("http", "https") or not bool(result.netloc):
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


def validate_cve(ctx, param, value) -> str:
    val_lowered = value.lower()
    if value and not re.match("cve-\\d{4}-\\d{4,7}", val_lowered):
        raise click.BadParameter("Must provide a correctly formatted CVE code.")

    return val_lowered
