import re
from urllib.parse import urlparse

import click


def validate_url(ctx, param, value) -> str:
    try:
        result = urlparse(value)
    except Exception:  # noqa: BLE001
        raise click.BadParameter(f"Malformed URL: {value}")

    if not result.scheme in ("http", "https") or not bool(result.netloc):
        raise click.BadParameter(f"Malformed URL: {value}")

    return value


def validate_proxy(ctx, param, value) -> dict:
    if value is None:
        return value

    try:
        result = urlparse(value)
    except Exception:  # noqa: BLE001
        raise click.BadParameter(f"Malformed URL: {value}")

    if not result.scheme in ("http", "https") or not bool(result.netloc):
        raise click.BadParameter(f"Malformed URL: {value}")

    return {"http": value, "https": value}


def validate_cve(ctx, param, value) -> str:
    val_lowered = value.lower()
    if value and not re.match("cve-\\d{4}-\\d{4,7}", val_lowered):
        raise click.BadParameter("Must provide a correctly formatted CVE code.")

    return val_lowered
