import logging
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError

import click

from flowhound.cli.banner import banner
from flowhound.cli.validators import (
    validate_application,
    validate_authentication,
    validate_cve,
    validate_file_path,
    validate_payload_args,
    validate_proxy,
    validate_url,
)
from flowhound.vulnerabilities.auxiliary.base_auxiliary_class import AuxiliaryBaseClass
from flowhound.vulnerabilities.cve.cve import ModuleType
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


def _run_with_timeout(fn, *args, timeout: int = EXPLOIT_TIMEOUT, **kwargs) -> bool:
    """Submit *fn* to a single-worker pool and wait up to *timeout* seconds."""
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(fn, *args, **kwargs)
        return future.result(timeout=timeout)


def _execute_exploit(
    exploit_module,
    base_url: str,
    username: str,
    password: str,
    proxies: dict[str, str] | None,
    payload,
    timeout: int = EXPLOIT_TIMEOUT,
) -> bool:
    """Execute an exploit module with a cross-platform timeout."""
    return _run_with_timeout(
        exploit_module.exploit,
        base_url=base_url,
        username=username,
        password=password,
        proxies=proxies,
        payload=payload,
        timeout=timeout,
    )


def _execute_auxiliary(
    auxiliary_module,
    base_url: str,
    f_path: str | None,
    username: str,
    password: str,
    proxies: dict[str, str] | None,
    timeout: int = EXPLOIT_TIMEOUT,
) -> bool:
    """Execute an auxiliary module with a cross-platform timeout."""
    return _run_with_timeout(
        auxiliary_module.run,
        base_url=base_url,
        f_path=f_path,
        username=username,
        password=password,
        proxies=proxies,
        timeout=timeout,
    )


def _detect_or_fail(
    url: str, proxy: dict[str, str] | None, application: str | None
) -> tuple[str, str]:
    logger.info(f"Detecting target application at {url}...")
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
            res = db.search_vulnerabilities(cve=cve, module_type=ModuleType.EXPLOIT)
            if not res:
                all_res = db.search_vulnerabilities(cve=cve)
                if all_res:
                    raise click.ClickException(
                        f"CVE '{cve}' is not an exploit module (it is of type '{all_res[0].module_type}')."
                    )
                raise click.ClickException(f"CVE '{cve}' not found.")
            return res
        return db.retrieve_vulnerabilities(
            application=application,
            target_version=target_version,
            is_auth=is_auth,
            module_type=ModuleType.EXPLOIT,
        )
    except (ValueError, RuntimeError) as e:
        if isinstance(e, click.ClickException):
            raise
        raise click.ClickException(f"Error retrieving exploits: {e}")


def _get_all_modules(
    db: Database,
    application: str,
    target_version: str,
    is_auth: bool,
) -> list:
    try:
        return db.retrieve_vulnerabilities(
            application=application,
            target_version=target_version,
            is_auth=is_auth,
            module_type=None,
        )
    except (ValueError, RuntimeError) as e:
        raise click.ClickException(f"Error retrieving modules: {e}")


def _get_auxiliary_modules(db: Database, cve: str) -> list:
    try:
        res = db.search_vulnerabilities(cve=cve, module_type=ModuleType.AUXILIARY)
        if cve and not res:
            all_res = db.search_vulnerabilities(cve=cve)
            if all_res:
                raise click.ClickException(
                    f"CVE '{cve}' is not an auxiliary module (it is of type '{all_res[0].module_type}')."
                )
            raise click.ClickException(f"CVE '{cve}' not found.")
        return res
    except (ValueError, RuntimeError) as e:
        if isinstance(e, click.ClickException):
            raise
        raise click.ClickException(f"Error retrieving auxiliary module: {e!s}")


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
        exploit_module = vuln.get_module_instance()
        if not isinstance(exploit_module, ExploitBaseClass):
            raise click.ClickException(
                f"Module loaded for {vuln.cve_id} is not an exploit module."
            )

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
            if payload and payload.blocking:
                # A blocking payload (e.g. reverse shell) keeps the exploit
                # thread alive for the duration of the shell session. A timeout
                # here means the payload is still running — treat it as success.
                logger.info(
                    f"Exploit for {vuln.cve_id} timed out — "
                    "blocking payload is still executing. Check your listener."
                )
                result = True
            else:
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
        f"Retrieving all known modules for {application} version {target_version}:"
    )
    vuln_lst = _get_all_modules(
        db=db, application=application, target_version=target_version, is_auth=True
    )

    for vuln in vuln_lst:
        logger.info(f"[{vuln.module_type}] {vuln.module}")


@click.command(help="Launch an auxiliary module against a target instance.")
@click.option(
    "--url", required=True, help="URL of target instance", callback=validate_url
)
@click.option(
    "--f_path",
    required=False,
    default=None,
    help="File path to read from (e.g. /etc/passwd).",
    callback=validate_file_path,
)
@click.option(
    "--cve",
    required=True,
    help="Target a specific CVE (e.g. CVE-2024-1234). Limits exploitation to that CVE only.",
    callback=validate_cve,
)
@click.option("--username", required=False, default="", help="Target instance username")
@click.option("--password", required=False, default="", help="Target instance password")
@click.option(
    "--proxy",
    required=False,
    default=None,
    help="HTTP(s) proxy to use for network I/O operations",
    callback=validate_proxy,
)
@click.pass_context
def scan(
    ctx: click.Context,
    url: str,
    f_path: str,
    cve: str,
    username: str,
    password: str,
    proxy: dict[str, str] | None,
):
    banner()
    db: Database = ctx.obj
    validate_authentication(username=username, password=password)

    aux_modules = _get_auxiliary_modules(db=db, cve=cve)

    for vuln in aux_modules:
        module = vuln.get_module_instance()
        if not isinstance(module, AuxiliaryBaseClass):
            raise click.ClickException(
                f"Module loaded for {vuln.cve_id} is not an auxiliary module."
            )
        _execute_auxiliary(
            auxiliary_module=module,
            base_url=url,
            f_path=f_path,
            username=username,
            password=password,
            proxies=proxy,
        )
