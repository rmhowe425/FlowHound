import logging
import click
from flowhound.cli.command import attack, sniff
from flowhound.cli.message_format import ClickLogHandler
from flowhound.vulnerabilities.io.database import Database

_logger = logging.getLogger("flowhound")
_logger.setLevel(logging.INFO)
if not _logger.handlers:
    _logger.addHandler(ClickLogHandler())

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.group(context_settings=CONTEXT_SETTINGS)
@click.pass_context
def main(ctx: click.Context):
    ctx.ensure_object(dict)
    ctx.obj = Database()

main.add_command(attack)
main.add_command(sniff)

if __name__ == '__main__':
    main()
