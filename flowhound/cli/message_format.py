import sys
import logging
from click import echo, style


class ClickLogHandler(logging.Handler):
    """
    Routes standard logging records to click.echo with custom styling and prefixes.
    """

    LEVEL_STYLES = {
        logging.DEBUG: {"fg": "cyan", "prefix": "[-] "},
        logging.INFO: {"fg": "blue", "prefix": "[+] "},
        logging.WARNING: {"fg": "yellow", "prefix": "[!] "},
        logging.ERROR: {"fg": "red", "prefix": "[!] "},
        logging.CRITICAL: {"fg": "red", "prefix": "[CRITICAL] ", "bold": True},
    }

    EXPLOIT_LOGGER_PREFIX = "flowhound.vulnerabilities.exploits"

    def emit(self, record: logging.LogRecord):
        try:
            msg = self.format(record)
            config = self.LEVEL_STYLES.get(record.levelno, {"fg": "blue", "prefix": "[+] "}).copy()
            if record.levelno == logging.INFO and record.name.startswith(self.EXPLOIT_LOGGER_PREFIX):
                config["fg"] = "green"
            prefix = config.pop("prefix", "")
            err_stream = record.levelno >= logging.ERROR

            echo(style(f"{prefix}{msg}", **config), file=sys.stderr if err_stream else sys.stdout)
            if err_stream:
                sys.stderr.flush()
            else:
                sys.stdout.flush()
        except Exception:
            self.handleError(record)


def output_banner(msg: str):
    echo(style(msg, fg='cyan'), file=sys.stdout)
    sys.stdout.flush()
