import logging
import sys

from pandas import DataFrame

logger = logging.getLogger(__name__)


def generate_report(findings: list[dict], f_name: str):
    """
    Generates a report of findings based on exploit attempts.

    Parameters
    ----------
    findings : list[dict]
        List of findings from exploit attempts.
    f_name : str
        Name of file to generate.
    """
    try:
        df = DataFrame(findings)
    except ValueError as e:
        logger.error("Report generation failed: %s", e)
        sys.exit(1)

    file_handlers = {"json": df.to_json, "csv": df.to_csv, "xlsx": df.to_excel}

    extension = f_name.rsplit(".", 1)[-1]

    if extension not in file_handlers:
        f_types = ", ".join(file_handlers)
        logger.error("Supported file types are: %s", f_types)
        sys.exit(1)

    file_handlers[extension](f_name)
