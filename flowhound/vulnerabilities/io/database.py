import json
from pathlib import Path

from flowhound.vulnerabilities.cve.cve import CVE
from flowhound.vulnerabilities.io.version_detection import (
    convert_tuple_to_version,
    convert_version_to_tuple,
)

_REQUIRED_FIELDS = {
    "application",
    "cve_id",
    "cve_description",
    "cvss_severity",
    "min_impacted_version",
    "max_impacted_version",
    "exploit_module",
    "exploit_class",
    "auth_required",
}

_VERSION_FIELDS = ("min_impacted_version", "max_impacted_version")


class Database:
    """
    Performs CRUD operations against the bundled vulnerabilities JSON data store.
    """

    def __init__(self):
        self.db_path = Path(__file__).parent / "vulnerabilities.json"
        self.records = self._load()

    def _load(self) -> list:
        """
        Load vulnerability records from the JSON data store.

        Returns
        -------
        list of dicts representing vulnerability records.

        Raises
        ------
        FileNotFoundError
            If the JSON data store cannot be found.
        ValueError
            If any record is missing a required field.
        """
        if not self.db_path.exists():
            raise FileNotFoundError(f"[-] Data store not found: {self.db_path}")

        with open(self.db_path, "r", encoding="utf-8") as f:
            records = json.load(f)

        for i, record in enumerate(records):
            missing = _REQUIRED_FIELDS - record.keys()
            if missing:
                raise ValueError(
                    f"Record at index {i} is missing required field(s): {', '.join(sorted(missing))}"
                )
            for field in _VERSION_FIELDS:
                value = record[field]
                if value is None:
                    raise ValueError(
                        f"Record at index {i} has a null value for '{field}'. "
                        "Both version bounds are required."
                    )
                if isinstance(value, list):
                    record[field] = convert_tuple_to_version(tuple(value))

        return records

    def retrieve_vulnerabilities(
        self, application: str, target_version: str, is_auth: bool
    ):
        """
        Retrieve a list of CVEs impacting a given application instance
        based on the detected application name and version number.

        Parameters
        ----------
        application : str
            Target application name (e.g. "langflow", "mlflow").
        target_version : str
            Target application version number.
        is_auth : bool
            Represents whether application credentials
            were supplied by the user.

        Returns
        -------
        List of CVE objects returned based on `application` and `target_version`.
        """
        try:
            version_formatted = convert_version_to_tuple(target_version=target_version)
        except ValueError as e:
            raise ValueError(f"Invalid target version {target_version!r}: {e}") from e

        results = []
        for record in self.records:
            if record["application"].lower() != application.lower():
                continue
            if not (is_auth or not record["auth_required"]):
                continue
            try:
                min_ver = convert_version_to_tuple(record["min_impacted_version"])
                max_ver = convert_version_to_tuple(record["max_impacted_version"])
            except ValueError:
                continue
            if min_ver <= version_formatted <= max_ver:
                results.append(record)

        return [CVE(**record) for record in results]

    def search_vulnerabilities(self, cve: str) -> list:
        """
        Retrieves a list of CVEs based on a defined list of
        criteria to pull their corresponding exploit modules.

        Parameters
        ----------
        cve : str
            CVE ID

        Returns
        -------
        A list of CVE objects
        """
        if not cve:
            return [CVE(**record) for record in self.records]
        results = [
            record for record in self.records if record["cve_id"].lower() == cve.lower()
        ]
        return [CVE(**record) for record in results]
