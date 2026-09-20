import json
from pathlib import Path

from flowhound.vulnerabilities.cve.cve import CVE
from flowhound.vulnerabilities.io.version_detection import convert_version_to_tuple

_REQUIRED_FIELDS = {
    "cve_id",
    "cve_description",
    "cvss_severity",
    "min_impacted_version",
    "max_impacted_version",
    "exploit_module",
    "exploit_class",
    "auth_required",
}


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

        return records

    def retrieve_vulnerabilities(self, target_version: str, is_auth: bool):
        """
        Retrieve a list of CVEs impacting a given Langflow instance
        based on the detected Langflow version number.

        Parameters
        ----------
        target_version : str
            Target Langflow version number.
        is_auth : bool
            Represents whether Langflow credentials
            were supplied by the user.

        Returns
        -------
        List of CVE objects returned based on `target_version`.
        """
        version_formatted = convert_version_to_tuple(target_version=target_version)

        results = [
            record
            for record in self.records
            if tuple(record["min_impacted_version"]) <= version_formatted
            and (
                record["max_impacted_version"] is None
                or tuple(record["max_impacted_version"]) >= version_formatted
            )
            and (is_auth or not record["auth_required"])
        ]

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
