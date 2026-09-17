import json
from pathlib import Path
from flowhound.vulnerabilities.cve.cve import CVE
from flowhound.vulnerabilities.io.version_detection import convert_version_to_int, convert_int_to_version


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
        """
        if not self.db_path.exists():
            raise FileNotFoundError(f"[-] Data store not found: {self.db_path}")

        with open(self.db_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def close(self):
        """
        No-op: retained for API compatibility. JSON has no persistent connection.
        """
        self.records = None

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
        version_formatted = convert_version_to_int(target_version=target_version)

        results = [
            record for record in self.records
            if record["min_impacted_version"] <= version_formatted
            and (record["max_impacted_version"] is None or record["max_impacted_version"] >= version_formatted)
            and (is_auth or record["auth_required"] == 0)
        ]

        cve_instances = [CVE(**record) for record in results]

        for cve in cve_instances:
            min_version = cve.get_min_impacted_version()
            max_version = cve.get_max_impacted_version()

            cve.set_max_impacted_version(
                version=convert_int_to_version(target_version=max_version)
            )
            cve.set_min_impacted_version(
                version=convert_int_to_version(target_version=min_version)
            )

        return cve_instances

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
            results = self.records
        else:
            results = [
                record for record in self.records
                if record["cve_id"].lower() == cve.lower()
            ]

        return [CVE(**record) for record in results]
