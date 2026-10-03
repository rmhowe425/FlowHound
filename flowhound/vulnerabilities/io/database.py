import json
from pathlib import Path

from flowhound.vulnerabilities.cve.cve import CVE, ModuleType
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
    "module",
    "module_class",
    "module_type",
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
        self,
        application: str,
        target_version: str,
        is_auth: bool,
        module_type: ModuleType | None = ModuleType.EXPLOIT,
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
        module_type : ModuleType | None
            Filter by module type (e.g. ModuleType.EXPLOIT or ModuleType.AUXILIARY).
            Pass None to retrieve all module types.

        Returns
        -------
        List of CVE objects returned based on `application`, `target_version`, and `module_type`.
        """
        try:
            version_formatted = convert_version_to_tuple(target_version=target_version)
        except ValueError as e:
            raise ValueError(f"Invalid target version {target_version!r}: {e}") from e

        results = []
        for record in self.records:
            if module_type is not None and record["module_type"] != module_type:
                continue
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

    def search_vulnerabilities(
        self, cve: str, module_type: ModuleType | None = None
    ) -> list:
        """
        Retrieves a list of CVEs based on a defined list of
        criteria to pull their corresponding exploit modules.

        Parameters
        ----------
        cve : str
            CVE ID
        module_type : str | None
            Optional filter by module type (e.g. "exploit" or "auxiliary").

        Returns
        -------
        A list of CVE objects
        """
        records = self.records
        if module_type is not None:
            records = [r for r in records if r["module_type"] == module_type]

        if not cve:
            return [CVE(**record) for record in records]
        results = [
            record for record in records if record["cve_id"].lower() == cve.lower()
        ]
        return [CVE(**record) for record in results]
