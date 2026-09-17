import importlib

class CVE:
    """
    Represents a known CVE impacting a given Langflow instance.
    """

    def __init__(
        self,
        cve_id: str,
        cve_description: str,
        cvss_severity: float,
        min_impacted_version: str,
        max_impacted_version: str,
        exploit_module: str,
        exploit_class: str,
        auth_required: bool,
    ):
        self.cve_id = cve_id
        self.cve_description = cve_description
        self.cvss_severity = cvss_severity
        self.min_impacted_version = min_impacted_version
        self.max_impacted_version = max_impacted_version
        self.exploit_module = exploit_module
        self.exploit_class = exploit_class
        self.auth_required = auth_required

    def get_cve(self) -> str:
        return self.cve_id

    def get_cve_description(self) -> str:
        return self.cve_description

    def get_cvss_severity(self) -> float:
        return self.cvss_severity

    def get_max_impacted_version(self) -> str:
        return self.max_impacted_version

    def get_min_impacted_version(self) -> str:
        return self.min_impacted_version

    def get_exploit_module(self) -> str:
        return self.exploit_module

    def get_exploit_class(self) -> str:
        return self.exploit_class

    def get_exploit_instance(self):
        try:
            module = importlib.import_module(self.get_exploit_module())
            exploit_class_inst = getattr(module, self.get_exploit_class())
        except Exception as e:
            raise RuntimeError(f"Error importing exploit module: {str(e)}")

        return exploit_class_inst()

    def get_auth_required(self) -> bool:
        return self.auth_required
    
    def get_max_impacted_version(self) -> str:
        return self.max_impacted_version

    def get_min_impacted_version(self) -> str:
        return self.min_impacted_version
    
    def set_max_impacted_version(self, version: str):
        if not isinstance(version, str) or not version:
            raise ValueError("`version` must be a non-empty string.")
        elif version.count(".") != 2:
            raise ValueError(f"`version` must take the form of `x.x.x`.")

        self.max_impacted_version = version

    def set_min_impacted_version(self, version: str):
        if not isinstance(version, str) or not version:
            raise ValueError("`version` must be a non-empty string.")
        elif version.count(".") != 2:
            raise ValueError(f"`version` must take the form of `x.x.x`.")

        self.min_impacted_version = version

