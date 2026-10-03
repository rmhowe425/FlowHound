import importlib
from enum import StrEnum

from flowhound.vulnerabilities.utils import convert_tuple_to_version


class ModuleType(StrEnum):
    EXPLOIT = "exploit"
    AUXILIARY = "auxiliary"


class CVE:
    """
    Represents a known CVE impacting a target application instance.
    """

    def __init__(
        self,
        application: str,
        cve_id: str,
        cve_description: str,
        cvss_severity: float,
        min_impacted_version: str,
        max_impacted_version: str,
        module: str,
        module_class: str,
        module_type: str,
        auth_required: bool,
    ):
        self.application = application
        self.cve_id = cve_id
        self.cve_description = cve_description
        self.cvss_severity = cvss_severity
        self.module = module
        self.module_class = module_class
        self.module_type = module_type
        self.auth_required = auth_required
        self.min_impacted_version = min_impacted_version
        self.max_impacted_version = max_impacted_version

    @property
    def module_type(self) -> str:
        """
        Retrieves the module type (exploit or auxiliary).
        """
        return self._module_type

    @module_type.setter
    def module_type(self, module_type):
        try:
            self._module_type = ModuleType(module_type)
        except ValueError:
            raise ValueError("`module_type` must be either 'exploit' or 'auxiliary'.")

    @property
    def application(self) -> str:
        """
        Retrieves the application name of the target.
        """
        return self._application

    @application.setter
    def application(self, application):
        if not isinstance(application, str) or not application:
            raise ValueError("`application` must be a non-empty string.")
        self._application = application

    @property
    def min_impacted_version(self) -> str:
        """
        Retrieves the minimum impacted version for a given CVE
        """
        return self._min_impacted_version

    @min_impacted_version.setter
    def min_impacted_version(self, version):
        """
        Sets the minimum impacted version for a given CVE
        """
        if isinstance(version, (tuple, list)) and len(version) > 0:
            version = convert_tuple_to_version(target_version=tuple(version))
        if not isinstance(version, str) or not version:
            raise ValueError("`version` must be a non-empty string.")
        elif version.count(".") != 2:
            raise ValueError("`version` must take the form of `x.x.x`.")
        self._min_impacted_version = version

    @property
    def max_impacted_version(self) -> str:
        """
        Retrieves the max impacted version for a given CVE
        """
        return self._max_impacted_version

    @max_impacted_version.setter
    def max_impacted_version(self, version):
        """
        Sets the max impacted version for a given CVE
        """
        if isinstance(version, (tuple, list)) and len(version) > 0:
            version = convert_tuple_to_version(target_version=tuple(version))
        if not isinstance(version, str) or not version:
            raise ValueError("`version` must be a non-empty string.")
        elif version.count(".") != 2:
            raise ValueError("`version` must take the form of `x.x.x`.")
        self._max_impacted_version = version

    def get_module_instance(self):
        try:
            module = importlib.import_module(self.module)
            module_class_inst = getattr(module, self.module_class)
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(f"Error importing module: {e!s}")

        return module_class_inst()
