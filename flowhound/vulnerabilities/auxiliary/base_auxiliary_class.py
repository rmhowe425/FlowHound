from abc import abstractmethod

from flowhound.vulnerabilities.base import BaseModule


class AuxiliaryBaseClass(BaseModule):
    @abstractmethod
    def run(
        self,
        base_url: str,
        f_path: str | None = None,
        username: str = "",
        password: str = "",
        proxies: dict[str, str] | None = None,
    ) -> bool:
        """
        Abstract method used as controller for auxiliary module.

        Parameters
        ----------
        base_url : str
            URL of target instance.
        f_path : str | None
            Optional file path argument (e.g. for path traversal modules).
        username : str
            Target instance username.
        password : str
            Target instance password.
        proxies : dict[str, str] | None
            HTTP(s) proxy dict to use for network I/O operations
        """
        ...
