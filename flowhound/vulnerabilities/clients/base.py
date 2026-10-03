import logging
from abc import ABC, abstractmethod


class TargetClient(ABC):
    """
    Abstract base class representing an HTTP client adapter for a target application.
    Encapsulates application-specific authentication, session management, and requests.
    """

    DEFAULT_TIMEOUT: int = 20

    def __init__(
        self,
        base_url: str,
        proxies: dict[str, str] | None = None,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        self.base_url = base_url.rstrip("/")
        self.proxies = proxies
        self.timeout = timeout

    @property
    def logger(self) -> logging.Logger:
        return logging.getLogger(type(self).__module__)

    @abstractmethod
    def authenticate(self, username: str, password: str) -> dict[str, str] | None:
        """
        Authenticate with target using supplied credentials.

        Parameters
        ----------
        username : str
            Username to authenticate with.
        password : str
            Password to authenticate with.

        Returns
        -------
        dict[str, str] | None
            Authentication headers (e.g. {'Authorization': 'Bearer ...'}) on success,
            or None on failure.
        """
        ...

    def auto_login(self) -> dict[str, str] | None:
        """
        Attempt unauthenticated auto-login if supported by the target.

        Returns
        -------
        dict[str, str] | None
            Authentication headers on success, or None on failure / unsupported.
        """
        return None

    def handle_authentication(
        self, username: str = "", password: str = ""
    ) -> dict[str, str] | None:
        """
        Resolve an auth header using the best available method.

        Tries ``auto_login()`` first.  If that fails and ``username`` and
        ``password`` are both provided, falls back to ``authenticate()``.

        Parameters
        ----------
        username : str
            Username to authenticate with (optional).
        password : str
            Password to authenticate with (optional).

        Returns
        -------
        dict[str, str] | None
            Authentication headers on success, or None on failure.
        """
        self.logger.info("Checking whether auto_login is enabled....")
        headers = self.auto_login()
        if headers is not None:
            self.logger.info("auto_login is enabled.")
            return headers

        self.logger.info("auto_login is not enabled.")
        if username and password:
            return self.authenticate(username=username, password=password)
        else:
            self.logger.warning("No credentials provided. Stopping exploit module.")

        return None
