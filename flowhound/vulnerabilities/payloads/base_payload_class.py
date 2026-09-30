from abc import ABC, abstractmethod


class PayloadBaseClass(ABC):
    blocking: bool = False
    """
    Set to True for payloads that block indefinitely (e.g. reverse shells).
    Exploits use this to decide whether to run the payload in a background thread.
    """

    raw_command: str | None = None
    """
    Set to the raw shell command string for payloads that should be passed
    directly to an executor (e.g. MCP ``command`` field) rather than being
    wrapped in ``python3 -c``.  When None the payload is treated as Python
    source code and wrapped appropriately by the exploit.
    """

    @abstractmethod
    def generate_payload(self, *_args, **_kwargs) -> str:
        """
        Abstract method for generating a payload
        """
        ...

    @abstractmethod
    def load_payload(self) -> str:
        """
        Abstract method for injecting a payload into an exploit
        """
        ...
