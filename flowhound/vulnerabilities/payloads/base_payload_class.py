from abc import ABC, abstractmethod


class PayloadBaseClass(ABC):
    blocking: bool = False
    """
    Set to True for payloads that block indefinitely (e.g. reverse shells).
    Exploits use this to decide whether to run the payload in a background thread.
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
