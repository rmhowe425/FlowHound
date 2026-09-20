from flowhound.vulnerabilities.payloads.execute_bash_command import (
    Payload as CommandPayload,
)
from flowhound.vulnerabilities.payloads.reverse_tcp_shell import (
    Payload as ReverseTcpShellPayload,
)

# Maps CLI flag names to their Payload classes.
# --command  → CommandPayload(cmd=...)
# --reverse_shell → ReverseTcpShellPayload(lhost=..., lport=...)
PAYLOAD_MAP = {
    "command": CommandPayload,
    "reverse_shell": ReverseTcpShellPayload,
}
