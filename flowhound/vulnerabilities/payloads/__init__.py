from flowhound.vulnerabilities.payloads.bind_langflow_http_shell import (
    Payload as BindLangflowHttpShellPayload,
)
from flowhound.vulnerabilities.payloads.bind_tcp_shell import (
    Payload as BindTcpShellPayload,
)
from flowhound.vulnerabilities.payloads.execute_bash_command import (
    Payload as CommandPayload,
)
from flowhound.vulnerabilities.payloads.reverse_tcp_shell import (
    Payload as ReverseTcpShellPayload,
)

# Maps CLI flag names to their Payload classes.
# --command            → CommandPayload(cmd=...)
# --reverse_shell      → ReverseTcpShellPayload(lhost=..., lport=...)
# --bind_shell         → BindTcpShellPayload(rhost=..., rport=...)
# --bind_langflow_http → BindLangflowHttpShellPayload(rhost=..., rport=...)
PAYLOAD_MAP = {
    "command": CommandPayload,
    "reverse_shell": ReverseTcpShellPayload,
    "bind_shell": BindTcpShellPayload,
    "bind_langflow_http": BindLangflowHttpShellPayload,
}
