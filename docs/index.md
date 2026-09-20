# FlowHound

FlowHound is an automated exploitation platform for scanning and testing insecure [Langflow](https://github.com/langflow-ai/langflow) deployments.

!!! warning "Authorised use only"
    FlowHound is intended exclusively for authorised security testing. Do not run it against systems you do not own or have explicit written permission to test.

---

## What is FlowHound?

Langflow is a low-code AI workflow builder. When deployed without proper hardening it exposes several unauthenticated and authenticated remote code execution (RCE) attack surfaces. FlowHound automates the entire assessment workflow:

1. **Version detection** — queries `/api/v1/version` on the target to identify the running Langflow release.
2. **CVE lookup** — searches the bundled vulnerability database for CVE records whose affected version range covers the detected version.
3. **Exploit dispatch** — dynamically loads each matching exploit module and executes it.
4. **Payload injection** — optionally replaces the built-in `id` probe with a custom shell command or a reverse TCP shell.

---

## Who is it for?

- Penetration testers assessing Langflow-backed AI infrastructure.
- Security engineers validating patch compliance on internal deployments.
- Red teams evaluating exposure of Langflow instances in lab environments.

---

## Major capabilities

| Capability | Description |
|---|---|
| Version detection | Identifies the exact Langflow version from the live API |
| CVE database | Bundled JSON database of known Langflow CVEs with CVSS scores and version ranges |
| Unauthenticated exploits | RCE exploits that require no credentials |
| Authenticated exploits | RCE exploits that leverage supplied credentials |
| Custom payloads | `--command` for arbitrary shell commands; `--reverse_shell` for a reverse TCP shell |
| Autopwn mode | `--autopwn` runs all matching exploits rather than stopping at the first success |
| Proxy support | Route all traffic through an HTTP(S) proxy |
| `sniff` mode | Detect version and list applicable CVEs without launching any exploits |

---

## Quick start

```bash
# Install
pip install flowhound

# Detect version and list CVEs (no exploits)
flowhound sniff --url http://TARGET:7860

# Unauthenticated attack
flowhound attack --url http://TARGET:7860

# Authenticated attack
flowhound attack --url http://TARGET:7860 --username admin --password secret
```

---

## Documentation

| Page | Contents |
|---|---|
| [Installation](installation.md) | Full installation instructions and requirements |
| [Quick Start](quickstart.md) | First run walkthrough |
| [CLI Overview](usage.md) | Complete CLI reference |
| [Attack](attack.md) | `attack` command in depth |
| [Sniff](sniff.md) | `sniff` command in depth |
| [Vulnerability Database](vulnerabilities.md) | CVE database schema and CVE coverage |
| [Architecture](architecture.md) | Module architecture and exploit pipeline |
| [Development Setup](development.md) | Developer environment and tooling |
| [Contributing](contributing.md) | How to contribute |
