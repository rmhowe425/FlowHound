# FlowHound

FlowHound is an automated exploitation platform for scanning and testing insecure [Langflow](https://github.com/langflow-ai/langflow) and [MLflow](https://github.com/mlflow/mlflow) deployments.

!!! warning "Authorised use only"
    FlowHound is intended exclusively for authorised security testing. Do not run it against systems you do not own or have explicit written permission to test.

---

## What is FlowHound?

Langflow and MLflow are widely deployed AI/ML platforms. When deployed without proper hardening they expose unauthenticated and authenticated attack surfaces. FlowHound automates the entire assessment workflow:

1. **Version detection** — probes the target to identify the running application and its version. When `--application` is provided the corresponding detector is called directly; otherwise all registered detectors are tried in sequence.
2. **CVE lookup** — searches the bundled vulnerability database for CVE records matching the detected application, version range, and authentication state.
3. **Exploit dispatch** — dynamically loads each matching exploit module and executes it.
4. **Payload injection** — optionally replaces the built-in `id` probe with a custom shell command or a reverse TCP shell.

---

## Who is it for?

- Penetration testers assessing Langflow- or MLflow-backed AI/ML infrastructure.
- Security engineers validating patch compliance on internal deployments.
- Red teams evaluating exposure of AI/ML platform instances in lab environments.

---

## Major capabilities

| Capability | Description |
|---|---|
| Multi-target detection | Auto-detects Langflow or MLflow from the live API; override with `--application` |
| CVE database | Bundled JSON database of known CVEs with CVSS scores and version ranges for each application |
| Unauthenticated exploits | Exploits that require no credentials |
| Authenticated exploits | Exploits that leverage supplied credentials |
| Custom payloads | `--command` for arbitrary shell commands; `--reverse_shell` for a reverse TCP shell |
| Autopwn mode | `--autopwn` runs all matching exploits rather than stopping at the first success |
| CVE targeting | `--cve` limits execution to a single named CVE |
| Proxy support | Route all traffic through an HTTP(S) proxy |
| `sniff` mode | Detect version and list applicable CVEs without launching any exploits |

---

## Quick start

```bash
# Install
pip install flowhound

# Detect version and list CVEs — no exploits launched
flowhound sniff --url http://TARGET:7860

# Unauthenticated attack (Langflow — auto-detected)
flowhound attack --url http://TARGET:7860

# Unauthenticated attack (MLflow — skip auto-detection)
flowhound attack --url http://TARGET:5000 --application mlflow

# Authenticated attack
flowhound attack --url http://TARGET:7860 --username admin --password secret

# Target a single CVE
flowhound attack --url http://TARGET:5000 --cve CVE-2023-1177
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
