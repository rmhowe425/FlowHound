# FlowHound

Automated exploitation platform for scanning and testing insecure [Langflow](https://github.com/langflow-ai/langflow) deployments.

## Installation

```bash
pip install .
```

## Usage

```
flowhound search --url <target-url> [--username <user>] [--password <pass>]
```

### Options

| Option | Required | Description |
|---|---|---|
| `--url` | Yes | URL of the target Langflow instance (e.g. `http://localhost:7860`) |
| `--username` | No | Langflow username — must be paired with `--password` |
| `--password` | No | Langflow password — must be paired with `--username` |
| `-h`, `--help` | No | Show help message |

### Examples

Unauthenticated scan:
```bash
flowhound search --url http://target.example.com:7860
```

Authenticated scan (includes auth-required CVEs):
```bash
flowhound search --url http://target.example.com:7860 --username admin --password secret
```

## How it works

1. Detects the running Langflow version via the `/api/v1/version` endpoint.
2. Queries a local SQLite database for CVEs whose affected version range covers the detected version.
3. Dynamically loads and executes each matching exploit module.

## Requirements

- Python 3.10+
- `requests`
- `click`

## Disclaimer

FlowHound is intended for authorised security testing only. Do not run it against systems you do not own or have explicit written permission to test.
