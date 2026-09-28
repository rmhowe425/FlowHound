# Sniff

The `sniff` command detects the running application and version, then lists all applicable CVEs without launching any exploits.

---

## Purpose

Use `sniff` to:

- Confirm a target is reachable and identify which supported application it is running.
- Identify the exact application version.
- Enumerate all CVEs in the database that apply to the detected application and version (both authenticated and unauthenticated) before deciding whether to proceed with `attack`.

`sniff` is read-only — it makes version-probe requests and then performs a local database lookup. No exploits are loaded or executed.

---

## Syntax

```
flowhound sniff --url <URL> [OPTIONS]
```

---

## Options

| Option | Required | Description |
|---|---|---|
| `--url` | Yes | URL of the target instance (e.g. `http://localhost:7860`) |
| `--proxy` | No | HTTP(S) proxy to route all traffic through |
| `--application` | No | Target application name (e.g. `langflow`, `mlflow`). Skips auto-detection when provided |
| `-h`, `--help` | No | Show help text and exit |

---

## What FlowHound identifies

1. **Application and version** — determined by probing the target with registered version detectors. Each detector hits an application-specific endpoint:
    - **Langflow** — `GET /api/v1/version` → `{"version": "x.x.x", "package": "Langflow"}`
    - **MLflow** — `GET /version` → plain-text semver string
2. **Applicable exploit modules** — the `exploit_module` field from every matching CVE record is printed to stdout.

`sniff` always queries with `is_auth=True`, so it lists all CVEs for the version regardless of whether credentials are available. This gives a complete picture of the attack surface.

---

## Example usage

Langflow target (auto-detected):

```bash
flowhound sniff --url http://target.example.com:7860
```

Example output:

```
[+] Detected langflow version 1.0.0.
[+] Retrieving all known exploits for langflow version 1.0.0:
[+] flowhound.vulnerabilities.exploits.cve_2026_9198
[+] flowhound.vulnerabilities.exploits.cve_2026_19295
[+] flowhound.vulnerabilities.exploits.cve_2026_18729
[+] flowhound.vulnerabilities.exploits.cve_2026_5027
[+] flowhound.vulnerabilities.exploits.cve_2026_7873
[+] flowhound.vulnerabilities.exploits.cve_2026_10134
```

MLflow target (skip auto-detection):

```bash
flowhound sniff --url http://target.example.com:5000 --application mlflow
```

Example output:

```
[+] Detected mlflow version 2.1.0.
[+] Retrieving all known exploits for mlflow version 2.1.0:
[+] flowhound.vulnerabilities.exploits.cve_2023_1177
```

Route traffic through a proxy:

```bash
flowhound sniff --url http://target.example.com:7860 --proxy http://127.0.0.1:8080
```

---

## Error handling

| Error | Cause | Resolution |
|---|---|---|
| `Error detecting target` | Target unreachable, connection refused, or not a supported application | Verify the URL and that the instance is running |
| `Unable to retrieve ... version` | The version endpoint responded with a non-200 status or unexpected body | Verify the target is a supported application version; try `--application` to force a specific detector |
| `Malformed URL` | The supplied `--url` is not a valid HTTP(S) URL | Ensure the URL includes a scheme (`http://` or `https://`) |

---

## See also

- [Attack](attack.md) — launching exploits after reconnaissance.
- [Vulnerability Database](vulnerabilities.md) — full CVE coverage details.
