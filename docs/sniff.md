# Sniff

The `sniff` command detects the running Langflow version and lists all applicable CVEs without launching any exploits.

---

## Purpose

Use `sniff` to:

- Confirm a target is reachable and is running Langflow.
- Identify the exact Langflow version.
- Enumerate all CVEs in the database that apply to the detected version (both authenticated and unauthenticated) before deciding whether to proceed with `attack`.

`sniff` is read-only — it makes a single GET request to `/api/v1/version` and then performs a local database lookup. No exploits are loaded or executed.

---

## Syntax

```
flowhound sniff --url <URL> [OPTIONS]
```

---

## Options

| Option | Required | Description |
|---|---|---|
| `--url` | Yes | URL of the target Langflow instance (e.g. `http://localhost:7860`) |
| `--proxy` | No | HTTP(S) proxy to route all traffic through |
| `-h`, `--help` | No | Show help text and exit |

---

## What FlowHound identifies

1. **Langflow version** — retrieved from the JSON body of `GET /api/v1/version` (`{"version": "x.x.x"}`).
2. **Applicable exploit modules** — the `exploit_module` field from every matching CVE record is printed to stdout.

`sniff` always queries with `is_auth=True`, so it lists all CVEs for the version regardless of whether credentials are available. This gives a complete picture of the attack surface.

---

## Example usage

```bash
flowhound sniff --url http://target.example.com:7860
```

Example output:

```
[+] Checking target Langflow version.
[+] Retrieving all known exploits for Langflow version 1.0.0:
[+] flowhound.vulnerabilities.exploits.cve_2026_9198
[+] flowhound.vulnerabilities.exploits.cve_2026_19295
[+] flowhound.vulnerabilities.exploits.cve_2026_18729
[+] flowhound.vulnerabilities.exploits.cve_2026_5027
[+] flowhound.vulnerabilities.exploits.cve_2026_7873
[+] flowhound.vulnerabilities.exploits.cve_2026_10134
```

Route traffic through a proxy:

```bash
flowhound sniff --url http://target.example.com:7860 --proxy http://127.0.0.1:8080
```

---

## Error handling

| Error | Cause | Resolution |
|---|---|---|
| `Error retrieving target Langflow version` | Target unreachable, connection refused, or not a Langflow instance | Verify the URL and that the Langflow instance is running |
| `Unable to retrieve Langflow version` | The endpoint responded with a non-200 status or a missing `version` field | Verify the target is a supported Langflow version |
| `Malformed URL` | The supplied `--url` is not a valid HTTP(S) URL | Ensure the URL includes a scheme (`http://` or `https://`) |

---

## See also

- [Attack](attack.md) — launching exploits after reconnaissance.
- [Vulnerability Database](vulnerabilities.md) — full CVE coverage details.
