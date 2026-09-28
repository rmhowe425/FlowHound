# Vulnerability Database

FlowHound bundles a JSON vulnerability database at:

```
flowhound/vulnerabilities/io/vulnerabilities.json
```

The database is loaded once at startup when the [`Database`](architecture.md#database-class) class is instantiated. No network access is required to read the database.

---

## Schema

Each record in the database is a JSON object with the following fields:

| Field | Type | Description |
|---|---|---|
| `application` | string | Canonical application name (e.g. `"langflow"`, `"mlflow"`) |
| `cve_id` | string | CVE identifier (e.g. `"CVE-2023-1177"`) |
| `cve_description` | string | Short description of the vulnerability |
| `cvss_severity` | float | CVSS base score |
| `min_impacted_version` | `[major, minor, patch]` | Lowest affected version (inclusive) |
| `max_impacted_version` | `[major, minor, patch]` | Highest affected version (inclusive) |
| `exploit_module` | string | Fully-qualified Python module path for the exploit |
| `exploit_class` | string | Class name inside the exploit module (always `"Exploit"`) |
| `auth_required` | boolean | Whether the exploit requires valid credentials |

### Example record

```json
{
    "application": "mlflow",
    "cve_id": "CVE-2023-1177",
    "cve_description": "Unauthenticated path traversal / arbitrary file read in MLflow via the artifact download endpoint",
    "cvss_severity": 9.8,
    "min_impacted_version": [1, 0, 0],
    "max_impacted_version": [2, 2, 0],
    "exploit_module": "flowhound.vulnerabilities.exploits.cve_2023_1177",
    "exploit_class": "Exploit",
    "auth_required": false
}
```

---

## Version matching

`min_impacted_version` and `max_impacted_version` are stored as three-element integer arrays `[major, minor, patch]`. At runtime `Database.retrieve_vulnerabilities` converts both the stored arrays and the detected target version into comparable tuples and applies an inclusive range check:

```
min_impacted_version <= target_version <= max_impacted_version
```

---

## Authentication filtering

When `is_auth=False` (no credentials supplied), only records where `auth_required` is `false` are returned. When `is_auth=True`, all CVEs within the version range are returned.

---

## CVE coverage

### Langflow

| CVE ID | CVSS | Auth Required | Min Version | Max Version |
|---|---|---|---|---|
| CVE-2026-9198 | 10.0 | No | 1.0.0 | 1.10.0 |
| CVE-2026-0768 | 9.8 | No | 1.4.2 | 1.4.2 |
| CVE-2026-19295 | 9.9 | Yes | 1.0.0 | 1.11.1 |
| CVE-2026-19286 | 9.8 | Yes | 1.11.0 | 1.11.1 |
| CVE-2026-18729 | 8.8 | Yes | 1.0.0 | 1.11.1 |
| CVE-2026-5027 | 8.8 | Yes | 1.0.0 | 1.8.4 |
| CVE-2026-7873 | 8.8 | Yes | 1.0.0 | 1.10.0 |
| CVE-2026-10134 | 8.8 | Yes | 1.0.0 | 1.9.3 |

### MLflow

| CVE ID | CVSS | Auth Required | Min Version | Max Version |
|---|---|---|---|---|
| CVE-2023-1177 | 9.8 | No | 1.0.0 | 2.2.0 |
| CVE-2024-27132 | 8.8 | Yes | 1.0.0 | 2.11.2 |
| CVE-2023-6977 | 7.5 | Yes | 1.0.0 | 2.9.1 |

---

## CVE search

The `Database.search_vulnerabilities(cve)` method supports programmatic lookup by CVE ID:

- Pass an empty string to return all records.
- Pass a CVE ID (case-insensitive) to return matching records.

This method is also invoked via the CLI `--cve` option, which limits `attack` to a single named CVE.

---

## Adding a new vulnerability

1. Create a new exploit module in `flowhound/vulnerabilities/exploits/` — see [Architecture](architecture.md#adding-a-new-exploit) for the required structure.
2. Add a new JSON record to `flowhound/vulnerabilities/io/vulnerabilities.json` following the schema above.
3. Ensure all nine required fields are present. The `Database._load` method raises `ValueError` for any record with missing fields.
4. Add tests to `flowhound/tests/` covering the new CVE.

---

## Required fields validation

The `Database._load` method validates every record on startup against the following required field set:

```python
{
    "application",
    "cve_id",
    "cve_description",
    "cvss_severity",
    "min_impacted_version",
    "max_impacted_version",
    "exploit_module",
    "exploit_class",
    "auth_required",
}
```

Any record missing one or more of these fields causes a `ValueError` at import time.
