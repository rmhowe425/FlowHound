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
| `module` | string | Fully-qualified Python module path for the exploit or auxiliary module |
| `module_class` | string | Class name inside the module (`"Exploit"` or `"Auxiliary"`) |
| `module_type` | string | Module classification: `"exploit"` or `"auxiliary"` |
| `auth_required` | boolean | Whether the module requires valid credentials |

### Example record

```json
{
    "application": "mlflow",
    "cve_id": "CVE-2023-1177",
    "cve_description": "Unauthenticated path traversal / arbitrary file read in MLflow via the artifact download endpoint",
    "cvss_severity": 9.8,
    "min_impacted_version": [1, 0, 0],
    "max_impacted_version": [2, 1, 1],
    "module": "flowhound.vulnerabilities.auxiliary.mlflow.cve_2023_1177",
    "module_class": "Auxiliary",
    "module_type": "auxiliary",
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

### Langflow (Exploits)

| CVE ID | CVSS | Auth Required | Type | Min Version | Max Version | Details |
|---|---|---|---|---|---|---|
| CVE-2026-9198 | 10.0 | No | exploit | 1.0.0 | 1.10.0 | [View Guide](cves/cve_2026_9198.md) |
| CVE-2026-93674 | 10.0 | Yes | exploit | 1.5.0 | 1.9.0 | [View Guide](cves/cve_2026_93674.md) |
| CVE-2026-0769 | 9.8 | No | exploit | 1.3.2 | 1.3.2 | [View Guide](cves/cve_2026_0769.md) |
| CVE-2026-0768 | 9.8 | No | exploit | 1.4.2 | 1.4.2 | [View Guide](cves/cve_2026_0768.md) |
| CVE-2026-19295 | 9.9 | Yes | exploit | 1.0.0 | 1.11.1 | [View Guide](cves/cve_2026_19295.md) |
| CVE-2026-19286 | 9.8 | Yes | exploit | 1.11.0 | 1.11.1 | [View Guide](cves/cve_2026_19286.md) |
| CVE-2026-18729 | 8.8 | Yes | exploit | 1.0.0 | 1.11.1 | [View Guide](cves/cve_2026_18729.md) |
| CVE-2026-5027 | 8.8 | Yes | exploit | 1.0.0 | 1.8.4 | [View Guide](cves/cve_2026_5027.md) |
| CVE-2026-7873 | 8.8 | Yes | exploit | 1.0.0 | 1.10.0 | [View Guide](cves/cve_2026_7873.md) |
| CVE-2026-10134 | 8.8 | Yes | exploit | 1.0.0 | 1.9.3 | [View Guide](cves/cve_2026_10134.md) |

### MLflow (Auxiliary)

| CVE ID | CVSS | Auth Required | Type | Min Version | Max Version | Details |
|---|---|---|---|---|---|---|
| CVE-2023-1177 | 9.8 | No | auxiliary | 1.0.0 | 2.1.1 | [View Guide](cves/cve_2023_1177.md) |
| CVE-2024-27132 | 8.8 | Yes | auxiliary | 1.0.0 | 2.11.2 | [View Guide](cves/cve_2024_27132.md) |

---

## CVE search

The `Database.search_vulnerabilities(cve, module_type)` method supports programmatic lookup by CVE ID and optional module type:

- Pass an empty string to return all records.
- Pass a CVE ID (case-insensitive) to return matching records.
- Filter by `ModuleType.EXPLOIT` or `ModuleType.AUXILIARY`.

This method is also invoked via the CLI `--cve` option in `attack` and `scan`.

---

## Adding a new vulnerability

1. Create a new exploit or auxiliary module in `flowhound/vulnerabilities/exploits/` or `flowhound/vulnerabilities/auxiliary/` — see [Architecture](architecture.md) for the required structure.
2. Add a new JSON record to `flowhound/vulnerabilities/io/vulnerabilities.json` following the schema above.
3. Ensure all ten required fields are present. The `Database._load` method raises `ValueError` for any record with missing fields.
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
    "module",
    "module_class",
    "module_type",
    "auth_required",
}
```

Any record missing one or more of these fields causes a `ValueError` at import time.
