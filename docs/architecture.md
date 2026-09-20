# Architecture

This page describes FlowHound's internal module architecture and the end-to-end exploit execution pipeline.

---

## Repository layout

```
flowhound/
├── __main__.py                        # CLI entry point; registers attack and sniff commands
├── cli/
│   ├── command.py                     # attack and sniff Click command definitions
│   ├── validators.py                  # URL, proxy, and CVE input validators
│   ├── banner.py                      # ASCII-art banner displayed on attack
│   └── message_format.py             # Coloured logging handler (ClickLogHandler)
└── vulnerabilities/
    ├── cve/
    │   └── cve.py                     # CVE data model; dynamically loads exploit modules
    ├── io/
    │   ├── database.py                # Reads vulnerabilities.json; filters by version & auth
    │   ├── version_detection.py       # Queries /api/v1/version; version string ↔ tuple helpers
    │   └── vulnerabilities.json       # Bundled CVE data store
    ├── exploits/
    │   ├── base_exploit_class.py      # Abstract base; auto_login / authenticate helpers
    │   └── cve_2026_*.py             # Individual exploit PoC modules
    └── payloads/
        ├── base_payload_class.py      # Abstract base; generate_payload / load_payload interface
        ├── execute_bash_command.py    # Runs an arbitrary shell command; captures stdout
        └── reverse_tcp_shell.py       # Opens a reverse TCP shell
```

---

## Layer rules

FlowHound enforces two import constraints via a pre-commit hook (`scripts/validate_architecture.py`):

| Rule | Description |
|---|---|
| `vulnerabilities` → no `cli` imports | The vulnerabilities layer must not depend on the CLI layer |
| `exploits` → no `io` imports | Exploit modules must not reach into I/O helpers directly |

---

## Exploit execution pipeline

```
Target URL supplied by user
         │
         ▼
  Version Detection
  (GET /api/v1/version)
         │
         ▼
  Vulnerability Database
  (vulnerabilities.json filtered by version + auth)
         │
         ▼
  Applicable CVEs (list of CVE objects)
         │
         ▼
  Authentication Filtering
  (auth_required=true excluded when no credentials supplied)
         │
         ▼
  Exploit Module Selection
  (CVE objects ordered by CVSS, unauthenticated first)
         │
         ▼
  Dynamic Import
  (importlib.import_module(exploit_module))
         │
         ▼
  Exploit Execution
  (ThreadPoolExecutor with 60-second timeout)
         │
         ▼
  Result / Next CVE (if --autopwn)
```

---

## Database class

[`flowhound/vulnerabilities/io/database.py`](https://github.com/rmhowe425/FlowHound/blob/main/flowhound/vulnerabilities/io/database.py)

`Database` is instantiated once at startup (inside the Click `main` group) and stored in Click's context object, making it available to all sub-commands.

**Key methods:**

| Method | Description |
|---|---|
| `_load()` | Reads and validates `vulnerabilities.json`; raises on missing fields |
| `retrieve_vulnerabilities(target_version, is_auth)` | Returns `CVE` objects matching the version range and auth filter |
| `search_vulnerabilities(cve)` | Returns `CVE` objects by CVE ID; returns all records if `cve` is empty |

---

## CVE class

[`flowhound/vulnerabilities/cve/cve.py`](https://github.com/rmhowe425/FlowHound/blob/main/flowhound/vulnerabilities/cve/cve.py)

The `CVE` class is a data model that wraps a single vulnerability record. Version fields are stored internally as `x.x.x` strings; the setters accept either strings or `[major, minor, patch]` lists (as stored in JSON) and normalise them.

**Key method:**

- `get_exploit_instance()` — uses `importlib.import_module(self.exploit_module)` to dynamically load the exploit module and returns an instance of the class named by `self.exploit_class`.

---

## ExploitBaseClass

[`flowhound/vulnerabilities/exploits/base_exploit_class.py`](https://github.com/rmhowe425/FlowHound/blob/main/flowhound/vulnerabilities/exploits/base_exploit_class.py)

Abstract base class that all exploit modules must subclass. Defines:

- `exploit(base_url, username, password, proxies, payload) -> bool` — **abstract**; the exploit entry point; returns `True` on success.
- `auto_login(base_url, proxies) -> dict | None` — authenticates via `/api/v1/auto_login`; returns `Authorization` header or `None`.
- `authenticate(base_url, username, password, proxies) -> dict | None` — authenticates via `/api/v1/login` with supplied credentials; returns `Authorization` header or `None`.

---

## PayloadBaseClass

[`flowhound/vulnerabilities/payloads/base_payload_class.py`](https://github.com/rmhowe425/FlowHound/blob/main/flowhound/vulnerabilities/payloads/base_payload_class.py)

Abstract base class that all payload classes must subclass. Defines:

- `generate_payload(*args, **kwargs) -> str` — **abstract**; constructs the payload string.
- `load_payload() -> str` — **abstract**; returns the ready-to-inject payload string.
- `blocking: bool` — class attribute; set to `True` for payloads that block (e.g. reverse shells).

### Built-in payloads

| Class | Module | `blocking` | Description |
|---|---|---|---|
| `Payload` | `execute_bash_command` | `False` | Runs a shell command via `subprocess.check_output`; captures stdout |
| `Payload` | `reverse_tcp_shell` | `True` | Connects back via TCP socket and execs `/bin/bash` |

---

## Adding a new exploit

1. Create `flowhound/vulnerabilities/exploits/cve_XXXX_NNNNN.py`.
2. Define a class named `Exploit` that subclasses `ExploitBaseClass`.
3. Implement the `exploit(self, base_url, username, password, proxies, payload) -> bool` method.
4. Use `self.auto_login()` or `self.authenticate()` for authentication as appropriate.
5. Use `payload.load_payload()` when a payload is provided; fall back to a built-in default otherwise.
6. Add a corresponding record to `vulnerabilities.json` — see [Vulnerability Database](vulnerabilities.md#adding-a-new-vulnerability).
7. Add tests in `flowhound/tests/`.

---

## Version detection

[`flowhound/vulnerabilities/io/version_detection.py`](https://github.com/rmhowe425/FlowHound/blob/main/flowhound/vulnerabilities/io/version_detection.py)

`get_target_version(base_url, proxies)` issues `GET <base_url>/api/v1/version` with a 20-second timeout and returns the `version` string from the JSON response. Raises `RuntimeError` if the request fails or the response does not contain a valid version.

Helper functions:

- `convert_version_to_tuple(version_str) -> (int, int, int)` — parses `"x.x.x"` into a comparable tuple.
- `convert_tuple_to_version(tuple) -> str` — converts a `(major, minor, patch)` tuple back to a string.

---

## Logging and output

[`flowhound/cli/message_format.py`](https://github.com/rmhowe425/FlowHound/blob/main/flowhound/cli/message_format.py)

All output goes through `ClickLogHandler`, which routes Python `logging` records to `click.echo` with colour-coded prefixes:

| Level | Prefix | Colour |
|---|---|---|
| `DEBUG` | `[-]` | Cyan |
| `INFO` | `[+]` | Blue (green for exploit loggers) |
| `WARNING` | `[!]` | Yellow |
| `ERROR` / `CRITICAL` | `[!]` / `[CRITICAL]` | Red |

Error-level messages are written to `stderr`; all others go to `stdout`.
