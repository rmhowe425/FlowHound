# Architecture

This page describes FlowHound's internal module architecture and the end-to-end exploit execution pipeline.

---

## Repository layout

```
flowhound/
├── __main__.py                        # CLI entry point; registers attack and sniff commands
├── cli/
│   ├── command.py                     # attack and sniff Click command definitions
│   ├── validators.py                  # URL, proxy, CVE, and application input validators
│   ├── banner.py                      # ASCII-art banner displayed on attack
│   └── message_format.py             # Coloured logging handler (ClickLogHandler)
└── vulnerabilities/
    ├── clients/
    │   ├── base.py                    # Abstract TargetClient adapter
    │   ├── langflow.py                # LangflowClient — auto-login & bearer-token auth
    │   └── mlflow.py                  # MLflowClient — HTTP Basic auth
    ├── cve/
    │   └── cve.py                     # CVE data model; dynamically loads exploit modules
    ├── io/
    │   ├── database.py                # Reads vulnerabilities.json; filters by app, version & auth
    │   ├── version_detection.py       # Per-application version probes; detect_target() dispatcher
    │   └── vulnerabilities.json       # Bundled CVE data store
    ├── exploits/
    │   ├── base_exploit_class.py      # Abstract base; _client_class, auto_login, authenticate
    │   ├── cve_2026_*.py              # Langflow exploit PoC modules
    │   └── cve_202[34]_*.py           # MLflow exploit PoC modules
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
  Application & Version Detection
  (detect_target() — probes all registered detectors, or calls one directly
   when --application is provided)
         │
         ▼
  Vulnerability Database
  (vulnerabilities.json filtered by application + version + auth)
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
  (ThreadPoolExecutor with 20-second timeout)
         │
         ▼
  Result / Next CVE (if --autopwn)
```

---

## TargetClient

[`flowhound/vulnerabilities/clients/base.py`](https://github.com/rmhowe425/FlowHound/blob/main/flowhound/vulnerabilities/clients/base.py)

`TargetClient` is the abstract base class for all application-specific HTTP client adapters. Each concrete subclass encapsulates the authentication flow and request logic for its target application.

**Abstract method:**

- `authenticate(username, password) -> dict[str, str] | None` — authenticate with the target and return an HTTP headers dict on success, or `None` on failure.

**Concrete method:**

- `auto_login() -> dict[str, str] | None` — attempt unauthenticated auto-login if the application supports it. Returns `None` by default; overridden by `LangflowClient`.

**Concrete implementations:**

| Class | Module | Authentication mechanism |
|---|---|---|
| `LangflowClient` | `clients/langflow.py` | `auto_login` via `GET /api/v1/auto_login`; `authenticate` via `POST /api/v1/login` (bearer token) |
| `MLflowClient` | `clients/mlflow.py` | `authenticate` via `GET /api/2.0/mlflow/experiments/search` with HTTP Basic credentials |

---

## Database class

[`flowhound/vulnerabilities/io/database.py`](https://github.com/rmhowe425/FlowHound/blob/main/flowhound/vulnerabilities/io/database.py)

`Database` is instantiated once at startup (inside the Click `main` group) and stored in Click's context object, making it available to all sub-commands.

**Key methods:**

| Method | Description |
|---|---|
| `_load()` | Reads and validates `vulnerabilities.json`; raises on missing fields |
| `retrieve_vulnerabilities(application, target_version, is_auth)` | Returns `CVE` objects matching the application, version range, and auth filter |
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

Abstract base class that all exploit modules must subclass. Each concrete subclass **must** declare a `_client_class` class variable pointing to the appropriate `TargetClient` implementation. The base class uses `_client_class` to instantiate the correct client in `auto_login` and `authenticate`.

**Class variable:**

- `_client_class: ClassVar[type[TargetClient]]` — the `TargetClient` subclass to use for all authentication and HTTP operations (e.g. `LangflowClient` or `MLflowClient`).

**Methods:**

- `exploit(base_url, username, password, proxies, payload) -> bool` — **abstract**; the exploit entry point; returns `True` on success.
- `auto_login(base_url, proxies) -> dict | None` — authenticates via the target's auto-login endpoint (delegates to `_client_class`).
- `authenticate(base_url, username, password, proxies) -> dict | None` — authenticates with supplied credentials (delegates to `_client_class`).

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
3. Declare `_client_class` pointing to the correct `TargetClient` subclass (e.g. `_client_class = MLflowClient`).
4. Implement the `exploit(self, base_url, username, password, proxies, payload) -> bool` method.
5. Use `self.auto_login()` or `self.authenticate()` for authentication as appropriate.
6. Use `payload.load_payload()` when a payload is provided; fall back to a built-in default otherwise.
7. Add a corresponding record to `vulnerabilities.json` — see [Vulnerability Database](vulnerabilities.md#adding-a-new-vulnerability).
8. Add tests in `flowhound/tests/`.

---

## Version detection

[`flowhound/vulnerabilities/io/version_detection.py`](https://github.com/rmhowe425/FlowHound/blob/main/flowhound/vulnerabilities/io/version_detection.py)

Version detection is application-specific. Each supported application has a dedicated detector function registered in the `_DETECTORS` dict:

| Application | Detector function | Endpoint |
|---|---|---|
| `langflow` | `get_langflow_target_version` | `GET /api/v1/version` — JSON body `{"version": "x.x.x", "package": "Langflow"}` |
| `mlflow` | `get_mlflow_target_version` | `GET /version` — plain-text semver string |

The public entry point is `detect_target(base_url, proxies, application)`:

- When `application` is provided, the matching detector is called directly.
- When `application` is `None`, every detector is tried in sequence; the first success is returned.
- Raises `RuntimeError` if no detector succeeds.

`supported_applications()` returns the frozenset of valid `--application` values derived from `_DETECTORS`.

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
