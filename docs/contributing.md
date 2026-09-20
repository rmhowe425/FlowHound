# Contributing

Thank you for your interest in contributing to FlowHound.

---

## Repository setup

```bash
git clone https://github.com/rmhowe425/FlowHound.git
cd FlowHound
pip install -e ".[dev]"
pre-commit install
```

---

## Development environment

See [Development Setup](development.md) for full instructions on installing dependencies, running tests, linting, and building the wheel.

---

## Running the test suite

```bash
pytest
```

All existing tests must pass before a pull request can be merged.

---

## Linting and formatting

```bash
ruff check .
ruff format --check .
```

Fix automatically:

```bash
ruff check --fix .
ruff format .
```

---

## Type checking

```bash
pyright
```

---

## Architecture rules

FlowHound enforces two import constraints:

1. `flowhound.vulnerabilities.*` must **not** import from `flowhound.cli.*`.
2. `flowhound.vulnerabilities.exploits.*` must **not** import from `flowhound.vulnerabilities.io.*`.

Verify before committing:

```bash
python scripts/validate_architecture.py
```

---

## Adding a vulnerability record

1. Create the exploit module — see **Adding an exploit module** below.
2. Open `flowhound/vulnerabilities/io/vulnerabilities.json`.
3. Append a new JSON object following the [database schema](vulnerabilities.md#schema).
4. Verify all eight required fields are present.
5. Add tests for the new CVE in `flowhound/tests/`.

---

## Adding an exploit module

1. Create `flowhound/vulnerabilities/exploits/cve_XXXX_NNNNN.py`.
2. Define a class named `Exploit` that subclasses `ExploitBaseClass`.
3. Implement `exploit(self, base_url, username, password, proxies, payload) -> bool`.
4. Use `self.auto_login()` or `self.authenticate()` as appropriate.
5. When a payload is supplied, call `payload.load_payload()`; otherwise use a built-in default.
6. Do **not** import from `flowhound.vulnerabilities.io.*` inside exploit modules (architecture rule 2).
7. Add the corresponding record to `vulnerabilities.json`.
8. Add tests in `flowhound/tests/`.

---

## Updating documentation

Documentation source files are in `docs/`. Install the docs extras and use `mkdocs serve` for a live preview:

```bash
pip install -e ".[docs]"
mkdocs serve
```

Validate the build:

```bash
mkdocs build --strict
```

---

## Building the package

```bash
pip install build
python -m build
```

---

## Pull requests

- Open pull requests against the `main` branch.
- Ensure all CI jobs pass: tests, ruff, pyright, build-wheel, install-wheel, and cli-check.
- Include tests for any new exploit module or vulnerability record.
- Keep commits focused; one logical change per commit is preferred.
- Update documentation pages if the change affects user-visible behaviour or the public API.
