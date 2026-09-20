# Development Setup

This page describes how to set up a local development environment for FlowHound.

---

## Requirements

- Python 3.10 or later (3.13 is used in CI)
- `git`
- `pip`

---

## Clone the repository

```bash
git clone https://github.com/rmhowe425/FlowHound.git
cd FlowHound
```

---

## Install development dependencies

Install FlowHound in editable mode with all development extras:

```bash
pip install -e ".[dev]"
```

This installs:

- `pytest` — test runner
- `ruff` — linter and formatter
- `pyright` — static type checker
- `vulture` — dead-code detector
- `codespell` — spell checker
- `pre-commit` — git hook manager

---

## Install documentation dependencies

```bash
pip install -e ".[docs]"
```

This installs:

- `mkdocs` — documentation site generator
- `mkdocs-material` — Material theme

---

## Install all extras

```bash
pip install -e ".[dev,docs]"
```

---

## Set up pre-commit hooks

```bash
pre-commit install
```

The pre-commit configuration (`.pre-commit-config.yaml`) runs on every commit and push:

| Hook | Runs on | Description |
|---|---|---|
| `ruff-check` | commit / push | Lint with auto-fix |
| `ruff-format` | commit / push | Format check |
| `vulture` | commit / push | Dead-code detection |
| `codespell` | commit / push | Spell checking |
| `check-case-conflict` | commit / push | File-name case conflicts |
| `check-toml` | commit / push | TOML syntax |
| `check-yaml` | commit / push | YAML syntax |
| `end-of-file-fixer` | commit / push | Trailing newline |
| `mixed-line-ending` | commit / push | Line-ending normalisation |
| `trailing-whitespace` | commit / push | Trailing whitespace |
| `check-added-large-files` | commit / push | Large-file guard |
| `architecture` | commit / push | Module architecture validation |
| `no-debugger` | commit / push | No `breakpoint()` / `pdb.set_trace()` |
| `no-print` | commit / push | No `print()` in application code |
| `pyright` | manual only | Static type checking |

---

## Running tests

```bash
pytest
```

Tests are located in `flowhound/tests/`. The CI pipeline stores JUnit XML results in `junit.xml`.

---

## Running Ruff

Lint:

```bash
ruff check .
```

Format check:

```bash
ruff format --check .
```

Auto-fix lint issues and format:

```bash
ruff check --fix .
ruff format .
```

---

## Running Pyright

```bash
pyright
```

Pyright is configured via `pyproject.toml` (no separate `pyrightconfig.json` is present). It is run as a manual pre-commit stage and in the CI `pyright` job.

---

## Building the wheel

```bash
pip install build
python -m build
```

The resulting wheel and sdist are written to `dist/`.

---

## Installing the wheel locally

```bash
pip install dist/*.whl
```

---

## Running the CLI from source

After `pip install -e .`:

```bash
flowhound --help
flowhound sniff --url http://TARGET:7860
```

---

## Documentation development

Serve the documentation locally with live reload:

```bash
mkdocs serve
```

The site is available at `http://127.0.0.1:8000` by default.

Build a static site (output to `site/`):

```bash
mkdocs build --strict
```

`--strict` promotes MkDocs warnings to errors, ensuring the build is clean.

---

## Architecture validation

The architecture script is run automatically by pre-commit. To run it manually:

```bash
python scripts/validate_architecture.py
```

This enforces:

1. `flowhound.vulnerabilities.*` must not import from `flowhound.cli.*`.
2. `flowhound.vulnerabilities.exploits.*` must not import from `flowhound.vulnerabilities.io.*`.

---

## CI/CD pipeline

FlowHound uses CircleCI (`.circleci/config.yml`). The `build-and-test` workflow runs these jobs in parallel (except `install-wheel`, which requires `build-wheel`):

| Job | What it does |
|---|---|
| `source-check` | Installs FlowHound and verifies `import flowhound` succeeds |
| `test` | Installs dev extras and runs `pytest` |
| `ruff` | Runs `ruff check .` and `ruff format --check .` |
| `pyright` | Installs dev extras and runs `pyright` |
| `build-wheel` | Builds the wheel with `python -m build` |
| `install-wheel` | Installs the built wheel and verifies the import |
| `cli-check` | Installs FlowHound and runs `flowhound --help` |

All jobs use the `cimg/python:3.13` Docker image.
