# Installation

## Requirements

- Python 3.10 or later
- `pip`

FlowHound is tested against Python 3.10, 3.11, 3.12, and 3.13.

---

## Standard installation

Install FlowHound from the local source tree:

```bash
pip install .
```

Once the package is distributed on PyPI the command will be:

```bash
pip install flowhound
```

---

## Development installation

Install FlowHound in editable mode together with the development dependencies (pytest, ruff, pyright, vulture, codespell, pre-commit):

```bash
pip install -e ".[dev]"
```

---

## Documentation development installation

Install FlowHound together with the documentation build dependencies (MkDocs and Material for MkDocs):

```bash
pip install -e ".[docs]"
```

To install both dev and docs extras at the same time:

```bash
pip install -e ".[dev,docs]"
```

---

## Verification

After installation, verify the CLI is available:

```bash
flowhound --help
```

Expected output includes the `attack` and `sniff` sub-commands:

```
Usage: flowhound [OPTIONS] COMMAND [ARGS]...

Options:
  -h, --help  Show this message and exit.

Commands:
  attack  Launch one or more exploits against a Langflow instance.
  sniff   Determine target Langflow version.
```

Verify the package imports correctly:

```bash
python -c "import flowhound; print('OK')"
```

---

## Common issues

**`flowhound` command not found**

The script entry point is installed into the Python environment's `bin` (or `Scripts` on Windows) directory. Make sure this directory is on your `PATH`, or activate the virtual environment in which FlowHound was installed.

**`ModuleNotFoundError: No module named 'flowhound'`**

Run `pip install .` (or `pip install -e .`) again inside the environment where you are running the `flowhound` command.
