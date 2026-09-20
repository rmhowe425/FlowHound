"""
Validate that FlowHound's module architecture rules are respected.

Enforced rules
--------------
1. flowhound.vulnerabilities.*  MUST NOT import from  flowhound.cli.*
2. flowhound.vulnerabilities.exploits.*  MUST NOT import from  flowhound.vulnerabilities.io.*
   (exploits must not reach into I/O helpers directly)

Exit code 0  — all rules pass
Exit code 2  — one or more violations found
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

RULES: list[tuple[str, str, str]] = [
    # (offending_package_prefix, forbidden_import_prefix, human_label)
    (
        "flowhound/vulnerabilities",
        "flowhound.cli",
        "vulnerabilities layer must not import from the cli layer",
    ),
    (
        "flowhound/vulnerabilities/exploits",
        "flowhound.vulnerabilities.io",
        "exploit modules must not import from the io layer directly",
    ),
]


def _imports_in_file(path: Path) -> list[str]:
    """Return all module names imported (top-level) in *path*."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        return []

    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.append(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
    return names


def main() -> int:
    violations: list[str] = []

    for offending_prefix, forbidden_prefix, label in RULES:
        search_dir = ROOT / offending_prefix
        if not search_dir.exists():
            continue

        for py_file in sorted(search_dir.rglob("*.py")):
            # Don't flag the forbidden package importing itself
            rel = py_file.relative_to(ROOT).as_posix()
            if forbidden_prefix.replace(".", "/") in rel:
                continue

            for imported in _imports_in_file(py_file):
                if not imported.startswith(forbidden_prefix):
                    continue
                violations.append(
                    f"  {rel}\n    imports '{imported}'\n    RULE: {label}"
                )

    if violations:
        print("Architecture violations detected:\n")
        for v in violations:
            print(v)
        return 2

    print("Architecture check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
