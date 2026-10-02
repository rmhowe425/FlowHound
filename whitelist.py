# Vulture whitelist — false positives produced by MagicMock attribute chains.
# MagicMock objects expose dynamic attributes that vulture cannot resolve
# through the mock framework and flags as unused.
# Listing the attributes here tells vulture they are intentionally accessed.

from unittest.mock import MagicMock

_mock = MagicMock()
_mock.return_value  # noqa: B018
_mock.side_effect  # noqa: B018
_mock.__enter__  # noqa: B018
_mock.__exit__  # noqa: B018

# The component stub template is loaded as raw text and executed server-side
# by Langflow; Python never imports it, so vulture cannot see it being used.
from flowhound.vulnerabilities.exploits.templates.cve_2026_10134_component_stub import (
    PythonCodeStructuredTool,
)

PythonCodeStructuredTool.build_tool  # noqa: B018
