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
