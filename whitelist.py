# Vulture whitelist — false positives produced by MagicMock attribute chains.
# MagicMock objects expose `.return_value` as a dynamic attribute; vulture
# cannot resolve this through the mock framework and flags it as unused.
# Listing the attribute here tells vulture it is intentionally accessed.

from unittest.mock import MagicMock

_mock = MagicMock()
_mock.return_value  # noqa: B018
