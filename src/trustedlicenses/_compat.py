"""Version-gated imports: the newest interpreter's feature first, then a shim for older ones."""

from __future__ import annotations

import sys
from typing import TypeVar

if sys.version_info >= (3, 12):
    from typing import override
else:
    _F = TypeVar("_F")

    def override(method: _F) -> _F:
        """Stand in for ``typing.override`` (3.12+), which only matters to type checkers."""
        return method


__all__ = ["override"]
