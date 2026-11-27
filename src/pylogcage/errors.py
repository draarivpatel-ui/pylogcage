"""Exception types used by pylogcage."""
from __future__ import annotations

from typing import Any, Optional


class LogCageError(ValueError):
    """Base error raised for invalid pylogcage input or options."""

    def __init__(self, code: str, message: str, *, field: Optional[str] = None, actual: Any = None, limit: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.reason = message
        self.field = field
        self.actual = actual
        self.limit = limit


class LogCageInputError(TypeError):
    """Raised when a public API receives a value of the wrong type."""


class LogCageOutputInvariantError(RuntimeError):
    """Raised if an internal output safety invariant cannot be verified."""


INVALID_INPUT = "ERR_PYLOGCAGE_INVALID_INPUT"
INVALID_OPTIONS = "ERR_PYLOGCAGE_INVALID_OPTIONS"
OUTPUT_INVARIANT = "ERR_PYLOGCAGE_OUTPUT_INVARIANT"


def invalid_options(message: str, field: Optional[str] = None) -> LogCageError:
    return LogCageError(INVALID_OPTIONS, message, field=field)
