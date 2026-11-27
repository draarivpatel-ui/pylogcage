"""pylogcage: CWE-117, terminal-sequence, secret, and PII protection for logs."""
from __future__ import annotations

from .core import LogCage, sanitize_log_line
from .errors import LogCageError, LogCageInputError, LogCageOutputInvariantError
from .jsonlog import format_safe_json_log
from .logging_integration import LogCageFilter, SafeJsonFormatter, SafeTextFormatter
from .record import sanitize_record
from .redactor import redact_secrets
from .sanitizer import strip_terminal_sequences

__version__ = "1.0.0"

__all__ = [
    "LogCage",
    "LogCageError",
    "LogCageFilter",
    "LogCageInputError",
    "LogCageOutputInvariantError",
    "SafeJsonFormatter",
    "SafeTextFormatter",
    "__version__",
    "format_safe_json_log",
    "redact_secrets",
    "sanitize_log_line",
    "sanitize_record",
    "strip_terminal_sequences",
]
