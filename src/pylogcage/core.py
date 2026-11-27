"""Public sanitizing pipeline and reusable LogCage configuration object."""
from __future__ import annotations

from typing import Any, Iterable, Optional

from .config import CageConfig, make_config
from .errors import LogCageInputError
from .redactor import redact_control_insensitive
from .sanitizer import (
    DEFAULT_REPLACEMENT,
    DEFAULT_TRUNCATION_MARKER,
    neutralize_chunks,
    strip_terminal_sequences,
    truncate_atomic_chunks,
)


def sanitize_line_with_config(text: str, config: CageConfig) -> str:
    """Sanitize one line using an already validated configuration.

    The ordering is a security invariant: terminal sequences are removed,
    secrets are redacted in a control-obfuscation-resistant view, remaining
    unsafe characters are escaped or stripped, and only then is the bounded
    output truncated. Redaction therefore cannot be bypassed by truncation.
    """
    if not isinstance(text, str):
        raise LogCageInputError("text must be a str")
    working = strip_terminal_sequences(text)
    if config.redact:
        working = redact_control_insensitive(
            working,
            extra_secrets=config.extra_secrets,
            pii=config.pii,
            replacement=config.replacement,
        )
    chunks = neutralize_chunks(working, config.mode)
    return truncate_atomic_chunks(chunks, config.max_length, config.truncation_marker)


def sanitize_log_line(text: str, *, mode: str = "escape", max_length: Optional[int] = 4096,
                      truncation_marker: str = DEFAULT_TRUNCATION_MARKER,
                      redact: bool = True,
                      replacement: str = DEFAULT_REPLACEMENT,
                      extra_secrets: Optional[Iterable[object]] = None,
                      redact_pii: bool = False,
                      pii: Optional[dict] = None) -> str:
    """Return a single-line, terminal-safe, secret-redacted log line.

    ``mode='escape'`` renders controls as visible Python-style escape tokens.
    ``mode='strip'`` removes them. ANSI and other terminal control sequences
    are always removed in both modes. ``max_length`` is measured in Python
    string characters and includes the truncation marker. Escape tokens are
    atomic and are never split.
    """
    config = make_config(
        mode=mode,
        max_length=max_length,
        truncation_marker=truncation_marker,
        redact=redact,
        replacement=replacement,
        extra_secrets=extra_secrets,
        redact_pii=redact_pii,
        pii=pii,
    )
    return sanitize_line_with_config(text, config)


class LogCage:
    """Reusable, immutable-configuration sanitizer, redactor, and formatter helper."""

    __slots__ = ("config",)

    def __init__(self, **options: Any) -> None:
        self.config = make_config(**options)

    def sanitize_line(self, text: str) -> str:
        return sanitize_line_with_config(text, self.config)

    def sanitize(self, text: str) -> str:
        return self.sanitize_line(text)

    def line(self, text: str) -> str:
        return self.sanitize_line(text)

    def sanitize_log_line(self, text: str) -> str:
        return self.sanitize_line(text)

    def redact(self, text: str) -> str:
        if not isinstance(text, str):
            raise LogCageInputError("text must be a str")
        return redact_control_insensitive(
            strip_terminal_sequences(text),
            extra_secrets=self.config.extra_secrets,
            pii=self.config.pii,
            replacement=self.config.replacement,
        )

    def redact_secrets(self, text: str) -> str:
        return self.redact(text)

    def record(self, value: Any) -> Any:
        from .record import sanitize_record_with_config
        return sanitize_record_with_config(value, self.config)

    def sanitize_record(self, value: Any) -> Any:
        return self.record(value)

    def format_json(self, level: object, message: object, meta: Any = None) -> str:
        from .jsonlog import format_json_with_config
        return format_json_with_config(level, message, meta, self.config)

    def json(self, level: object, message: object, meta: Any = None) -> str:
        return self.format_json(level, message, meta)

    def format_safe_json_log(self, level: object, message: object, meta: Any = None) -> str:
        return self.format_json(level, message, meta)

    def logging_filter(self) -> "object":
        from .logging_integration import LogCageFilter
        return LogCageFilter(cage=self)

    def json_formatter(self) -> "object":
        from .logging_integration import SafeJsonFormatter
        return SafeJsonFormatter(cage=self)

    def text_formatter(self, fmt: Optional[str] = None, datefmt: Optional[str] = None) -> "object":
        from .logging_integration import SafeTextFormatter
        return SafeTextFormatter(fmt=fmt, datefmt=datefmt, cage=self)
