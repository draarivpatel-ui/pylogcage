"""Drop-in integration with Python's standard logging package."""
from __future__ import annotations

import copy
import logging
import traceback
from typing import Any, Dict, Optional, Tuple

from .core import LogCage, sanitize_line_with_config
from .jsonlog import format_json_with_config
from .record import sanitize_record_with_config

_STANDARD_RECORD_ATTRIBUTES = frozenset((
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName", "processName",
    "process", "message", "asctime", "taskName",
))


def _safe_str(value: Any) -> str:
    try:
        return str(value)
    except Exception:
        return "[Unstringable " + type(value).__name__ + "]"


def _safe_repr(value: Any) -> str:
    try:
        return repr(value)
    except Exception:
        return "[Unrepresentable " + type(value).__name__ + "]"


def format_message_safely(msg: Any, args: Any) -> str:
    """Format a logging percent-style message without double-formatting args.

    Stdlib logging uses percent formatting. If the template and arguments do
    not agree, the unformatted template is retained and a repr of the arguments
    is appended; the caller sanitizes the complete result before it can reach a
    handler. Once a record is formatted by pylogcage, its args are emptied, so a
    percent sign inside an argument is never interpreted as a second template.
    """
    text = _safe_str(msg)
    if args:
        try:
            return text % args
        except Exception:
            return text + " [unformatted args " + _safe_repr(args) + "]"
    return text


def render_exception_safely(exc_info: Any) -> str:
    """Render exception information without invoking unusual formatter machinery."""
    try:
        exc_type, exc_value, exc_tb = exc_info
        return "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
    except Exception:
        try:
            if isinstance(exc_info, tuple) and len(exc_info) >= 2:
                return _safe_str(exc_info[1])
        except Exception:
            pass
        return "[Unreadable exception]"


def _custom_extra_items(record: logging.LogRecord) -> Tuple[Tuple[str, Any], ...]:
    items = []
    for key, value in record.__dict__.items():
        if key not in _STANDARD_RECORD_ATTRIBUTES:
            items.append((key, value))
    return tuple(items)


class LogCageFilter(logging.Filter):
    """A logging filter that sanitizes messages, args, exceptions, and extras.

    Values passed by the caller through ``extra=`` are copied into the record
    after sanitization. The original dictionaries, objects, exceptions, and arg
    values owned by the caller are never mutated.
    """

    def __init__(self, cage: Optional[LogCage] = None, *, name: str = "", **options: Any) -> None:
        if isinstance(cage, str):
            name = cage
            cage = None
        super().__init__(name)
        self.cage = cage if cage is not None else LogCage(**options)

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            formatted = format_message_safely(record.msg, record.args)
            record.msg = sanitize_line_with_config(formatted, self.cage.config)
            record.args = ()

            if record.exc_info:
                rendered = render_exception_safely(record.exc_info)
                record.exc_text = sanitize_line_with_config(rendered, self.cage.config)
                record.exc_info = None
            elif record.exc_text:
                record.exc_text = sanitize_line_with_config(record.exc_text, self.cage.config)

            if record.stack_info:
                record.stack_info = sanitize_line_with_config(record.stack_info, self.cage.config)

            for key, value in _custom_extra_items(record):
                setattr(record, key, sanitize_record_with_config(value, self.cage.config))
            return True
        except Exception:
            try:
                record.msg = "[LogCage filter error]"
                record.args = ()
                record.exc_info = None
                record.exc_text = None
            except Exception:
                pass
            return True


class SafeJsonFormatter(logging.Formatter):
    """Formatter emitting bounded single-line sanitized NDJSON records."""

    def __init__(self, cage: Optional[LogCage] = None, max_output_bytes: Optional[int] = None, **options: Any) -> None:
        if cage is not None and options:
            raise ValueError("pass either cage or formatter options, not both")
        if cage is None:
            if max_output_bytes is not None:
                options["max_output_bytes"] = max_output_bytes
            cage = LogCage(**options)
        elif max_output_bytes is not None and max_output_bytes != cage.config.max_output_bytes:
            raise ValueError("max_output_bytes is fixed by the supplied cage")
        super().__init__()
        self.cage = cage

    def format(self, record: logging.LogRecord) -> str:
        try:
            message = sanitize_line_with_config(format_message_safely(record.msg, record.args), self.cage.config)
            meta = {}  # type: Dict[str, Any]
            for key, value in _custom_extra_items(record):
                if key in ("logger", "exception", "stack"):
                    continue
                safe_key = sanitize_line_with_config(key, self.cage.config)
                if safe_key:
                    meta[safe_key] = sanitize_record_with_config(value, self.cage.config)
            meta["logger"] = sanitize_line_with_config(record.name, self.cage.config)
            if record.exc_info:
                meta["exception"] = sanitize_line_with_config(render_exception_safely(record.exc_info), self.cage.config)
            elif record.exc_text:
                meta["exception"] = sanitize_line_with_config(record.exc_text, self.cage.config)
            if record.stack_info:
                meta["stack"] = sanitize_line_with_config(record.stack_info, self.cage.config)
            return format_json_with_config(record.levelname, message, meta, self.cage.config)
        except Exception:
            try:
                return format_json_with_config(record.levelname, "[log formatting error]", {"logger": record.name}, self.cage.config)
            except Exception:
                return "{}"


class SafeTextFormatter(logging.Formatter):
    """Formatter emitting one CWE-117-safe text line per record."""

    DEFAULT_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"

    def __init__(self, fmt: Optional[str] = None, datefmt: Optional[str] = None,
                 cage: Optional[LogCage] = None, **options: Any) -> None:
        if cage is not None and options:
            raise ValueError("pass either cage or formatter options, not both")
        if cage is None:
            cage = LogCage(**options)
        super().__init__(fmt=fmt or self.DEFAULT_FORMAT, datefmt=datefmt)
        self.cage = cage

    def format(self, record: logging.LogRecord) -> str:
        try:
            safe_record = copy.copy(record)
            safe_record.msg = format_message_safely(record.msg, record.args)
            safe_record.args = ()
            if record.exc_info:
                safe_record.exc_text = render_exception_safely(record.exc_info)
                safe_record.exc_info = None
            try:
                rendered = super().format(safe_record)
            except Exception:
                rendered = record.levelname + " " + record.name + ": " + safe_record.msg
            return sanitize_line_with_config(rendered, self.cage.config)
        except Exception:
            return sanitize_line_with_config("ERROR [log formatting error]", self.cage.config)
