"""Bounded deterministic single-line JSON log formatting."""
from __future__ import annotations

import json
from typing import Any, Dict, Optional

from .config import CageConfig, make_config
from .core import sanitize_line_with_config
from .errors import LogCageOutputInvariantError
from .record import sanitize_record_with_config


def _safe_str(value: Any) -> str:
    try:
        return str(value)
    except Exception:
        return "[Unstringable " + type(value).__name__ + "]"


def _render_json(entry: Dict[str, Any]) -> str:
    return json.dumps(entry, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _utf8_len(text: str) -> int:
    return len(text.encode("utf-8"))


def _verify_output(output: str, max_output_bytes: int) -> str:
    if "\n" in output or "\r" in output:
        raise LogCageOutputInvariantError("serialized log entry contains a line break")
    if _utf8_len(output) > max_output_bytes:
        raise LogCageOutputInvariantError("serialized log entry exceeds max_output_bytes")
    json.loads(output)
    return output


def _atomic_prefix(text: str, count: int) -> str:
    """Return at most count characters without splitting a visible escape token."""
    if count >= len(text):
        return text
    if count <= 0:
        return ""
    out = []  # type: list[str]
    total = 0
    index = 0
    while index < len(text):
        width = 1
        if text[index] == "\\" and index + 1 < len(text):
            kind = text[index + 1]
            if kind in "nrt":
                width = 2
            elif kind == "x" and index + 3 < len(text):
                width = 4
            elif kind == "u" and index + 5 < len(text):
                width = 6
            elif kind == "U" and index + 9 < len(text):
                width = 10
        if total + width > count:
            break
        out.append(text[index:index + width])
        total += width
        index += width
    return "".join(out)


def _fit_message(entry: Dict[str, Any], safe_message: str, marker: str, max_output_bytes: int) -> Optional[str]:
    """Binary-search the longest truncated message fitting this entry shape."""
    if len(safe_message) <= 1:
        return None
    low = 0
    high = len(safe_message) - 1
    best = None  # type: Optional[str]
    while low <= high:
        middle = (low + high) // 2
        candidate_message = _atomic_prefix(safe_message, middle) + marker
        trial = dict(entry)
        trial["message"] = candidate_message
        try:
            rendered = _render_json(trial)
        except (TypeError, ValueError):
            return None
        if _utf8_len(rendered) <= max_output_bytes:
            best = rendered
            low = middle + 1
        else:
            high = middle - 1
    return best


def _fallback_output(max_output_bytes: int) -> str:
    candidates = (
        {"level": "INFO", "message": "[truncated]", "truncated": True},
        {"message": "[truncated]", "truncated": True},
        {"truncated": True},
        {},
    )
    for candidate in candidates:
        rendered = _render_json(candidate)
        if _utf8_len(rendered) <= max_output_bytes:
            return rendered
    if max_output_bytes >= 1:
        return "0"
    raise LogCageOutputInvariantError("max_output_bytes is too small for any JSON value")


def format_json_with_config(level: Any, message: Any, meta: Any, config: CageConfig) -> str:
    """Format a bounded NDJSON record with a validated configuration.

    Output is deterministic for deterministic input: keys are sorted, separators
    are fixed, no implicit timestamp is added, ASCII JSON escaping is used, and
    exactly zero raw line separators are emitted. If the full record exceeds
    the byte cap, metadata is first reduced or omitted and the message is then
    truncated. The last resort is a small valid JSON object with no log content.
    """
    safe_level = sanitize_line_with_config(_safe_str(level), config)
    if not safe_level:
        safe_level = "UNKNOWN"
    safe_message = sanitize_line_with_config(_safe_str(message), config)

    include_meta = meta is not None
    safe_meta = sanitize_record_with_config(meta, config) if include_meta else None

    entry = {"level": safe_level, "message": safe_message}  # type: Dict[str, Any]
    if include_meta:
        entry["meta"] = safe_meta
    try:
        rendered = _render_json(entry)
        if _utf8_len(rendered) <= config.max_output_bytes:
            return _verify_output(rendered, config.max_output_bytes)
    except (TypeError, ValueError):
        pass

    meta_variants = []
    if include_meta:
        meta_variants.append({"truncated": True})
        meta_variants.append(None)
    else:
        meta_variants.append(None)

    for meta_variant in meta_variants:
        reduced = {"level": safe_level, "message": safe_message}  # type: Dict[str, Any]
        if meta_variant is not None:
            reduced["meta"] = meta_variant
        try:
            rendered = _render_json(reduced)
        except (TypeError, ValueError):
            continue
        if _utf8_len(rendered) <= config.max_output_bytes:
            return _verify_output(rendered, config.max_output_bytes)
        fitted = _fit_message(reduced, safe_message, config.truncation_marker, config.max_output_bytes)
        if fitted is not None:
            return _verify_output(fitted, config.max_output_bytes)

    return _verify_output(_fallback_output(config.max_output_bytes), config.max_output_bytes)


def format_safe_json_log(level: Any, message: Any, meta: Any = None, *, max_output_bytes: int = 262144, **options: Any) -> str:
    """Emit one bounded, sanitized, deterministic JSON log record.

    The returned string contains no raw LF or CR and is verified to satisfy
    ``len(result.encode('utf-8')) <= max_output_bytes``. Oversized records fail
    closed to redacted/truncated JSON rather than raising or emitting an
    unbounded line.
    """
    options["max_output_bytes"] = max_output_bytes
    config = make_config(**options)
    return format_json_with_config(level, message, meta, config)
