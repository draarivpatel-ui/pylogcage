"""Linear time terminal-sequence stripping and CWE-117 line sanitization."""
from __future__ import annotations

import unicodedata
from typing import Iterable, List, Optional, Sequence, Tuple

from .errors import INVALID_INPUT, LogCageError, LogCageInputError, invalid_options

DEFAULT_TRUNCATION_MARKER = "[truncated]"
DEFAULT_REPLACEMENT = "[REDACTED]"
MIN_MAX_LENGTH = 16
MAX_MAX_LENGTH = 1048576
MAX_MARKER_LENGTH = 64

_SEQUENCE_START_C1 = frozenset((0x90, 0x98, 0x9B, 0x9D, 0x9E, 0x9F))
_STRING_START_C1 = frozenset((0x90, 0x98, 0x9D, 0x9E, 0x9F))


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise LogCageInputError(label + " must be a str")
    return value


def is_lone_surrogate_codepoint(cp: int) -> bool:
    return 0xD800 <= cp <= 0xDFFF


def is_noncharacter_codepoint(cp: int) -> bool:
    return 0xFDD0 <= cp <= 0xFDEF or (cp & 0xFFFE) == 0xFFFE


def is_variation_selector(cp: int) -> bool:
    return 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF


_UNSAFE_CODEPOINT_CACHE = {}
_UNSAFE_CACHE_LIMIT = 8192


def _is_unsafe_nonascii_codepoint(cp: int, ch: str) -> bool:
    if cp in (0x2028, 0x2029):
        return True
    if is_lone_surrogate_codepoint(cp) or is_noncharacter_codepoint(cp):
        return True
    if is_variation_selector(cp):
        return True
    if cp in (0x00AD, 0x061C, 0x06DD, 0x070F, 0x0890, 0x0891, 0x08E2, 0x180E, 0xFEFF):
        return True
    if 0x0600 <= cp <= 0x0605:
        return True
    if 0x200B <= cp <= 0x200F:
        return True
    if 0x202A <= cp <= 0x202E:
        return True
    if 0x2060 <= cp <= 0x206F:
        return True
    if 0xFFF9 <= cp <= 0xFFFB:
        return True
    if cp in (0x110BD, 0x110CD, 0xE0001):
        return True
    if 0x13430 <= cp <= 0x1343F:
        return True
    if 0x1BCA0 <= cp <= 0x1BCA3:
        return True
    if 0x1D173 <= cp <= 0x1D17A:
        return True
    if 0xE0020 <= cp <= 0xE007F:
        return True
    return unicodedata.category(ch) == "Cf"


def is_unsafe_control_or_format_char(ch: str) -> bool:
    """Return True for characters that can forge log lines or terminal state.

    The set intentionally includes every C0 and C1 control, DEL, Unicode line
    and paragraph separators, format characters (general category Cf),
    variation selectors, noncharacters, and lone UTF-16 surrogate code points.
    Ordinary combining marks and ordinary non-ASCII text are not affected.
    """
    if len(ch) != 1:
        raise ValueError("expected exactly one character")
    cp = ord(ch)
    if cp <= 0x1F or 0x7F <= cp <= 0x9F:
        return True
    if 0x20 <= cp <= 0x7E:
        return False
    cached = _UNSAFE_CODEPOINT_CACHE.get(cp)
    if cached is not None:
        return cached
    result = _is_unsafe_nonascii_codepoint(cp, ch)
    if len(_UNSAFE_CODEPOINT_CACHE) < _UNSAFE_CACHE_LIMIT:
        _UNSAFE_CODEPOINT_CACHE[cp] = result
    return result


def is_sequence_start_c1(cp: int) -> bool:
    return cp in _SEQUENCE_START_C1


def escape_for_codepoint(cp: int) -> str:
    if cp == 10:
        return "\\n"
    if cp == 13:
        return "\\r"
    if cp == 9:
        return "\\t"
    if cp <= 0xFF:
        return "\\x%02x" % cp
    if cp <= 0xFFFF:
        return "\\u%04x" % cp
    return "\\U%08x" % cp


def validate_marker(value: str, field: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_MARKER_LENGTH:
        raise invalid_options(field + " must be a string of 1 to 64 characters", field)
    for ch in value:
        if is_unsafe_control_or_format_char(ch):
            raise invalid_options(field + " contains an unsafe control or format character", field)
    return value


def validate_max_length(value: Optional[int], marker: str) -> int:
    if value is None:
        value = 4096
    if isinstance(value, bool) or not isinstance(value, int):
        raise invalid_options("max_length must be an integer", "max_length")
    if value < MIN_MAX_LENGTH or value > MAX_MAX_LENGTH:
        raise invalid_options("max_length must be in the range 16 to 1048576", "max_length")
    if value <= len(marker):
        raise invalid_options("max_length must be greater than the truncation marker length", "max_length")
    return value


def validate_mode(mode: str) -> str:
    if mode not in ("escape", "strip"):
        raise invalid_options("mode must be 'escape' or 'strip'", "mode")
    return mode


def _scan_csi(text: str, index: int) -> int:
    """Consume bytes after a CSI introducer through its final byte.

    ECMA-48 final bytes are 0x40 through 0x7e. An unterminated sequence is
    consumed through end-of-input. The scan is a single forward pass.
    """
    n = len(text)
    i = index
    while i < n:
        cp = ord(text[i])
        if 0x40 <= cp <= 0x7E:
            return i + 1
        i += 1
    return i


def _scan_string_control(text: str, index: int, allow_bel: bool) -> int:
    """Consume an OSC, DCS, SOS, PM, or APC payload through its terminator."""
    n = len(text)
    i = index
    while i < n:
        cp = ord(text[i])
        if allow_bel and cp == 0x07:
            return i + 1
        if cp == 0x9C:
            return i + 1
        if cp == 0x1B and i + 1 < n and text[i + 1] == "\\":
            return i + 2
        i += 1
    return i


def _scan_escape_sequence(text: str, index: int) -> int:
    """Consume one escape sequence beginning at text[index] == ESC."""
    n = len(text)
    if index + 1 >= n:
        return index + 1
    nxt = ord(text[index + 1])
    if nxt == 0x5B:  # CSI: ESC [
        return _scan_csi(text, index + 2)
    if nxt == 0x5D:  # OSC: ESC ]
        return _scan_string_control(text, index + 2, True)
    if nxt in (0x50, 0x58, 0x5E, 0x5F):  # DCS, SOS, PM, APC
        return _scan_string_control(text, index + 2, False)
    if nxt == 0x1B:
        return index + 1
    if nxt == 0x5C:  # A stray ST encoded as ESC backslash.
        return index + 2
    if 0x20 <= nxt <= 0x2F:
        i = index + 1
        while i < n and 0x20 <= ord(text[i]) <= 0x2F:
            i += 1
        if i < n and 0x30 <= ord(text[i]) <= 0x7E:
            return i + 1
        return i
    if 0x30 <= nxt <= 0x7E:
        return index + 2
    return index + 1


def _scan_c1_sequence(text: str, index: int) -> int:
    cp = ord(text[index])
    if cp == 0x9B:
        return _scan_csi(text, index + 1)
    if cp == 0x9D:
        return _scan_string_control(text, index + 1, True)
    if cp in _STRING_START_C1:
        return _scan_string_control(text, index + 1, False)
    return index + 1


def strip_terminal_sequences(text: str) -> str:
    """Remove ANSI, OSC, DCS, PM, APC, SOS, and 8-bit C1 control sequences.

    Malformed and unterminated sequences fail closed: the introducer and its
    remaining payload are removed rather than being passed to a terminal. The
    function is strictly linear time because each input index is consumed once.
    It intentionally does not remove ordinary control characters that are not
    sequence introducers; use :func:`sanitize_log_line` for full neutralization.
    """
    text = _require_text(text, "text")
    out = []  # type: List[str]
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        cp = ord(ch)
        if cp == 0x1B:
            i = _scan_escape_sequence(text, i)
            continue
        if cp in _SEQUENCE_START_C1:
            i = _scan_c1_sequence(text, i)
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def neutralize_chunks(text: str, mode: str = "escape") -> List[str]:
    """Return atomic output chunks with unsafe characters escaped or removed."""
    validate_mode(mode)
    chunks = []  # type: List[str]
    for ch in text:
        cp = ord(ch)
        if is_unsafe_control_or_format_char(ch):
            if mode == "escape":
                chunks.append(escape_for_codepoint(cp))
        else:
            chunks.append(ch)
    return chunks


def truncate_atomic_chunks(chunks: Sequence[str], max_length: int, marker: str = DEFAULT_TRUNCATION_MARKER) -> str:
    """Truncate atomic chunks so the marker is included in max_length.

    A chunk is never split. This matters for visible tokens such as ``\\u2028``
    and for astral characters, which Python already represents as one string
    element. The caller's configuration validation guarantees that
    ``max_length > len(marker)``.
    """
    total = 0
    kept = []  # type: List[str]
    truncated = False
    for chunk in chunks:
        size = len(chunk)
        if total + size <= max_length:
            kept.append(chunk)
            total += size
        else:
            truncated = True
            break
    if not truncated:
        return "".join(kept)
    capacity = max_length - len(marker)
    while total > capacity and kept:
        removed = kept.pop()
        total -= len(removed)
    return "".join(kept) + marker


def truncate_preserving_escape_tokens(text: str, max_length: int, marker: str = DEFAULT_TRUNCATION_MARKER) -> str:
    """Truncate already-neutralized text without splitting a backslash token."""
    chunks = []  # type: List[str]
    i = 0
    n = len(text)
    while i < n:
        width = 1
        if text[i] == "\\" and i + 1 < n:
            kind = text[i + 1]
            if kind in "nrt":
                width = 2
            elif kind == "x" and i + 3 < n:
                width = 4
            elif kind == "u" and i + 5 < n:
                width = 6
            elif kind == "U" and i + 9 < n:
                width = 10
        chunks.append(text[i:i + width])
        i += width
    return truncate_atomic_chunks(chunks, max_length, marker)


def detection_view(text: str) -> Tuple[str, List[int]]:
    """Build a control-resistant detection string and an index map.

    Line-break controls retain their record-separator meaning as ``\n`` and a
    horizontal tab remains a tab. Other unsafe control, format, noncharacter,
    and surrogate code points are removed. This lets secret detectors see a
    token that an attacker interrupted with a zero-width or terminal-control
    character without erasing the line structure used by header parsers.
    """
    chars = []  # type: List[str]
    mapping = []  # type: List[int]
    for index, ch in enumerate(text):
        cp = ord(ch)
        if ch in ("\r", "\n", "\t"):
            chars.append(ch)
            mapping.append(index)
        elif cp in (0x85, 0x2028, 0x2029):
            chars.append("\n")
            mapping.append(index)
        elif is_unsafe_control_or_format_char(ch):
            continue
        else:
            chars.append(ch)
            mapping.append(index)
    return "".join(chars), mapping


def map_detection_span(mapping: Sequence[int], start: int, end: int) -> Tuple[int, int]:
    """Map a half-open detection-string span back to original coordinates."""
    if start >= end:
        return (mapping[start], mapping[start]) if start < len(mapping) else (0, 0)
    return mapping[start], mapping[end - 1] + 1


def sanitize_line_chunks(text: str, mode: str = "escape") -> List[str]:
    """Strip terminal sequences and return atomic neutralized chunks.

    Redaction is deliberately not performed here. The redaction pipeline calls
    these primitives in the required order: strip terminal sequences, redact,
    neutralize, then truncate.
    """
    stripped = strip_terminal_sequences(text)
    return neutralize_chunks(stripped, mode)


def sanitize_log_line_neutral_only(text: str, *, mode: str = "escape", max_length: Optional[int] = 4096,
                                   truncation_marker: str = DEFAULT_TRUNCATION_MARKER) -> str:
    """Sanitize a line without secret redaction.

    This helper is internal but importable for specialized callers. The public
    :func:`pylogcage.sanitize_log_line` performs redaction before truncation.
    """
    text = _require_text(text, "text")
    validate_mode(mode)
    marker = validate_marker(truncation_marker, "truncation_marker")
    limit = validate_max_length(max_length, marker)
    return truncate_atomic_chunks(sanitize_line_chunks(text, mode), limit, marker)


def assert_no_unsafe_characters(text: str) -> None:
    """Raise if a sanitized output still contains an unsafe raw character."""
    for ch in text:
        if is_unsafe_control_or_format_char(ch):
            raise LogCageError(
                "ERR_PYLOGCAGE_OUTPUT_INVARIANT",
                "sanitized output contains an unsafe control or format character",
                actual=ord(ch),
            )
