"""Shared immutable configuration for pylogcage APIs."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, FrozenSet, Iterable, Optional, Sequence, Tuple

from .errors import invalid_options
from .redactor import PIIFlags, SecretValue, normalize_extra_secrets, normalize_pii, validate_replacement
from .sanitizer import (
    DEFAULT_REPLACEMENT,
    DEFAULT_TRUNCATION_MARKER,
    is_unsafe_control_or_format_char,
    validate_marker,
    validate_max_length,
    validate_mode,
)

MAX_SENSITIVE_KEYS = 128
MAX_PATHS = 128
MAX_PATH_SEGMENTS = 64
MAX_KEY_LENGTH = 128
MAX_PATH_TEXT_LENGTH = 512

DEFAULT_SENSITIVE_KEY_NAMES = frozenset((
    "password", "passwd", "pwd", "secret", "token", "apikey", "authorization",
    "cookie", "setcookie", "privatekey", "accesstoken", "refreshtoken",
    "clientsecret", "sessionid", "ssn", "creditcard", "csrftoken", "xsrftoken",
    "secretaccesskey", "awssecretaccesskey", "accesskey", "sessionkey", "encryptionkey",
))

DANGEROUS_OBJECT_KEYS = frozenset(("__proto__", "constructor", "prototype"))


def _validate_bool(value: bool, field: str) -> bool:
    if not isinstance(value, bool):
        raise invalid_options(field + " must be a boolean", field)
    return value


def _validate_int(value: int, minimum: int, maximum: int, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > maximum:
        raise invalid_options(field + " must be an integer in range", field)
    return value


def normalize_key_name(key: object) -> str:
    """Canonicalize a key for sensitive-key and path comparisons.

    Separators and unsafe format/control characters are ignored, ASCII is
    lowercased, and other ordinary Unicode letters are casefolded. This makes
    obfuscated forms such as ``access-token`` and a control-padded key compare
    equal to their canonical sensitive name.
    """
    if not isinstance(key, str):
        key = str(key)
    output = []  # type: list[str]
    for ch in key:
        if ch in "_-. \t":
            continue
        if is_unsafe_control_or_format_char(ch):
            continue
        if "A" <= ch <= "Z":
            output.append(chr(ord(ch) + 32))
        else:
            output.append(ch.casefold())
    return "".join(output)


def is_dangerous_object_key(key: object) -> bool:
    if not isinstance(key, str):
        return False
    lowered = key.strip().lower()
    return lowered in DANGEROUS_OBJECT_KEYS or normalize_key_name(key) in DANGEROUS_OBJECT_KEYS


def _normalize_key_set(values: Optional[Iterable[object]], field: str) -> FrozenSet[str]:
    if values is None:
        return frozenset()
    if isinstance(values, (str, bytes, bytearray)):
        raise invalid_options(field + " must be an iterable of key names", field)
    try:
        items = list(values)
    except TypeError:
        raise invalid_options(field + " must be an iterable of key names", field)
    if len(items) > MAX_SENSITIVE_KEYS:
        raise invalid_options(field + " exceeds the count limit", field)
    output = set()
    for item in items:
        if not isinstance(item, str) or not 1 <= len(item) <= MAX_KEY_LENGTH:
            raise invalid_options(field + " entries must be non-empty strings within the length limit", field)
        canonical = normalize_key_name(item)
        if not canonical:
            raise invalid_options(field + " entries must contain a key character", field)
        output.add(canonical)
    return frozenset(output)


def _normalize_path_entry(entry: object, field: str) -> Tuple[str, ...]:
    if isinstance(entry, str):
        if not 1 <= len(entry) <= MAX_PATH_TEXT_LENGTH:
            raise invalid_options(field + " string entries must be within the length limit", field)
        raw_segments = entry.split(".")
    elif isinstance(entry, (list, tuple)):
        if not 1 <= len(entry) <= MAX_PATH_SEGMENTS:
            raise invalid_options(field + " array entries must have a bounded segment count", field)
        raw_segments = list(entry)
    else:
        raise invalid_options(field + " entries must be strings or arrays of strings", field)
    segments = []
    for segment in raw_segments:
        if not isinstance(segment, str) or not 1 <= len(segment) <= MAX_KEY_LENGTH:
            raise invalid_options(field + " segments must be non-empty strings within the length limit", field)
        if segment == "*":
            canonical = "*"
        else:
            canonical = normalize_key_name(segment)
        if not canonical:
            raise invalid_options(field + " segments must contain a key character", field)
        segments.append(canonical)
    return tuple(segments)


def _normalize_paths(values: Optional[Iterable[object]], field: str) -> Tuple[Tuple[str, ...], ...]:
    if values is None:
        return ()
    if isinstance(values, (str, bytes, bytearray)):
        values = (values,)
    try:
        items = list(values)
    except TypeError:
        raise invalid_options(field + " must be an iterable", field)
    if len(items) > MAX_PATHS:
        raise invalid_options(field + " exceeds the count limit", field)
    return tuple(_normalize_path_entry(item, field) for item in items)


@dataclass(frozen=True)
class CageConfig:
    mode: str
    max_length: int
    truncation_marker: str
    replacement: str
    redact: bool
    extra_secrets: Tuple[SecretValue, ...]
    pii: PIIFlags
    max_depth: int
    max_keys: int
    max_sequence_items: int
    max_nodes: int
    sensitive_keys: FrozenSet[str]
    drop_keys: FrozenSet[str]
    redact_paths: Tuple[Tuple[str, ...], ...]
    drop_paths: Tuple[Tuple[str, ...], ...]
    max_output_bytes: int


def make_config(*, mode: str = "escape", max_length: Optional[int] = 4096,
                truncation_marker: str = DEFAULT_TRUNCATION_MARKER,
                replacement: str = DEFAULT_REPLACEMENT,
                redact: bool = True,
                extra_secrets: Optional[Iterable[object]] = None,
                redact_pii: bool = False,
                pii: Optional[Dict[str, bool]] = None,
                max_depth: int = 12,
                max_keys: int = 200,
                max_sequence_items: Optional[int] = None,
                max_array_length: Optional[int] = None,
                max_nodes: int = 2000,
                sensitive_keys: Optional[Iterable[object]] = None,
                drop_keys: Optional[Iterable[object]] = None,
                redact_paths: Optional[Iterable[object]] = None,
                sensitive_paths: Optional[Iterable[object]] = None,
                drop_paths: Optional[Iterable[object]] = None,
                max_output_bytes: int = 262144) -> CageConfig:
    """Validate and normalize all pylogcage options.

    ``max_array_length`` is accepted as a compatibility alias for
    ``max_sequence_items``. ``sensitive_paths`` is an alias for
    ``redact_paths``.
    """
    validate_mode(mode)
    marker = validate_marker(truncation_marker, "truncation_marker")
    limit = validate_max_length(max_length, marker)
    replacement = validate_replacement(replacement)
    _validate_bool(redact, "redact")

    if max_sequence_items is not None and max_array_length is not None and max_sequence_items != max_array_length:
        raise invalid_options("max_sequence_items and max_array_length disagree", "max_sequence_items")
    sequence_items = max_sequence_items if max_sequence_items is not None else max_array_length
    if sequence_items is None:
        sequence_items = 200

    if redact_paths is not None and sensitive_paths is not None:
        raise invalid_options("use only one of redact_paths and sensitive_paths", "redact_paths")
    effective_redact_paths = redact_paths if redact_paths is not None else sensitive_paths

    sensitive = set(DEFAULT_SENSITIVE_KEY_NAMES)
    sensitive.update(_normalize_key_set(sensitive_keys, "sensitive_keys"))

    return CageConfig(
        mode=mode,
        max_length=limit,
        truncation_marker=marker,
        replacement=replacement,
        redact=redact,
        extra_secrets=normalize_extra_secrets(extra_secrets),
        pii=normalize_pii(redact_pii, pii),
        max_depth=_validate_int(max_depth, 1, 64, "max_depth"),
        max_keys=_validate_int(max_keys, 1, 10000, "max_keys"),
        max_sequence_items=_validate_int(sequence_items, 1, 10000, "max_sequence_items"),
        max_nodes=_validate_int(max_nodes, 1, 100000, "max_nodes"),
        sensitive_keys=frozenset(sensitive),
        drop_keys=_normalize_key_set(drop_keys, "drop_keys"),
        redact_paths=_normalize_paths(effective_redact_paths, "redact_paths"),
        drop_paths=_normalize_paths(drop_paths, "drop_paths"),
        max_output_bytes=_validate_int(max_output_bytes, 1, 4194304, "max_output_bytes"),
    )


def path_matches(path: Sequence[str], patterns: Sequence[Sequence[str]]) -> bool:
    """Match a canonical path against exact patterns with ``*`` wildcards."""
    for pattern in patterns:
        if len(pattern) != len(path):
            continue
        same = True
        for want, actual in zip(pattern, path):
            if want != "*" and want != actual:
                same = False
                break
        if same:
            return True
    return False
