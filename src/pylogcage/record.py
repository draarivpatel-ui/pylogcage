"""Recursive structured-record sanitization."""
from __future__ import annotations

import datetime as _datetime
import math
import os
import uuid as _uuid
from decimal import Decimal
from pathlib import PurePath
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple

from .config import CageConfig, is_dangerous_object_key, make_config, normalize_key_name, path_matches
from .core import sanitize_line_with_config

_NODE_LIMIT = "[NodeLimit]"
_DEPTH_LIMIT = "[MaxDepth]"
_CIRCULAR = "[Circular]"
_TRUNCATED = "[Truncated]"
_UNREADABLE = "[Unreadable]"
_UNREADABLE_SENTINEL = object()


class _RecordState:
    __slots__ = ("nodes", "max_nodes", "active")

    def __init__(self, max_nodes: int) -> None:
        self.nodes = 0
        self.max_nodes = max_nodes
        self.active = set()

    def consume(self) -> bool:
        if self.nodes >= self.max_nodes:
            return False
        self.nodes += 1
        return True


def sanitize_record(record: Any, **options: Any) -> Any:
    """Return a sanitized JSON-compatible copy of a structured log record.

    The input object graph is never mutated. Strings are line-sanitized and
    redacted, sensitive keys and configured paths are replaced or dropped,
    circular references and depth/key/sequence/node caps fail closed, and keys
    that are dangerous for downstream JavaScript JSON consumers are omitted.
    """
    config = make_config(**options)
    return sanitize_record_with_config(record, config)


def sanitize_record_with_config(record: Any, config: CageConfig) -> Any:
    state = _RecordState(config.max_nodes)
    return _sanitize_value(record, 0, (), state, config)


def _safe_str(value: Any) -> str:
    try:
        return str(value)
    except Exception:
        return "[Unstringable " + type(value).__name__ + "]"


def _safe_bytes_text(value: bytes) -> str:
    return value.decode("utf-8", "backslashreplace")


def _key_text(key: Any) -> str:
    if isinstance(key, str):
        return key
    if isinstance(key, (bytes, bytearray)):
        return _safe_bytes_text(bytes(key))
    if key is None or isinstance(key, (bool, int, float)):
        return str(key)
    return "<" + type(key).__name__ + " key>"


def _set_output_key(output: Dict[str, Any], key: str, value: Any) -> None:
    candidate = key
    if candidate in output:
        counter = 2
        while candidate + " [duplicate " + str(counter) + "]" in output:
            counter += 1
        candidate = candidate + " [duplicate " + str(counter) + "]"
    output[candidate] = value


def _path_child(path: Tuple[str, ...], segment: str) -> Tuple[str, ...]:
    return path + (segment,)


def _key_decision(raw_key: Any, safe_key: str, path: Tuple[str, ...], config: CageConfig) -> Tuple[bool, bool, Tuple[str, ...]]:
    """Return (drop, redact, child_path) for a mapping or attribute key."""
    raw_text = _key_text(raw_key)
    if is_dangerous_object_key(raw_text) or is_dangerous_object_key(safe_key):
        return True, False, path
    raw_canonical = normalize_key_name(raw_text)
    safe_canonical = normalize_key_name(safe_key)
    canonical = safe_canonical or raw_canonical
    child_path = _path_child(path, canonical)
    if raw_canonical in config.drop_keys or safe_canonical in config.drop_keys:
        return True, False, child_path
    if path_matches(child_path, config.drop_paths):
        return True, False, child_path
    sensitive = (
        raw_canonical in config.sensitive_keys
        or safe_canonical in config.sensitive_keys
        or path_matches(child_path, config.redact_paths)
    )
    return False, sensitive, child_path


def _sanitize_mapping(value: Mapping[Any, Any], depth: int, path: Tuple[str, ...], state: _RecordState, config: CageConfig) -> Dict[str, Any]:
    output = {}  # type: Dict[str, Any]
    count = 0
    total = 0
    truncated = False
    try:
        iterator = iter(value.items())
    except Exception:
        return {"type": type(value).__name__, "error": _UNREADABLE}
    while True:
        try:
            item = next(iterator)
        except StopIteration:
            break
        except Exception:
            truncated = True
            break
        total += 1
        if count >= config.max_keys:
            truncated = True
            break
        raw_key, child_value = item
        key_text = _key_text(raw_key)
        safe_key = sanitize_line_with_config(key_text, config)
        if not safe_key:
            safe_key = "[empty-key]"
        drop, redact, child_path = _key_decision(raw_key, safe_key, path, config)
        if drop:
            count += 1
            continue
        count += 1
        if redact:
            child = config.replacement
        else:
            child = _sanitize_value(child_value, depth + 1, child_path, state, config)
        _set_output_key(output, safe_key, child)
    if truncated:
        marker_key = "truncated"
        suffix = 2
        while marker_key in output:
            marker_key = "truncated " + str(suffix)
            suffix += 1
        output[marker_key] = "additional keys omitted"
    return output


def _sanitize_sequence(value: Sequence[Any], depth: int, path: Tuple[str, ...], state: _RecordState, config: CageConfig) -> List[Any]:
    output = []  # type: List[Any]
    try:
        length = len(value)
    except Exception:
        length = 0
    count = min(length, config.max_sequence_items)
    for index in range(count):
        try:
            item = value[index]
        except Exception:
            output.append(_UNREADABLE)
            continue
        output.append(_sanitize_value(item, depth + 1, _path_child(path, str(index)), state, config))
    if length > config.max_sequence_items:
        output.append(_TRUNCATED)
    return output


def _set_member_key(item: Any) -> Tuple[str, str]:
    if item is None:
        return ("0-none", "")
    if isinstance(item, bool):
        return ("1-bool", "1" if item else "0")
    if isinstance(item, (int, float, str)):
        return ("2-" + type(item).__name__, repr(item))
    return ("9-" + type(item).__name__, type(item).__name__)


def _sanitize_set(value: Iterable[Any], depth: int, path: Tuple[str, ...], state: _RecordState, config: CageConfig) -> List[Any]:
    try:
        items = list(value)
    except Exception:
        return [_UNREADABLE]
    try:
        items.sort(key=_set_member_key)
    except Exception:
        pass
    output = []  # type: List[Any]
    count = min(len(items), config.max_sequence_items)
    for index in range(count):
        output.append(_sanitize_value(items[index], depth + 1, _path_child(path, str(index)), state, config))
    if len(items) > config.max_sequence_items:
        output.append(_TRUNCATED)
    return output


def _iter_slot_names(obj: Any) -> Iterator[str]:
    seen = set()
    try:
        mro = type(obj).__mro__
    except Exception:
        return
    for cls in mro:
        try:
            slots = cls.__dict__.get("__slots__", ())
        except Exception:
            continue
        if isinstance(slots, str):
            names = (slots,)
        else:
            try:
                names = tuple(slots)
            except Exception:
                continue
        for name in names:
            if not isinstance(name, str) or name in ("__dict__", "__weakref__") or name in seen:
                continue
            seen.add(name)
            yield name


def _copy_object_attributes(obj: Any, output: Dict[str, Any], depth: int, path: Tuple[str, ...],
                            state: _RecordState, config: CageConfig, skipped: Iterable[str]) -> None:
    skip = set(skipped)
    entries = []  # type: List[Tuple[str, Any]]
    seen = set()
    try:
        variables = vars(obj)
    except Exception:
        variables = {}
    try:
        items = list(variables.items())
    except Exception:
        items = []
    for name, child in items:
        if isinstance(name, str) and name not in seen:
            seen.add(name)
            entries.append((name, child))
    for name in _iter_slot_names(obj):
        if name in seen:
            continue
        try:
            child = getattr(obj, name)
        except Exception:
            child = _UNREADABLE_SENTINEL
        seen.add(name)
        entries.append((name, child))

    count = 0
    truncated = False
    for name, child_value in entries:
        if name in skip:
            continue
        if count >= config.max_keys:
            truncated = True
            continue
        count += 1
        safe_key = sanitize_line_with_config(name, config)
        if not safe_key:
            safe_key = "[empty-key]"
        drop, redact, child_path = _key_decision(name, safe_key, path, config)
        if drop:
            continue
        if redact:
            child = config.replacement
        elif child_value is _UNREADABLE_SENTINEL:
            child = _UNREADABLE
        else:
            child = _sanitize_value(child_value, depth + 1, child_path, state, config)
        _set_output_key(output, safe_key, child)
    if truncated:
        _set_output_key(output, "truncated", "additional attributes omitted")


def _safe_type_name(value: Any) -> str:
    try:
        return type(value).__name__
    except Exception:
        return "object"


def _sanitize_exception(value: BaseException, depth: int, path: Tuple[str, ...], state: _RecordState, config: CageConfig) -> Dict[str, Any]:
    output = {}  # type: Dict[str, Any]
    output["type"] = sanitize_line_with_config(_safe_type_name(value), config)
    output["message"] = sanitize_line_with_config(_safe_str(value), config)

    try:
        args = getattr(value, "args", ())
    except Exception:
        args = ()
    if args:
        try:
            args_value = tuple(args)
        except Exception:
            output["args"] = _UNREADABLE
        else:
            output["args"] = _sanitize_value(args_value, depth + 1, _path_child(path, "args"), state, config)

    try:
        notes = getattr(value, "__notes__", ())
    except Exception:
        notes = ()
    if isinstance(notes, (list, tuple)) and notes:
        output["notes"] = _sanitize_value(list(notes), depth + 1, _path_child(path, "notes"), state, config)

    for field in ("__cause__", "__context__"):
        try:
            child = getattr(value, field)
        except Exception:
            child = None
        if child is not None:
            key = "cause" if field == "__cause__" else "context"
            output[key] = _sanitize_value(child, depth + 1, _path_child(path, key), state, config)

    try:
        grouped = getattr(value, "exceptions", None)
    except Exception:
        grouped = None
    if isinstance(grouped, (list, tuple)) and grouped:
        output["exceptions"] = _sanitize_value(list(grouped), depth + 1, _path_child(path, "exceptions"), state, config)

    _copy_object_attributes(
        value,
        output,
        depth,
        path,
        state,
        config,
        skipped=("args", "__notes__", "__cause__", "__context__", "exceptions", "type", "message"),
    )
    return output


def _sanitize_plain_object(value: Any, depth: int, path: Tuple[str, ...], state: _RecordState, config: CageConfig) -> Dict[str, Any]:
    output = {"type": sanitize_line_with_config(_safe_type_name(value), config)}  # type: Dict[str, Any]
    _copy_object_attributes(value, output, depth, path, state, config, skipped=("type",))
    return output


def _sanitize_container(value: Any, depth: int, path: Tuple[str, ...], state: _RecordState, config: CageConfig) -> Any:
    if depth >= config.max_depth:
        return _DEPTH_LIMIT
    ident = id(value)
    if ident in state.active:
        return _CIRCULAR
    state.active.add(ident)
    try:
        if isinstance(value, BaseException):
            return _sanitize_exception(value, depth, path, state, config)
        if isinstance(value, Mapping):
            return _sanitize_mapping(value, depth, path, state, config)
        if isinstance(value, (list, tuple)):
            return _sanitize_sequence(value, depth, path, state, config)
        if isinstance(value, (set, frozenset)):
            return _sanitize_set(value, depth, path, state, config)
        return _sanitize_plain_object(value, depth, path, state, config)
    except Exception:
        return _UNREADABLE
    finally:
        state.active.discard(ident)


def _sanitize_value(value: Any, depth: int, path: Tuple[str, ...], state: _RecordState, config: CageConfig) -> Any:
    if not state.consume():
        return _NODE_LIMIT
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, str):
        return sanitize_line_with_config(value, config)
    if isinstance(value, (bytes, bytearray)):
        return sanitize_line_with_config(_safe_bytes_text(bytes(value)), config)
    if isinstance(value, (_datetime.datetime, _datetime.date, _datetime.time)):
        try:
            return sanitize_line_with_config(value.isoformat(), config)
        except Exception:
            return sanitize_line_with_config(_safe_str(value), config)
    if isinstance(value, Decimal):
        return sanitize_line_with_config(str(value), config)
    if isinstance(value, _uuid.UUID):
        return str(value)
    if isinstance(value, PurePath):
        return sanitize_line_with_config(str(value), config)
    if isinstance(value, os.PathLike):
        try:
            fs_value = os.fspath(value)
            if isinstance(fs_value, (bytes, bytearray)):
                fs_text = _safe_bytes_text(bytes(fs_value))
            else:
                fs_text = str(fs_value)
            return sanitize_line_with_config(fs_text, config)
        except Exception:
            return sanitize_line_with_config(_safe_str(value), config)
    return _sanitize_container(value, depth, path, state, config)
