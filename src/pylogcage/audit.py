"""Safe log-stream audit primitives used by the pylogcage CLI."""
from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from typing import BinaryIO, Dict, List, Optional

from .redactor import secret_finding_kinds
from .sanitizer import is_sequence_start_c1, is_unsafe_control_or_format_char

MAX_AUDIT_FINDINGS = 1000


class AuditInputError(OSError):
    """Raised when an audit source is not a safe regular file or stream."""


@dataclass(frozen=True)
class AuditFinding:
    line: int
    kind: str


@dataclass(frozen=True)
class AuditResult:
    ok: bool
    lines: int
    findings: tuple
    counts: Dict[str, int]
    findings_truncated: bool

    def to_dict(self) -> Dict[str, object]:
        return {
            "ok": self.ok,
            "lines": self.lines,
            "findings": [{"line": item.line, "type": item.kind} for item in self.findings],
            "counts": dict(sorted(self.counts.items())),
            "findings_truncated": self.findings_truncated,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=True, sort_keys=True, separators=(",", ":"))

    def to_text(self) -> str:
        lines = []
        for item in self.findings:
            lines.append("line " + str(item.line) + " " + item.kind)
        total = sum(self.counts.values())
        lines.append("summary " + str(total) + " finding(s) in " + str(self.lines) + " line(s)")
        if self.findings_truncated:
            lines.append("findings truncated after " + str(MAX_AUDIT_FINDINGS) + " entries")
        return "\n".join(lines)


def _decode_line(raw: bytes) -> tuple:
    try:
        return raw.decode("utf-8"), False
    except UnicodeDecodeError:
        return raw.decode("utf-8", "backslashreplace"), True


def _utf8_unit(data: bytes, index: int):
    """Return (codepoint, width) for one UTF-8 unit, or (None, 1) if invalid."""
    first = data[index]
    if first < 0x80:
        return first, 1
    remaining = len(data) - index
    if 0xC2 <= first <= 0xDF:
        width = 2
        second_low, second_high = 0x80, 0xBF
    elif first == 0xE0:
        width = 3
        second_low, second_high = 0xA0, 0xBF
    elif 0xE1 <= first <= 0xEF:
        width = 3
        second_low, second_high = 0x80, 0xBF
    elif first == 0xF0:
        width = 4
        second_low, second_high = 0x90, 0xBF
    elif 0xF1 <= first <= 0xF3:
        width = 4
        second_low, second_high = 0x80, 0xBF
    elif first == 0xF4:
        width = 4
        second_low, second_high = 0x80, 0x8F
    else:
        return None, 1
    if remaining < width:
        return None, 1
    second = data[index + 1]
    if not (second_low <= second <= second_high):
        return None, 1
    for offset in range(2, width):
        if not (0x80 <= data[index + offset] <= 0xBF):
            return None, 1
    if width == 2:
        cp = ((first & 0x1F) << 6) | (second & 0x3F)
    elif width == 3:
        cp = ((first & 0x0F) << 12) | ((second & 0x3F) << 6) | (data[index + 2] & 0x3F)
    else:
        cp = ((first & 0x07) << 18) | ((second & 0x3F) << 12) | ((data[index + 2] & 0x3F) << 6) | (data[index + 3] & 0x3F)
    if 0xD800 <= cp <= 0xDFFF or cp > 0x10FFFF:
        return None, 1
    return cp, width


def _raw_byte_control_findings(raw: bytes) -> tuple:
    """Scan byte-accurate control facts without mistaking UTF-8 continuations."""
    terminal = False
    control = False
    index = 0
    while index < len(raw):
        byte = raw[index]
        cp, width = _utf8_unit(raw, index)
        if cp is None:
            if byte in (0x90, 0x98, 0x9B, 0x9D, 0x9E, 0x9F):
                terminal = True
            if 0x7F <= byte <= 0x9F:
                control = True
        else:
            if is_sequence_start_c1(cp):
                terminal = True
            if cp <= 0x1F or 0x7F <= cp <= 0x9F:
                control = True
        index += width
    return terminal, control


def audit_stream(stream: BinaryIO, *, max_findings: int = MAX_AUDIT_FINDINGS) -> AuditResult:
    """Audit a binary stream without printing or returning raw log content."""
    findings = []  # type: List[AuditFinding]
    counts = {
        "cwe117_control": 0,
        "terminal_escape": 0,
        "secret_leak": 0,
        "invalid_utf8": 0,
    }
    line_number = 0
    truncated = False
    for raw in stream:
        line_number += 1
        if raw.endswith(b"\n"):
            raw = raw[:-1]
        text, invalid_utf8 = _decode_line(raw)
        kinds = []
        if invalid_utf8:
            kinds.append("invalid_utf8")
        raw_terminal, raw_control = _raw_byte_control_findings(raw)
        if raw_terminal or "\x1b" in text or any(is_sequence_start_c1(ord(ch)) for ch in text):
            kinds.append("terminal_escape")
        if raw_control or any(is_unsafe_control_or_format_char(ch) for ch in text):
            kinds.append("cwe117_control")
        if secret_finding_kinds(text):
            kinds.append("secret_leak")
        for kind in kinds:
            counts[kind] += 1
            if len(findings) < max_findings:
                findings.append(AuditFinding(line_number, kind))
            else:
                truncated = True
    total = sum(counts.values())
    return AuditResult(total == 0, line_number, tuple(findings), counts, truncated)


def _open_regular_file(path: str) -> BinaryIO:
    flags = os.O_RDONLY
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise AuditInputError("audit source is not a regular file")
        return os.fdopen(fd, "rb")
    except Exception:
        os.close(fd)
        raise


def audit_source(source: str, stdin: Optional[BinaryIO] = None) -> AuditResult:
    """Audit ``-`` as a stream or a path after rejecting non-regular files."""
    if source == "-":
        if stdin is None:
            raise AuditInputError("standard input is unavailable")
        return audit_stream(stdin)
    with _open_regular_file(source) as stream:
        return audit_stream(stream)
