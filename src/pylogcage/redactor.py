"""Secret and optional PII redaction with control-obfuscation resistance."""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from .errors import LogCageInputError, invalid_options
from .sanitizer import (
    DEFAULT_REPLACEMENT,
    detection_view,
    is_unsafe_control_or_format_char,
    map_detection_span,
    strip_terminal_sequences,
    validate_marker,
)

MAX_EXTRA_SECRETS = 64
MAX_EXTRA_SECRET_LENGTH = 4096

Span = Tuple[int, int, str]


@dataclass(frozen=True)
class PIIFlags:
    email: bool = False
    luhn_card: bool = False
    ssn: bool = False
    ipv4: bool = False


@dataclass(frozen=True)
class SecretValue:
    text: str
    data: bytes


def validate_replacement(value: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        raise invalid_options("replacement must be a string of 1 to 128 characters", "replacement")
    for ch in value:
        if is_unsafe_control_or_format_char(ch):
            raise invalid_options("replacement contains an unsafe control or format character", "replacement")
    return value


def normalize_pii(redact_pii: bool = False, pii: Optional[Dict[str, bool]] = None) -> PIIFlags:
    if not isinstance(redact_pii, bool):
        raise invalid_options("redact_pii must be a boolean", "redact_pii")
    values = {
        "email": redact_pii,
        "luhn_card": redact_pii,
        "ssn": redact_pii,
        "ipv4": redact_pii,
    }
    if pii is not None:
        if not isinstance(pii, dict):
            raise invalid_options("pii must be a dict", "pii")
        for key, value in pii.items():
            if key not in values:
                raise invalid_options("pii contains an unknown key", "pii")
            if not isinstance(value, bool):
                raise invalid_options("pii values must be booleans", "pii")
            values[key] = value
    return PIIFlags(values["email"], values["luhn_card"], values["ssn"], values["ipv4"])


def _secret_to_value(secret: object) -> SecretValue:
    if isinstance(secret, str):
        if not 1 <= len(secret) <= MAX_EXTRA_SECRET_LENGTH:
            raise invalid_options("extra_secrets entries must be non-empty strings within the length limit", "extra_secrets")
        data = secret.encode("utf-8", "surrogatepass")
        return SecretValue(secret, data)
    if isinstance(secret, (bytes, bytearray)):
        data = bytes(secret)
        if not 1 <= len(data) <= MAX_EXTRA_SECRET_LENGTH:
            raise invalid_options("extra_secrets byte entries must be non-empty within the length limit", "extra_secrets")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin-1")
        return SecretValue(text, data)
    raise invalid_options("extra_secrets entries must be str, bytes, or bytearray", "extra_secrets")


def normalize_extra_secrets(extra_secrets: Optional[Iterable[object]]) -> Tuple[SecretValue, ...]:
    if extra_secrets is None:
        return ()
    if isinstance(extra_secrets, (str, bytes, bytearray)):
        raise invalid_options("extra_secrets must be an iterable of secrets, not one scalar secret", "extra_secrets")
    try:
        values = list(extra_secrets)
    except TypeError:
        raise invalid_options("extra_secrets must be an iterable", "extra_secrets")
    if len(values) > MAX_EXTRA_SECRETS:
        raise invalid_options("extra_secrets exceeds the count limit", "extra_secrets")
    return tuple(_secret_to_value(item) for item in values)


def _is_ascii_alpha(cp: int) -> bool:
    return 65 <= cp <= 90 or 97 <= cp <= 122


def _is_ascii_digit(cp: int) -> bool:
    return 48 <= cp <= 57


def _is_ascii_alnum(cp: int) -> bool:
    return _is_ascii_alpha(cp) or _is_ascii_digit(cp)


def _ascii_lower(ch: str) -> str:
    cp = ord(ch)
    if 65 <= cp <= 90:
        return chr(cp + 32)
    return ch


def _starts_case_insensitive(text: str, index: int, needle: str) -> bool:
    if index + len(needle) > len(text):
        return False
    for pos, ch in enumerate(needle):
        if _ascii_lower(text[index + pos]) != _ascii_lower(ch):
            return False
    return True


def _word_boundary_before(text: str, index: int) -> bool:
    if index <= 0:
        return True
    cp = ord(text[index - 1])
    return not _is_ascii_alnum(cp) and cp != 95


def _select_nonoverlapping_spans(spans: Iterable[Span]) -> List[Span]:
    unique = set()
    for start, end, kind in spans:
        if start < end:
            unique.add((start, end, kind))
    longest_first = sorted(unique, key=lambda item: (-(item[1] - item[0]), item[0], item[2]))
    selected = []  # type: List[Span]
    for span in longest_first:
        start, end, _kind = span
        overlaps = False
        for old_start, old_end, _old_kind in selected:
            if start < old_end and old_start < end:
                overlaps = True
                break
        if not overlaps:
            selected.append(span)
    return sorted(selected, key=lambda item: (item[0], item[1]))


def _merge_overlapping_spans(spans: Iterable[Span]) -> List[Span]:
    ordered = sorted((span for span in spans if span[0] < span[1]), key=lambda item: (item[0], item[1]))
    merged = []  # type: List[Span]
    for start, end, kind in ordered:
        if not merged or start > merged[-1][1]:
            merged.append((start, end, kind))
        else:
            old_start, old_end, old_kind = merged[-1]
            merged[-1] = (old_start, max(old_end, end), old_kind)
    return merged


def _apply_spans(text: str, spans: Sequence[Span], replacement: str) -> str:
    if not spans:
        return text
    out = []  # type: List[str]
    cursor = 0
    for start, end, _kind in _merge_overlapping_spans(spans):
        if start < cursor:
            continue
        out.append(text[cursor:start])
        out.append(replacement)
        cursor = end
    out.append(text[cursor:])
    return "".join(out)


def _collapsed_detection_view(text: str) -> Tuple[str, List[int]]:
    """Remove every unsafe control or format char for fail-closed detection.

    Unlike :func:`detection_view`, this view does not preserve line-break or
    tab controls as syntax. It is used as a second detection pass so a secret
    interrupted by those characters cannot survive as two raw fragments.
    """
    chars = []  # type: List[str]
    mapping = []  # type: List[int]
    for index, ch in enumerate(text):
        if is_unsafe_control_or_format_char(ch):
            continue
        chars.append(ch)
        mapping.append(index)
    return "".join(chars), mapping


def _whitespace_normalized_detection_view(text: str) -> Tuple[str, List[int]]:
    """Replace every unsafe control or format char with one ASCII space.

    Some secret grammar separators are themselves whitespace, most importantly
    the space after an authorization scheme or inside a caller-supplied secret.
    The collapsed view intentionally joins control-interrupted fragments, but
    that join would erase those separators. This complementary view preserves
    separator shape while remaining control-resistant.
    """
    chars = []  # type: List[str]
    mapping = []  # type: List[int]
    for index, ch in enumerate(text):
        if is_unsafe_control_or_format_char(ch):
            chars.append(" ")
        else:
            chars.append(ch)
        mapping.append(index)
    return "".join(chars), mapping


def _detection_view_specs(text: str) -> List[Tuple[Callable[[str], Tuple[str, List[int]]], bool]]:
    """Return detection view factories paired with cookie-detection flags."""
    specs = [(detection_view, True)]  # type: List[Tuple[Callable[[str], Tuple[str, List[int]]], bool]]
    if any(is_unsafe_control_or_format_char(ch) for ch in text):
        specs.append((_whitespace_normalized_detection_view, False))
        specs.append((_collapsed_detection_view, False))
    return specs


def _is_pem_label_char(cp: int) -> bool:
    return _is_ascii_alnum(cp) or cp == 32


def detect_pem_spans(text: str) -> List[Span]:
    spans = []  # type: List[Span]
    search = 0
    prefix = "-----BEGIN "
    while True:
        index = text.find(prefix, search)
        if index < 0:
            return spans
        cursor = index + len(prefix)
        label_start = cursor
        while cursor < len(text) and text[cursor] != "-" and text[cursor] not in "\r\n" and cursor - label_start <= 64:
            if not _is_pem_label_char(ord(text[cursor])):
                break
            cursor += 1
        label = text[label_start:cursor]
        valid = (
            0 < len(label) <= 64
            and label.endswith("PRIVATE KEY")
            and text.startswith("-----", cursor)
        )
        if not valid:
            search = index + 1
            continue
        body_start = cursor + 5
        end_marker = "-----END " + label + "-----"
        end_at = text.find(end_marker, body_start)
        if end_at >= 0:
            end = end_at + len(end_marker)
        else:
            end = len(text)
        spans.append((index, end, "pem_private_key"))
        search = max(end, index + 1)


def _is_scheme_char(cp: int) -> bool:
    return _is_ascii_alnum(cp) or cp in (43, 45, 46)


def _is_authority_terminator(ch: str) -> bool:
    cp = ord(ch)
    return cp <= 0x20 or cp == 0x7F or ch in "/?#\"'<>" or ch == "\\" or ch.isspace()


def detect_url_userinfo_spans(text: str) -> List[Span]:
    spans = []  # type: List[Span]
    n = len(text)
    search = 0
    while True:
        separator = text.find("://", search)
        if separator < 0:
            return spans
        scheme_start = -1
        cursor = separator - 1
        while cursor >= 0 and separator - cursor <= 33 and _is_scheme_char(ord(text[cursor])):
            if _is_ascii_alpha(ord(text[cursor])):
                scheme_start = cursor
                break
            cursor -= 1
        if scheme_start < 0:
            search = separator + 3
            continue
        authority_start = separator + 3
        authority_end = authority_start
        while authority_end < n and not _is_authority_terminator(text[authority_end]):
            authority_end += 1
        at = text.rfind("@", authority_start, authority_end)
        if at > authority_start:
            spans.append((authority_start, at, "url_userinfo"))
        search = separator + 3
    return spans


def _is_bearer_token_char(cp: int) -> bool:
    return _is_ascii_alnum(cp) or cp in (45, 46, 95, 126, 43, 47, 61)


def _looks_like_token_shape(token: str) -> bool:
    if len(token) < 8:
        return False
    if len(token) >= 24:
        return True
    has_digit = False
    has_symbol = False
    for ch in token:
        cp = ord(ch)
        if _is_ascii_digit(cp):
            has_digit = True
        elif not _is_ascii_alpha(cp):
            has_symbol = True
    return has_digit or has_symbol


def _has_authorization_header_context(text: str, index: int) -> bool:
    cursor = index - 1
    while cursor >= 0 and text[cursor] in " \t":
        cursor -= 1
    if cursor < 0 or text[cursor] != ":":
        return False
    cursor -= 1
    while cursor >= 0 and text[cursor] in " \t":
        cursor -= 1
    word = "authorization"
    start = cursor - len(word) + 1
    if start < 0 or not _starts_case_insensitive(text, start, word):
        return False
    return _word_boundary_before(text, start)


_AUTH_SCHEME_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9_])(?:bearer|basic)[ \t]", re.IGNORECASE | re.ASCII)


def detect_auth_scheme_spans(text: str) -> List[Span]:
    spans = []  # type: List[Span]
    n = len(text)
    for match in _AUTH_SCHEME_CANDIDATE_RE.finditer(text):
        index = match.start()
        scheme_length = 6 if _starts_case_insensitive(text, index, "bearer") else 5
        cursor = index + scheme_length
        while cursor < n and text[cursor] in " \t":
            cursor += 1
        token_start = cursor
        while cursor < n and _is_bearer_token_char(ord(text[cursor])):
            cursor += 1
        token = text[token_start:cursor]
        authorization_context = _has_authorization_header_context(text, index)
        if token and (authorization_context or _looks_like_token_shape(token)):
            spans.append((token_start, cursor, "authorization_token"))
    return spans


def _cookie_name_length(text: str, index: int) -> int:
    if _starts_case_insensitive(text, index, "set-cookie"):
        return len("set-cookie")
    if _starts_case_insensitive(text, index, "cookie"):
        return len("cookie")
    return 0


def _loose_cookie_name_pattern(name: str) -> str:
    return r"[\t\r\n]*".join(re.escape(ch) for ch in name)


_COOKIE_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:" + _loose_cookie_name_pattern("set-cookie") + "|" + _loose_cookie_name_pattern("cookie") + r")(?![A-Za-z0-9_-])",
    re.IGNORECASE | re.ASCII,
)


def detect_cookie_spans(text: str) -> List[Span]:
    spans = []  # type: List[Span]
    n = len(text)
    covered_through = -1
    for match in _COOKIE_CANDIDATE_RE.finditer(text):
        index = match.start()
        if index < covered_through:
            continue
        name_length = len(match.group(0))
        cursor = index + name_length
        while cursor < n and text[cursor] in " \t\r\n":
            cursor += 1
        if cursor >= n or text[cursor] != ":":
            continue
        cursor += 1
        while cursor < n and text[cursor] in " \t\r\n":
            cursor += 1
        value_start = cursor
        while cursor < n and text[cursor] not in "\r\n":
            cursor += 1
        if cursor > value_start:
            spans.append((value_start, cursor, "cookie_header"))
            covered_through = cursor
    return spans


_GENERIC_SECRET_KEYS = tuple(sorted((
    "awssecretaccesskey", "secretaccesskey", "encryptionkey", "sessionkey",
    "accesstoken", "refreshtoken", "clientsecret", "privatekey", "csrftoken",
    "xsrftoken", "sessionid", "creditcard", "accesskey", "password", "passwd",
    "apikey", "secret", "token", "ssn", "pwd",
), key=lambda item: (-len(item), item)))


_GENERIC_KEYS_BY_FIRST = {}
for _canonical_key in _GENERIC_SECRET_KEYS:
    _GENERIC_KEYS_BY_FIRST.setdefault(_canonical_key[0], []).append(_canonical_key)


def _match_generic_secret_key(text: str, index: int) -> Optional[int]:
    first_index = index
    while first_index < len(text) and text[first_index] in "_-":
        first_index += 1
    if first_index >= len(text):
        return None
    first = _ascii_lower(text[first_index])
    for canonical in _GENERIC_KEYS_BY_FIRST.get(first, ()):
        ti = first_index + 1
        ki = 1
        while ki < len(canonical):
            while ti < len(text) and text[ti] in "_-":
                ti += 1
            if ti >= len(text) or _ascii_lower(text[ti]) != canonical[ki]:
                break
            ti += 1
            ki += 1
        if ki == len(canonical):
            if ti < len(text):
                cp = ord(text[ti])
                if _is_ascii_alnum(cp):
                    continue
            return ti
    return None


_GENERIC_KEY_LETTER_RE = re.compile(r"[asercptx]", re.IGNORECASE | re.ASCII)


def _generic_candidate_start(text: str, letter_index: int) -> Optional[int]:
    run_start = letter_index
    while run_start > 0 and text[run_start - 1] in "_-":
        run_start -= 1
    for index in range(run_start, letter_index + 1):
        if _word_boundary_before(text, index):
            return index
    return None


def detect_generic_key_value_spans(text: str) -> List[Span]:
    spans = []  # type: List[Span]
    n = len(text)
    covered_through = -1
    for match in _GENERIC_KEY_LETTER_RE.finditer(text):
        index = _generic_candidate_start(text, match.start())
        if index is None or index < covered_through:
            continue
        key_end = _match_generic_secret_key(text, index)
        if key_end is None:
            continue
        cursor = key_end
        if cursor < n and text[cursor] in "\"'":
            cursor += 1
        while cursor < n and text[cursor] in " \t":
            cursor += 1
        if cursor >= n or text[cursor] not in ":=":
            continue
        cursor += 1
        while cursor < n and text[cursor] in " \t":
            cursor += 1
        if cursor < n and text[cursor] in "\"'":
            quote = text[cursor]
            value_start = cursor + 1
            value_end = value_start
            closed = False
            while value_end < n:
                ch = text[value_end]
                if ch == "\\":
                    value_end += 2
                    continue
                if ch == quote:
                    closed = True
                    break
                if ch in "\r\n":
                    break
                value_end += 1
            if value_end > value_start:
                spans.append((value_start, value_end, "generic_secret"))
            covered_through = value_end + (1 if closed else 0)
            continue
        value_start = cursor
        value_end = value_start
        while value_end < n:
            ch = text[value_end]
            cp = ord(ch)
            if cp <= 32 or ch in ",;&\"')]}<>[":
                break
            value_end += 1
        if value_end > value_start:
            spans.append((value_start, value_end, "generic_secret"))
            covered_through = value_end
    return spans


_JWT_RE = re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]+\.(?:[A-Za-z0-9_-]{8,})?(?![A-Za-z0-9_-])")


def detect_jwt_spans(text: str) -> List[Span]:
    return [(match.start(), match.end(), "jwt") for match in _JWT_RE.finditer(text)]


_VENDOR_TOKEN_PATTERNS = tuple(re.compile(pattern) for pattern in (
    r"(?<![A-Z0-9])(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}(?![A-Z0-9])",
    r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{20,80}|github_pat_[A-Za-z0-9_]{20,120}|glpat-[A-Za-z0-9_-]{20,120})(?![A-Za-z0-9_])",
    r"(?<![A-Za-z0-9_])(?:[sr]k_(?:live|test)_[A-Za-z0-9]{12,120}|whsec_[A-Za-z0-9]{12,120})(?![A-Za-z0-9_])",
    r"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{10,120}(?![A-Za-z0-9])",
    r"(?<![A-Za-z0-9])xapp-[A-Za-z0-9-]{10,120}(?![A-Za-z0-9])",
    r"(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_-]{20,160}(?![A-Za-z0-9_-])",
    r"(?<![A-Za-z0-9])sk-(?:proj-)?[A-Za-z0-9_-]{20,160}(?![A-Za-z0-9_-])",
    r"(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{30,80}(?![A-Za-z0-9_])",
    r"(?<![A-Za-z0-9_-])pypi-[A-Za-z0-9_-]{20,160}(?![A-Za-z0-9_-])",
    r"(?<![A-Za-z0-9_-])AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])",
    r"(?<![A-Za-z0-9_])dop_v1_[a-f0-9]{64}(?![A-Za-z0-9_])",
    r"(?<![0-9])[0-9]{8,10}:[A-Za-z0-9_-]{30,80}(?![A-Za-z0-9_-])",
))


def detect_vendor_token_spans(text: str) -> List[Span]:
    spans = []  # type: List[Span]
    for pattern in _VENDOR_TOKEN_PATTERNS:
        for match in pattern.finditer(text):
            spans.append((match.start(), match.end(), "vendor_token"))
    return spans


def _percent_hex_pattern(encoded: str) -> str:
    pieces = []  # type: List[str]
    index = 0
    while index < len(encoded):
        if encoded[index] == "%" and index + 2 < len(encoded):
            pieces.append("%")
            for digit in (encoded[index + 1], encoded[index + 2]):
                if digit.isalpha() and digit.lower() != digit.upper():
                    pieces.append("[" + digit.upper() + digit.lower() + "]")
                else:
                    pieces.append(re.escape(digit))
            index += 3
        else:
            pieces.append(re.escape(encoded[index]))
            index += 1
    return "".join(pieces)


def _percent_encode_bytes(data: bytes, plus: bool = False) -> str:
    out = []  # type: List[str]
    for byte in data:
        ch = chr(byte)
        if _is_ascii_alnum(byte) or ch in "_.-~":
            out.append(ch)
        elif plus and byte == 32:
            out.append("+")
        else:
            out.append("%" + "%02X" % byte)
    return "".join(out)


def _extra_secret_raw_pattern(raw: str) -> str:
    pieces = []  # type: List[str]
    in_whitespace = False
    for ch in raw:
        if ch.isspace():
            if not in_whitespace:
                pieces.append(r"\s+")
                in_whitespace = True
        else:
            pieces.append(re.escape(ch))
            in_whitespace = False
    return "".join(pieces)


def _extra_secret_patterns(secret: SecretValue) -> List[Tuple[str, int]]:
    raw = secret.text
    data = secret.data
    standard64 = base64.b64encode(data).decode("ascii")
    url64 = base64.urlsafe_b64encode(data).decode("ascii")
    variants = [
        (_extra_secret_raw_pattern(raw), re.IGNORECASE),
        (_percent_hex_pattern(_percent_encode_bytes(data, False)), 0),
        (_percent_hex_pattern(_percent_encode_bytes(data, True)), 0),
        (re.escape(standard64), 0),
        (re.escape(standard64.rstrip("=")), 0),
        (re.escape(url64), 0),
        (re.escape(url64.rstrip("=")), 0),
    ]
    output = []  # type: List[Tuple[str, int]]
    seen = set()
    for pattern, flags in variants:
        key = (pattern, flags)
        if len(pattern) == 0 or key in seen:
            continue
        seen.add(key)
        output.append(key)
    return output


def detect_extra_secret_spans(text: str, secrets: Sequence[SecretValue]) -> List[Span]:
    matches = []  # type: List[Span]
    for secret in secrets:
        for pattern_text, flags in _extra_secret_patterns(secret):
            pattern = re.compile(pattern_text, flags)
            for match in pattern.finditer(text):
                matches.append((match.start(), match.end(), "extra_secret"))
    return _select_nonoverlapping_spans(matches)


_EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}(?![A-Za-z0-9._%+-])")
_SSN_RE = re.compile(r"(?<![0-9])[0-9]{3}-[0-9]{2}-[0-9]{4}(?![0-9])")
_IPV4_RE = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")


def _valid_ssn(value: str) -> bool:
    area = int(value[0:3])
    group = int(value[4:6])
    serial = int(value[7:11])
    return area != 0 and area != 666 and area < 900 and group != 0 and serial != 0


def _valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part or len(part) > 3 or not part.isdigit() or int(part) > 255:
            return False
    return True


def _luhn_valid(digits: str) -> bool:
    total = 0
    double_digit = False
    for ch in reversed(digits):
        value = ord(ch) - 48
        if double_digit:
            value *= 2
            if value > 9:
                value -= 9
        total += value
        double_digit = not double_digit
    return total % 10 == 0


def detect_luhn_card_spans(text: str) -> List[Span]:
    spans = []  # type: List[Span]
    index = 0
    n = len(text)
    while index < n:
        if not text[index].isdigit() or (index > 0 and _is_ascii_alnum(ord(text[index - 1]))):
            index += 1
            continue
        cursor = index
        digits = []  # type: List[str]
        end = index
        while cursor < n:
            ch = text[cursor]
            if ch.isdigit():
                digits.append(ch)
                cursor += 1
                end = cursor
                continue
            if ch in " -" and digits and cursor + 1 < n and text[cursor + 1].isdigit():
                cursor += 1
                continue
            break
        digit_text = "".join(digits)
        after_ok = end >= n or not _is_ascii_alnum(ord(text[end]))
        if 13 <= len(digit_text) <= 19 and after_ok and _luhn_valid(digit_text):
            spans.append((index, end, "pii_luhn_card"))
        index = max(end, index + 1)
    return spans


def detect_pii_spans(text: str, flags: PIIFlags) -> List[Span]:
    spans = []  # type: List[Span]
    if flags.email:
        for match in _EMAIL_RE.finditer(text):
            spans.append((match.start(), match.end(), "pii_email"))
    if flags.ssn:
        for match in _SSN_RE.finditer(text):
            if _valid_ssn(match.group(0)):
                spans.append((match.start(), match.end(), "pii_ssn"))
    if flags.ipv4:
        for match in _IPV4_RE.finditer(text):
            if _valid_ipv4(match.group(0)):
                spans.append((match.start(), match.end(), "pii_ipv4"))
    if flags.luhn_card:
        spans.extend(detect_luhn_card_spans(text))
    return spans


def detect_secret_spans(text: str, *, extra_secrets: Sequence[SecretValue] = (), pii: PIIFlags = PIIFlags(), include_cookie: bool = True) -> List[Span]:
    """Detect secret spans in already control-normalized text.

    The returned spans are non-overlapping and sorted. Detector regexes are
    fixed-shape and bounded; no nested quantifiers or catastrophic backtracking
    constructs are used.
    """
    spans = []  # type: List[Span]
    spans.extend(detect_pem_spans(text))
    spans.extend(detect_url_userinfo_spans(text))
    spans.extend(detect_auth_scheme_spans(text))
    if include_cookie:
        spans.extend(detect_cookie_spans(text))
    spans.extend(detect_generic_key_value_spans(text))
    spans.extend(detect_jwt_spans(text))
    spans.extend(detect_vendor_token_spans(text))
    spans.extend(detect_extra_secret_spans(text, extra_secrets))
    spans.extend(detect_pii_spans(text, pii))
    return _select_nonoverlapping_spans(spans)


def redact_control_insensitive(text: str, *, extra_secrets: Sequence[SecretValue] = (),
                               pii: PIIFlags = PIIFlags(), replacement: str = DEFAULT_REPLACEMENT) -> str:
    """Redact secrets even when unsafe control characters interrupt them.

    Detection is performed on a view that removes zero-width/control characters
    while retaining line separators. Matches are then mapped back to the
    original string, so the redaction consumes the obfuscating characters along
    with the secret instead of leaking fragments.
    """
    replacement = validate_replacement(replacement)
    original_spans = []  # type: List[Span]
    for view_factory, include_cookie in _detection_view_specs(text):
        view, mapping = view_factory(text)
        detected = detect_secret_spans(view, extra_secrets=extra_secrets, pii=pii, include_cookie=include_cookie)
        for start, end, kind in detected:
            original_start, original_end = map_detection_span(mapping, start, end)
            original_spans.append((original_start, original_end, kind))
    selected = _select_nonoverlapping_spans(original_spans)
    return _apply_spans(text, _merge_overlapping_spans(selected), replacement)


def redact_secrets(text: str, *, extra_secrets: Optional[Iterable[object]] = None,
                   redact_pii: bool = False, pii: Optional[Dict[str, bool]] = None,
                   replacement: str = DEFAULT_REPLACEMENT, strip_terminal: bool = True) -> str:
    """Redact common secrets and caller-supplied secrets from text.

    Terminal escape sequences are stripped first by default because they are a
    practical obfuscation channel in logs. This function is a redactor, not a
    full CWE-117 sanitizer; use :func:`pylogcage.sanitize_log_line` for log
    output.
    """
    if not isinstance(text, str):
        raise LogCageInputError("text must be a str")
    replacement = validate_replacement(replacement)
    secrets = normalize_extra_secrets(extra_secrets)
    flags = normalize_pii(redact_pii, pii)
    working = strip_terminal_sequences(text) if strip_terminal else text
    return redact_control_insensitive(working, extra_secrets=secrets, pii=flags, replacement=replacement)


def secret_finding_kinds(text: str) -> List[str]:
    """Return secret finding type names without exposing any secret content."""
    working = strip_terminal_sequences(text)
    kinds = set()
    for view_factory, include_cookie in _detection_view_specs(working):
        view, _mapping = view_factory(working)
        kinds.update(
            kind for _start, _end, kind in detect_secret_spans(view, include_cookie=include_cookie)
        )
    return sorted(kinds)
