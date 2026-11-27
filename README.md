# pylogcage

`pylogcage` is a zero-dependency Python 3.9+ library for writing logs that cannot forge extra log lines, inject terminal control sequences, or accidentally carry common secrets. It provides a small functional API, a reusable `LogCage` object, and drop-in `logging.Filter` and `logging.Formatter` implementations.

## Install

PyPI publication is pending final review. The package name `pylogcage` was verified as unclaimed before release preparation, but it is not installable from PyPI until the first trusted publication is made. Until then, install from the public GitHub repository or use a source checkout:

```bash
python3 -m pip install git+https://github.com/draarivpatel-ui/pylogcage.git
```

For local development:

```bash
python3 -m pip install .
```

For use directly from a source checkout:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Threat model

`pylogcage` protects log consumers against attacker-controlled text that attempts to:

- Forge additional log entries with CR, LF, NEL, Unicode line separators, or other control characters.
- Reorder or hide text with bidi controls, zero-width format characters, noncharacters, or lone UTF-16 surrogate code points.
- Move the cursor, change colors, create hyperlinks, write clipboard content, or otherwise control a terminal with ANSI CSI, OSC, DCS, SOS, PM, APC, or 8-bit C1 sequences.
- Leak URL userinfo, authorization tokens, cookies, key-value secrets, compact JWTs, PEM private keys, common vendor-shaped tokens, or caller-supplied secrets.
- Evade redaction by interrupting a secret with unsafe control or invisible format characters.
- Evade redaction through truncation. Redaction always runs before truncation.
- Produce multiline or oversized structured logs.

It does not make a complete logging system safe by itself. It does not validate log transport integrity, authorize access to log storage, prevent all application-specific sensitive data from being logged, or replace secret scanning in source control. Optional PII redaction is conservative and should be treated as a second layer, not as proof that a log is free of personal data.

## Quick start

```python
from pylogcage import sanitize_log_line

text = "first\r\nsecond password=paste-your-token \x1b[31mred"
print(sanitize_log_line(text))
# first\r\nsecond password=[REDACTED] red
```

The exact output uses visible backslash escape text for CR and LF. No raw line break or terminal escape reaches the output.

### Escape or strip

```python
from pylogcage import sanitize_log_line

sanitize_log_line("a\nb")                       # escape mode, the default
sanitize_log_line("a\nb", mode="strip")         # remove unsafe characters
sanitize_log_line("a\nb", max_length=32)        # bounded output
```

`max_length` is measured in Python string characters and includes the truncation marker. Visible escape tokens are atomic and are never split.

## Redacting secrets

```python
from pylogcage import redact_secrets

redact_secrets("Authorization: Bearer abcdefghijklmnop")
redact_secrets("postgres://user:pass@example.test/db")
redact_secrets("password=paste-your-token")
```

Caller-supplied secrets are matched longest-first in raw form, percent-encoded form, form-encoded form, base64, and base64url with padded and unpadded variants:

```python
sanitize_log_line(
    "the deployment value is here",
    extra_secrets=["the deployment value"],
)
```

`extra_secrets` entries may be `str`, `bytes`, or `bytearray`. Do not pass live production secrets unless the process is already authorized to handle them.

Optional PII redaction covers email addresses, Luhn-valid card numbers, US-style SSNs, and IPv4 addresses:

```python
sanitize_log_line("contact user@example.test", redact_pii=True)
```

## Structured records

```python
from pylogcage import sanitize_record

safe = sanitize_record({
    "user": "alice",
    "password": "paste-your-token",
    "nested": {"message": "hello\nworld"},
})
```

The result is a new JSON-compatible object graph. The caller's object is not mutated. The sanitizer handles nested dictionaries, lists, tuples, sets, frozensets, bytes, bytearrays, exceptions and exception chains, exception notes, grouped exceptions, custom attributes, slotted objects, dates, decimals, UUIDs, and paths. Circular references, excessive depth, excessive key or sequence counts, and excessive total node counts fail closed.

Sensitive keys are redacted by name. Additional keys and exact paths can be configured:

```python
safe = sanitize_record(
    {"auth": {"session": "value"}, "dropme": 1},
    sensitive_keys=["session"],
    redact_paths=["auth.session"],
    drop_keys=["dropme"],
)
```

Path entries support `*` as one wildcard segment. Keys named `__proto__`, `constructor`, or `prototype` are omitted so downstream JavaScript consumers do not receive object-injection keys.

## Bounded NDJSON

```python
from pylogcage import format_safe_json_log

line = format_safe_json_log(
    "INFO",
    "job finished",
    meta={"job_id": 42},
    max_output_bytes=4096,
)
```

The output is deterministic for deterministic input: keys are sorted, whitespace is fixed, no implicit timestamp is added, and the line contains no raw CR or LF. The implementation verifies `len(line.encode("utf-8")) <= max_output_bytes`. Oversized records are reduced and then replaced by a valid bounded JSON fallback rather than emitted partially.

## Standard logging integration

### Text logs

```python
import logging
from pylogcage import LogCageFilter, SafeTextFormatter

logger = logging.getLogger("app")
logger.setLevel(logging.INFO)

handler = logging.StreamHandler()
handler.setFormatter(SafeTextFormatter("%(levelname)s %(name)s: %(message)s"))
handler.addFilter(LogCageFilter())
logger.addHandler(handler)

logger.info("bad input %s", "line one\nline two")
```

### NDJSON logs

```python
import logging
from pylogcage import SafeJsonFormatter

handler = logging.StreamHandler()
handler.setFormatter(SafeJsonFormatter(max_output_bytes=4096))
```

`SafeJsonFormatter` sanitizes even when no filter is installed. `LogCageFilter` additionally pre-formats percent-style arguments safely, preventing a percent sign inside an argument from being interpreted as a second template and sanitizing custom `extra` values without mutating caller-owned objects.

### Reusable configuration

```python
from pylogcage import LogCage

cage = LogCage(mode="escape", max_length=2048, redact_pii=True)
handler.addFilter(cage.logging_filter())
handler.setFormatter(cage.json_formatter())
```

## CLI

Sanitize standard input line by line:

```bash
pylogcage sanitize < input.log > safe.log
pylogcage sanitize --strip --max-length 512 < input.log
pylogcage sanitize --redact-pii < input.log
```

Audit a regular file or stdin without printing raw log content:

```bash
pylogcage audit app.log
pylogcage audit app.log --json
cat app.log | pylogcage audit -
```

Audit exit codes:

- `0`: no findings
- `1`: at least one CWE-117 marker, terminal escape attack, invalid UTF-8 sequence, or secret-shaped leak
- `2`: usage error, I/O error, or a rejected source type

File audit uses `os.open` and `os.fstat` and rejects symlinks, FIFOs, devices, directories, sockets, other non-regular files, and regular files larger than 64 MiB. Output contains line numbers and finding types only, never raw secrets or raw log lines.

## Security properties and limits

- Terminal sequence stripping is a linear single pass and does not use nested or catastrophic regular expressions.
- Redaction happens before neutralization and truncation through a control-resistant detection view.
- Truncation never splits a visible escape token.
- Structured sanitization never mutates caller input.
- JSON output is ASCII escaped and bounded in UTF-8 bytes.
- The package has no runtime dependencies.

Secret detection is heuristic. Application-specific sensitive values should be supplied through `extra_secrets`, sensitive keys, or redact paths. The safest policy is still to avoid logging secrets at all.

## Development

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
python3 -m build
```

The standard-library test suite currently contains 634 tests. The project supports Python 3.9 through 3.13. Contributions must keep the runtime dependency-free and must not introduce dynamic typing syntax or standard-library modules unavailable on Python 3.9.
