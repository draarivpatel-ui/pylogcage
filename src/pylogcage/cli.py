"""Command line interface for pylogcage."""
from __future__ import annotations

import argparse
import sys
from typing import BinaryIO, Iterable, Optional

from . import __version__
from .audit import audit_source
from .core import sanitize_log_line as _sanitize_line_public
from .errors import LogCageError


def _binary_stdin() -> BinaryIO:
    stream = sys.stdin
    buffer = getattr(stream, "buffer", None)
    if buffer is not None:
        return buffer
    raise OSError("standard input is not a binary stream")


def _write_stdout_line(text: str) -> None:
    data = text.encode("utf-8") + b"\n"
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is not None:
        buffer.write(data)
        buffer.flush()
    else:
        sys.stdout.write(text + "\n")
        sys.stdout.flush()


def _write_stderr_line(text: str) -> None:
    data = text.encode("utf-8") + b"\n"
    buffer = getattr(sys.stderr, "buffer", None)
    if buffer is not None:
        buffer.write(data)
        buffer.flush()
    else:
        sys.stderr.write(text + "\n")
        sys.stderr.flush()


def _safe_error_text(prefix: str, exc: BaseException) -> str:
    try:
        detail = str(exc)
    except Exception:
        detail = exc.__class__.__name__
    try:
        detail = _sanitize_line_public(detail, max_length=256)
    except Exception:
        detail = "[unprintable error]"
    return prefix + detail


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pylogcage",
        description="Sanitize CWE-117 log injection, terminal escapes, secrets, and optional PII.",
    )
    parser.add_argument("--version", action="version", version="pylogcage " + __version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    sanitize = subparsers.add_parser("sanitize", help="sanitize stdin line by line")
    mode = sanitize.add_mutually_exclusive_group()
    mode.add_argument("--strip", action="store_true", help="remove unsafe control and format characters")
    mode.add_argument("--escape", action="store_true", help="escape unsafe characters visibly (default)")
    sanitize.add_argument("--max-length", type=int, default=4096, help="maximum output characters per line")
    sanitize.add_argument("--redact-pii", action="store_true", help="redact email, Luhn-valid card, SSN, and IPv4 values")
    sanitize.add_argument("--extra-secret", action="append", default=[], help="additional secret value to redact; may be repeated")
    sanitize.add_argument("--no-redact", action="store_true", help="disable secret redaction")

    audit = subparsers.add_parser("audit", help="audit a log file or stdin without printing raw content")
    audit.add_argument("source", help="regular file path, or '-' for stdin")
    audit.add_argument("--json", action="store_true", dest="json_output", help="emit machine-readable JSON")
    return parser


def _decode_input_line(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", "backslashreplace")


def run_sanitize(args: argparse.Namespace) -> int:
    mode = "strip" if args.strip else "escape"
    for raw in _binary_stdin():
        if raw.endswith(b"\n"):
            raw = raw[:-1]
        text = _decode_input_line(raw)
        output = _sanitize_line_public(
            text,
            mode=mode,
            max_length=args.max_length,
            redact=not args.no_redact,
            extra_secrets=args.extra_secret,
            redact_pii=args.redact_pii,
        )
        _write_stdout_line(output)
    return 0


def run_audit(args: argparse.Namespace) -> int:
    result = audit_source(args.source, stdin=_binary_stdin() if args.source == "-" else None)
    if args.json_output:
        _write_stdout_line(result.to_json())
    else:
        _write_stdout_line(result.to_text())
    return 0 if result.ok else 1


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if args.command == "sanitize":
            return run_sanitize(args)
        if args.command == "audit":
            return run_audit(args)
        parser.error("unknown command")
        return 2
    except BrokenPipeError:
        return 0
    except (LogCageError, OSError) as exc:
        _write_stderr_line(_safe_error_text("pylogcage error ", exc))
        return 2


if __name__ == "__main__":
    sys.exit(main())
