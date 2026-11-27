from __future__ import annotations

import io
import json
import logging
import unittest

from pylogcage import LogCage, LogCageFilter, SafeJsonFormatter, SafeTextFormatter
from pylogcage.logging_integration import format_message_safely

from helpers import PylogcageTestCase


def make_record(msg="hello", args=None, level=logging.INFO, name="test"):
    record = logging.LogRecord(name, level, __file__, 10, msg, args, None)
    return record


def make_logger(name, handler):
    logger = logging.getLogger(name)
    logger.handlers[:] = []
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger


class TestFormatMessageSafely(PylogcageTestCase):
    def test_plain_percent_format(self):
        self.assertEqual(format_message_safely("hello %s", ("world",)), "hello world")

    def test_mapping_format(self):
        self.assertEqual(format_message_safely("hello %(name)s", {"name": "world"}), "hello world")

    def test_no_args_percent_retained(self):
        self.assertEqual(format_message_safely("100%", None), "100%")

    def test_mismatched_args_no_raise(self):
        output = format_message_safely("%s %s", ("one",))
        self.assertIn("unformatted args", output)
        self.assertIn("%s %s", output)

    def test_nonstring_message(self):
        self.assertEqual(format_message_safely(123, None), "123")

    def test_throwing_string_object(self):
        class Bad:
            def __str__(self):
                raise RuntimeError("bad")
        self.assertIn("Unstringable", format_message_safely(Bad(), None))


class TestLogCageFilter(PylogcageTestCase):
    def test_filter_returns_true(self):
        self.assertIs(LogCageFilter().filter(make_record()), True)

    def test_filter_sanitizes_msg(self):
        record = make_record("a\nb\x1b[31m")
        LogCageFilter().filter(record)
        self.assertEqual(record.msg, "a\\nb")

    def test_filter_formats_args_and_empties(self):
        record = make_record("hello %s", ("a\nb",))
        LogCageFilter().filter(record)
        self.assertEqual(record.msg, "hello a\\nb")
        self.assertEqual(record.args, ())

    def test_filter_prevents_double_formatting(self):
        record = make_record("%s", ("%s",))
        LogCageFilter().filter(record)
        self.assertEqual(record.msg, "%s")
        self.assertEqual(record.args, ())

    def test_filter_mismatched_args_no_crash(self):
        record = make_record("%s %s", ("one",))
        self.assertTrue(LogCageFilter().filter(record))
        self.assertIn("unformatted args", record.msg)

    def test_filter_redacts_message_secret(self):
        record = make_record("password=abc")
        LogCageFilter().filter(record)
        self.assertEqual(record.msg, "password=[REDACTED]")

    def test_filter_sanitizes_extra_string(self):
        record = make_record()
        record.custom = "a\nb"
        LogCageFilter().filter(record)
        self.assertEqual(record.custom, "a\\nb")

    def test_filter_sanitizes_extra_mapping_copy(self):
        original = {"token": "abc", "text": "a\nb"}
        record = make_record()
        record.custom = original
        LogCageFilter().filter(record)
        self.assertEqual(record.custom, {"token": "[REDACTED]", "text": "a\\nb"})
        self.assertEqual(original, {"token": "abc", "text": "a\nb"})

    def test_filter_does_not_mutate_extra_object(self):
        class Extra:
            def __init__(self):
                self.text = "a\nb"
        original = Extra()
        record = make_record()
        record.custom = original
        LogCageFilter().filter(record)
        self.assertEqual(original.text, "a\nb")
        self.assertIsNot(record.custom, original)

    def test_filter_exception_info(self):
        try:
            raise ValueError("bad password=abc")
        except ValueError:
            import sys
            record = make_record()
            record.exc_info = sys.exc_info()
        LogCageFilter().filter(record)
        self.assertIsNone(record.exc_info)
        self.assertIn("bad password=[REDACTED]", record.exc_text)
        self.assertNotIn("\n", record.exc_text)

    def test_filter_existing_exc_text(self):
        record = make_record()
        record.exc_text = "bad\npassword=abc"
        LogCageFilter().filter(record)
        self.assertEqual(record.exc_text, "bad\\npassword=[REDACTED]")

    def test_filter_stack_info(self):
        record = make_record()
        record.stack_info = "stack\nline"
        LogCageFilter().filter(record)
        self.assertEqual(record.stack_info, "stack\\nline")


class TestSafeJsonFormatter(PylogcageTestCase):
    def test_json_formatter_valid_line(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(SafeJsonFormatter(max_output_bytes=4096))
        logger = make_logger("json.valid", handler)
        logger.info("hello %s", "world")
        line = stream.getvalue().rstrip("\n")
        data = json.loads(line)
        self.assertEqual(data["level"], "INFO")
        self.assertEqual(data["message"], "hello world")
        self.assertEqual(data["meta"]["logger"], "json.valid")

    def test_json_formatter_sanitizes_without_filter(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(SafeJsonFormatter(max_output_bytes=4096))
        logger = make_logger("json.raw", handler)
        logger.info("bad %s", "a\nb\x1b[31m")
        line = stream.getvalue().rstrip("\n")
        self.assertEqual(json.loads(line)["message"], "bad a\\nb")
        self.assertNotIn("\x1b", line)

    def test_json_formatter_redacts_extra(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(SafeJsonFormatter(max_output_bytes=4096))
        logger = make_logger("json.extra", handler)
        logger.info("hello", extra={"token": "abc", "nested": {"password": "abc"}})
        data = json.loads(stream.getvalue())
        self.assertEqual(data["meta"]["token"], "[REDACTED]")
        self.assertEqual(data["meta"]["nested"]["password"], "[REDACTED]")

    def test_json_formatter_exception(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(SafeJsonFormatter(max_output_bytes=8192))
        logger = make_logger("json.exc", handler)
        try:
            raise ValueError("bad password=abc")
        except ValueError:
            logger.exception("failed")
        data = json.loads(stream.getvalue())
        self.assertEqual(data["level"], "ERROR")
        self.assertIn("bad password=[REDACTED]", data["meta"]["exception"])
        self.assertNotIn("\n", stream.getvalue().rstrip("\n"))

    def test_json_formatter_byte_bound(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(SafeJsonFormatter(max_output_bytes=100))
        logger = make_logger("json.bound", handler)
        logger.info("x" * 1000, extra={"big": "y" * 1000})
        line = stream.getvalue().rstrip("\n")
        self.assertLessEqual(len(line.encode("utf-8")), 100)
        json.loads(line)

    def test_json_formatter_does_not_mutate_record_args(self):
        record = make_record("hello %s", ("world",))
        formatter = SafeJsonFormatter(max_output_bytes=4096)
        formatter.format(record)
        self.assertEqual(record.args, ("world",))

    def test_json_formatter_percent_arg_not_double_formatted(self):
        record = make_record("%s", ("%s",))
        data = json.loads(SafeJsonFormatter(max_output_bytes=4096).format(record))
        self.assertEqual(data["message"], "%s")


class TestSafeTextFormatter(PylogcageTestCase):
    def test_text_formatter_single_line(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(SafeTextFormatter("%(levelname)s %(name)s: %(message)s"))
        logger = make_logger("text.one", handler)
        logger.info("a\nb\x1b[31m")
        self.assertEqual(stream.getvalue(), "INFO text.one: a\\nb\n")

    def test_text_formatter_redacts_secret(self):
        record = make_record("password=abc")
        output = SafeTextFormatter("%(message)s").format(record)
        self.assertEqual(output, "password=[REDACTED]")

    def test_text_formatter_exception_single_line(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(SafeTextFormatter("%(levelname)s %(message)s"))
        logger = make_logger("text.exc", handler)
        try:
            raise ValueError("bad\npassword=abc")
        except ValueError:
            logger.exception("failed")
        output = stream.getvalue()
        self.assertEqual(output.count("\n"), 1)
        self.assertTrue(output.endswith("\n"))
        self.assertIn("bad\\npassword=[REDACTED]", output)

    def test_text_formatter_broken_format_falls_back(self):
        record = make_record("hello")
        output = SafeTextFormatter("%(missing)s").format(record)
        self.assertIn("hello", output)
        self.assertNotIn("\n", output)

    def test_text_formatter_max_length(self):
        record = make_record("x" * 1000)
        output = SafeTextFormatter("%(message)s", max_length=32).format(record)
        self.assertLessEqual(len(output), 32)
        self.assertTrue(output.endswith("[truncated]"))

    def test_text_formatter_does_not_mutate_record(self):
        record = make_record("hello %s", ("world",))
        SafeTextFormatter("%(message)s").format(record)
        self.assertEqual(record.args, ("world",))
        self.assertEqual(record.msg, "hello %s")


class TestLogCageIntegrationHelpers(PylogcageTestCase):
    def test_cage_logging_filter_type(self):
        self.assertIsInstance(LogCage().logging_filter(), LogCageFilter)

    def test_cage_json_formatter_type(self):
        self.assertIsInstance(LogCage().json_formatter(), SafeJsonFormatter)

    def test_cage_text_formatter_type(self):
        self.assertIsInstance(LogCage().text_formatter(), SafeTextFormatter)

    def test_cage_custom_pii_applies_in_filter(self):
        record = make_record("mail user@example.test")
        LogCageFilter(redact_pii=True).filter(record)
        self.assertEqual(record.msg, "mail [REDACTED]")


if __name__ == "__main__":
    unittest.main()
