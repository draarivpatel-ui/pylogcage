from __future__ import annotations

import json
import unittest

from pylogcage import format_safe_json_log
from pylogcage.errors import LogCageError

from helpers import PylogcageTestCase


def parse(line):
    return json.loads(line)


class TestSafeJsonLog(PylogcageTestCase):
    def test_basic_shape(self):
        output = format_safe_json_log("INFO", "hello", {"x": 1}, max_output_bytes=200)
        self.assertEqual(parse(output), {"level": "INFO", "message": "hello", "meta": {"x": 1}})

    def test_single_line_invariant(self):
        output = format_safe_json_log("INFO", "a\nb\rc", {"x": "y\u2028z"}, max_output_bytes=500)
        self.assertNotIn("\n", output)
        self.assertNotIn("\r", output)

    def test_utf8_byte_cap_exact(self):
        for cap in (32, 40, 64, 100, 200, 1024):
            output = format_safe_json_log("INFO", "x" * 1000, {"m": "y" * 1000}, max_output_bytes=cap)
            self.assertLessEqual(len(output.encode("utf-8")), cap)
            parse(output)

    def test_meta_none_omitted(self):
        self.assertEqual(parse(format_safe_json_log("INFO", "hello", max_output_bytes=200)), {"level": "INFO", "message": "hello"})

    def test_meta_empty_dict_included(self):
        self.assertEqual(parse(format_safe_json_log("INFO", "hello", {}, max_output_bytes=200))["meta"], {})

    def test_message_control_escaped(self):
        output = format_safe_json_log("INFO", "a\nb", max_output_bytes=200)
        self.assertEqual(parse(output)["message"], "a\\nb")

    def test_message_secret_redacted(self):
        output = format_safe_json_log("INFO", "password=abc", max_output_bytes=200)
        self.assertEqual(parse(output)["message"], "password=[REDACTED]")

    def test_level_control_escaped(self):
        output = format_safe_json_log("IN\nFO", "hello", max_output_bytes=200)
        self.assertEqual(parse(output)["level"], "IN\\nFO")

    def test_empty_level_fallback(self):
        output = format_safe_json_log("\x1b[31m", "hello", max_output_bytes=200)
        self.assertEqual(parse(output)["level"], "UNKNOWN")

    def test_nonstring_level(self):
        self.assertEqual(parse(format_safe_json_log(20, "hello", max_output_bytes=200))["level"], "20")

    def test_nonstring_message(self):
        self.assertEqual(parse(format_safe_json_log("INFO", 123, max_output_bytes=200))["message"], "123")

    def test_unicode_ascii_escaped(self):
        output = format_safe_json_log("INFO", "café 東京", max_output_bytes=200)
        self.assertNotIn("café", output)
        self.assertEqual(parse(output)["message"], "café 東京")

    def test_meta_secret_redacted(self):
        output = format_safe_json_log("INFO", "hello", {"token": "abc", "text": "password=abc"}, max_output_bytes=500)
        data = parse(output)
        self.assertEqual(data["meta"]["token"], "[REDACTED]")
        self.assertEqual(data["meta"]["text"], "password=[REDACTED]")

    def test_meta_dangerous_keys_dropped(self):
        output = format_safe_json_log("INFO", "hello", {"__proto__": 1, "constructor": 2, "safe": 3}, max_output_bytes=500)
        self.assertEqual(parse(output)["meta"], {"safe": 3})

    def test_meta_nested_single_line(self):
        output = format_safe_json_log("INFO", "hello", {"nested": {"x": "a\nb"}}, max_output_bytes=500)
        self.assertEqual(parse(output)["meta"]["nested"]["x"], "a\\nb")
        self.assertNotIn("\n", output)

    def test_meta_nonfinite_float_safe(self):
        output = format_safe_json_log("INFO", "hello", {"nan": float("nan"), "inf": float("inf")}, max_output_bytes=500)
        data = parse(output)
        self.assertEqual(data["meta"], {"inf": "inf", "nan": "nan"})

    def test_deterministic_repeated_output(self):
        first = format_safe_json_log("INFO", "hello", {"b": 2, "a": 1}, max_output_bytes=500)
        second = format_safe_json_log("INFO", "hello", {"b": 2, "a": 1}, max_output_bytes=500)
        self.assertEqual(first, second)

    def test_sorted_keys(self):
        output = format_safe_json_log("INFO", "hello", {"z": 1, "a": 2}, max_output_bytes=500)
        self.assertLess(output.index('"a"'), output.index('"z"'))

    def test_no_implicit_timestamp(self):
        output = format_safe_json_log("INFO", "hello", {"x": 1}, max_output_bytes=500)
        self.assertNotIn("ts", parse(output))
        self.assertNotIn("timestamp", parse(output))

    def test_long_message_truncated_to_cap(self):
        output = format_safe_json_log("INFO", "x" * 1000, max_output_bytes=100)
        data = parse(output)
        self.assertTrue(data["message"].endswith("[truncated]"))
        self.assertLessEqual(len(output.encode()), 100)

    def test_large_meta_reduced_or_truncated(self):
        output = format_safe_json_log("INFO", "hello", {"x": "y" * 5000}, max_output_bytes=100)
        parse(output)
        self.assertLessEqual(len(output.encode()), 100)

    def test_fallback_valid_json_tiny_cap_two(self):
        output = format_safe_json_log("INFO", "hello", max_output_bytes=2)
        self.assertEqual(output, "{}")
        self.assertEqual(parse(output), {})

    def test_fallback_valid_json_cap_one(self):
        output = format_safe_json_log("INFO", "hello", max_output_bytes=1)
        self.assertEqual(output, "0")
        self.assertEqual(parse(output), 0)

    def test_invalid_zero_cap(self):
        with self.assertRaises(LogCageError):
            format_safe_json_log("INFO", "hello", max_output_bytes=0)

    def test_invalid_negative_cap(self):
        with self.assertRaises(LogCageError):
            format_safe_json_log("INFO", "hello", max_output_bytes=-1)

    def test_bytes_meta(self):
        output = format_safe_json_log("INFO", "hello", {"data": b"a\xff\n"}, max_output_bytes=500)
        self.assertEqual(parse(output)["meta"]["data"], "a\\xff\\n")

    def test_exception_meta(self):
        output = format_safe_json_log("INFO", "hello", {"error": ValueError("bad password=abc")}, max_output_bytes=1000)
        error = parse(output)["meta"]["error"]
        self.assertEqual(error["type"], "ValueError")
        self.assertEqual(error["message"], "bad password=[REDACTED]")

    def test_circular_meta(self):
        value = {}
        value["self"] = value
        output = format_safe_json_log("INFO", "hello", value, max_output_bytes=1000)
        self.assertEqual(parse(output)["meta"]["self"], "[Circular]")

    def test_cap_with_unicode_content(self):
        output = format_safe_json_log("INFO", "東京" * 500, max_output_bytes=128)
        self.assertLessEqual(len(output.encode("utf-8")), 128)
        parse(output)

    def test_control_obfuscated_secret_in_json(self):
        output = format_safe_json_log("INFO", "password=ab\x00cdef", max_output_bytes=200)
        self.assertEqual(parse(output)["message"], "password=[REDACTED]")

    def test_truncated_output_remains_single_line(self):
        output = format_safe_json_log("INFO", "a\n" * 500, {"x": "b\r" * 500}, max_output_bytes=120)
        self.assertNotIn("\n", output)
        self.assertNotIn("\r", output)
        parse(output)


if __name__ == "__main__":
    unittest.main()
