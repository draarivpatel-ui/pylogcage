from __future__ import annotations

import time
import unittest

from pylogcage import sanitize_log_line, strip_terminal_sequences
from pylogcage.errors import LogCageError, LogCageInputError
from pylogcage.sanitizer import is_unsafe_control_or_format_char

from helpers import PylogcageTestCase, ch, esc


class TestSanitizeLogLine(PylogcageTestCase):
    def test_plain_ascii_unchanged(self):
        self.assertEqual(sanitize_log_line("plain ascii 123 !@#$%^&*()"), "plain ascii 123 !@#$%^&*()")

    def test_plain_unicode_unchanged(self):
        self.assertEqual(sanitize_log_line("hello café 東京 مرحبا"), "hello café 東京 مرحبا")

    def test_astral_character_unchanged(self):
        self.assertEqual(sanitize_log_line("music \U0001f600 end"), "music \U0001f600 end")

    def test_empty_input(self):
        self.assertEqual(sanitize_log_line(""), "")

    def test_only_terminal_sequences(self):
        self.assertEqual(sanitize_log_line("\x1b[31m\x1b]0;x\x07\x90y\x9c"), "")

    def test_strip_terminal_sequences_type_error(self):
        with self.assertRaises(TypeError):
            strip_terminal_sequences(None)

    def test_sanitize_type_error(self):
        with self.assertRaises(TypeError):
            sanitize_log_line(None)


def _make_input_type_test(value):
    def test(self):
        with self.assertRaises(TypeError):
            sanitize_log_line(value)
    return test


for _label, _value in [
    ("none", None), ("int", 1), ("bool", True), ("bytes", b"x"),
    ("list", []), ("dict", {}), ("object", object()),
]:
    setattr(TestSanitizeLogLine, "test_rejects_input_type_" + _label, _make_input_type_test(_value))


def _make_line_break_test(name, cp):
    def test_escape(self):
        self.assertEqual(sanitize_log_line("a" + ch(cp) + "b"), "a" + esc(cp) + "b")
    def test_strip(self):
        self.assertEqual(sanitize_log_line("a" + ch(cp) + "b", mode="strip"), "ab")
    return test_escape, test_strip


for _name, _cp in [("lf", 10), ("cr", 13), ("nel", 0x85), ("ls", 0x2028), ("ps", 0x2029)]:
    _escape_test, _strip_test = _make_line_break_test(_name, _cp)
    setattr(TestSanitizeLogLine, "test_escape_line_break_" + _name, _escape_test)
    setattr(TestSanitizeLogLine, "test_strip_line_break_" + _name, _strip_test)


def _make_c0_test(cp):
    def test_escape(self):
        expected = "a" if cp == 0x1B else "a" + esc(cp) + "b"
        self.assertEqual(sanitize_log_line("a" + ch(cp) + "b"), expected)
    def test_strip(self):
        expected = "a" if cp == 0x1B else "ab"
        self.assertEqual(sanitize_log_line("a" + ch(cp) + "b", mode="strip"), expected)
    return test_escape, test_strip


for _cp in range(0x20):
    _escape_test, _strip_test = _make_c0_test(_cp)
    setattr(TestSanitizeLogLine, "test_escape_c0_%02x" % _cp, _escape_test)
    setattr(TestSanitizeLogLine, "test_strip_c0_%02x" % _cp, _strip_test)


def _make_c1_test(cp):
    sequence_starter = cp in (0x90, 0x98, 0x9B, 0x9D, 0x9E, 0x9F)
    def test_escape(self):
        expected = "a" if sequence_starter else "a" + esc(cp) + "b"
        self.assertEqual(sanitize_log_line("a" + ch(cp) + "b"), expected)
    def test_strip(self):
        expected = "a" if sequence_starter else "ab"
        self.assertEqual(sanitize_log_line("a" + ch(cp) + "b", mode="strip"), expected)
    return test_escape, test_strip


for _cp in range(0x7F, 0xA0):
    _escape_test, _strip_test = _make_c1_test(_cp)
    setattr(TestSanitizeLogLine, "test_escape_del_c1_%02x" % _cp, _escape_test)
    setattr(TestSanitizeLogLine, "test_strip_del_c1_%02x" % _cp, _strip_test)


_TERMINAL_VECTORS = [
    ("csi_color", "a\x1b[31mb", "ab"),
    ("csi_cursor", "a\x1b[2Jb", "ab"),
    ("csi_private", "a\x1b[?25lb", "ab"),
    ("csi_unterminated", "a\x1b[31;", "a"),
    ("csi_empty_final", "a\x1b[b", "a"),
    ("c1_csi_color", "a\x9b31mb", "ab"),
    ("c1_csi_unterminated", "a\x9b31;", "a"),
    ("osc_bel", "a\x1b]0;title\x07b", "ab"),
    ("osc_st", "a\x1b]0;title\x1b\\b", "ab"),
    ("osc_c1_st", "a\x1b]0;title\x9cb", "ab"),
    ("osc8_link", "a\x1b]8;;https://example.test\x1b\\label\x1b]8;;\x1b\\b", "alabelb"),
    ("osc52_clipboard", "a\x1b]52;c;SGVsbG8=\x07b", "ab"),
    ("osc_unterminated", "a\x1b]52;c;SGVsbG8=", "a"),
    ("c1_osc", "a\x9d0;title\x07b", "ab"),
    ("dcs", "a\x1bPpayload\x1b\\b", "ab"),
    ("c1_dcs", "a\x90payload\x9cb", "ab"),
    ("sos", "a\x1bXpayload\x1b\\b", "ab"),
    ("pm", "a\x1b^payload\x1b\\b", "ab"),
    ("apc", "a\x1b_payload\x1b\\b", "ab"),
    ("c1_apc", "a\x9fpayload\x9cb", "ab"),
    ("c1_pm", "a\x9epayload\x9cb", "ab"),
    ("c1_sos", "a\x98payload\x9cb", "ab"),
    ("lone_esc_end", "ab\x1b", "ab"),
    ("esc_final", "a\x1bb", "a"),
    ("esc_reset", "a\x1bcb", "ab"),
    ("esc_save", "a\x1b7b", "ab"),
    ("esc_charset", "a\x1b(0b", "ab"),
    ("esc_hash", "a\x1b#8b", "ab"),
    ("double_esc", "a\x1b\x1b[31mb", "ab"),
    ("malformed_escape_control", "a\x1b\x01b", "a\\x01b"),
]


def _make_terminal_test(input_text, expected):
    def test(self):
        self.assertEqual(sanitize_log_line(input_text), expected)
        self.assertNoUnsafe(sanitize_log_line(input_text))
    return test


for _name, _input, _expected in _TERMINAL_VECTORS:
    setattr(TestSanitizeLogLine, "test_terminal_" + _name, _make_terminal_test(_input, _expected))


_BIDI_CPS = [0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x200E, 0x200F, 0x061C]


def _make_bidi_test(cp):
    def test_escape(self):
        self.assertEqual(sanitize_log_line("a" + ch(cp) + "b"), "a" + esc(cp) + "b")
    def test_strip(self):
        self.assertEqual(sanitize_log_line("a" + ch(cp) + "b", mode="strip"), "ab")
    return test_escape, test_strip


for _cp in _BIDI_CPS:
    _escape_test, _strip_test = _make_bidi_test(_cp)
    setattr(TestSanitizeLogLine, "test_escape_bidi_%04x" % _cp, _escape_test)
    setattr(TestSanitizeLogLine, "test_strip_bidi_%04x" % _cp, _strip_test)


_FORMAT_CPS = [
    0x00AD, 0x0600, 0x0605, 0x06DD, 0x070F, 0x0890, 0x0891, 0x08E2,
    0x180E, 0x200B, 0x200C, 0x200D, 0x2060, 0x2064, 0x206A, 0x206F,
    0xFE00, 0xFE0F, 0xFEFF, 0xFFF9, 0xFFFB, 0x110BD, 0x110CD,
    0x13430, 0x1343F, 0x1BCA0, 0x1BCA3, 0x1D173, 0x1D17A,
    0xE0001, 0xE0020, 0xE007F, 0xE0100, 0xE01EF,
]


def _make_format_test(cp):
    def test(self):
        self.assertEqual(sanitize_log_line("a" + ch(cp) + "b"), "a" + esc(cp) + "b")
        self.assertNoUnsafe(sanitize_log_line("a" + ch(cp) + "b"))
    return test


for _cp in _FORMAT_CPS:
    setattr(TestSanitizeLogLine, "test_invisible_format_%x" % _cp, _make_format_test(_cp))


_NONCHARACTER_CPS = [0xFDD0, 0xFDEF, 0xFFFE, 0xFFFF, 0x1FFFE, 0x1FFFF, 0x10FFFE, 0x10FFFF]


def _make_noncharacter_test(cp):
    def test(self):
        self.assertEqual(sanitize_log_line("a" + ch(cp) + "b"), "a" + esc(cp) + "b")
    return test


for _cp in _NONCHARACTER_CPS:
    setattr(TestSanitizeLogLine, "test_noncharacter_%x" % _cp, _make_noncharacter_test(_cp))


_SURROGATE_CASES = [
    ("lone_high", "\ud800"), ("lone_low", "\udc00"), ("high_before_ascii", "\ud800x"),
    ("low_after_ascii", "x\udfff"), ("two_high", "\ud800\ud800"),
]


def _make_surrogate_test(value):
    def test(self):
        output = sanitize_log_line("a" + value + "b")
        self.assertNotIn("\ud800", output)
        self.assertNotIn("\udfff", output)
        self.assertNoUnsafe(output)
    return test


for _name, _value in _SURROGATE_CASES:
    setattr(TestSanitizeLogLine, "test_lone_surrogate_" + _name, _make_surrogate_test(_value))


class TestTruncation(PylogcageTestCase):
    def test_marker_included_in_max_length(self):
        output = sanitize_log_line("x" * 17, max_length=16)
        self.assertEqual(output, "xxxxx[truncated]")
        self.assertEqual(len(output), 16)

    def test_exact_max_not_truncated(self):
        self.assertEqual(sanitize_log_line("x" * 16, max_length=16), "x" * 16)

    def test_one_over_max_truncated(self):
        self.assertEqual(sanitize_log_line("x" * 17, max_length=16), "xxxxx[truncated]")

    def test_escape_token_not_split(self):
        output = sanitize_log_line("x" * 16 + "\n", max_length=16)
        self.assertEqual(output, "xxxxx[truncated]")
        self.assertLessEqual(len(output), 16)
        self.assertFalse(output.endswith("\\x[truncated]"))

    def test_astral_not_split(self):
        output = sanitize_log_line("x" * 16 + "\U0001f600", max_length=16)
        self.assertEqual(output, "xxxxx[truncated]")
        self.assertNotIn("\ud800", output)
        self.assertNotIn("\udc00", output)


    def test_custom_marker_length_matrix(self):
        cases = [
            ("!", "abcdefghijklmno!"),
            ("...", "abcdefghijklm..."),
            ("[CUT]", "abcdefghijk[CUT]"),
            ("#" * 15, "a" + "#" * 15),
        ]

        for marker, expected in cases:
            with self.subTest(marker=marker):
                output = sanitize_log_line(
                    "abcdefghijklmnopqrstuvwxyz",
                    max_length=16,
                    truncation_marker=marker,
                )
                self.assertEqual(output, expected)
                self.assertEqual(len(output), 16)

    def test_invalid_custom_marker_matrix(self):
        for marker in ("", "x" * 17, "bad\x00", "bad\r"):
            with self.subTest(marker=marker):
                with self.assertRaises(LogCageError):
                    sanitize_log_line(
                        "abcdefghijklmnopqrstuvwxyz",
                        max_length=16,
                        truncation_marker=marker,
                    )

    def test_custom_marker_preserves_escape_token(self):
        output = sanitize_log_line(
            "abcdefghijk\nmnopqrstuvwxyz",
            max_length=16,
            truncation_marker="...",
        )
        self.assertEqual(output, "abcdefghijk\\n...")
        self.assertEqual(len(output), 16)

    def test_custom_marker_does_not_split_escape_token(self):
        output = sanitize_log_line(
            "abcdefghijkl\nmnopqrstuvwxyz",
            max_length=16,
            truncation_marker="...",
        )
        self.assertEqual(output, "abcdefghijkl...")
        self.assertEqual(len(output), 15)

    def test_custom_marker(self):
        output = sanitize_log_line("abcdefghijklmnopqrstuvwxyz", max_length=16, truncation_marker="[cut]")
        self.assertEqual(output, "abcdefghijk[cut]")
        self.assertEqual(len(output), 16)

    def test_terminal_after_capacity_not_truncation(self):
        self.assertEqual(sanitize_log_line("abcde\x1b[31m", max_length=16), "abcde")

    def test_unsafe_after_capacity_counts_escape_mode(self):
        self.assertEqual(sanitize_log_line("x" * 16 + "\n", max_length=16), "xxxxx[truncated]")

    def test_unsafe_after_capacity_not_counted_strip_mode(self):
        self.assertEqual(sanitize_log_line("x" * 16 + "\n", max_length=16, mode="strip"), "x" * 16)

    def test_long_visible_input_strip_mode(self):
        output = sanitize_log_line("x" * 1000, max_length=32, mode="strip")
        self.assertEqual(len(output), 32)
        self.assertTrue(output.endswith("[truncated]"))

    def test_large_escape_token_still_atomic(self):
        output = sanitize_log_line("abc\U0001d173def", max_length=16)
        self.assertNotIn("\\U0001d17[", output)
        self.assertNoUnsafe(output)

    def test_zero_width_joiner_escaped(self):
        self.assertEqual(sanitize_log_line("a\u200db"), "a\\u200db")

    def test_reject_bad_mode(self):
        with self.assertRaises(LogCageError):
            sanitize_log_line("x", mode="remove")

    def test_reject_small_max_length(self):
        with self.assertRaises(LogCageError):
            sanitize_log_line("x", max_length=4)

    def test_reject_marker_equal_max(self):
        with self.assertRaises(LogCageError):
            sanitize_log_line("x", max_length=16, truncation_marker="x" * 16)

    def test_reject_newline_marker(self):
        with self.assertRaises(LogCageError):
            sanitize_log_line("x", truncation_marker="bad\n")

    def test_reject_escape_marker(self):
        with self.assertRaises(LogCageError):
            sanitize_log_line("x", truncation_marker="bad\x1b")

    def test_pathological_100kb_terminal_input_linear(self):
        unit = "\x1b[31m\x1b]52;c;AAAA\x07\x90abc\x1b\\\n\x00\u2028\u202e"
        repeat = (100 * 1024) // len(unit) + 1
        text = unit * repeat
        self.assertGreaterEqual(len(text), 100 * 1024)
        started = time.monotonic()
        output = sanitize_log_line(text, max_length=1024)
        elapsed = time.monotonic() - started
        self.assertLessEqual(len(output), 1024)
        self.assertNoUnsafe(output)
        self.assertLess(elapsed, 5.0)


if __name__ == "__main__":
    unittest.main()
