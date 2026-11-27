from __future__ import annotations

import json
import os
import tempfile
import unittest

from pylogcage.audit import MAX_AUDIT_FILE_BYTES

from helpers import PylogcageTestCase, run_cli


class TestCliSanitize(PylogcageTestCase):
    def test_version(self):
        result = run_cli(["--version"])
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"pylogcage 1.0.0", result.stdout)

    def test_sanitize_clean_input(self):
        result = run_cli(["sanitize"], b"hello world\n")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"hello world\n")

    def test_sanitize_redacts_password(self):
        result = run_cli(["sanitize"], b"password=abc\n")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"password=[REDACTED]\n")

    def test_sanitize_escapes_newline_in_record(self):
        result = run_cli(["sanitize"], b"a\\nb\n")
        self.assertEqual(result.stdout, b"a\\nb\n")

    def test_sanitize_strips_ansi(self):
        result = run_cli(["sanitize"], b"a\x1b[31mb\n")
        self.assertEqual(result.stdout, b"ab\n")

    def test_sanitize_escape_mode_escapes_cr(self):
        result = run_cli(["sanitize", "--escape"], b"a\rb\n")
        self.assertEqual(result.stdout, b"a\\rb\n")

    def test_sanitize_strip_mode_removes_cr(self):
        result = run_cli(["sanitize", "--strip"], b"a\rb\n")
        self.assertEqual(result.stdout, b"ab\n")

    def test_sanitize_max_length(self):
        result = run_cli(["sanitize", "--max-length", "16"], b"x" * 100 + b"\n")
        self.assertEqual(result.returncode, 0)
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines[0]), 16)
        self.assertTrue(lines[0].endswith(b"[truncated]"))

    def test_sanitize_redact_pii(self):
        result = run_cli(["sanitize", "--redact-pii"], b"mail user@example.test\n")
        self.assertEqual(result.stdout, b"mail [REDACTED]\n")

    def test_sanitize_extra_secret(self):
        result = run_cli(["sanitize", "--extra-secret", "alpha beta"], b"x alpha beta y\n")
        self.assertEqual(result.stdout, b"x [REDACTED] y\n")

    def test_sanitize_no_redact(self):
        result = run_cli(["sanitize", "--no-redact"], b"password=abc\n")
        self.assertEqual(result.stdout, b"password=abc\n")

    def test_sanitize_multiple_lines(self):
        result = run_cli(["sanitize"], b"one\ntwo\nthree\n")
        self.assertEqual(result.stdout, b"one\ntwo\nthree\n")

    def test_sanitize_invalid_utf8_does_not_crash(self):
        result = run_cli(["sanitize"], b"a\xffb\n")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"a\\xffb\n")

    def test_sanitize_invalid_max_length_exit_two(self):
        result = run_cli(["sanitize", "--max-length", "4"], b"x\n")
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"max_length", result.stderr)


class TestCliAudit(PylogcageTestCase):
    def test_audit_clean_stdin_exit_zero(self):
        result = run_cli(["audit", "-", "--json"], b"safe line\n")
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertTrue(data["ok"])
        self.assertEqual(data["findings"], [])

    def test_audit_crlf_finding(self):
        result = run_cli(["audit", "-", "--json"], b"bad\rline\n")
        self.assertEqual(result.returncode, 1)
        data = json.loads(result.stdout)
        self.assertEqual(data["counts"]["cwe117_control"], 1)

    def test_audit_terminal_escape_finding(self):
        result = run_cli(["audit", "-", "--json"], b"a\x1b[31mb\n")
        self.assertEqual(result.returncode, 1)
        data = json.loads(result.stdout)
        self.assertEqual(data["counts"]["terminal_escape"], 1)

    def test_audit_raw_c1_escape_byte_finding(self):
        result = run_cli(["audit", "-", "--json"], b"a\x9b31mb\n")
        self.assertEqual(result.returncode, 1)
        data = json.loads(result.stdout)
        self.assertEqual(data["counts"]["terminal_escape"], 1)
        self.assertEqual(data["counts"]["cwe117_control"], 1)

    def test_audit_control_obfuscated_secret_finding(self):
        result = run_cli(["audit", "-", "--json"], b"password=ab\tcdef\n")
        self.assertEqual(result.returncode, 1)
        data = json.loads(result.stdout)
        self.assertEqual(data["counts"]["secret_leak"], 1)
        self.assertNotIn(b"abcdef", result.stdout)

    def test_audit_utf8_continuation_not_terminal_escape(self):
        result = run_cli(["audit", "-", "--json"], "\u0410 safe\n".encode("utf-8"))
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["counts"]["terminal_escape"], 0)
        self.assertEqual(data["counts"]["cwe117_control"], 0)

    def test_audit_secret_finding_without_raw_secret(self):
        secret = b"alphabeticsecretvalue"
        result = run_cli(["audit", "-", "--json"], b"Authorization: Bearer " + secret + b"\n")
        self.assertEqual(result.returncode, 1)
        data = json.loads(result.stdout)
        self.assertEqual(data["counts"]["secret_leak"], 1)
        self.assertNotIn(secret, result.stdout)

    def test_audit_invalid_utf8_finding(self):
        result = run_cli(["audit", "-", "--json"], b"a\xffb\n")
        self.assertEqual(result.returncode, 1)
        data = json.loads(result.stdout)
        self.assertEqual(data["counts"]["invalid_utf8"], 1)

    def test_audit_line_numbers(self):
        result = run_cli(["audit", "-", "--json"], b"safe\nbad\rline\nsafe\n")
        data = json.loads(result.stdout)
        self.assertIn({"line": 2, "type": "cwe117_control"}, data["findings"])

    def test_audit_text_output_no_raw_secret(self):
        secret = b"alphabeticsecretvalue"
        result = run_cli(["audit", "-"], b"Authorization: Bearer " + secret + b"\n")
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"secret_leak", result.stdout)
        self.assertNotIn(secret, result.stdout)

    def test_audit_regular_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "app.log")
            with open(path, "wb") as handle:
                handle.write(b"safe\n")
            result = run_cli(["audit", path, "--json"])
        self.assertEqual(result.returncode, 0)
        self.assertTrue(json.loads(result.stdout)["ok"])

    def test_audit_directory_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            result = run_cli(["audit", folder])
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"not a regular file", result.stderr)

    def test_audit_missing_file_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "missing.log")
            result = run_cli(["audit", path])
        self.assertEqual(result.returncode, 2)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_audit_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            real = os.path.join(folder, "real.log")
            link = os.path.join(folder, "link.log")
            with open(real, "wb") as handle:
                handle.write(b"safe\n")
            os.symlink(real, link)
            result = run_cli(["audit", link])
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"symbolic link", result.stderr)

    def test_audit_oversized_regular_file_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "oversized.log")
            with open(path, "wb") as handle:
                handle.truncate(MAX_AUDIT_FILE_BYTES + 1)
            result = run_cli(["audit", path])
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"maximum regular-file size", result.stderr)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO support required")
    def test_audit_fifo_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "pipe.log")
            os.mkfifo(path)
            result = run_cli(["audit", path], input_bytes=b"", cwd=folder)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"not a regular file", result.stderr)

    def test_audit_empty_file_clean(self):
        result = run_cli(["audit", "-", "--json"], b"")
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["lines"], 0)
        self.assertTrue(data["ok"])

    def test_audit_tab_is_control_finding(self):
        result = run_cli(["audit", "-", "--json"], b"a\tb\n")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["counts"]["cwe117_control"], 1)

    def test_usage_error_exit_two(self):
        result = run_cli(["unknown"])
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"usage:", result.stderr)


if __name__ == "__main__":
    unittest.main()
