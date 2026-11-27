"""Shared test helpers. Synthetic token shapes are assembled at runtime."""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest

from pylogcage.sanitizer import escape_for_codepoint, is_unsafe_control_or_format_char


def ch(cp):
    return chr(cp)


def esc(cp):
    return escape_for_codepoint(cp)


def assert_no_unsafe(testcase, text):
    for char in text:
        testcase.assertFalse(is_unsafe_control_or_format_char(char), "unsafe U+%04X in %r" % (ord(char), text))


def shaped_jwt():
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(b"{}").decode().rstrip("=")
    signature = base64.urlsafe_b64encode(b"signature").decode().rstrip("=")
    return header + "." + payload + "." + signature


def synthetic_vendor_secrets():
    return {
        "aws_access": "AK" + "IA" + "A" * 16,
        "aws_temp": "AS" + "IA" + "B" * 16,
        "github_legacy": "gh" + "p_" + "c" * 36,
        "github_fine": "github" + "_pat_" + "d" * 40,
        "gitlab_pat": "gl" + "pat-" + "e" * 24,
        "stripe_secret": "s" + "k_live_" + "f" * 24,
        "stripe_restricted": "r" + "k_test_" + "g" * 24,
        "stripe_webhook": "wh" + "sec_" + "h" * 24,
        "slack_bot": "xo" + "xb-" + "i" * 24,
        "slack_app": "xa" + "pp-" + "j" * 24,
        "anthropic": "s" + "k-ant-" + "k" * 32,
        "openai": "s" + "k-" + "l" * 32,
        "openai_project": "s" + "k-proj-" + "m" * 32,
        "npm": "np" + "m_" + "n" * 36,
        "pypi": "py" + "pi-" + "o" * 36,
        "google_api": "AI" + "za" + "p" * 35,
        "digitalocean": "do" + "p_v1_" + "0123456789abcdef" * 4,
        "telegram": "12345678" + ":" + "q" * 35,
    }


def run_cli(args, input_bytes=b"", cwd=None):
    env = dict(os.environ)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env["PYTHONPATH"] = os.path.join(root, "src")
    command = [sys.executable, "-m", "pylogcage"] + list(args)
    return subprocess.run(command, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd or root, env=env, timeout=10)


class PylogcageTestCase(unittest.TestCase):
    def assertNoUnsafe(self, text):
        assert_no_unsafe(self, text)
