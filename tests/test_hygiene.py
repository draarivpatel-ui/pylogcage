from __future__ import annotations

import ast
import os
import re
import subprocess
import unittest

import pylogcage

from helpers import PylogcageTestCase

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _hygiene_text_file(name):
    return name.endswith((".py", ".md", ".toml", ".yml", ".txt", ".in")) or name in ("LICENSE", ".gitignore", ".gitattributes")


def tracked_text_files():
    try:
        git_output = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        git_output = None
    if git_output is not None:
        output = []
        for raw_name in git_output.split(b"\0"):
            if not raw_name:
                continue
            name = os.path.basename(os.fsdecode(raw_name))
            if _hygiene_text_file(name):
                path = os.path.join(ROOT, os.fsdecode(raw_name))
                if os.path.isfile(path):
                    output.append(path)
        return sorted(output)

    output = []
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [item for item in dirs if item not in (".git", "__pycache__", "build", "dist")]
        for name in files:
            if _hygiene_text_file(name):
                output.append(os.path.join(base, name))
    return sorted(output)


def read_bytes(path):
    with open(path, "rb") as handle:
        return handle.read()


def read_text(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


class TestPackageHygiene(PylogcageTestCase):
    def test_version(self):
        self.assertEqual(pylogcage.__version__, "1.0.0")

    def test_public_api_exports(self):
        expected = {
            "LogCage", "LogCageFilter", "SafeJsonFormatter", "SafeTextFormatter",
            "format_safe_json_log", "redact_secrets", "sanitize_log_line",
            "sanitize_record", "strip_terminal_sequences",
        }
        self.assertTrue(expected.issubset(set(pylogcage.__all__)))
        for name in expected:
            self.assertTrue(hasattr(pylogcage, name), name)

    def test_py_typed_exists(self):
        self.assertTrue(os.path.isfile(os.path.join(ROOT, "src", "pylogcage", "py.typed")))

    def test_pyproject_name_version(self):
        text = read_text(os.path.join(ROOT, "pyproject.toml"))
        self.assertIn('name = "pylogcage"', text)
        self.assertIn('version = "1.0.0"', text)

    def test_pyproject_python_and_dependencies(self):
        text = read_text(os.path.join(ROOT, "pyproject.toml"))
        self.assertIn('requires-python = ">=3.9"', text)
        self.assertIn("dependencies = []", text)

    def test_pyproject_license_and_script(self):
        text = read_text(os.path.join(ROOT, "pyproject.toml"))
        self.assertIn('license = "MIT"', text)
        self.assertIn('pylogcage = "pylogcage.cli:main"', text)

    def test_pyproject_urls(self):
        text = read_text(os.path.join(ROOT, "pyproject.toml"))
        self.assertIn("https://github.com/draarivpatel-ui/pylogcage", text)

    def test_pyproject_package_data_and_excludes(self):
        text = read_text(os.path.join(ROOT, "pyproject.toml"))
        self.assertIn('pylogcage = ["py.typed"]', text)
        self.assertIn('exclude = ["tests*"]', text)

    def test_ci_python_matrix(self):
        text = read_text(os.path.join(ROOT, ".github", "workflows", "ci.yml"))
        for version in ("3.9", "3.10", "3.11", "3.12", "3.13"):
            self.assertIn('"' + version + '"', text)
        self.assertIn("ubuntu-24.04", text)
        self.assertIn("python3 -m unittest discover -s tests", text)

    def test_publish_oidc_hardening(self):
        text = read_text(os.path.join(ROOT, ".github", "workflows", "publish.yml"))
        self.assertIn("id-token: write", text)
        self.assertIn("name: pypi", text)
        self.assertIn("pypa/gh-action-pypi-publish@release/v1", text)
        self.assertNotIn("PYPI_TOKEN", text)
        self.assertNotIn("password:", text)

    def test_required_docs_exist(self):
        required = [
            "README.md", "CONTRIBUTING.md", "SECURITY.md", "LICENSE",
            os.path.join("docs", "GOOD_FIRST_ISSUES.md"),
            os.path.join(".github", "PULL_REQUEST_TEMPLATE.md"),
            os.path.join(".github", "ISSUE_TEMPLATE", "bug_report.md"),
            os.path.join(".github", "ISSUE_TEMPLATE", "feature_request.md"),
        ]
        for relative in required:
            self.assertTrue(os.path.isfile(os.path.join(ROOT, relative)), relative)

    def test_readme_threat_model_and_logging_examples(self):
        text = read_text(os.path.join(ROOT, "README.md"))
        self.assertIn("## Threat model", text)
        self.assertIn("LogCageFilter", text)
        self.assertIn("SafeJsonFormatter", text)
        self.assertIn("format_safe_json_log", text)
        self.assertIn("PyPI publication is pending", text)

    def test_license_mit(self):
        text = read_text(os.path.join(ROOT, "LICENSE"))
        self.assertIn("MIT License", text)
        self.assertIn("Permission is hereby granted", text)

    def test_untracked_files_not_scanned_in_git_checkout(self):
        inside_git = subprocess.call(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ) == 0
        if not inside_git:
            self.skipTest("git checkout required")
        probe = os.path.join(ROOT, "UNTRACKED_HYGIENE_PROBE.md")
        with open(probe, "w", encoding="utf-8") as handle:
            handle.write("untracked probe\n")
        try:
            self.assertNotIn(probe, tracked_text_files())
        finally:
            os.remove(probe)

    def test_no_crlf_in_text_files(self):
        offenders = [path for path in tracked_text_files() if b"\r\n" in read_bytes(path)]
        self.assertEqual(offenders, [])

    def test_no_em_or_en_dash_bytes(self):
        em = b"\xe2\x80" + bytes([0x94])
        en = b"\xe2\x80" + bytes([0x93])
        offenders = [path for path in tracked_text_files() if em in read_bytes(path) or en in read_bytes(path)]
        self.assertEqual(offenders, [])

    def test_no_private_paths_or_email_markers(self):
        private_home = ("/" + "Users" + "/" + "aarivpatel").encode()
        gmail_marker = ("someone" + "@" + "gmail" + ".com").encode()
        offenders = []
        for path in tracked_text_files():
            data = read_bytes(path)
            if private_home in data or gmail_marker in data:
                offenders.append(path)
        self.assertEqual(offenders, [])

    def test_no_literal_vendor_shaped_secrets(self):
        shapes = [
            "(?:AKIA|ASIA)[A-Z0-9]{16}",
            "gh[pousr]_[A-Za-z0-9]{20,}",
            "github_pat_[A-Za-z0-9_]{20,}",
            "glpat-[A-Za-z0-9_-]{20,}",
            "[sr]k_(?:live|test)_[A-Za-z0-9]{12,}",
            "whsec_[A-Za-z0-9]{12,}",
            "xox[baprs]-[A-Za-z0-9-]{10,}",
            "sk-ant-[A-Za-z0-9_-]{20,}",
            "sk-(?:proj-)?[A-Za-z0-9_-]{20,}",
            "npm_[A-Za-z0-9]{30,}",
            "pypi-[A-Za-z0-9_-]{20,}",
            "AIza[A-Za-z0-9_-]{35}",
        ]
        offenders = []
        for path in tracked_text_files():
            text = read_bytes(path).decode("utf-8", "ignore")
            for shape in shapes:
                if re.search(shape, text):
                    offenders.append((path, shape))
        self.assertEqual(offenders, [])

    def test_no_python_runtime_dependencies_in_imports(self):
        allowed = {
            "argparse", "base64", "binascii", "copy", "dataclasses", "datetime",
            "decimal", "json", "logging", "math", "os", "pathlib", "re", "stat",
            "sys", "traceback", "typing", "unicodedata", "uuid", "pylogcage", "__future__",
        }
        offenders = []
        package_dir = os.path.join(ROOT, "src", "pylogcage")
        for base, _dirs, files in os.walk(package_dir):
            for name in files:
                if not name.endswith(".py"):
                    continue
                path = os.path.join(base, name)
                tree = ast.parse(read_text(path), filename=path)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            if alias.name.split(".")[0] not in allowed:
                                offenders.append((path, alias.name))
                    elif isinstance(node, ast.ImportFrom):
                        if node.level == 0 and node.module and node.module.split(".")[0] not in allowed:
                            offenders.append((path, node.module))
        self.assertEqual(offenders, [])

    def test_no_tomllib_or_match_case_syntax(self):
        offenders = []
        package_dir = os.path.join(ROOT, "src", "pylogcage")
        for base, _dirs, files in os.walk(package_dir):
            for name in files:
                if name.endswith(".py"):
                    path = os.path.join(base, name)
                    text = read_text(path)
                    if "tomllib" in text or "\nmatch " in text or "\ncase " in text:
                        offenders.append(path)
        self.assertEqual(offenders, [])

    def test_exception_notes_access_is_defensive(self):
        text = read_text(os.path.join(ROOT, "src", "pylogcage", "record.py"))
        self.assertIn('getattr(value, "__notes__", ())', text)

    def test_bytecode_and_build_outputs_are_gitignored(self):
        text = read_text(os.path.join(ROOT, ".gitignore"))
        self.assertIn("__pycache__/", text)
        self.assertIn("*.py[cod]", text)
        self.assertIn("build/", text)
        self.assertIn("dist/", text)


if __name__ == "__main__":
    unittest.main()
