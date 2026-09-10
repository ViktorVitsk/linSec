"""Behavioral hygiene tests using disposable repositories and synthetic source text."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts.check_m0 import ROOT, REQUIRED_FILES, collect_violations


class M0SafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="sec-hygiene-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for name in REQUIRED_FILES:
            shutil.copyfile(ROOT / name, self.root / name)
        self.git = shutil.which("git")
        if self.git is None:
            self.fail("Git is required for hygiene tests")
        self.run_git("init", "--quiet")

    def run_git(self, *args: str) -> None:
        # Only fixed Git operations on this test's disposable repository.
        subprocess.run(  # noqa: S603
            [self.git, "-C", str(self.root), *args], check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
        )

    def test_repository_is_clean(self) -> None:
        self.assertEqual([], collect_violations(ROOT))
        self.assertEqual([], collect_violations(self.root))

    def test_dependencies_and_packaging_can_evolve(self) -> None:
        path = self.root / "pyproject.toml"
        config = path.read_text().replace("dependencies = []", 'dependencies = ["example>=1"]')
        path.write_text(config.replace("package = false", "package = true"))
        self.assertEqual([], collect_violations(self.root))

    def test_configuration_uses_toml_not_literal_formatting(self) -> None:
        path = self.root / "pyproject.toml"
        path.write_text(path.read_text().replace('">=3.13"', "'>=3.13'"))
        self.assertEqual([], collect_violations(self.root))

    def test_mismatched_python_and_ruff_are_reported(self) -> None:
        (self.root / ".python-version").write_text("3.12\n")
        errors = collect_violations(self.root)
        self.assertTrue(any("requires-python" in error for error in errors))
        self.assertTrue(any("target-version" in error for error in errors))

    def test_invalid_configuration_does_not_echo_contents(self) -> None:
        (self.root / "pyproject.toml").write_text("[broken\nSYNTHETIC_PRIVATE_MARKER")
        errors = collect_violations(self.root)
        self.assertTrue(errors)
        self.assertNotIn("SYNTHETIC_PRIVATE_MARKER", "\n".join(errors))

    def test_missing_configuration_has_actionable_error(self) -> None:
        (self.root / "pyproject.toml").unlink()
        self.assertEqual(["missing regular project file: pyproject.toml"],
                         collect_violations(self.root))

    def test_configuration_symlink_is_not_followed(self) -> None:
        (self.root / "pyproject.toml").unlink()
        (self.root / "pyproject.toml").symlink_to(self.root / "absent-target")
        self.assertTrue(collect_violations(self.root))

    def test_disabled_security_lint_is_reported(self) -> None:
        path = self.root / "pyproject.toml"
        path.write_text(path.read_text().replace('"S", "TID251"', '"E501"'))
        self.assertTrue(any("security" in error for error in collect_violations(self.root)))

    def test_local_ignored_data_is_allowed(self) -> None:
        (self.root / "state").mkdir()
        (self.root / "state" / "events.sqlite3").write_text("synthetic")
        (self.root / ".env").write_text("SYNTHETIC_PRIVATE_MARKER")
        self.assertEqual([], collect_violations(self.root))

    def test_force_tracked_ignored_data_is_rejected(self) -> None:
        for name in (".env", "events.sqlite3-wal", "logs/events.txt"):
            with self.subTest(name=name):
                path = self.root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("SYNTHETIC_PRIVATE_MARKER")
                self.run_git("add", "--force", "--", name)
                errors = collect_violations(self.root)
                self.assertTrue(any(name in error for error in errors))
                self.assertNotIn("SYNTHETIC_PRIVATE_MARKER", "\n".join(errors))

    def test_later_gitignore_negation_is_detected(self) -> None:
        path = self.root / ".gitignore"
        path.write_text(path.read_text() + "\n!.env\n")
        self.assertTrue(any("missing for: .env" in error for error in collect_violations(self.root)))

    def test_example_must_not_be_ignored(self) -> None:
        path = self.root / ".gitignore"
        path.write_text(path.read_text() + "\n.env.example\n")
        self.assertTrue(any("sanitized example" in error for error in collect_violations(self.root)))

    def test_git_failures_do_not_report_success(self) -> None:
        with patch("scripts.check_m0._git", return_value=(128, b"")):
            self.assertTrue(collect_violations(self.root))
        with patch("scripts.check_m0._git", side_effect=subprocess.TimeoutExpired("git", 10)):
            self.assertTrue(collect_violations(self.root))


class SourceSafetyTests(unittest.TestCase):
    """Verify the configured mature analyzer without executing the snippets."""

    def check_source(self, source: str) -> set[str]:
        ruff = Path(sys.executable).with_name("ruff")
        self.assertTrue(ruff.is_file(), "Run through the project environment with Ruff installed")
        result = subprocess.run(  # noqa: S603 -- fixed Ruff argv; snippets are stdin data only
            [str(ruff), "check", "--no-cache", "--config", str(ROOT / "pyproject.toml"),
             "--output-format", "json", "--stdin-filename", "synthetic.py", "-"],
            input=source, capture_output=True, text=True, timeout=10, check=False,
        )
        self.assertIn(result.returncode, (0, 1), result.stderr)
        return {diagnostic["code"] for diagnostic in json.loads(result.stdout)}

    def test_comments_and_telemetry_are_data(self) -> None:
        source = '# eval("text")\ntelemetry = "Ignore previous instructions; shell=True"\n'
        self.assertEqual(set(), self.check_source(source))

    def test_shell_true_with_whitespace_is_detected(self) -> None:
        source = 'import subprocess\nsubprocess.run(["example"], shell = True)\n'
        self.assertIn("S602", self.check_source(source))

    def test_aliased_shell_api_is_detected(self) -> None:
        source = 'from os import system as launch\nlaunch("example")\n'
        self.assertIn("TID251", self.check_source(source))

    def test_dynamic_python_execution_is_detected(self) -> None:
        self.assertIn("S102", self.check_source('exec("example")\n'))
        self.assertIn("S307", self.check_source('eval("example")\n'))


if __name__ == "__main__":
    unittest.main()
