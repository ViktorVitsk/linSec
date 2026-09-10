"""Regression tests for the repository-level M0 safety gate."""

import unittest

from scripts.check_m0 import ROOT, _forbidden_local_file, collect_violations


class M0SafetyTests(unittest.TestCase):
    def test_repository_safety_gate_is_clean(self) -> None:
        self.assertEqual([], collect_violations())

    def test_uv_project_metadata_is_present(self) -> None:
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("[dependency-groups]", pyproject)
        self.assertIn('"ruff",', pyproject)
        self.assertIn("package = false", pyproject)
        self.assertEqual("3.10", (ROOT / ".python-version").read_text(encoding="utf-8").strip())

    def test_runtime_and_secret_names_are_rejected(self) -> None:
        self.assertTrue(_forbidden_local_file(ROOT / ".env"))
        self.assertTrue(_forbidden_local_file(ROOT / ".env.local"))
        self.assertTrue(_forbidden_local_file(ROOT / "state" / "events.sqlite3"))
        self.assertFalse(_forbidden_local_file(ROOT / ".env.example"))

    def test_firewall_plan_keeps_snapshot_fail_closed(self) -> None:
        plan = (ROOT / "docs/operations/HOST_FIREWALL_HARDENING_PLAN.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("bounded_run", plan)
        self.assertIn("atomic rename", plan)
        self.assertNotIn("iptables-save | sudo -- tee /var/backups/security-orchestrator-fw-m1", plan)
        audit = (ROOT / "docs/audit/INITIAL_SECURITY_AUDIT.md").read_text(encoding="utf-8")
        self.assertIn("Исторические рекомендации первоначального inventory", audit)


if __name__ == "__main__":
    unittest.main()
