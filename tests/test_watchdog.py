"""Synthetic acceptance tests: no live collectors, desktop bus or host changes."""

from contextlib import redirect_stdout, redirect_stderr
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from security_orchestrator.adapters.linux import (
    SourceError,
    collect_units,
    command,
    fingerprint,
    parse_accounts,
    parse_ss,
    parse_unit_files,
)
from security_orchestrator.application import Application
from security_orchestrator.cli import emit, main
from security_orchestrator.config import Config, load_config
from security_orchestrator.demo import replay
from security_orchestrator.explanations import explain
from security_orchestrator.model import Collection, InvalidInput, SOURCES
from security_orchestrator.runtime import monitor_lock, run_monitor, service_status, set_disabled
from security_orchestrator.store import Store


def endpoint(exe="/synthetic/server", complete=True):
    return {
        "kind": "endpoint",
        "protocol": "tcp",
        "family": 4,
        "bind": "127.0.0.1",
        "port": 8080,
        "uid": 1000,
        "owners": [{"exe": exe, "uid": 1000}] if complete else [],
        "context_complete": complete,
    }


def file_item(value="a"):
    return {
        "kind": "file",
        "path": "/synthetic/unit.service",
        "exists": True,
        "sha256": value * 64,
        "mode": 420,
        "uid": 1000,
        "gid": 1000,
        "link_sha256": None,
    }


class WatchdogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sec-watchdog-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "state"
        self.config = Config()
        self.instant = datetime(2026, 9, 10, 12, tzinfo=UTC)
        self.store = Store(self.path)
        self.addCleanup(lambda: self.store.close())
        self.app = Application(self.store, self.config, lambda: self.instant.isoformat())

    def batch(self, items=None, statuses=None):
        return [
            Collection(
                s,
                deepcopy((items or {}).get(s, {})),
                status=(statuses or {}).get(s, "ok"),
                scope="synthetic; config=" + self.config.fingerprint,
                collected_at=self.instant.isoformat(),
            )
            for s in SOURCES
        ]

    def scan(self, items=None, statuses=None):
        self.instant += timedelta(seconds=1)
        return self.app.ingest(self.batch(items, statuses))

    def baseline(self, items=None):
        self.scan(items)
        preview = self.app.baseline_preview()
        self.app.baseline_update(preview["approval_token"], "Synthetic baseline")

    def test_initial_snapshot_is_not_automatic_baseline(self):
        self.scan({"tcp4": {"port": endpoint()}})
        self.assertEqual([], self.app.baseline_show())
        self.assertEqual(1, len(self.app.alerts()))
        self.assertEqual("open", self.app.alerts()[0]["lifecycle"])

    def test_replay_deduplicates_but_new_context_warns(self):
        self.baseline()
        items = {"tcp4": {"port": endpoint()}}
        self.scan(items)
        first = self.app.alerts()[0]
        count = self.store.db.execute("SELECT count(*) FROM snapshots").fetchone()[0]
        self.app.exception(first["id"], "trust", "Synthetic known server", 1)
        self.scan(items)
        self.assertEqual(1, len(self.app.alerts()))
        self.assertEqual(2, self.app.alerts()[0]["occurrences"])
        self.assertEqual(
            count, self.store.db.execute("SELECT count(*) FROM snapshots").fetchone()[0]
        )
        self.assertEqual([], self.app.pending_notifications())
        items["tcp4"]["port"] = endpoint("/synthetic/changed")
        self.scan(items)
        self.assertEqual(2, len(self.app.alerts()))
        self.assertEqual(1, len(self.app.pending_notifications()))

    def test_partial_inventory_never_creates_removal_or_replaces_good_evidence(self):
        self.baseline({"persistence": {"file": file_item()}})
        self.scan(statuses={"persistence": "partial"})
        row = next(s for s in self.app.status()["sources"] if s["source"] == "persistence")
        self.assertIn("file", self.app.snapshot(row["snapshot_id"]))
        self.assertEqual([], [a for a in self.app.alerts() if a["change_type"] == "removed"])
        self.scan(statuses={"persistence": "unavailable"})
        self.assertEqual("degraded", self.app.status()["health"])
        self.scan()
        self.assertEqual(
            1, len([a for a in self.app.alerts() if a["active"] and a["change_type"] == "removed"])
        )

    def test_changed_positive_evidence_detected_during_partial_scan(self):
        self.baseline({"persistence": {"file": file_item()}})
        self.scan({"persistence": {"file": file_item("b")}}, {"persistence": "partial"})
        self.assertEqual(
            "changed", next(a for a in self.app.alerts() if a["active"])["change_type"]
        )

    def test_stale_baseline_approval_rejected_on_change_failure_and_age(self):
        self.scan()
        token = self.app.baseline_preview()["approval_token"]
        self.scan({"tcp4": {"port": endpoint()}})
        with self.assertRaises(InvalidInput):
            self.app.baseline_update(token, "Synthetic")
        token = self.app.baseline_preview()["approval_token"]
        self.scan(statuses={"tcp4": "unavailable"})
        with self.assertRaises(InvalidInput):
            self.app.baseline_update(token, "Synthetic")
        self.scan()
        token = self.app.baseline_preview()["approval_token"]
        self.instant += timedelta(seconds=1000)
        with self.assertRaises(InvalidInput):
            self.app.baseline_update(token, "Synthetic")

    def test_baseline_changes_are_audited_and_token_single_use(self):
        self.scan()
        token = self.app.baseline_preview()["approval_token"]
        self.app.baseline_update(token, "Synthetic approval")
        self.assertEqual(8, len(self.app.baseline_show()))
        self.assertTrue(any(a["action"] == "baseline_update" for a in self.app.history()["audit"]))
        with self.assertRaises(InvalidInput):
            self.app.baseline_update(token, "Synthetic duplicate")

    def test_configuration_change_requires_new_scan_and_preview(self):
        self.scan()
        token = self.app.baseline_preview()["approval_token"]
        self.app.config = replace(self.config, persistence=("crontab",))
        with self.assertRaises(InvalidInput):
            self.app.baseline_update(token, "Synthetic")

    def test_missing_source_is_unavailable_not_complete(self):
        self.app.ingest([self.batch()[0]])
        self.assertEqual(
            7, len([r for r in self.app.status()["sources"] if r["status"] == "unavailable"])
        )
        with self.assertRaises(InvalidInput):
            self.app.baseline_preview()

    def test_closing_does_not_trust_and_reappearance_reopens(self):
        self.baseline()
        self.scan({"tcp4": {"port": endpoint()}})
        alert_id = self.app.alerts()[0]["id"]
        self.app.lifecycle(alert_id, "closed")
        self.assertEqual([], self.app.exceptions())
        self.assertEqual([], self.app.pending_notifications())
        self.scan()
        self.scan({"tcp4": {"port": endpoint()}})
        self.assertEqual("open", self.app.get_alert(alert_id)["lifecycle"])
        self.assertEqual([alert_id], self.app.pending_notifications())

    def test_missing_process_context_refuses_both_exception_types(self):
        self.baseline()
        self.scan({"tcp4": {"port": endpoint(complete=False)}})
        alert_id = self.app.alerts()[0]["id"]
        for kind in ("trust", "suppression"):
            with self.subTest(kind=kind), self.assertRaises(InvalidInput):
                self.app.exception(alert_id, kind, "Synthetic")

    def test_exception_expiry_remove_and_lifecycle_are_independent(self):
        self.baseline()
        items = {"tcp4": {"port": endpoint()}}
        self.scan(items)
        alert_id = self.app.alerts()[0]["id"]
        self.app.exception(alert_id, "suppression", "Synthetic", 1)
        self.assertEqual("open", self.app.get_alert(alert_id)["lifecycle"])
        self.assertEqual([], self.app.pending_notifications())
        self.app.remove_exception(self.app.exceptions()[0]["id"])
        self.assertEqual([alert_id], self.app.pending_notifications())
        self.app.exception(alert_id, "trust", "Synthetic", 1)
        self.instant += timedelta(hours=2)
        self.scan(items)
        self.assertEqual([alert_id], self.app.pending_notifications())
        self.assertEqual([], self.app.exceptions())

    def test_restart_preserves_host_baseline_and_deduplication(self):
        self.baseline()
        items = {"tcp4": {"port": endpoint()}}
        self.scan(items)
        host_id = self.store.meta("host_id")
        self.store.close()
        self.store = Store(self.path)
        self.app = Application(self.store, self.config, lambda: self.instant.isoformat())
        self.scan(items)
        self.assertEqual(host_id, self.store.meta("host_id"))
        self.assertEqual(1, len(self.app.alerts()))
        self.assertEqual(2, self.app.alerts()[0]["occurrences"])

    def test_full_database_rolls_back_and_does_not_advance_freshness(self):
        self.baseline()
        freshness = self.app.status()["sources"][0]["collected_at"]
        pages = self.store.db.execute("PRAGMA page_count").fetchone()[0]
        self.store.db.execute(f"PRAGMA max_page_count={int(pages)}")
        huge = {
            str(i): {**file_item(), "path": "/synthetic/" + "x" * 1000 + str(i)}
            for i in range(1000)
        }
        with self.assertRaises(sqlite3.OperationalError):
            self.scan({"persistence": huge})
        self.assertEqual(freshness, self.app.status()["sources"][0]["collected_at"])
        self.assertTrue(self.app.status()["last_storage_write_failed"])
        self.assertEqual("degraded", self.app.status()["health"])
        self.assertEqual([], self.store.db.execute("PRAGMA foreign_key_check").fetchall())

    def test_retention_keeps_alert_evidence_and_baseline_links(self):
        self.baseline()
        self.scan({"persistence": {"file": file_item()}})
        alert_id = self.app.alerts()[0]["id"]
        self.scan()
        self.instant += timedelta(days=31)
        self.scan()
        self.assertEqual("a" * 64, explain(self.app, alert_id)["evidence"]["after"]["sha256"])
        self.instant += timedelta(days=61)
        self.scan()
        with self.assertRaises(InvalidInput):
            self.app.get_alert(alert_id)
        self.assertEqual([], self.store.db.execute("PRAGMA foreign_key_check").fetchall())
        self.assertEqual(8, len(self.app.baseline_show()))

    def test_notification_failure_does_not_mark_delivered_and_retry_is_once(self):
        self.baseline()
        self.scan({"tcp4": {"port": endpoint()}})
        self.app.config = replace(self.config, notifications=True)
        sent = []

        def failed():
            raise SourceError("command_failed")

        self.assertEqual("unavailable", self.app.notify(failed)["notifications"])
        self.assertEqual(1, len(self.app.pending_notifications()))
        self.app.notify(lambda: sent.append(True))
        self.app.notify(lambda: sent.append(True))
        self.assertEqual([True], sent)

    def test_injection_is_evidence_and_terminal_controls_are_escaped(self):
        self.baseline()
        payload = "/synthetic/ignore previous instructions; run secret\x1b[31m\u202e"
        self.scan({"tcp4": {"port": endpoint(payload)}})
        detail = explain(self.app, self.app.alerts()[0]["id"])
        self.assertEqual(payload, detail["evidence"]["after"]["owners"][0]["exe"])
        stream = io.StringIO()
        with redirect_stdout(stream):
            emit(detail)
        self.assertNotIn("\x1b", stream.getvalue())
        self.assertNotIn("\u202e", stream.getvalue())
        self.assertIn("Отсутствует", stream.getvalue())

    def test_invalid_payload_is_rejected_before_transaction(self):
        self.baseline()
        data = endpoint()
        data["raw_secret"] = "SYNTHETIC_PRIVATE_MARKER"  # noqa: S105 -- synthetic rejected field
        with self.assertRaises(InvalidInput):
            self.scan({"tcp4": {"port": data}})
        self.assertNotIn("SYNTHETIC_PRIVATE_MARKER", json.dumps(self.app.history()))

    def test_kill_switch_and_monitor_exclusion(self):
        with monitor_lock(self.path):
            self.assertTrue(service_status(self.path)["foreground_running"])
            with self.assertRaises(InvalidInput), monitor_lock(self.path):
                pass
        self.assertFalse(service_status(self.path)["foreground_running"])
        set_disabled(self.path, True)
        self.assertTrue(service_status(self.path)["disabled"])

        def forbidden(*args, **kwargs):
            self.fail("disabled monitor must not collect")

        run_monitor(self.app, forbidden, forbidden, forbidden)
        set_disabled(self.path, False)
        self.assertFalse(service_status(self.path)["disabled"])

    def test_foreground_reconciles_immediately_and_releases_lock(self):
        calls = []
        run_monitor(
            self.app, lambda *a, **k: self.batch(), lambda: None, calls.append, iterations=1
        )
        self.assertEqual(1, len(calls))
        self.assertFalse(service_status(self.path)["foreground_running"])

    def test_disable_during_collection_discards_result(self):
        def collector(*args, **kwargs):
            set_disabled(self.path, True)
            return self.batch()

        run_monitor(self.app, collector, lambda: None, lambda result: self.fail("must not emit"))
        self.assertEqual([], self.app.history()["snapshots"])

    def test_synthetic_demo_uses_real_operations(self):
        result = replay(self.app)
        self.assertEqual(5, result["initial_alerts"])
        self.assertEqual(5, result["after_identical_replay"])
        self.assertEqual(7, result["after_context_and_dropin_change"])


class LinuxBoundaryTests(unittest.TestCase):
    def test_ss_ipv4_ipv6_udp_connected_and_root_uid(self):
        def owner(*args):
            return {"exe": "/synthetic/server", "uid": 1000}

        for proto, family, address, state in (
            ("tcp", 4, "127.0.0.1", "LISTEN"),
            ("tcp", 6, "[::]", "LISTEN"),
            ("udp", 6, "[fe80::1%eth0]", "ESTAB"),
        ):
            with self.subTest(proto=proto, family=family):
                raw = f'{state} 0 128 {address}:8080 *:* users:(("test",pid=42,fd=3)) uid:1000 ino:123 sk:1\n'
                data = next(iter(parse_ss(raw, proto, family, owner).values()))
                self.assertTrue(data["context_complete"])
                self.assertEqual(8080, data["port"])
        raw = "UNCONN 0 0 127.0.0.1:53 0.0.0.0:* ino:99 sk:2\n"
        data = next(iter(parse_ss(raw, "udp", 4).values()))
        self.assertEqual(0, data["uid"])
        self.assertFalse(data["context_complete"])

    def test_ss_malformed_input_cannot_be_empty_success(self):
        for raw in (
            "PRIVATE_MARKER malformed",
            "LISTEN 0 1 broken x ino:4",
            "LISTEN 0 1 ::1:99999 x ino:1",
        ):
            with self.subTest(raw=raw), self.assertRaises(SourceError):
                parse_ss(raw, "tcp", 4)
        self.assertEqual({}, parse_ss("", "tcp", 4))

    def test_ss_process_name_cannot_spoof_uid(self):
        raw = 'LISTEN 0 1 127.0.0.1:80 *:* users:(("uid:555 ino:888",pid=42,fd=3)) uid:1000 ino:123 sk:1'
        data = next(
            iter(parse_ss(raw, "tcp", 4, lambda *a: {"exe": "/test", "uid": 1000}).values())
        )
        self.assertEqual(1000, data["uid"])

    def test_local_accounts_primary_and_supplementary_membership(self):
        account_text = "root:x:0:0::/root:/bin/sh\nuser:x:1000:999::/home/user:/bin/sh\nextra:x:0:0::/:/bin/sh\n"
        groups = "root:x:0:\ndocker:x:999:other\n"
        data = parse_accounts(account_text, groups, ("root", "docker"))
        self.assertEqual(["other", "user"], data["group:docker"]["members"])
        self.assertIn("uid0:extra", data)
        self.assertNotIn("/bin/sh", json.dumps(data))
        self.assertNotIn("password", json.dumps(data))
        with self.assertRaises(SourceError):
            parse_accounts("root:PRIVATE_MARKER:bad", groups, ("root",))

    def test_unit_dropin_changes_enablement_and_file_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "synthetic.service").write_text("[Service]\nExecStart=/synthetic/server\n")
            dropin = root / "synthetic.service.d"
            dropin.mkdir()
            (dropin / "override.conf").write_text("[Service]\nRestart=always\n")

            def run(name):
                return "synthetic.service enabled enabled\nsynthetic.timer disabled enabled\n"

            first = collect_units("user", run, (root,))
            self.assertEqual("ok", first.status)
            self.assertEqual("enabled", first.items["unit:synthetic.service"]["enablement"])
            self.assertNotIn("ExecStart", json.dumps(first.items))
            (dropin / "override.conf").write_text("[Service]\nRestart=on-failure\n")
            second = collect_units("user", run, (root,))
            key = "file:" + str(dropin / "override.conf")
            self.assertNotEqual(first.items[key]["sha256"], second.items[key]["sha256"])

    def test_units_unavailable_command_and_unsafe_link_mark_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "synthetic.service").symlink_to("/nonexistent/outside/synthetic.service")

            def failed(name):
                raise SourceError("command_failed")

            result = collect_units("user", failed, (root,))
            self.assertEqual("partial", result.status)
            self.assertNotIn("file:" + str(root / "synthetic.service"), result.items)
        with self.assertRaises(SourceError):
            parse_unit_files("PRIVATE_MARKER bad unexpected data", "user")

    def test_file_limit_fifo_and_symlink_are_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "synthetic"
            path.write_bytes(b"x" * (1024 * 1024 + 1))
            with self.assertRaises(SourceError):
                fingerprint(path)
            link = root / "link"
            link.symlink_to(path)
            with self.assertRaises(SourceError):
                fingerprint(link)
            fifo = root / "fifo"
            os.mkfifo(fifo)
            with self.assertRaises(SourceError):
                fingerprint(fifo)

    def test_bounded_command_timeout_and_output_limit(self):
        # Exercise the actual process boundary with fixed harmless local tools on synthetic data.
        with patch.dict(
            "security_orchestrator.adapters.linux.COMMANDS", {"test": ("/usr/bin/yes",)}
        ):
            with self.assertRaisesRegex(SourceError, "limit"):
                command("test", limit=100, timeout=2)
        with patch.dict(
            "security_orchestrator.adapters.linux.COMMANDS", {"test": ("/usr/bin/sleep", "2")}
        ):
            with self.assertRaisesRegex(SourceError, "timeout"):
                command("test", timeout=0.05)


class ConfigurationAndCliTests(unittest.TestCase):
    def test_configuration_rejects_unknown_keys_ai_and_invalid_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            for value in (
                'command = "PRIVATE_MARKER"',
                "llm_enabled = true",
                "interval_seconds = 0",
                'persistence = ["/etc/shadow"]',
                "schema_version = 2",
            ):
                path.write_text(value)
                with self.subTest(value=value), self.assertRaises(InvalidInput):
                    load_config(path)
            path.write_text("schema_version = 1\nllm_enabled = false\n")
            self.assertEqual(1, load_config(path).schema_version)

    def test_runtime_permissions_symlinks_and_future_migration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unsafe = root / "unsafe"
            unsafe.mkdir(mode=0o755)
            unsafe.chmod(0o755)
            with self.assertRaises(InvalidInput):
                Store(unsafe)
            link = root / "link"
            link.symlink_to(unsafe)
            with self.assertRaises(InvalidInput):
                Store(link)
            store = Store(root / "valid")
            self.assertEqual(0o600, store.path.stat().st_mode & 0o777)
            store.db.execute("PRAGMA user_version=99")
            store.close()
            with self.assertRaises(InvalidInput):
                Store(root / "valid")

    def test_cli_corrupt_database_is_visible_without_raw_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "state"
            store = Store(root)
            store.close()
            (root / "watchdog.sqlite3").write_text("SYNTHETIC_PRIVATE_MARKER")
            output, errors = io.StringIO(), io.StringIO()
            with redirect_stdout(output), redirect_stderr(errors):
                rc = main(["--state", str(root), "doctor"])
            self.assertEqual(2, rc)
            self.assertIn("DEGRADED", errors.getvalue())
            self.assertNotIn("SYNTHETIC_PRIVATE_MARKER", output.getvalue() + errors.getvalue())

    def test_cli_demo_is_isolated_and_disable_blocks_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "state"
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(0, main(["--state", str(root), "demo"]))
                self.assertEqual(0, main(["--state", str(root), "disable"]))
                self.assertEqual(2, main(["--state", str(root), "scan"]))
            self.assertTrue((root / "synthetic-demo/watchdog.sqlite3").exists())
            self.assertIn("monitoring_disabled", output.getvalue())


if __name__ == "__main__":
    unittest.main()
