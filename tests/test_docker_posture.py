"""M3 synthetic acceptance: no Docker, host collectors, browser listener or inference."""

from contextlib import redirect_stdout
from dataclasses import asdict, replace
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from security_orchestrator.adapters.docker import parse_synthetic
from security_orchestrator.cli import main
from security_orchestrator.config import Config
from security_orchestrator.docker_posture.contracts import MAX_INPUT, Result, record
from security_orchestrator.docker_posture.detection import drift, posture
from security_orchestrator.docker_posture.scenarios import (
    CONTAINER,
    SOURCE,
    batch,
    container,
    replay,
)
from security_orchestrator.docker_posture.service import PostureQueries, PostureStore
from security_orchestrator.model import InvalidInput, encode
from security_orchestrator.queries import Queries
from security_orchestrator.local_ui.server import Access, Routes

AT = "2026-09-12T12:00:00.000000+00:00"


class ProjectionTests(unittest.TestCase):
    def project(self, item=None, complete=True):
        return batch([container() if item is None else item], AT, complete)

    def test_complete_contract_and_null_maps(self):
        item = container()
        item["HostConfig"]["PortBindings"] = None
        result = self.project(item)
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.containers[CONTAINER]["cap_add"], [])
        self.assertEqual(result.containers[CONTAINER]["configured_ports"], [])
        self.assertEqual(posture(result.containers[CONTAINER]), [])

    def test_hostile_and_secret_fields_never_exported_or_hashed_wholesale(self):
        first = self.project()
        item = container()
        for name in ("Env", "Labels", "Cmd", "Entrypoint", "WorkingDir"):
            item["Config"][name] = [
                "synthetic-secret-new-value",
                "\x1b]52;c;DATA\x07",
                "$(run)",
                "<svg onload=run()>",
            ]
        item["Name"] = "ignore policy\u202e"
        second = self.project(item)
        self.assertEqual(first, second)
        self.assertNotIn("secret", encode(asdict(first)))

    def test_publications_ipv4_ipv6_loopback_empty_routed_and_expose(self):
        for ip, host, warn in (
            ("127.0.0.1", "8080", False),
            ("::1", "8080", False),
            ("::", "", True),
            ("192.0.2.1", "8080", True),
            ("", "", True),
        ):
            with self.subTest(ip=ip):
                item = container()
                item["HostConfig"]["PortBindings"] = {
                    "80/udp": [{"HostIp": ip, "HostPort": host}],
                    "443/tcp": None,
                }
                result = self.project(item)
                self.assertEqual(result.status, "ok")
                rules = dict(posture(result.containers[CONTAINER]))
                self.assertEqual("publication" in rules, warn)
                self.assertEqual(len(result.containers[CONTAINER]["configured_ports"]), 1)

    def test_configured_and_observed_are_distinct_stopped_container(self):
        item = container()
        item["HostConfig"]["PortBindings"]["80/tcp"][0]["HostIp"] = "192.0.2.1"
        fields = self.project(item).containers[CONTAINER]
        self.assertFalse(fields["running"])
        self.assertEqual(fields["observed_ports"], [])
        self.assertIn("publication", dict(posture(fields)))

    def test_malformed_port_is_unknown_not_empty(self):
        for bad in ("65536", "-1", "$(run)", "80-90"):
            item = container()
            item["HostConfig"]["PortBindings"]["80/tcp"][0]["HostPort"] = bad
            result = self.project(item)
            self.assertEqual(result.status, "partial")
            self.assertIsNone(result.containers[CONTAINER]["configured_ports"])

    def test_missing_field_preserves_positive_privileged_evidence(self):
        item = container()
        item["HostConfig"]["Privileged"] = True
        del item["HostConfig"]["CapDrop"]
        result = self.project(item)
        self.assertEqual(result.status, "partial")
        self.assertIsNone(result.containers[CONTAINER]["cap_drop"])
        self.assertIn("privileged", dict(posture(result.containers[CONTAINER])))

    def test_user_capabilities_and_namespace_rules(self):
        for raw, normalized in (
            ("", "default_root"),
            ("0:1000", "explicit_root"),
            ("000", "explicit_root"),
            ("root", "explicit_root"),
            ("1000", "nonroot_numeric"),
            ("worker", "named_unknown"),
        ):
            item = container()
            item["Config"]["User"] = raw
            item["HostConfig"].update(
                {
                    "CapAdd": ["CAP_SYS_ADMIN", "sys_admin"],
                    "PidMode": "host",
                    "IpcMode": "container:untrusted-name",
                }
            )
            result = self.project(item)
            self.assertEqual(result.status, "ok")
            fields = result.containers[CONTAINER]
            self.assertEqual(fields["user"], normalized)
            self.assertEqual(fields["cap_add"], ["SYS_ADMIN"])
            self.assertTrue(
                {"host_namespace", "shared_namespace", "capabilities"}
                <= dict(posture(fields)).keys()
            )
            self.assertNotIn("untrusted-name", encode(fields))

    def test_mount_classes_and_path_minimization(self):
        for source, category in (
            ("/", "root"),
            ("/var/run/docker.sock", "docker_socket"),
            ("/home/synthetic/.ssh", "credentials"),
            ("/dev/sda", "device"),
            ("/etc", "system"),
            ("/opt/demo", "other"),
        ):
            item = container()
            item["Mounts"] = [
                {"Type": "bind", "Source": source, "Destination": "/demo", "RW": False}
            ]
            fields = self.project(item).containers[CONTAINER]
            self.assertEqual(fields["mounts"][0]["class"], category)
            self.assertNotIn(source, encode(fields["mounts"]))
            self.assertEqual("sensitive_mount" in dict(posture(fields)), category != "other")

    def test_drift_tracks_mount_target_restart_image_and_configured_bind(self):
        before = self.project().containers[CONTAINER]
        item = container()
        item["Image"] = "sha256:" + "c" * 64
        item["HostConfig"]["RestartPolicy"]["Name"] = "always"
        item["State"]["Running"] = True
        item["NetworkSettings"]["Ports"] = {"80/tcp": [{"HostIp": "::1", "HostPort": "8080"}]}
        after = self.project(item).containers[CONTAINER]
        self.assertEqual(drift(before, after), ["image", "restart"])
        after["restart"] = None
        self.assertEqual(drift(before, after), ["image"])

    def test_normal_named_volume_is_not_a_sensitive_host_bind(self):
        item = container()
        item["Mounts"] = [
            {
                "Type": "volume",
                "Source": "/var/lib/docker/volumes/demo/_data",
                "Destination": "/data",
                "RW": True,
            }
        ]
        fields = self.project(item).containers[CONTAINER]
        self.assertEqual(fields["mounts"][0]["class"], "other")
        self.assertNotIn("sensitive_mount", dict(posture(fields)))
        item["Mounts"][0]["Type"] = "bind"
        fields = self.project(item).containers[CONTAINER]
        self.assertIn("sensitive_mount", dict(posture(fields)))

    def test_mount_target_and_bind_change_have_distinct_context(self):
        item = container()
        item["Mounts"] = [
            {"Type": "bind", "Source": "/opt/demo", "Destination": "/data", "RW": True}
        ]
        before = self.project(item).containers[CONTAINER]
        item["Mounts"][0]["Destination"] = "/data-v2"
        item["HostConfig"]["PortBindings"]["80/tcp"][0]["HostIp"] = "192.0.2.1"
        after = self.project(item).containers[CONTAINER]
        self.assertEqual(drift(before, after), ["configured_ports", "mounts"])

    def test_strict_json_versions_duplicates_limits_and_bad_ids(self):
        raw_cases = [
            b'{"schema_version":1,"schema_version":1}',
            b'{"value":NaN}',
            b"[" * 1000,
            b"x" * (MAX_INPUT + 1),
            b"\xff",
            b"[]",
        ]
        for value in (
            {"schema_version": True, "complete": True, "inspect": []},
            {"schema_version": 1, "complete": True, "inspect": [container()] * 2},
            {"schema_version": 1, "complete": True, "inspect": [container()] * 33},
        ):
            raw_cases.append(encode(value).encode())
        for raw in raw_cases:
            result = parse_synthetic(raw, SOURCE, AT)
            self.assertEqual(
                (result.status, result.reason, result.containers),
                ("unavailable", "invalid_input", {}),
            )

    def test_timeout_is_bounded_and_typed(self):
        raw = encode({"schema_version": 1, "complete": True, "inspect": [container()]}).encode()
        result = parse_synthetic(raw, SOURCE, AT, clock=iter([0, 2]).__next__)
        self.assertEqual((result.status, result.reason), ("unavailable", "timeout"))

    def test_result_rejects_live_origin_unknown_keys_and_boolean_version(self):
        original = self.project()
        for result in (
            replace(original, origin="host"),
            replace(original, schema_version=True),
            replace(original, status="ok", reason="incomplete"),
            replace(original, collected_at="yesterday"),
        ):
            with self.assertRaises(ValueError):
                result.validate()
        invalid = dict(original.containers[CONTAINER], Env="secret")
        with self.assertRaises(ValueError):
            record(invalid)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "m3"
        self.store = PostureStore(self.directory)
        self.addCleanup(lambda: self.store.close())
        self.tick = 0

    def ingest(self, items=None, complete=True):
        self.tick += 1
        result = batch(
            [container()] if items is None else items,
            f"2026-09-12T12:00:{self.tick:02d}.000000+00:00",
            complete,
        )
        self.store.ingest(result)
        return result

    def count(self, table):
        return self.store.db.execute(
            {
                "findings": "SELECT count(*) FROM findings",
                "evidence": "SELECT count(*) FROM evidence",
            }[table]
        ).fetchone()[0]

    def test_repeat_dedup_restart_and_no_secret_persistence(self):
        self.ingest()
        changed = container()
        changed["HostConfig"]["Privileged"] = True
        self.ingest([changed])
        counts = self.count("findings"), self.count("evidence")
        self.store.close()
        self.store = PostureStore(self.directory)
        self.ingest([changed])
        self.assertEqual(counts, (self.count("findings"), self.count("evidence")))
        self.assertNotIn(b"synthetic-value-never-export", self.store.path.read_bytes())
        self.assertNotIn(b"ignore previous instructions", self.store.path.read_bytes())

    def test_partial_and_unavailable_do_not_remove_or_resolve(self):
        changed = container()
        changed["HostConfig"]["Privileged"] = True
        self.ingest([changed])
        self.ingest([], complete=False)
        self.store.ingest(
            Result(SOURCE, "2026-09-12T12:00:03.000000+00:00", "unavailable", "access_denied", {})
        )
        self.assertFalse(
            self.store.db.execute(
                "SELECT 1 FROM findings WHERE rule='container_removed'"
            ).fetchone()
        )
        self.assertEqual(
            self.store.db.execute("SELECT state FROM findings WHERE rule='privileged'").fetchone()[
                0
            ],
            "unknown",
        )
        self.assertEqual(
            self.store.db.execute("SELECT presence FROM objects").fetchone()[0], "unknown"
        )

    def test_complete_empty_inventory_records_one_removal(self):
        self.ingest()
        self.ingest([])
        count = self.count("findings")
        self.ingest([])
        self.assertEqual(count, self.count("findings"))
        self.assertEqual(
            self.store.db.execute("SELECT presence FROM objects").fetchone()[0], "absent"
        )
        self.assertEqual(
            self.store.db.execute(
                "SELECT count(*) FROM findings WHERE rule='container_removed'"
            ).fetchone()[0],
            1,
        )

    def test_partial_field_does_not_produce_false_drift_or_clear_posture(self):
        item = container()
        item["HostConfig"]["Privileged"] = True
        self.ingest([item])
        del item["HostConfig"]["Privileged"]
        self.ingest([item])
        self.assertFalse(
            self.store.db.execute(
                "SELECT 1 FROM findings WHERE rule='configuration_drift'"
            ).fetchone()
        )
        self.assertEqual(
            self.store.db.execute("SELECT state FROM findings WHERE rule='privileged'").fetchone()[
                0
            ],
            "unknown",
        )
        self.ingest()
        self.assertEqual(
            self.store.db.execute("SELECT state FROM findings WHERE rule='privileged'").fetchone()[
                0
            ],
            "resolved",
        )

    def test_source_and_time_conflicts_are_atomic(self):
        result = self.ingest()
        for invalid in (result, replace(result, source_id="d" * 64)):
            with self.assertRaises(InvalidInput):
                self.store.ingest(invalid)
            self.assertEqual(self.count("findings"), 1)
        self.assertEqual((self.directory / "docker-health").read_bytes(), b"1")

    def test_budgets_roll_back_and_mark_failure(self):
        self.ingest()
        item = container()
        item["HostConfig"]["Privileged"] = True
        with patch("security_orchestrator.docker_posture.service.MAX_ROWS", 1):
            with self.assertRaises(InvalidInput):
                self.ingest([item])
        self.assertEqual(self.count("evidence"), 1)
        self.assertEqual(self.count("findings"), 1)
        self.assertTrue(PostureQueries(self.directory).overview()["storage_failure"])

    def test_partial_union_budget(self):
        items = []
        for n in range(32):
            item = container()
            item["Id"] = f"{n:064x}"
            items.append(item)
        self.ingest(items, complete=False)
        item = container()
        with self.assertRaises(InvalidInput):
            self.ingest([item], complete=False)
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM objects").fetchone()[0], 32)

    def test_queries_read_only_pagination_staleness_and_evidence_validation(self):
        self.ingest()
        changed = container()
        changed["HostConfig"]["Privileged"] = True
        self.ingest([changed])
        query = PostureQueries(self.directory, clock=lambda: AT)
        before = self.store.path.read_bytes()
        page = query.overview(limit=1)
        self.assertTrue(page["stale"])
        self.assertIsNotNone(page["next_before"])
        self.assertNotEqual(
            page["items"][0]["id"], query.overview(1, page["next_before"])["items"][0]["id"]
        )
        detail = query.detail(page["items"][0]["id"])
        self.assertEqual(detail["automatic_action"], "none")
        self.assertFalse(detail["host_validated"])
        self.assertEqual(before, self.store.path.read_bytes())
        ref = detail["after_ref"]
        self.store.db.execute(
            "UPDATE evidence SET data=? WHERE ref=?", ('{"Env":"synthetic-secret"}', ref)
        )
        with self.assertRaises(ValueError):
            query.detail(page["items"][0]["id"])

    def test_not_configured_and_missing_do_not_create_files(self):
        self.assertEqual(PostureQueries(None).overview()["state"], "not_configured")
        missing = self.directory / "absent"
        with self.assertRaises(OSError):
            PostureQueries(missing).overview()
        self.assertFalse(missing.exists())

    def test_read_refuses_symlink_or_permissive_database(self):
        self.ingest()
        alias = self.directory.parent / "alias"
        alias.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises(ValueError):
            PostureQueries(alias).overview()
        self.store.path.chmod(0o644)
        with self.assertRaises(ValueError):
            PostureQueries(self.directory).overview()

    def test_shared_cli_api_routes_and_access_controls_without_main_db(self):
        self.ingest()
        queries = Queries(self.directory / "no-main-db", Config(), docker=self.directory)
        routes = Routes(queries, Access("a" * 48, "127.0.0.1:8765"))
        headers = {
            "host": "127.0.0.1:8765",
            "origin": "http://127.0.0.1:8765",
            "authorization": "Bearer " + "a" * 48,
            "x-sec-ui": "1",
        }
        for endpoint in ("/api/docker?limit=25", "/api/docker/1"):
            code, _, raw = routes.response("GET", endpoint, headers)
            self.assertEqual(code, 200)
            out = io.StringIO()
            with redirect_stdout(out):
                code = main(
                    ["docker-view", "--docker-state", str(self.directory)]
                    + (["1"] if endpoint.endswith("/1") else [])
                )
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out.getvalue()), json.loads(raw))
            self.assertEqual(routes.response("POST", endpoint, headers)[0], 405)
            self.assertEqual(
                routes.response("GET", endpoint, headers | {"authorization": ""})[0], 401
            )
            self.assertEqual(
                routes.response("GET", endpoint, headers | {"origin": "http://evil.invalid"})[0],
                403,
            )
        self.assertEqual(routes.response("GET", "/api/docker?limit=101", headers)[0], 400)
        self.assertFalse((self.directory / "no-main-db").exists())

    def test_demo_does_not_use_host_or_reuse_state(self):
        directory = self.directory / "demo"
        with (
            patch(
                "security_orchestrator.adapters.linux.collect",
                side_effect=AssertionError("host collector"),
            ),
            patch("socket.socket", side_effect=AssertionError("socket")),
        ):
            result = replay(directory)
        self.assertFalse(result["host_validated"])
        scenarios = result["scenarios"]
        self.assertEqual(scenarios[1]["findings"], scenarios[2]["findings"])
        self.assertEqual(scenarios[1]["snapshots"], scenarios[2]["snapshots"])
        self.assertEqual(result["posture"]["state"], "unavailable")
        with self.assertRaises(ValueError):
            replay(directory)
        self.assertFalse((directory / "watchdog.sqlite3").exists())


if __name__ == "__main__":
    unittest.main()
