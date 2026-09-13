"""M3 synthetic acceptance: no Docker, host collectors, browser listener or inference."""

from dataclasses import asdict, replace
import unittest

from security_orchestrator.adapters.docker import parse_synthetic
from security_orchestrator.docker_posture.contracts import MAX_INPUT, record
from security_orchestrator.docker_posture.detection import posture
from docker_fixtures import CONTAINER, SOURCE, batch, container
from security_orchestrator.model import encode

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


if __name__ == "__main__":
    unittest.main()
