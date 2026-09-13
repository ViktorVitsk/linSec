"""Prepared live boundary tested only with synthetic responses and mocked process/OS access."""

from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from security_orchestrator.adapters import docker_acquire as adapter
from security_orchestrator.cli import main
from security_orchestrator.docker_posture.acquisition import plan, run
from security_orchestrator.docker_posture.review import read_capture, review, validate
from security_orchestrator.docker_posture.scenarios import CONTAINER, container
from security_orchestrator.model import InvalidInput, digest, encode

VERSION = {"version": "28.3.3", "api": "1.51", "min_api": "1.24", "os": "linux"}


class FakeRunner:
    def __init__(self, config=None, deadline=None):
        self.deadline = deadline or time.monotonic() + 45
        self.records = {CONTAINER: container()}
        self.lists = [[CONTAINER], [CONTAINER]]
        self.identities = ["b" * 64, "b" * 64]
        self.version = VERSION.copy()
        self.calls = []
        self.error = None

    def identity(self):
        return self.identities.pop(0)

    def call(self, name, key=None):
        self.calls.append((name, key))
        if self.error:
            raise adapter.AcquisitionError(self.error)
        if name == "version":
            return encode(self.version).encode()
        if name == "list":
            return (
                ("\n".join(self.lists.pop(0)) + "\n").encode() if self.lists[0] else self._empty()
            )
        record = self.records[key]
        if isinstance(record, Exception):
            raise record
        return encode(record).encode()

    def _empty(self):
        self.lists.pop(0)
        return b""


class CaptureTests(unittest.TestCase):
    def test_version_template_selects_go_fields_not_json_tags(self):
        # Docker CLI versionInfo.Server is *types.Version, not a JSON-key map.
        # Source: docker/cli v28.3.3 cli/command/system/version.go, APIVersion field.
        server = SimpleNamespace(
            Version="28.3.3", APIVersion="1.51", MinAPIVersion="1.24", Os="linux"
        )

        def render_selector(match):
            return json.dumps(getattr(server, match[1]))

        rendered = re.sub(
            r"\{\{json \.Server\.([A-Za-z]+)\}\}", render_selector, adapter.VERSION_FORMAT
        )
        self.assertEqual(adapter.version(rendered.encode()), VERSION)
        self.assertFalse(hasattr(server, "ApiVersion"))

    def test_complete_projected_capture_is_not_synthetic_or_host_acceptance(self):
        runner = FakeRunner()
        result = adapter.capture(runner)
        self.assertEqual((result["status"], result["origin"]), ("ok", "docker_cli_capture"))
        self.assertFalse(result["host_validated"])
        self.assertFalse(result["daemon_identity_verified"])
        self.assertFalse(result["atomic_snapshot"])
        self.assertTrue(result["socket_unchanged"])
        self.assertTrue(result["inventory_consistent"])
        self.assertNotIn("synthetic-value-never-export", encode(result))
        self.assertNotIn("ignore previous instructions", encode(result))
        self.assertNotIn("Name", encode(result))
        self.assertEqual([x[0] for x in runner.calls], ["version", "list", "inspect", "list"])

    def test_changed_lists_or_disappearance_are_partial(self):
        for disappeared in (False, True):
            runner = FakeRunner()
            if disappeared:
                runner.records[CONTAINER] = adapter.AcquisitionError("command_failed")
            else:
                runner.lists[1] = []
            result = adapter.capture(runner)
            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["reason"], "incomplete_or_changed")

    def test_empty_inventory_does_not_inspect(self):
        runner = FakeRunner()
        runner.lists = [[], []]
        result = adapter.capture(runner)
        self.assertEqual((result["status"], result["containers"]), ("ok", {}))
        self.assertEqual([x[0] for x in runner.calls], ["version", "list", "list"])

    def test_socket_replacement_discards_mixed_evidence(self):
        runner = FakeRunner()
        runner.identities[-1] = "c" * 64
        result = adapter.capture(runner)
        self.assertEqual(
            (result["status"], result["reason"], result["containers"]),
            ("unavailable", "socket_changed", {}),
        )

    def test_missing_field_stays_unknown_with_positive_evidence(self):
        runner = FakeRunner()
        runner.records[CONTAINER]["HostConfig"]["Privileged"] = True
        del runner.records[CONTAINER]["Config"]["User"]
        result = adapter.capture(runner)
        self.assertEqual(result["status"], "partial")
        self.assertTrue(result["containers"][CONTAINER]["privileged"])
        self.assertIsNone(result["containers"][CONTAINER]["user"])

    def test_wrong_id_and_oversized_inventory_never_become_complete(self):
        runner = FakeRunner()
        runner.records[CONTAINER]["Id"] = "d" * 64
        self.assertEqual(adapter.capture(runner)["reason"], "invalid_input")
        for raw in (b"--help\n", b"a" * 65, (CONTAINER + "\n").encode() * 2, b"\xff", b"x" * 2146):
            with self.assertRaises(ValueError):
                adapter.ids(raw)

    def test_unsupported_version_and_os_stop_before_list(self):
        for change in (
            {"api": "1.50"},
            {"min_api": "1.52"},
            {"os": "windows"},
            {"version": "\x1b[31msecret"},
        ):
            runner = FakeRunner()
            runner.version.update(change)
            result = adapter.capture(runner)
            self.assertEqual(result["status"], "unavailable")
            self.assertEqual(len(runner.calls), 1)
            self.assertNotIn("secret", encode(result))

    def test_failures_are_fixed_and_timeout_keeps_only_positive_evidence(self):
        runner = FakeRunner()
        runner.error = "access_or_io"
        result = adapter.capture(runner)
        self.assertEqual(result["reason"], "access_or_io")
        self.assertEqual(result["last_failed_step"], "version")
        runner = FakeRunner()
        result = adapter.capture(runner, clock=lambda: runner.deadline + 1)
        self.assertEqual((result["status"], result["reason"]), ("unavailable", "timeout"))
        self.assertEqual(len(runner.calls), 2)

    def test_command_registry_and_environment_cannot_select_arbitrary_daemon_or_code(self):
        config = Path("/synthetic/empty-config")
        for name in ("version", "list", "inspect"):
            args = adapter.argv(config, name, CONTAINER if name == "inspect" else None)
            self.assertEqual(
                args[:5],
                ("/usr/bin/docker", "--config", str(config), "--host", "unix:///run/docker.sock"),
            )
        for command in ("info", "run", "exec", "pull", "start", "rm"):
            with self.assertRaises(adapter.AcquisitionError):
                adapter.argv(config, command)
        with self.assertRaises(ValueError):
            adapter.argv(config, "inspect", "--help")
        with patch.dict(
            os.environ,
            {"DOCKER_HOST": "tcp://evil.invalid", "LD_PRELOAD": "secret", "DOCKER_CONTEXT": "evil"},
        ):
            env = adapter.environment(config)
        self.assertEqual(env["HOME"], str(config))
        self.assertEqual(env["DOCKER_API_VERSION"], "1.51")
        self.assertFalse(
            {"DOCKER_HOST", "DOCKER_CONTEXT", "LD_PRELOAD", "HTTP_PROXY", "SSH_AUTH_SOCK"}
            & env.keys()
        )
        for field in (
            ".Config.Env",
            ".Config.Labels",
            ".Config.Cmd",
            "{{json .Name}}",
            "{{json .Config}}",
            "{{json .HostConfig}}",
        ):
            self.assertNotIn(field, adapter.INSPECT_FORMAT)


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / "capture"

    def test_preview_and_wrong_token_do_not_touch_docker_or_create_output(self):
        with (
            patch.object(adapter, "Runner", side_effect=AssertionError("no runner")),
            patch.object(adapter.os, "lstat", side_effect=AssertionError("no socket metadata")),
        ):
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(main(["docker-acquire", "--output", str(self.output)]), 0)
            reviewed = json.loads(out.getvalue())
            self.assertEqual(len(reviewed["approval_token"]), 64)
            with self.assertRaises(InvalidInput):
                run(self.output, "wrong")
        self.assertFalse(self.output.exists())

    def test_approval_binds_path_code_and_limits(self):
        original = plan(self.output)["approval_token"]
        self.assertNotEqual(original, plan(self.output / "other")["approval_token"])
        with patch.object(adapter, "TOTAL_SECONDS", 46):
            self.assertNotEqual(original, plan(self.output)["approval_token"])

    def test_root_and_existing_output_refused_before_capture(self):
        token = plan(self.output)["approval_token"]
        with patch("os.getuid", return_value=0), self.assertRaises(InvalidInput):
            run(self.output, token)
        self.assertFalse(self.output.exists())
        self.output.mkdir()
        with self.assertRaises(InvalidInput):
            run(self.output, token)

    def test_approved_fake_capture_is_private_minimized_and_not_imported(self):
        token = plan(self.output)["approval_token"]
        result = run(self.output, token, runner_factory=FakeRunner)
        self.assertEqual(result["status"], "ok")
        self.assertFalse(result["database_imported"])
        artifact = self.output / "capture.json"
        raw = artifact.read_bytes()
        self.assertNotIn(b"synthetic-value-never-export", raw)
        self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        self.assertFalse(list(self.output.glob("*.sqlite3")))
        self.assertFalse((self.output / "capture.pending").exists())
        self.assertEqual(json.loads(raw)["approval_token"], token)
        with self.assertRaises(InvalidInput):
            run(self.output, token, runner_factory=FakeRunner)

    def test_socket_metadata_rejects_leaf_symlink_nonroot_or_world_writable(self):
        runner = adapter.Runner(self.output, time.monotonic() + 10)
        for mode, uid in (
            (stat.S_IFLNK | 0o777, 0),
            (stat.S_IFSOCK | 0o660, 1000),
            (stat.S_IFSOCK | 0o666, 0),
        ):
            info = SimpleNamespace(st_mode=mode, st_uid=uid)
            with (
                patch.object(adapter.os, "lstat", return_value=info),
                self.assertRaises(adapter.AcquisitionError),
            ):
                runner.identity()


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "capture.json"
        self.value = adapter.capture(FakeRunner()) | {"approval_token": "e" * 64}

    def save(self, value=None, raw=None):
        if raw is None:
            raw = encode(self.value if value is None else value).encode()
        self.path.write_bytes(raw)
        self.path.chmod(0o600)
        return hashlib.sha256(raw).hexdigest()

    def test_review_matches_shared_rules_without_exposing_object_metadata_or_mutations(self):
        from security_orchestrator.docker_posture.detection import posture

        sha = self.save()
        before = self.path.read_bytes()
        with (
            patch.object(adapter.subprocess, "Popen", side_effect=AssertionError("no process")),
            patch.object(adapter.Runner, "identity", side_effect=AssertionError("no socket")),
        ):
            result = review(self.path, sha)
            out = io.StringIO()
            state = self.path.parent / "unused-state"
            with redirect_stdout(out):
                rc = main([
                    "--state", str(state), "docker-review", "--capture", str(self.path),
                    "--sha256", sha,
                ])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out.getvalue()), result)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertFalse(state.exists())
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])
        self.assertEqual(
            {f["rule"] for f in result["findings"]},
            {rule for rule, _ in posture(self.value["containers"][CONTAINER])},
        )
        self.assertTrue(result["artifact_valid"])
        self.assertFalse(result["host_validated"])
        self.assertFalse(result["database_imported"])
        self.assertNotIn(CONTAINER, encode(result))
        self.assertNotIn("source_ref", encode(result))
        self.assertNotIn("approval_token", result)
        self.assertEqual(sha, digest(self.value))

    def test_failed_partial_empty_and_socket_changed_artifacts_remain_honest(self):
        for scenario in ("failed", "unknown", "disappeared", "changed", "socket", "empty", "timeout"):
            with self.subTest(scenario=scenario):
                runner = FakeRunner()
                if scenario == "failed":
                    runner.error = "command_failed"
                elif scenario == "unknown":
                    del runner.records[CONTAINER]["Config"]["User"]
                elif scenario == "disappeared":
                    runner.records[CONTAINER] = adapter.AcquisitionError(
                        "command_failed", returncode=1, stderr_present=True
                    )
                elif scenario == "changed":
                    runner.lists[-1] = []
                elif scenario == "socket":
                    runner.identities[-1] = "d" * 64
                elif scenario == "empty":
                    runner.lists = [[], []]
                elif scenario == "timeout":
                    runner.error = "timeout"
                value = adapter.capture(runner) | {"approval_token": "e" * 64}
                sha = self.save(value)
                result = review(self.path, sha)
                self.assertTrue(result["artifact_valid"])
                self.assertEqual(result["status"], value["status"])
                self.assertFalse(result["host_validated"])
                if scenario == "unknown":
                    self.assertEqual(result["unknown_fields"], {"user": 1})
                if scenario == "disappeared":
                    self.assertEqual(result["inspect_failures"], 1)
                    self.assertEqual(result["command_exit_code"], 1)
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(
                        main(["docker-review", "--capture", str(self.path), "--sha256", sha]),
                        0 if scenario == "empty" else 2,
                    )

    def test_contradictory_or_unminimized_capture_is_rejected_even_with_matching_hash(self):
        changes = [
            {"Env": ["synthetic-private-value"]}, {"schema_version": True},
            {"origin": "synthetic"}, {"host_validated": True}, {"atomic_snapshot": True},
            {"daemon_identity_verified": True}, {"source_id": None}, {"engine": None},
            {"inventory_consistent": False}, {"socket_unchanged": False},
            {"status": "unavailable", "reason": "timeout"}, {"reason": "synthetic-private-value"},
            {"inspect_failures": True}, {"inspect_failures": 1},
            {"last_failed_step": "synthetic-private-value"}, {"command_exit_code": True},
            {"stderr_present": "synthetic-private-value"}, {"approval_token": "bad"},
            {"finished_at": "2000-01-01T00:00:00+00:00"},
            {"started_at": "2026-09-13T12:00:00+03:00"},
            {"status": "partial", "reason": "incomplete_or_changed"},
        ]
        values = [self.value | change for change in changes]
        for field, content in (("privileged", None), ("Env", ["synthetic-private-value"]), ("user", [])):
            value = deepcopy(self.value)
            value["containers"][CONTAINER][field] = content
            values.append(value)
        value = deepcopy(self.value)
        value["engine"]["api"] = "1.50"
        values.append(value)
        for value in values:
            with self.subTest(change=value.keys()):
                with self.assertRaisesRegex(InvalidInput, "invalid_docker_capture_contents_omitted"):
                    read_capture(self.path, self.save(value))

    def test_duplicate_keys_noncanonical_json_and_resource_limits_are_rejected(self):
        for raw in (
            b'{"origin":"docker_cli_capture","origin":"synthetic-private-value"}',
            b"[" * 1000 + b"]" * 1000,
            json.dumps(self.value, indent=2).encode(),
            b"x" * (adapter.MAX_INPUT + 1),
        ):
            with self.assertRaises(InvalidInput):
                read_capture(self.path, self.save(raw=raw))
        with self.assertRaises(InvalidInput):
            validate(self.value | {"containers": {f"{i:064x}": self.value["containers"][CONTAINER] for i in range(33)}})

    def test_hash_mismatch_refuses_replaced_evidence_without_reflecting_contents(self):
        sha = self.save()
        self.save(self.value | {"reason": "synthetic-private-value"})
        out = io.StringIO()
        with redirect_stdout(out):
            rc = main(["docker-review", "--capture", str(self.path), "--sha256", sha])
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(out.getvalue()), {"error": "docker_capture_sha256_mismatch"})
        with patch("os.open", side_effect=AssertionError("no file read")), self.assertRaises(InvalidInput):
            read_capture(self.path, "bad")

    def test_symlink_hardlink_fifo_and_nonprivate_artifacts_are_refused(self):
        sha = self.save()
        self.path.chmod(0o644)
        with self.assertRaises(InvalidInput):
            read_capture(self.path, sha)
        self.path.chmod(0o600)
        for kind in ("symlink", "hardlink", "fifo", "directory"):
            target = self.path.parent / kind
            if kind == "symlink":
                target.symlink_to(self.path)
            elif kind == "hardlink":
                target.hardlink_to(self.path)
            elif kind == "fifo":
                os.mkfifo(target, 0o600)
            else:
                target.mkdir(mode=0o700)
            with self.assertRaises(InvalidInput):
                read_capture(target, sha)
            if kind == "directory":
                target.rmdir()
            else:
                target.unlink()
        self.path.parent.chmod(0o755)
        with self.assertRaises(InvalidInput):
            read_capture(self.path, sha)
        self.path.parent.chmod(0o700)

    def test_details_keep_stopped_and_unknown_states_separate_from_posture(self):
        runner = FakeRunner()
        raw = runner.records[CONTAINER]
        raw["Config"]["User"] = "0"
        raw["HostConfig"]["PortBindings"] = {
            "80/tcp": [{"HostIp": "192.0.2.10", "HostPort": "8080"}]
        }
        value = adapter.capture(runner) | {"approval_token": "e" * 64}
        value.update(status="partial", reason="incomplete_or_changed")
        running = deepcopy(value["containers"][CONTAINER])
        running["running"] = True
        unknown = deepcopy(running)
        unknown["running"] = None
        value["containers"].update({"c" * 64: running, "d" * 64: unknown})
        sha = self.save(value)
        summary = review(self.path, sha)
        result = review(self.path, sha, details=True)
        self.assertEqual(result["container_states"], {"running": 1, "stopped": 1, "unknown": 1})
        self.assertEqual(result["containers_with_findings"], 3)
        self.assertNotIn("container_details", summary)
        self.assertNotIn(CONTAINER, encode(summary))
        self.assertNotIn("192.0.2.10", encode(summary))
        self.assertEqual(
            [(item["container_id"], item["state"]) for item in result["container_details"]],
            [(CONTAINER, "stopped"), ("c" * 64, "running"), ("d" * 64, "unknown")],
        )
        for item in result["container_details"]:
            by_rule = {finding["rule"]: finding for finding in item["findings"]}
            self.assertEqual(set(by_rule), {"publication", "root_user"})
            publication = by_rule["publication"]["evidence"]
            self.assertEqual(publication.keys(), {"configured_ports"})
            self.assertEqual(publication["configured_ports"][0]["ip"], "192.0.2.10")
            self.assertEqual(item["unknown_fields"], ["running"] if item["state"] == "unknown" else [])
        self.assertFalse(result["host_validated"])

    def test_detail_cli_minimizes_mount_references_and_cannot_collect_or_modify(self):
        runner = FakeRunner()
        raw = runner.records[CONTAINER]
        raw["Mounts"] = [
            {"Type": "bind", "Source": source, "Destination": target, "RW": True}
            for source, target in (("/etc/synthetic-a", "/mount-a"), ("/etc/synthetic-b", "/mount-b"))
        ]
        raw["Config"]["User"] = "root"
        raw["HostConfig"].update(Privileged=True, PidMode="host", CapAdd=["SYS_ADMIN"])
        self.value = adapter.capture(runner) | {"approval_token": "e" * 64}
        sha = self.save()
        before = self.path.read_bytes()
        with (
            patch.object(adapter.subprocess, "Popen", side_effect=AssertionError("no process")),
            patch.object(adapter.Runner, "identity", side_effect=AssertionError("no socket")),
        ):
            result = review(self.path, sha, details=True)
            out = io.StringIO()
            with redirect_stdout(out):
                rc = main([
                    "docker-review", "--capture", str(self.path), "--sha256", sha, "--details",
                ])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out.getvalue()), result)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])
        self.assertFalse(result["database_imported"])
        findings = {item["rule"]: item for item in result["container_details"][0]["findings"]}
        self.assertEqual(findings["sensitive_mount"]["evidence"], {
            "mounts": [{"class": "system", "type": "bind", "rw": True}] * 2,
        })
        self.assertEqual(findings["host_namespace"]["evidence"], {"pid": "host"})
        self.assertEqual(findings["privileged"]["evidence"], {"privileged": True})
        for forbidden in (
            "source_ref", "target_ref", "image", "approval_token", "source_id", "Config",
            "synthetic-value-never-export", "ignore previous instructions", "/etc/synthetic-a",
        ):
            self.assertNotIn(forbidden, encode(result))
        for mount in self.value["containers"][CONTAINER]["mounts"]:
            self.assertNotIn(mount["source_ref"], encode(result))
            self.assertNotIn(mount["target_ref"], encode(result))

    def test_details_empty_and_unavailable_never_claim_host_validation(self):
        for failed in (False, True):
            runner = FakeRunner()
            runner.lists = [[], []]
            runner.error = "timeout" if failed else None
            sha = self.save(adapter.capture(runner) | {"approval_token": "e" * 64})
            result = review(self.path, sha, details=True)
            self.assertEqual(result["container_details"], [])
            self.assertEqual(result["container_states"], {"running": 0, "stopped": 0, "unknown": 0})
            self.assertFalse(result["host_validated"])
            self.assertEqual(result["status"], "unavailable" if failed else "ok")

    def test_detail_options_and_hostile_file_fail_before_any_evidence_output(self):
        with patch("os.open", side_effect=AssertionError("no file read")), self.assertRaises(InvalidInput):
            review(self.path, "e" * 64, details="true")
        value = deepcopy(self.value)
        value["containers"][CONTAINER]["user"] = "synthetic-private-value"
        sha = self.save(value)
        out = io.StringIO()
        with redirect_stdout(out):
            rc = main([
                "docker-review", "--capture", str(self.path), "--sha256", sha, "--details",
            ])
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(out.getvalue()), {"error": "invalid_docker_capture_contents_omitted"})

    def test_details_cover_full_inventory_and_distinguish_configured_from_observed_bindings(self):
        runner = FakeRunner()
        raw = runner.records[CONTAINER]
        raw["State"]["Running"] = True
        raw["HostConfig"]["PortBindings"] = {
            "80/tcp": [{"HostIp": "192.0.2.1", "HostPort": "8080"}]
        }
        raw["NetworkSettings"]["Ports"] = {
            "80/tcp": [{"HostIp": "2001:db8::1", "HostPort": "8081"}]
        }
        value = adapter.capture(runner) | {"approval_token": "e" * 64}
        item = value["containers"][CONTAINER]
        value["containers"] = {f"{i:064x}": deepcopy(item) for i in range(32)}
        result = review(self.path, self.save(value), details=True)
        self.assertEqual(len(result["container_details"]), 32)
        self.assertEqual(result["container_states"], {"running": 32, "stopped": 0, "unknown": 0})
        for item in result["container_details"]:
            findings = {finding["rule"]: finding for finding in item["findings"]}
            ports = findings["publication"]["evidence"]
            self.assertEqual(ports["configured_ports"][0]["host_port"], 8080)
            self.assertEqual(ports["observed_ports"][0]["host_port"], 8081)
        self.assertLessEqual(len(encode(result)), 2 * adapter.MAX_INPUT)


class ProcessTests(unittest.TestCase):
    def test_bounded_runner_drains_stderr_kills_owned_process_and_never_reflects_it(self):
        class Stream:
            def __init__(self, fd):
                self.fd = fd

            def fileno(self):
                return self.fd

        class Process:
            stdout, stderr = Stream(20), Stream(21)
            killed = False

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def poll(self):
                return 0 if self.killed else None

            def kill(self):
                self.killed = True

            def wait(self, **kwargs):
                return 0

        class Selector:
            def __init__(self):
                self.keys = {}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def register(self, stream, events, data):
                self.keys[stream] = SimpleNamespace(fileobj=stream, data=data)

            def unregister(self, stream):
                del self.keys[stream]

            def get_map(self):
                return self.keys

            def select(self, timeout):
                return [(key, 1) for key in self.keys.values()]

        for payload, expected in (
            (b"synthetic-private-stderr", "command_failed"),
            (b"x" * (adapter.COMMAND_BYTES + 1), "output_limit"),
        ):
            process = Process()
            chunks = {20: [b"{}", b""], 21: [payload, b""]}
            runner = adapter.Runner(Path("/synthetic"), time.monotonic() + 10)
            with (
                patch.object(adapter.subprocess, "Popen", return_value=process) as popen,
                patch.object(adapter.selectors, "DefaultSelector", Selector),
                patch.object(
                    adapter.os, "read", side_effect=lambda fd, n, data=chunks: data[fd].pop(0)
                ),
            ):
                with self.assertRaises(adapter.AcquisitionError) as caught:
                    runner.call("version")
                self.assertEqual(str(caught.exception), expected)
                if expected == "command_failed":
                    self.assertEqual(caught.exception.returncode, 0)
                    self.assertTrue(caught.exception.stderr_present)
                self.assertTrue(process.killed)
                self.assertFalse(popen.call_args.kwargs["shell"])
                self.assertTrue(popen.call_args.kwargs["close_fds"])

    def test_timeout_and_command_budget_do_not_start_process(self):
        runner = adapter.Runner(Path("/synthetic"), time.monotonic() - 1)
        with patch.object(
            adapter.subprocess, "Popen", side_effect=AssertionError("must not start")
        ):
            with self.assertRaises(adapter.AcquisitionError):
                runner.call("version")
            runner.calls = adapter.MAX_COMMANDS
            with self.assertRaises(adapter.AcquisitionError):
                runner.call("version")


if __name__ == "__main__":
    unittest.main()
