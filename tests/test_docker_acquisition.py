"""Prepared live boundary tested only with synthetic responses and mocked process/OS access."""

from contextlib import redirect_stdout
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
from security_orchestrator.docker_posture.scenarios import CONTAINER, container
from security_orchestrator.model import InvalidInput, encode

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
