"""Explicit one-shot Docker CLI capture. Fixed local endpoint; no automatic invocation."""

from dataclasses import dataclass
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import time

from ..docker_posture.contracts import MAX_CONTAINERS, MAX_INPUT, hex_id, record
from ..investigation.contracts import require, strict_json
from ..model import digest, encode, now
from .docker import project_record

SOCKET = "unix:///run/docker.sock"
API = "1.51"
TOTAL_SECONDS = 45
COMMAND_SECONDS = 8
TOTAL_BYTES = 1024 * 1024
COMMAND_BYTES = 128 * 1024
MAX_COMMANDS = MAX_CONTAINERS + 3
VERSION_FORMAT = '{"version":{{json .Server.Version}},"api":{{json .Server.APIVersion}},"min_api":{{json .Server.MinAPIVersion}},"os":{{json .Server.Os}}}'
# json escapes untrusted values. No entire Config/HostConfig, Env, labels, commands,
# credentials, names, volume driver options or descriptions enter stdout.
INSPECT_FORMAT = (
    '{"Id":{{json .Id}},"Image":{{json .Image}},"Config":{"User":{{json .Config.User}}},'
    '"State":{"Running":{{json .State.Running}}},"HostConfig":{'
    '"Privileged":{{json .HostConfig.Privileged}},"NetworkMode":{{json .HostConfig.NetworkMode}},'
    '"PidMode":{{json .HostConfig.PidMode}},"IpcMode":{{json .HostConfig.IpcMode}},'
    '"UTSMode":{{json .HostConfig.UTSMode}},"UsernsMode":{{json .HostConfig.UsernsMode}},'
    '"CapAdd":{{json .HostConfig.CapAdd}},"CapDrop":{{json .HostConfig.CapDrop}},'
    '"RestartPolicy":{"Name":{{json .HostConfig.RestartPolicy.Name}},'
    '"MaximumRetryCount":{{json .HostConfig.RestartPolicy.MaximumRetryCount}}},'
    '"PortBindings":{{json .HostConfig.PortBindings}}},'
    '"NetworkSettings":{"Ports":{{json .NetworkSettings.Ports}}},'
    '"Mounts":[{{range $i, $m := .Mounts}}{{if $i}},{{end}}'
    '{"Type":{{json $m.Type}},"Source":{{json $m.Source}},'
    '"Destination":{{json $m.Destination}},"RW":{{json $m.RW}}}{{end}}]}'
)


class AcquisitionError(Exception):
    """Fixed code only; raw stderr/exception text must never escape acquisition."""

    def __init__(self, code, *, returncode=None, stderr_present=None):
        super().__init__(code)
        self.returncode = (
            returncode if type(returncode) is int and -128 <= returncode <= 255 else None
        )
        self.stderr_present = stderr_present if type(stderr_present) is bool else None


def argv(config: Path, operation: str, container_id=None) -> tuple[str, ...]:
    prefix = ("/usr/bin/docker", "--config", str(config), "--host", SOCKET)
    if operation == "version":
        suffix = ("version", "--format", VERSION_FORMAT)
    elif operation == "list":
        suffix = ("container", "ls", "--all", "--no-trunc", "--format", "{{.ID}}")
    elif operation == "inspect":
        require(hex_id(container_id), "docker_requires_full_container_id")
        suffix = ("container", "inspect", "--format", INSPECT_FORMAT, container_id)
    else:
        raise AcquisitionError("operation_refused")
    require(operation == "inspect" or container_id is None)
    return prefix + suffix


def environment(config):
    return {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "HOME": str(config),
        "DOCKER_CONFIG": str(config),
        "DOCKER_API_VERSION": API,
        "GOMAXPROCS": "2",
        "GOMEMLIMIT": "128MiB",
    }


@dataclass
class Runner:
    config: Path
    deadline: float
    remaining_bytes: int = TOTAL_BYTES
    calls: int = 0

    def identity(self):
        try:
            info = os.lstat("/run/docker.sock")
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o002:
                raise AcquisitionError("socket_metadata_refused")
            return digest([SOCKET, API, info.st_dev, info.st_ino, info.st_ctime_ns])
        except OSError:
            raise AcquisitionError("socket_unavailable") from None

    def call(self, operation, container_id=None):
        arguments = argv(self.config, operation, container_id)
        self.calls += 1
        if self.calls > MAX_COMMANDS:
            raise AcquisitionError("command_limit")
        deadline = min(self.deadline, time.monotonic() + COMMAND_SECONDS)
        if time.monotonic() >= deadline:
            raise AcquisitionError("timeout")
        try:
            # Only validated registry argv. No inherited Docker context, credentials,
            # loader/proxy variables, stdin, shell or file descriptors.
            with subprocess.Popen(  # noqa: S603 -- fixed registry and full hex ID
                arguments,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                env=environment(self.config),
                cwd=self.config,
            ) as process:
                output, used, stderr_seen = bytearray(), 0, False
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(process.stdout, selectors.EVENT_READ, True)
                        selector.register(process.stderr, selectors.EVENT_READ, False)
                        while selector.get_map():
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                raise AcquisitionError("timeout")
                            for key, _ in selector.select(min(remaining, 0.1)):
                                chunk = os.read(key.fileobj.fileno(), 8192)
                                if not chunk:
                                    selector.unregister(key.fileobj)
                                    continue
                                used += len(chunk)
                                self.remaining_bytes -= len(chunk)
                                if used > COMMAND_BYTES or self.remaining_bytes < 0:
                                    raise AcquisitionError("output_limit")
                                if key.data:
                                    output.extend(chunk)
                                else:
                                    stderr_seen = True
                    rc = process.wait(timeout=max(0.001, deadline - time.monotonic()))
                    if rc or stderr_seen:
                        raise AcquisitionError(
                            "command_failed", returncode=rc, stderr_present=stderr_seen
                        )
                finally:
                    if process.poll() is None:
                        process.kill()  # Only this owned CLI child, never daemon/containers.
                        process.wait(timeout=2)
            return bytes(output)
        except FileNotFoundError:
            raise AcquisitionError("missing_cli") from None
        except subprocess.TimeoutExpired:
            raise AcquisitionError("timeout") from None
        except OSError:
            raise AcquisitionError("access_or_io") from None


def ids(raw):
    require(isinstance(raw, bytes) and len(raw) <= 65 * MAX_CONTAINERS)
    lines = raw.decode("ascii").splitlines()
    require(len(lines) <= MAX_CONTAINERS and len(set(lines)) == len(lines))
    require(all(hex_id(value) for value in lines))
    return sorted(lines)


def version(raw):
    value = strict_json(raw, 4096)
    require(isinstance(value, dict) and value.keys() == {"version", "api", "min_api", "os"})
    require(
        isinstance(value["version"], str)
        and re.fullmatch(
            r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:[-+][A-Za-z0-9.-]{1,32})?", value["version"]
        )
    )
    for name in ("api", "min_api"):
        require(isinstance(value[name], str) and re.fullmatch(r"1\.[0-9]{1,3}", value[name]))
    if value["os"] != "linux" or not int(value["min_api"].split(".")[1]) <= 51 <= int(
        value["api"].split(".")[1]
    ):
        raise AcquisitionError("unsupported_engine")
    return value


def capture(runner: Runner, *, clock=time.monotonic):
    """No synthetic Result conversion or database import: live provenance stays explicit."""
    result = {
        "schema_version": 1,
        "origin": "docker_cli_capture",
        "host_validated": False,
        "started_at": now(),
        "finished_at": None,
        "status": "unavailable",
        "reason": "not_started",
        "source_id": None,
        "engine": None,
        "atomic_snapshot": False,
        "daemon_identity_verified": False,
        "inventory_consistent": False,
        "socket_unchanged": False,
        "containers": {},
        "last_failed_step": None,
        "command_exit_code": None,
        "stderr_present": None,
        "inspect_failures": 0,
    }
    step = "socket_before"
    try:
        source = runner.identity()
        step = "version"
        result["engine"] = version(runner.call("version"))
        result["source_id"] = source
        step = "list_before"
        first = ids(runner.call("list"))
        partial = False
        for key in first:
            step = "inspect"
            if clock() >= runner.deadline:
                raise AcquisitionError("timeout")
            try:
                item = strict_json(runner.call("inspect", key), COMMAND_BYTES)
                require(isinstance(item, dict) and item.get("Id") == key)
                projected = record(project_record(item, deadline=runner.deadline, clock=clock))
                partial |= any(v is None for v in projected.values())
                result["containers"][key] = projected
                require(len(encode(result)) <= MAX_INPUT)
            except AcquisitionError as error:
                if str(error) != "command_failed":
                    raise
                result.update(
                    last_failed_step=step,
                    command_exit_code=error.returncode,
                    stderr_present=error.stderr_present,
                )
                result["inspect_failures"] += 1
                partial = True  # Disappearance/inspect error is never a complete empty record.
        step = "list_after"
        last = ids(runner.call("list"))
        step = "socket_after"
        if runner.identity() != source:
            result["containers"] = {}
            raise AcquisitionError("socket_changed")
        result["socket_unchanged"] = True
        result["inventory_consistent"] = first == last
        partial |= first != last
        result["status"] = "partial" if partial else "ok"
        result["reason"] = "incomplete_or_changed" if partial else "none"
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        result.update(
            status="unavailable", reason="invalid_input", containers={}, last_failed_step=step
        )
    except TimeoutError:
        result.update(
            status="partial" if result["containers"] else "unavailable",
            reason="timeout",
            last_failed_step=step,
        )
    except AcquisitionError as error:
        result.update(
            status="partial" if result["containers"] else "unavailable",
            reason=str(error),
            last_failed_step=step,
            command_exit_code=error.returncode,
            stderr_present=error.stderr_present,
        )
    result["finished_at"] = now()
    if len(encode(result)) > MAX_INPUT:
        result.update(status="unavailable", reason="output_limit", containers={})
    return result
