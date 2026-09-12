"""Reviewable one-shot capture operation, kept outside synthetic databases and the UI."""

import os
from pathlib import Path
import time

from ..adapters import docker_acquire as adapter
from ..investigation.contracts import require
from ..model import digest, encode
from ..store import private_directory


def plan(output: Path):
    output = output.absolute()
    client = output / "client-config"
    modules = (
        Path(adapter.__file__),
        Path(__file__),
        Path(adapter.__file__).with_name("docker.py"),
        Path(__file__).with_name("contracts.py"),
    )
    payload = {
        "schema_version": 1,
        "operation": "docker_one_shot_capture",
        "network_scope": adapter.SOCKET,
        "output_directory": str(output),
        "code_fingerprint": digest([p.read_text() for p in modules]),
        "argv": {name: adapter.argv(client, name) for name in ("version", "list")},
        "inspect_argv_example": adapter.argv(client, "inspect", "a" * 64),
        "inspect_id_policy": "Один фактический полный hex ID из первого списка вместо example ID; максимум 32.",
        "sequence": "socket metadata → version → list → inspect каждого ID → list → socket metadata",
        "environment": adapter.environment(client),
        "limits": {
            "seconds_total": adapter.TOTAL_SECONDS,
            "seconds_per_command": adapter.COMMAND_SECONDS,
            "bytes_total": adapter.TOTAL_BYTES,
            "bytes_per_command": adapter.COMMAND_BYTES,
            "commands_max": adapter.MAX_COMMANDS,
            "output_bytes_max": adapter.MAX_INPUT,
        },
        "writes": [str(output / "capture.json"), str(client)],
        "warning": "Read-only команды не ограничивают полномочия rootful socket. Это одноразовое чтение с правами текущего пользователя, без sudo; отдельный sandbox worker не создан.",
        "coverage": "Списки сверяются, но snapshot не атомарный. Неизменный socket не доказывает identity daemon. Env/labels/names/argv не выводятся и не сохраняются; raw API inspect всё ещё обрабатывает сам Docker CLI в памяти.",
    }
    return payload | {"approval_token": digest(payload)}


def run(output: Path, approval: str, *, runner_factory=adapter.Runner):
    reviewed = plan(output)
    require(approval == reviewed["approval_token"], "docker_capture_requires_exact_plan_approval")
    require(os.getuid() != 0, "docker_capture_refuses_root")
    output = output.absolute()
    require(not any(p.is_symlink() for p in (output, *output.parents)), "runtime_symlink_refused")
    require(not output.exists(), "docker_capture_requires_new_directory")
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output.mkdir(mode=0o700)  # Exclusive; concurrent/repeated captures cannot overwrite evidence.
    private_directory(output)
    client = private_directory(output / "client-config")
    runner = runner_factory(client, time.monotonic() + adapter.TOTAL_SECONDS)
    result = adapter.capture(runner)
    result["approval_token"] = approval
    raw = encode(result).encode()
    require(len(raw) <= adapter.MAX_INPUT, "docker_capture_output_limit")
    # Publish a complete artifact only. Partial tmp on write failure is not a valid capture.
    temporary = output / "capture.pending"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, output / "capture.json")
    fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    # Transport prints fixed summary only. Capture remains local for owner review.
    return {
        "origin": result["origin"],
        "host_validated": False,
        "status": result["status"],
        "reason": result["reason"],
        "last_failed_step": result["last_failed_step"],
        "command_exit_code": result["command_exit_code"],
        "stderr_present": result["stderr_present"],
        "inspect_failures": result["inspect_failures"],
        "containers": len(result["containers"]),
        "capture": str(output / "capture.json"),
        "capture_sha256": digest(result),
        "database_imported": False,
    }
