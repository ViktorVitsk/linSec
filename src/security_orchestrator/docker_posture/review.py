"""Offline, bounded review of minimized captures; no acquisition or database admission."""

from datetime import datetime
import hashlib
import os
from pathlib import Path
import stat

from ..adapters.docker_acquire import version
from ..investigation.contracts import integer, require, strict_json
from ..model import InvalidInput, encode
from .contracts import MAX_CONTAINERS, MAX_INPUT, hex_id, instant, record
from .detection import RULES, posture

FIELDS = {
    "schema_version", "origin", "host_validated", "started_at", "finished_at",
    "status", "reason", "source_id", "engine", "atomic_snapshot",
    "daemon_identity_verified", "inventory_consistent", "socket_unchanged",
    "containers", "last_failed_step", "command_exit_code", "stderr_present",
    "inspect_failures", "approval_token",
}
REASONS = {
    "none", "incomplete_or_changed", "invalid_input", "timeout", "output_limit",
    "socket_metadata_refused", "socket_unavailable", "socket_changed",
    "unsupported_engine", "command_limit", "command_failed", "missing_cli", "access_or_io",
}
STEPS = {"socket_before", "version", "list_before", "inspect", "list_after", "socket_after"}


def validate(value):
    """Reject untrusted fields and contradictory completeness before computing findings."""
    try:
        require(isinstance(value, dict) and value.keys() == FIELDS)
        require(type(value["schema_version"]) is int and value["schema_version"] == 1)
        require(value["origin"] == "docker_cli_capture")
        for key in ("host_validated", "atomic_snapshot", "daemon_identity_verified"):
            require(value[key] is False)
        for key in ("inventory_consistent", "socket_unchanged"):
            require(type(value[key]) is bool)
        start, end = (instant(value[key]) for key in ("started_at", "finished_at"))
        require(datetime.fromisoformat(start) <= datetime.fromisoformat(end))
        require(hex_id(value["approval_token"]))
        require(value["source_id"] is None or hex_id(value["source_id"]))
        if value["engine"] is not None:
            version(encode(value["engine"]).encode())
        require(value["status"] in ("ok", "partial", "unavailable"))
        require(value["reason"] in REASONS)
        require((value["status"] == "ok") == (value["reason"] == "none"))
        require(value["last_failed_step"] is None or value["last_failed_step"] in STEPS)
        require(value["command_exit_code"] is None or integer(value["command_exit_code"], -128, 255))
        require(value["stderr_present"] is None or type(value["stderr_present"]) is bool)
        require(integer(value["inspect_failures"], 0, MAX_CONTAINERS))
        containers = value["containers"]
        require(isinstance(containers, dict) and len(containers) <= MAX_CONTAINERS)
        require(len(containers) + value["inspect_failures"] <= MAX_CONTAINERS)
        require(value["status"] != "unavailable" or not containers)
        for key, item in containers.items():
            require(hex_id(key))
            record(item)
        if value["status"] != "unavailable":
            require(value["source_id"] is not None and value["engine"] is not None)
        if value["inventory_consistent"]:
            require(value["socket_unchanged"])
        if value["status"] == "ok":
            require(value["inventory_consistent"] and value["socket_unchanged"])
            require(value["inspect_failures"] == 0 and value["last_failed_step"] is None)
            require(value["command_exit_code"] is None and value["stderr_present"] is None)
            require(all(field is not None for item in containers.values() for field in item.values()))
        elif value["reason"] == "incomplete_or_changed":
            require(value["status"] == "partial" and value["socket_unchanged"])
            require(
                not value["inventory_consistent"] or value["inspect_failures"] > 0
                or any(field is None for item in containers.values() for field in item.values())
            )
        if value["reason"] == "socket_changed":
            require(value["status"] == "unavailable" and not value["socket_unchanged"])
        require(len(encode(value)) <= MAX_INPUT)
    except Exception:
        # Contract helpers and API parsing may throw several types; never reflect evidence.
        raise InvalidInput("invalid_docker_capture_contents_omitted") from None
    return value


def read_capture(path: Path, expected_sha256: str):
    require(hex_id(expected_sha256), "docker_review_requires_capture_sha256")
    path = path.absolute()
    try:
        require(not any(p.is_symlink() for p in (path, *path.parents)))
        directory = path.parent.stat()
        require(
            stat.S_ISDIR(directory.st_mode) and directory.st_uid == os.getuid()
            and not directory.st_mode & 0o077
        )
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            require(
                stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and not before.st_mode & 0o077 and before.st_nlink == 1
                and 0 < before.st_size <= MAX_INPUT
            )
            raw = stream.read(MAX_INPUT + 1)
            after = os.fstat(stream.fileno())
            require(
                (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                and len(raw) == before.st_size
            )
    except (OSError, ValueError):
        raise InvalidInput("docker_capture_file_refused") from None
    require(hashlib.sha256(raw).hexdigest() == expected_sha256, "docker_capture_sha256_mismatch")
    try:
        value = validate(strict_json(raw, MAX_INPUT))
        # The writer's digest is SHA-256 of these exact canonical bytes.
        require(raw == encode(value).encode())
    except (ValueError, TypeError, RecursionError):
        raise InvalidInput("invalid_docker_capture_contents_omitted") from None
    return value


def review(path: Path, expected_sha256: str):
    value = read_capture(path, expected_sha256)
    counts, unknown, affected = {}, {}, 0
    for item in value["containers"].values():
        findings = posture(item)
        affected += bool(findings)
        for rule, _ in findings:
            counts[rule] = counts.get(rule, 0) + 1
        for field, content in item.items():
            if content is None:
                unknown[field] = unknown.get(field, 0) + 1
    # Aggregate only: no container IDs, IPs, ports, mount hashes or untrusted text.
    return {
        "schema_version": 1,
        "origin": "docker_cli_capture",
        "capture_sha256": expected_sha256,
        "artifact_valid": True,
        "host_validated": False,
        "database_imported": False,
        "started_at": value["started_at"],
        "finished_at": value["finished_at"],
        "engine": value["engine"],
        "status": value["status"],
        "reason": value["reason"],
        "inventory_consistent": value["inventory_consistent"],
        "socket_unchanged": value["socket_unchanged"],
        "atomic_snapshot": False,
        "daemon_identity_verified": False,
        "last_failed_step": value["last_failed_step"],
        "command_exit_code": value["command_exit_code"],
        "stderr_present": value["stderr_present"],
        "inspect_failures": value["inspect_failures"],
        "containers": len(value["containers"]),
        "containers_with_findings": affected,
        "unknown_fields": dict(sorted(unknown.items())),
        "findings": [
            {"rule": rule, "containers": count, "severity": RULES[rule][0], "explanation": RULES[rule][1]}
            for rule, count in sorted(counts.items())
        ],
        "limitations": [
            "Проверен сохранённый артефакт, а не текущее состояние Docker или безопасность хоста.",
            "SHA-256 сверяет файл с указанным digest; это не подпись и не доказательство происхождения.",
            "Partial/unavailable и неизвестные поля не означают отсутствие риска. Пропуски не восстановлены.",
            "Host acceptance, нагрузку CLI и соответствие конфигурации проверяет владелец отдельно.",
        ],
    }
