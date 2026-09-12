"""Versioned minimized Docker evidence, independent of watchdog and AI schemas."""

from dataclasses import asdict, dataclass
from datetime import datetime
import ipaddress
import re

from ..investigation.contracts import integer, require
from ..model import encode

VERSION = 1
MAX_CONTAINERS = 32
MAX_ENTRIES = 32
MAX_INPUT = 256 * 1024
MAX_RECORD = 32 * 1024
FIELDS = {
    "image",
    "running",
    "privileged",
    "network",
    "pid",
    "ipc",
    "uts",
    "userns",
    "mounts",
    "cap_add",
    "cap_drop",
    "user",
    "restart",
    "configured_ports",
    "observed_ports",
}
CAPS = set(
    "ALL AUDIT_CONTROL AUDIT_READ AUDIT_WRITE BLOCK_SUSPEND BPF CHECKPOINT_RESTORE CHOWN DAC_OVERRIDE DAC_READ_SEARCH FOWNER FSETID IPC_LOCK IPC_OWNER KILL LEASE LINUX_IMMUTABLE MAC_ADMIN MAC_OVERRIDE MKNOD NET_ADMIN NET_BIND_SERVICE NET_BROADCAST NET_RAW PERFMON SETFCAP SETGID SETPCAP SETUID SYS_ADMIN SYS_BOOT SYS_CHROOT SYS_MODULE SYS_NICE SYS_PACCT SYS_PTRACE SYS_RAWIO SYS_RESOURCE SYS_TIME SYS_TTY_CONFIG SYSLOG WAKE_ALARM".split()
)
MODES = {"default", "host", "private", "shareable", "none", "container", "other"}
MOUNT_CLASSES = {"root", "docker_socket", "credentials", "system", "device", "other"}
REASONS = {
    "none",
    "incomplete",
    "invalid_input",
    "limit",
    "timeout",
    "access_denied",
    "not_configured",
}


def hex_id(value) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[a-f0-9]{64}", value))


def instant(value) -> str:
    require(isinstance(value, str) and len(value) <= 40, "invalid_docker_timestamp")
    try:
        parsed = datetime.fromisoformat(value)
        require(parsed.utcoffset() is not None and parsed.utcoffset().total_seconds() == 0)
        return parsed.isoformat(timespec="microseconds")
    except (ValueError, OverflowError) as error:
        raise ValueError("invalid_docker_timestamp") from error


def record(value: dict) -> dict:
    require(isinstance(value, dict) and value.keys() == FIELDS, "invalid_docker_record")
    require(len(encode(value)) <= MAX_RECORD, "docker_record_limit")
    for key, item in value.items():
        if item is None:
            continue  # Unknown is never silently converted into a safe default.
        if key == "image":
            require(hex_id(item))
        elif key in {"running", "privileged"}:
            require(type(item) is bool)
        elif key in {"network", "pid", "ipc", "uts", "userns"}:
            require(isinstance(item, str) and item in MODES)
        elif key == "user":
            require(item in ("default_root", "explicit_root", "nonroot_numeric", "named_unknown"))
        elif key == "restart":
            require(isinstance(item, dict) and item.keys() == {"name", "retries"})
            require(item["name"] in ("no", "always", "unless-stopped", "on-failure"))
            require(integer(item["retries"], 0, 1000000))
        else:
            require(isinstance(item, list) and len(item) <= MAX_ENTRIES)
            require(
                item == sorted(item, key=encode) and len({encode(x) for x in item}) == len(item)
            )
            for entry in item:
                if key in {"cap_add", "cap_drop"}:
                    require(isinstance(entry, str) and entry in CAPS)
                elif key == "mounts":
                    require(
                        isinstance(entry, dict)
                        and entry.keys() == {"class", "type", "rw", "source_ref", "target_ref"}
                    )
                    require(
                        entry["class"] in MOUNT_CLASSES
                        and entry["type"] in {"bind", "volume", "tmpfs"}
                    )
                    require(type(entry["rw"]) is bool)
                    require(hex_id(entry["source_ref"]) and hex_id(entry["target_ref"]))
                else:
                    require(
                        isinstance(entry, dict)
                        and entry.keys() == {"ip", "host_port", "container_port", "protocol"}
                    )
                    require(
                        isinstance(entry["ip"], str)
                        and len(entry["ip"]) <= 45
                        and "%" not in entry["ip"]
                    )
                    require(
                        entry["ip"] == "" or str(ipaddress.ip_address(entry["ip"])) == entry["ip"]
                    )
                    require(entry["host_port"] is None or integer(entry["host_port"], 1, 65535))
                    require(integer(entry["container_port"], 1, 65535))
                    require(entry["protocol"] in ("tcp", "udp", "sctp"))
    return value


@dataclass(frozen=True)
class Result:
    source_id: str
    collected_at: str
    status: str
    reason: str
    containers: dict
    origin: str = "synthetic"
    schema_version: int = VERSION
    adapter_version: int = VERSION

    def validate(self):
        require(type(self.schema_version) is int and self.schema_version == VERSION)
        require(type(self.adapter_version) is int and self.adapter_version == VERSION)
        require(self.origin == "synthetic", "docker_live_acquisition_not_approved")
        require(hex_id(self.source_id))
        require(self.collected_at == instant(self.collected_at))
        require(self.status in ("ok", "partial", "unavailable") and self.reason in REASONS)
        require((self.status == "ok") == (self.reason == "none"))
        require(isinstance(self.containers, dict) and len(self.containers) <= MAX_CONTAINERS)
        require(self.status != "unavailable" or not self.containers)
        for key, value in self.containers.items():
            require(hex_id(key))
            record(value)
            require(self.status != "ok" or all(v is not None for v in value.values()))
        require(len(encode(asdict(self))) <= MAX_INPUT, "docker_result_limit")
        return self
