"""Pure bounded inspect projection. No CLI, subprocess, socket, URL or file access."""

import ipaddress
from pathlib import PurePosixPath
import re
import time

from ..docker_posture.contracts import (
    CAPS,
    FIELDS,
    MAX_CONTAINERS,
    MAX_ENTRIES,
    MAX_INPUT,
    MODES,
    Result,
    hex_id,
    instant,
)
from ..investigation.contracts import integer, require, strict_json
from ..model import digest, encode


def string(value):
    require(isinstance(value, str) and len(value) <= 4096 and "\0" not in value)
    return value


def boolean(value):
    require(type(value) is bool)
    return value


def entries(value):
    require(isinstance(value, list) and len(value) <= MAX_ENTRIES)
    return value


def canonical(value):
    return sorted({encode(x): x for x in value}.values(), key=encode)


def ports(value):
    if value is None:
        return []  # Explicit Docker null map; an absent field still remains unknown.
    require(isinstance(value, dict) and len(value) <= MAX_ENTRIES)
    output = []
    for key, bindings in value.items():
        require(isinstance(key, str) and re.fullmatch(r"[0-9]{1,5}/(tcp|udp|sctp)", key))
        port, protocol = key.split("/")
        require(1 <= int(port) <= 65535)
        if bindings is None:
            continue  # EXPOSE without a publication is not a published port.
        for binding in entries(bindings):
            require(isinstance(binding, dict))
            ip, host = string(binding["HostIp"]), string(binding["HostPort"])
            require("%" not in ip)
            ip = str(ipaddress.ip_address(ip)) if ip else ""
            require(host == "" or re.fullmatch(r"[0-9]{1,5}", host))
            require(host == "" or 1 <= int(host) <= 65535)
            output.append(
                {
                    "ip": ip,
                    "host_port": int(host) if host else None,
                    "container_port": int(port),
                    "protocol": protocol,
                }
            )
            require(len(output) <= MAX_ENTRIES)
    return canonical(output)


def mode(value):
    value = string(value)
    if value in {"", "default", "bridge"}:
        return "default"
    if value.startswith("container:"):
        return "container"
    return value if value in MODES else "other"


def capabilities(value):
    if value is None:  # Docker uses null for an empty CapAdd/CapDrop list.
        return []
    output = []
    for cap in entries(value):
        cap = string(cap).upper().removeprefix("CAP_")
        require(cap in CAPS)
        output.append(cap)
    return canonical(output)


def user(value):
    value = string(value).split(":", 1)[0]
    if value == "":
        return "default_root"
    if value == "root" or value.isascii() and value.isdigit() and int(value) == 0:
        return "explicit_root"
    return "nonroot_numeric" if re.fullmatch(r"[0-9]{1,10}", value) else "named_unknown"


def restart(value):
    require(isinstance(value, dict))
    name, retries = value["Name"], value["MaximumRetryCount"]
    require(name in ("no", "always", "unless-stopped", "on-failure"))
    require(integer(retries, 0, 1000000))
    return {"name": name, "retries": retries}


def image(value):
    value = string(value).removeprefix("sha256:")
    require(hex_id(value))
    return value


def path(value):
    value = string(value)
    require(value.startswith("/") and not value.startswith("//"))
    require(".." not in PurePosixPath(value).parts)
    return str(PurePosixPath(value))


def mount_class(source, target):
    # A lexical hint, not filesystem resolution or a complete sensitive-path inventory.
    if any(PurePosixPath(p).name == "docker.sock" for p in (source, target)):
        return "docker_socket"
    if source == "/":
        return "root"
    if any(
        part in {".ssh", ".aws", ".gnupg", ".kube", ".docker"}
        for part in PurePosixPath(source).parts
    ):
        return "credentials"
    if source == "/dev" or source.startswith("/dev/"):
        return "device"
    if any(
        source == p or source.startswith(p + "/")
        for p in (
            "/etc",
            "/proc",
            "/sys",
            "/run",
            "/var",
            "/var/run",
            "/var/lib/docker",
            "/root",
            "/home",
            "/boot",
            "/usr",
        )
    ):
        return "system"
    return "other"


def mounts(value):
    output = []
    for item in entries(value):
        require(isinstance(item, dict) and item["Type"] in {"bind", "volume", "tmpfs"})
        source = path(item["Source"]) if item["Type"] != "tmpfs" else ""
        target = path(item["Destination"])
        output.append(
            {
                "class": mount_class(source, target) if item["Type"] == "bind" else "other",
                "type": item["Type"],
                "rw": boolean(item["RW"]),
                "source_ref": digest(source),
                "target_ref": digest(target),
            }
        )
    return canonical(output)


PROJECTION = {
    "image": (("Image",), image),
    "running": (("State", "Running"), boolean),
    "privileged": (("HostConfig", "Privileged"), boolean),
    "network": (("HostConfig", "NetworkMode"), mode),
    "pid": (("HostConfig", "PidMode"), mode),
    "ipc": (("HostConfig", "IpcMode"), mode),
    "uts": (("HostConfig", "UTSMode"), mode),
    "userns": (("HostConfig", "UsernsMode"), mode),
    "mounts": (("Mounts",), mounts),
    "cap_add": (("HostConfig", "CapAdd"), capabilities),
    "cap_drop": (("HostConfig", "CapDrop"), capabilities),
    "user": (("Config", "User"), user),
    "restart": (("HostConfig", "RestartPolicy"), restart),
    "configured_ports": (("HostConfig", "PortBindings"), ports),
    "observed_ports": (("NetworkSettings", "Ports"), ports),
}


def parse_synthetic(
    raw: bytes, source_id: str, collected_at: str, *, clock=time.monotonic
) -> Result:
    """Parse an explicit synthetic envelope; never imply authenticated or live host evidence.

    Missing per-field evidence becomes null. Duplicate IDs invalidate the batch. A
    malformed container never permits removals of unseen objects. Raw metadata lives
    only within this bounded call and is never returned, hashed wholesale or logged.
    """
    at = instant(collected_at)
    deadline = clock() + 1.0
    output = {}
    reason = "none"
    try:
        data = strict_json(raw, MAX_INPUT)
        require(isinstance(data, dict) and data.keys() == {"schema_version", "complete", "inspect"})
        require(type(data["schema_version"]) is int and data["schema_version"] == 1)
        require(type(data["complete"]) is bool)
        require(isinstance(data["inspect"], list) and len(data["inspect"]) <= MAX_CONTAINERS)
        reason = "none" if data["complete"] else "incomplete"
        seen = set()
        for item in data["inspect"]:
            require(isinstance(item, dict) and hex_id(item.get("Id")))
            key = item["Id"]
            require(key not in seen)
            seen.add(key)
            projected = dict.fromkeys(FIELDS)
            for field, (keys, convert) in PROJECTION.items():
                if clock() > deadline:
                    return Result(
                        source_id, at, "partial" if output else "unavailable", "timeout", output
                    ).validate()
                try:
                    value = item
                    for part in keys:
                        value = value[part]
                    projected[field] = convert(value)
                except (ValueError, TypeError, KeyError, OverflowError):
                    reason = "incomplete"
            output[key] = projected
        return Result(
            source_id, at, "ok" if reason == "none" else "partial", reason, output
        ).validate()
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
        return Result(source_id, at, "unavailable", "invalid_input", {}).validate()
