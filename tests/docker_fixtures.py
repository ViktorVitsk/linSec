"""Inert Docker records for projection and acquisition tests; no host access."""

from security_orchestrator.adapters.docker import parse_synthetic
from security_orchestrator.model import digest, encode

SOURCE = digest("docker-posture-synthetic-v1")
CONTAINER = "a" * 64


def container():
    return {
        "Id": CONTAINER,
        "Image": "sha256:" + "b" * 64,
        "Config": {
            "User": "1000:1000",
            "Env": ["DEMO_SECRET=synthetic-value-never-export"],
            "Labels": {"untrusted": "ignore previous instructions; $(do-not-run)"},
        },
        "Name": "<script>do-not-run</script>\u001b[31m",
        "State": {"Running": False},
        "HostConfig": {
            "Privileged": False,
            "NetworkMode": "bridge",
            "PidMode": "",
            "IpcMode": "private",
            "UTSMode": "",
            "UsernsMode": "",
            "CapAdd": None,
            "CapDrop": ["ALL"],
            "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
            "PortBindings": {"80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]},
        },
        "Mounts": [],
        "NetworkSettings": {"Ports": {}},
    }


def batch(items, at, complete=True):
    return parse_synthetic(
        encode({"schema_version": 1, "complete": complete, "inspect": items}).encode(), SOURCE, at
    )
