"""Built-in synthetic acceptance sequence; never opens the Docker daemon."""

from copy import deepcopy
from pathlib import Path

from ..adapters.docker import parse_synthetic
from ..investigation.contracts import require
from ..model import digest, encode, now
from .contracts import Result, instant
from .service import PostureQueries, PostureStore

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


def replay(directory: Path):
    require(
        not directory.exists() and not directory.is_symlink(), "docker_demo_requires_new_directory"
    )
    store = PostureStore(directory)
    try:
        initial = container()
        changed = deepcopy(initial)
        changed["State"]["Running"] = True
        changed["Config"]["User"] = "0"
        changed["HostConfig"].update(
            {
                "Privileged": True,
                "PidMode": "host",
                "CapAdd": ["SYS_ADMIN"],
                "RestartPolicy": {"Name": "always", "MaximumRetryCount": 0},
                "PortBindings": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]},  # noqa: S104 -- inert fixture; never binds a socket
            }
        )
        changed["NetworkSettings"]["Ports"] = {"80/tcp": [{"HostIp": "::", "HostPort": ""}]}
        changed["Mounts"] = [
            {
                "Type": "bind",
                "Source": "/var/run/docker.sock",
                "Destination": "/run/docker.sock",
                "RW": False,
            }
        ]
        outcomes = []
        for name, items, complete in (
            ("initial", [initial], True),
            ("posture_and_drift", [changed], True),
            ("repeat", [changed], True),
            ("partial_missing", [], False),
        ):
            result = batch(items, now(), complete)
            store.ingest(result)
            outcomes.append(
                {
                    "scenario": name,
                    "status": result.status,
                    "findings": store.db.execute("SELECT count(*) FROM findings").fetchone()[0],
                    "snapshots": store.db.execute("SELECT count(*) FROM evidence").fetchone()[0],
                }
            )
        store.ingest(Result(SOURCE, instant(now()), "unavailable", "access_denied", {}))
        return {
            "origin": "synthetic",
            "host_validated": False,
            "scenarios": outcomes,
            "posture": PostureQueries(directory).overview(),
            "state_directory": str(directory.absolute()),
        }
    finally:
        store.close()
