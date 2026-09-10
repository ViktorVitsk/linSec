"""Synthetic replay through the real application operations, in a separate database."""

from copy import deepcopy

from .application import Application
from .model import Collection, SOURCES


def replay(app: Application) -> dict:
    if app.store.rows("SELECT id FROM snapshots LIMIT 1"):
        raise ValueError("demo_requires_empty_synthetic_database")

    def batch(items):
        return [
            Collection(
                s,
                deepcopy(items.get(s, {})),
                collected_at=app.clock(),
                scope="synthetic; config=" + app.config.fingerprint,
            )
            for s in SOURCES
        ]

    app.ingest(batch({}))
    preview = app.baseline_preview()
    app.baseline_update(preview["approval_token"], "Синтетическая пустая база демонстрации")
    endpoint = {
        "kind": "endpoint",
        "protocol": "tcp",
        "family": 4,
        "bind": "127.0.0.1",
        "port": 8080,
        "uid": 1000,
        "owners": [{"exe": "/synthetic/server", "uid": 1000}],
        "context_complete": True,
    }
    unit = {"kind": "unit", "name": "synthetic.service", "scope": "user", "enablement": "enabled"}
    file = {
        "kind": "file",
        "path": "/synthetic/synthetic.service.d/override.conf",
        "exists": True,
        "sha256": "a" * 64,
        "mode": 420,
        "uid": 1000,
        "gid": 1000,
        "link_sha256": None,
    }
    items = {
        "tcp4": {"demo_endpoint": endpoint},
        "systemd_user": {"unit": unit, "dropin": file},
        "accounts": {
            "uid0:synthetic": {"kind": "uid0", "name": "synthetic", "uid": 0, "gid": 0},
            "group:docker": {
                "kind": "group",
                "name": "docker",
                "gid": 999,
                "members": ["synthetic"],
            },
        },
    }
    app.ingest(batch(items))
    first_count = len(app.alerts())
    alert_id = next(a["id"] for a in app.alerts() if a["source"] == "tcp4")
    app.exception(alert_id, "trust", "Ожидаемый synthetic server", 1)
    app.ingest(batch(items))
    repeat_count = len(app.alerts())
    items["tcp4"]["demo_endpoint"]["owners"] = [{"exe": "/synthetic/other", "uid": 1000}]
    items["systemd_user"]["dropin"]["sha256"] = "b" * 64
    app.ingest(batch(items))
    return {
        "mode": "synthetic_only",
        "initial_alerts": first_count,
        "after_identical_replay": repeat_count,
        "after_context_and_dropin_change": len(app.alerts()),
        "trusted_alert_id": alert_id,
        "pending_notifications": app.pending_notifications(),
        "host_collection": False,
        "system_changes": False,
    }
