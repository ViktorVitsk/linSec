"""Shared scan, baseline, alert and exception operations for CLI and future UI."""

from datetime import datetime, timedelta

from .config import Config
from .model import (
    COLLECTOR_VERSION,
    SCHEMA_VERSION,
    SOURCES,
    MAX_PAYLOAD,
    Collection,
    InvalidInput,
    changes,
    detector,
    decode_items,
    digest,
    encode,
    now,
    validate_items,
)
from .store import Store


class Application:
    def __init__(self, store: Store, config: Config, clock=now):
        self.store, self.db, self.config, self.clock = store, store.db, config, clock

    def snapshot(self, snapshot_id: int | None) -> dict:
        if snapshot_id is None:
            return {}
        # Corrupt or locally edited database content remains untrusted on read as well as write.
        row = self.db.execute(
            "SELECT substr(data,1,?) FROM snapshots WHERE id=?", (MAX_PAYLOAD + 1, snapshot_id)
        ).fetchone()
        if row is None:
            raise InvalidInput("missing_evidence")
        return decode_items(row[0])

    def audit(self, action: str, detail: object) -> None:
        self.db.execute(
            "INSERT INTO audit(at,action,detail) VALUES (?,?,?)",
            (self.clock(), action, encode(detail)),
        )

    def ingest(self, results: list[Collection]) -> dict:
        indexed = {}
        for result in results:
            result.validate()
            if result.source in indexed:
                raise InvalidInput("duplicate_source")
            indexed[result.source] = result
        # Every configured source receives freshness, including collectors omitted by a failure.
        for source in SOURCES:
            indexed.setdefault(
                source,
                Collection(
                    source, status="unavailable", reason="source_missing", collected_at=self.clock()
                ),
            )
        timestamp = self.clock()
        with self.store.transaction():
            self._retain(timestamp)
            for source, result in indexed.items():
                prior = self.db.execute(
                    "SELECT * FROM sources WHERE source=?", (source,)
                ).fetchone()
                previous_snapshot = (
                    self.db.execute(
                        "SELECT scope FROM snapshots WHERE id=?", (prior["snapshot_id"],)
                    ).fetchone()
                    if prior
                    else None
                )
                same_scope = previous_snapshot is not None and previous_snapshot[0] == result.scope
                old_id = prior["snapshot_id"] if same_scope else None
                old_items = self.snapshot(old_id)
                current = dict(result.items) if result.status == "ok" else old_items | result.items
                try:
                    validate_items(current)
                except InvalidInput:
                    self.store.mark_storage_error(True)
                    raise
                snapshot_id = old_id
                if result.status != "unavailable":
                    fingerprint = digest([current, result.scope, result.status])
                    prior_fingerprint = self.db.execute(
                        "SELECT fingerprint FROM snapshots WHERE id=?", (old_id,)
                    ).fetchone()
                    if not prior_fingerprint or prior_fingerprint[0] != fingerprint:
                        cursor = self.db.execute(
                            """INSERT INTO snapshots(host_id,source,schema_version,collector_version,
                            created_at,scope,completeness,fingerprint,data) VALUES (?,?,?,?,?,?,?,?,?)""",
                            (
                                self.store.meta("host_id"),
                                source,
                                SCHEMA_VERSION,
                                COLLECTOR_VERSION,
                                result.collected_at,
                                result.scope,
                                result.status,
                                fingerprint,
                                encode(current),
                            ),
                        )
                        snapshot_id = cursor.lastrowid
                    base = self.db.execute(
                        "SELECT snapshot_id FROM baseline WHERE source=?", (source,)
                    ).fetchone()
                    before_id = base[0] if base else None
                    before = self.snapshot(before_id)
                    baseline_scope = self.db.execute(
                        "SELECT scope FROM snapshots WHERE id=?", (before_id,)
                    ).fetchone()
                    scope_matches = not baseline_scope or baseline_scope[0] == result.scope
                    # Only positive evidence from partial scans. Never diff a merged stale set as fresh.
                    diff = changes(
                        before, result.items, complete=result.status == "ok" and scope_matches
                    )
                    active = set()
                    for change in diff:
                        finding = detector(source, change)
                        active.add(finding["context"])
                        self.db.execute(
                            """INSERT INTO alerts(context,source,object_key,detector_id,detector_version,
                            severity,change_type,before_id,after_id,first_seen,last_seen,occurrences,
                            lifecycle,active,notified) VALUES (?,?,?,?,?,?,?,?,?,?,?,1,'open',1,0)
                            ON CONFLICT(context) DO UPDATE SET
                                last_seen=excluded.last_seen, occurrences=alerts.occurrences+1,
                                lifecycle=CASE WHEN alerts.active=0 THEN 'open' ELSE alerts.lifecycle END,
                                notified=CASE WHEN alerts.active=0 THEN 0 ELSE alerts.notified END,
                                active=1""",
                            (
                                finding["context"],
                                source,
                                change["key"],
                                finding["detector_id"],
                                finding["detector_version"],
                                finding["severity"],
                                change["change"],
                                before_id,
                                snapshot_id,
                                timestamp,
                                timestamp,
                            ),
                        )
                    if result.status == "ok" and scope_matches:
                        for alert in self.store.rows(
                            "SELECT id,context FROM alerts WHERE source=?", (source,)
                        ):
                            if alert["context"] not in active:
                                self.db.execute(
                                    "UPDATE alerts SET active=0 WHERE id=?", (alert["id"],)
                                )
                # Preserve last known data on unavailability, even if the requested scope changed.
                if result.status == "unavailable" and prior:
                    snapshot_id = prior["snapshot_id"]
                last_ok = (
                    result.collected_at
                    if result.status == "ok"
                    else prior["last_ok"]
                    if prior
                    else None
                )
                self.db.execute(
                    """INSERT INTO sources VALUES (?,?,?,?,?,?,?) ON CONFLICT(source) DO UPDATE SET
                    status=excluded.status,reason=excluded.reason,collected_at=excluded.collected_at,
                    last_ok=excluded.last_ok,scope=excluded.scope,snapshot_id=excluded.snapshot_id""",
                    (
                        source,
                        result.status,
                        result.reason,
                        result.collected_at,
                        last_ok,
                        result.scope,
                        snapshot_id,
                    ),
                )
            self.audit("scan", {s: r.status for s, r in indexed.items()})
        self.store.mark_storage_error(False)
        return {
            "sources": {s: r.status for s, r in indexed.items()},
            "pending_notifications": len(self.pending_notifications()),
            "at": timestamp,
        }

    def status(self) -> dict:
        timestamp = datetime.fromisoformat(self.clock())
        rows = {row["source"]: row for row in self.store.rows("SELECT * FROM sources")}
        sources = []
        for source in SOURCES:
            row = rows.get(
                source,
                {
                    "source": source,
                    "status": "unavailable",
                    "reason": "never_collected",
                    "collected_at": None,
                    "last_ok": None,
                    "scope": "",
                    "snapshot_id": None,
                },
            )
            age = (
                (timestamp - datetime.fromisoformat(row["collected_at"])).total_seconds()
                if row["collected_at"]
                else None
            )
            row["age_seconds"] = age
            row["stale"] = age is None or age < 0 or age > self.config.stale_seconds
            base = self.db.execute(
                "SELECT snapshot_id FROM baseline WHERE source=?", (source,)
            ).fetchone()
            row["baseline_id"] = base[0] if base else None
            base_scope = (
                self.db.execute("SELECT scope FROM snapshots WHERE id=?", (base[0],)).fetchone()
                if base
                else None
            )
            row["baseline_scope_changed"] = bool(base_scope and base_scope[0] != row["scope"])
            row["config_changed"] = not row["scope"].endswith("config=" + self.config.fingerprint)
            sources.append(row)
        failed = self.store.storage_failed()
        healthy = not failed and all(
            r["status"] == "ok"
            and not r["stale"]
            and not r["baseline_scope_changed"]
            and not r["config_changed"]
            and r["reason"] == "none"
            for r in sources
        )
        return {
            "host_id": self.store.meta("host_id"),
            "sources": sources,
            "health": "current" if healthy else "degraded",
            "storage_bytes": self.store.size(),
            "last_storage_write_failed": failed,
            "storage_budget_bytes": self.store.budget,
            "disabled": (self.store.directory / "disabled").exists(),
            "baseline_revision": int(self.store.meta("baseline_revision")),
            "llm_enabled": False,
        }

    def _preview(self) -> dict:
        status = self.status()
        sources = status["sources"]
        if status["last_storage_write_failed"] or any(
            r["status"] not in {"ok", "partial"} or r["stale"] or r["config_changed"]
            for r in sources
        ):
            raise InvalidInput("baseline_requires_fresh_available_scan_with_current_config")
        proposed = []
        for row in sources:
            before = self.snapshot(row["baseline_id"])
            observed = self.snapshot(row["snapshot_id"])
            retained = []
            if row["status"] == "partial":
                validate_items(before | observed)
                retained = sorted(before.keys() - observed.keys())
            proposed.append(
                {
                    "source": row["source"],
                    "snapshot_id": row["snapshot_id"],
                    "baseline_id": row["baseline_id"],
                    "scope": row["scope"],
                    "completeness": row["status"],
                    "warning": row["reason"],
                    "collected_at": row["collected_at"],
                    "last_ok": row["last_ok"],
                    "baseline_scope_changed": row["baseline_scope_changed"],
                    "retained_baseline_keys": retained,
                    "changes": changes(
                        before,
                        observed,
                        complete=row["status"] == "ok",
                    ),
                }
            )
        return {
            "approval_token": digest(
                [
                    self.store.meta("host_id"),
                    self.config.fingerprint,
                    status["baseline_revision"],
                    proposed,
                ]
            ),
            "baseline_revision": status["baseline_revision"],
            "proposed": proposed,
            "meaning": "Baseline = known/acknowledged state, не clean state. Даже первый baseline может описывать уже скомпрометированную машину.",
            "partial_meaning": "Partial baseline сохраняет последние известные объекты, включая ранее наблюдавшиеся: их наличие сейчас не подтверждено. Пробелы покрытия остаются degraded; отсутствие объекта не доказывает удаление.",
        }

    def baseline_preview(self) -> dict:
        with self.store.transaction():
            return self._preview()

    def baseline_update(self, token: str, reason: str) -> dict:
        self._reason(reason)
        with self.store.transaction():
            preview = self._preview()
            if token != preview["approval_token"]:
                raise InvalidInput("stale_approval_get_new_baseline_diff")
            for item in preview["proposed"]:
                snapshot_id = item["snapshot_id"]
                if item["completeness"] == "partial":
                    observed = self.snapshot(snapshot_id)
                    # An intervening complete scan may have dropped baseline objects from
                    # the latest inventory. Partial approval must preserve them as unknown.
                    accepted = self.snapshot(item["baseline_id"]) | observed
                    validate_items(accepted)
                    if accepted != observed:
                        cursor = self.db.execute(
                            """INSERT INTO snapshots(host_id,source,schema_version,collector_version,
                            created_at,scope,completeness,fingerprint,data)
                            SELECT host_id,source,schema_version,collector_version,
                            created_at,scope,completeness,?,? FROM snapshots WHERE id=?""",
                            (
                                digest([accepted, item["scope"], "partial"]),
                                encode(accepted),
                                snapshot_id,
                            ),
                        )
                        snapshot_id = cursor.lastrowid
                item["accepted_snapshot_id"] = snapshot_id
                self.db.execute(
                    """INSERT INTO baseline(source,snapshot_id,collected_at,last_ok,reason)
                    VALUES (?,?,?,?,?) ON CONFLICT(source) DO UPDATE SET
                    snapshot_id=excluded.snapshot_id,collected_at=excluded.collected_at,
                    last_ok=excluded.last_ok,reason=excluded.reason""",
                    (
                        item["source"],
                        snapshot_id,
                        item["collected_at"],
                        item["last_ok"],
                        item["warning"],
                    ),
                )
            revision = preview["baseline_revision"] + 1
            self.db.execute(
                "UPDATE metadata SET value=? WHERE key='baseline_revision'", (str(revision),)
            )
            self.db.execute("UPDATE alerts SET active=0")
            self.audit(
                "baseline_update",
                {
                    "revision": revision,
                    "preview": token,
                    "reason": reason,
                    "snapshots": {
                        p["source"]: p["accepted_snapshot_id"] for p in preview["proposed"]
                    },
                    "coverage": [
                        {k: v for k, v in p.items() if k != "changes"} for p in preview["proposed"]
                    ],
                },
            )
            return {"baseline_revision": revision}

    def baseline_show(self) -> list[dict]:
        return [
            {**row, "items": self.snapshot(row["snapshot_id"])}
            for row in self.store.rows(
                """SELECT baseline.*,snapshots.scope,snapshots.completeness
                FROM baseline JOIN snapshots ON snapshots.id=baseline.snapshot_id
                ORDER BY baseline.source"""
            )
        ]

    def alerts(self, limit: int = 100) -> list[dict]:
        rows = self.store.rows(
            "SELECT * FROM alerts ORDER BY last_seen DESC,id DESC LIMIT ?", (limit,)
        )
        for row in rows:
            row["exceptions"] = self.store.rows(
                "SELECT id,kind,expires_at FROM exceptions WHERE context=? AND (expires_at IS NULL OR expires_at>?)",
                (row["context"], self.clock()),
            )
        return rows

    def get_alert(self, alert_id: int) -> dict:
        rows = self.store.rows("SELECT * FROM alerts WHERE id=?", (alert_id,))
        if not rows:
            raise InvalidInput("alert_not_found")
        return rows[0]

    def lifecycle(self, alert_id: int, state: str) -> dict:
        if state not in {"open", "reviewed", "closed"}:
            raise InvalidInput("invalid_lifecycle")
        with self.store.transaction():
            self.get_alert(alert_id)
            self.db.execute("UPDATE alerts SET lifecycle=? WHERE id=?", (state, alert_id))
            self.audit("lifecycle", {"alert_id": alert_id, "state": state})
        return {"id": alert_id, "lifecycle": state}

    @staticmethod
    def _reason(reason: str) -> None:
        if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 500 or "\x00" in reason:
            raise InvalidInput("reason_required_max_500_no_secrets")

    def exception(self, alert_id: int, kind: str, reason: str, hours: int | None = None) -> dict:
        self._reason(reason)
        if kind not in {"trust", "suppression"}:
            raise InvalidInput("invalid_exception_kind")
        if hours is not None and (type(hours) is not int or not 1 <= hours <= 8760):
            raise InvalidInput("invalid_expiry_hours")
        with self.store.transaction():
            alert = self.get_alert(alert_id)
            source = next(r for r in self.status()["sources"] if r["source"] == alert["source"])
            if (
                not alert["active"]
                or source["stale"]
                or source["status"] != "ok"
                or source["config_changed"]
            ):
                raise InvalidInput("exception_requires_current_active_evidence")
            current = self.snapshot(source["snapshot_id"]).get(alert["object_key"])
            evidence = self.snapshot(alert["after_id"]).get(alert["object_key"])
            if current != evidence or evidence is None:
                raise InvalidInput("exception_requires_present_unchanged_object")
            if evidence["kind"] == "endpoint" and not evidence["context_complete"]:
                raise InvalidInput("exception_requires_executable_and_user_context")
            timestamp = self.clock()
            expiry = (
                (datetime.fromisoformat(timestamp) + timedelta(hours=hours)).isoformat()
                if hours
                else None
            )
            self.db.execute(
                """INSERT INTO exceptions(context,kind,reason,created_at,expires_at,provenance)
                VALUES (?,?,?,?,?,'owner_cli') ON CONFLICT(context,kind) DO UPDATE SET
                reason=excluded.reason,created_at=excluded.created_at,expires_at=excluded.expires_at""",
                (alert["context"], kind, reason, timestamp, expiry),
            )
            self.audit(
                "exception_add",
                {"alert_id": alert_id, "kind": kind, "reason": reason, "expires_at": expiry},
            )
        return {"alert_id": alert_id, "kind": kind, "expires_at": expiry}

    def exceptions(self) -> list[dict]:
        return self.store.rows("SELECT * FROM exceptions ORDER BY id")

    def remove_exception(self, exception_id: int) -> dict:
        with self.store.transaction():
            row = self.db.execute(
                "SELECT context FROM exceptions WHERE id=?", (exception_id,)
            ).fetchone()
            if row is None:
                raise InvalidInput("exception_not_found")
            self.db.execute("DELETE FROM exceptions WHERE id=?", (exception_id,))
            self.db.execute("UPDATE alerts SET notified=0 WHERE context=?", (row[0],))
            self.audit("exception_remove", {"id": exception_id})
        return {"removed": exception_id}

    def pending_notifications(self) -> list[int]:
        return [
            row[0]
            for row in self.db.execute(
                """SELECT a.id FROM alerts a WHERE a.active=1 AND a.lifecycle!='closed'
            AND a.notified=0 AND NOT EXISTS (SELECT 1 FROM exceptions e WHERE e.context=a.context
            AND (e.expires_at IS NULL OR e.expires_at>?)) ORDER BY a.id""",
                (self.clock(),),
            )
        ]

    def notify(self, send) -> dict:
        ids = self.pending_notifications()
        if not self.config.notifications or not ids:
            return {"notifications": "disabled" if not self.config.notifications else "none"}
        # The notification is static: no untrusted telemetry or secrets reach the desktop bus.
        try:
            send()
        except Exception:
            with self.store.transaction():
                self.audit("notification_failed", {"pending": len(ids)})
            return {"notifications": "unavailable"}
        with self.store.transaction():
            self.db.executemany("UPDATE alerts SET notified=1 WHERE id=?", [(i,) for i in ids])
            self.audit("notification_sent", {"count": len(ids)})
        return {"notifications": "sent", "count": len(ids)}

    def history(self, limit: int = 100) -> dict:
        return {
            "snapshots": self.store.rows(
                "SELECT id,source,created_at,scope,completeness FROM snapshots ORDER BY id DESC LIMIT ?",
                (limit,),
            ),
            "audit": self.store.rows("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)),
        }

    def _retain(self, timestamp: str) -> None:
        instant = datetime.fromisoformat(timestamp)
        event_cutoff = (instant - timedelta(days=30)).isoformat()
        alert_cutoff = (instant - timedelta(days=90)).isoformat()
        # Active alerts remain actionable; bounded storage may require owner review if pinned data grows.
        self.db.execute("DELETE FROM alerts WHERE last_seen<? AND active=0", (alert_cutoff,))
        self.db.execute("DELETE FROM audit WHERE at<?", (alert_cutoff,))
        expired = self.db.execute(
            "SELECT context FROM exceptions WHERE expires_at<=?", (timestamp,)
        ).fetchall()
        for row in expired:
            self.db.execute("UPDATE alerts SET notified=0 WHERE context=?", (row[0],))
        self.db.execute("DELETE FROM exceptions WHERE expires_at<=?", (timestamp,))
        self.db.execute(
            """DELETE FROM snapshots WHERE created_at<?
            AND id NOT IN (SELECT snapshot_id FROM sources WHERE snapshot_id IS NOT NULL)
            AND id NOT IN (SELECT snapshot_id FROM baseline)
            AND id NOT IN (SELECT before_id FROM alerts WHERE before_id IS NOT NULL)
            AND id NOT IN (SELECT after_id FROM alerts)""",
            (event_cutoff,),
        )

    def doctor(self) -> dict:
        status = self.status()
        integrity = self.db.execute("PRAGMA quick_check(1)").fetchone()[0] == "ok"
        references = not self.db.execute("PRAGMA foreign_key_check").fetchall()
        return {
            **status,
            "sqlite_integrity": integrity,
            "evidence_links": references,
            "healthy": integrity and references and status["health"] == "current",
        }
