"""Shared bounded read-only application queries for CLI and local UI."""

from dataclasses import dataclass
import fcntl
import os
from pathlib import Path
import sqlite3
import stat
import time

from .application import Application
from .config import Config
from .investigation.contracts import require, strict_json
from .investigation.evidence import EvidenceReader, PackBuilder, fallback, timestamp
from .model import InvalidInput, SOURCES, now
from .reliability.store import APPLICATION_ID
from .reliability.contracts import MESSAGE_IDS, SOURCE, State


def bounded_reader(directory: Path) -> EvidenceReader:
    reader = EvidenceReader(directory)
    deadline = time.monotonic() + 1
    reader.db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
    return reader


def read_private(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.getuid()
            and not info.st_mode & 0o077
            and info.st_nlink == 1
        )
        data = os.read(fd, limit + 1)
        require(len(data) <= limit)
        return data
    finally:
        os.close(fd)


class ReadStore:
    """Read adapter for existing Application.status; no constructor migrations/writes."""

    def __init__(self, reader: EvidenceReader, directory: Path, config: Config):
        self.db, self.directory = reader.db, directory
        self.path, self.budget = directory / "watchdog.sqlite3", config.storage_mib * 1024 * 1024

    def rows(self, sql: str, params: tuple = ()) -> list[dict]:
        return [dict(row) for row in self.db.execute(sql, params)]

    def meta(self, key: str) -> str:
        row = self.db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
        require(row is not None)
        return row[0]

    def size(self) -> int:
        return sum(
            p.stat().st_size
            for p in (
                self.path,
                Path(str(self.path) + "-journal"),
                Path(str(self.path) + "-wal"),
                Path(str(self.path) + "-shm"),
            )
            if p.exists()
        )

    def storage_failed(self) -> bool:
        try:
            return read_private(self.directory / "storage-health", 1) != b"0"
        except (OSError, ValueError):
            return True


def running_state(directory: Path) -> str:
    try:
        fd = os.open(directory / "monitor.lock", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return "not_running"
    except OSError:
        return "unknown"
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            return "unknown"
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return "not_running"
        except BlockingIOError:
            return "running"
    finally:
        os.close(fd)


@dataclass(frozen=True)
class AlertSummary:
    id: int
    severity: str
    type: str
    status: str
    at: str
    source: str
    summary: str
    active: bool

    def wire(self) -> dict:
        return {
            "id": self.id,
            "severity": self.severity,
            "type": self.type,
            "status": self.status,
            "at": self.at,
            "source": self.source,
            "summary": self.summary,
            "active": self.active,
        }


class Queries:
    def __init__(self, directory: Path, config: Config, reliability: Path | None = None, clock=now):
        self.directory, self.config, self.reliability, self.clock = (
            directory,
            config,
            reliability,
            clock,
        )

    def overview(self) -> dict:
        reader = bounded_reader(self.directory)
        try:
            with reader.read():
                require(
                    reader.db.execute("SELECT count(*) FROM sources").fetchone()[0] <= len(SOURCES)
                )
                require(
                    not reader.db.execute(
                        "SELECT 1 FROM sources WHERE length(source)>32 OR length(status)>16 OR length(reason)>64 OR length(scope)>4096 OR length(collected_at)>64 OR length(last_ok)>64 LIMIT 1"
                    ).fetchone()
                )
                require(
                    not reader.db.execute(
                        "SELECT 1 FROM metadata WHERE length(value)>128 LIMIT 1"
                    ).fetchone()
                )
                store = ReadStore(reader, self.directory, self.config)
                status = Application(store, self.config, self.clock).status()
                active = reader.db.execute(
                    "SELECT count(*) FROM alerts WHERE active=1 AND lifecycle!='closed'"
                ).fetchone()[0]
                pending = Application(store, self.config, self.clock).pending_notification_count()
                sources = []
                for row in status["sources"]:
                    if row["collected_at"] is not None:
                        row["collected_at"] = timestamp(row["collected_at"])
                    require(
                        row["source"] in SOURCES
                        and row["status"] in {"ok", "partial", "unavailable"}
                    )
                    reasons = []
                    if row["status"] != "ok":
                        reasons.append(row["status"])
                    if row["stale"]:
                        reasons.append("stale")
                    if row["config_changed"] or row["baseline_scope_changed"]:
                        reasons.append("configuration_mismatch")
                    if row["reason"] == "invalid_input":
                        reasons.append("parser_failure")
                    elif row["reason"] != "none":
                        known = {
                            "never_collected",
                            "access_or_io",
                            "limit",
                            "timeout",
                            "command_failed",
                            "missing_command",
                            "context_missing",
                            "unsupported_platform",
                            "source_missing",
                            "cancelled",
                        }
                        reasons.append(
                            row["reason"] if row["reason"] in known else "unknown_diagnostic"
                        )
                    sources.append(
                        {
                            "source": row["source"],
                            "status": row["status"],
                            "at": row["collected_at"],
                            "reasons": reasons,
                            "snapshot_id": row["snapshot_id"],
                        }
                    )
                result = {
                    "schema_version": 1,
                    "application_version": "0.1.0",
                    "database_version": 2,
                    "monitor": running_state(self.directory),
                    "disabled": status["disabled"],
                    "health": status["health"],
                    "sources": sources,
                    "active_alerts": active,
                    "pending_notifications": pending,
                    "baseline_revision": status["baseline_revision"],
                    "baseline_meaning": "Acknowledged state, не clean host",
                    "storage_bytes": status["storage_bytes"],
                    "storage_failure": status["last_storage_write_failed"],
                    "llm_enabled": False,
                }
        finally:
            reader.close()
        result["reliability"] = self.reliability_view()
        return result

    def alerts(self, limit: int = 25, before: int = 2**63 - 1) -> dict:
        require(type(limit) is int and 1 <= limit <= 100, "invalid_page_limit")
        require(type(before) is int and 1 <= before <= 2**63 - 1, "invalid_page_cursor")
        reader = bounded_reader(self.directory)
        try:
            with reader.read():
                rows = reader.db.execute(
                    "SELECT id,substr(severity,1,32) severity,substr(detector_id,1,32) detector_id,substr(lifecycle,1,32) lifecycle,substr(last_seen,1,65) last_seen,substr(source,1,32) source,substr(change_type,1,32) change_type,active FROM alerts WHERE id<? ORDER BY id DESC LIMIT ?",
                    (before, limit + 1),
                ).fetchall()
                items = []
                for row in rows[:limit]:
                    timestamp(row["last_seen"])
                    require(
                        row["severity"] in {"info", "medium", "high"}
                        and row["lifecycle"] in {"open", "reviewed", "closed"}
                        and row["source"] in SOURCES
                        and row["active"] in {0, 1}
                        and row["change_type"] in {"added", "removed", "changed"}
                        and row["detector_id"]
                        in {
                            "endpoint-drift",
                            "file-drift",
                            "unit-drift",
                            "uid0-drift",
                            "group-drift",
                        }
                    )
                    items.append(
                        AlertSummary(
                            row["id"],
                            row["severity"],
                            row["detector_id"],
                            row["lifecycle"],
                            timestamp(row["last_seen"]),
                            row["source"],
                            row["change_type"] + " · " + row["detector_id"],
                            bool(row["active"]),
                        ).wire()
                    )
                return {
                    "schema_version": 1,
                    "items": items,
                    "next_before": items[-1]["id"] if len(rows) > limit else None,
                }
        finally:
            reader.close()

    def detail(self, alert_id: int) -> dict:
        require(type(alert_id) is int and 0 < alert_id < 2**31, "invalid_alert_id")
        reader = bounded_reader(self.directory)
        try:
            if not reader.db.execute("SELECT 1 FROM alerts WHERE id=?", (alert_id,)).fetchone():
                raise InvalidInput("alert_not_found")
            pack, _ = PackBuilder(reader, self.config.stale_seconds, self.clock).build(alert_id)
        finally:
            reader.close()
        reliability = self.reliability_view(alert_id)
        return {
            "schema_version": 1,
            "representation": "pseudonymized_local_view",
            "evidence": pack,
            "deterministic": fallback(pack, "llm_disabled"),
            "saved_investigation": reliability.get("investigation"),
            "investigation_storage_state": reliability["state"],
            "timeline_notice": "M2b без opt-in записи не сохраняет историю расследований. Отсутствие записи не означает отсутствие вызова.",
        }

    def reliability_view(self, alert_id: int | None = None) -> dict:
        if self.reliability is None:
            return {"state": "not_configured", "history_recovered": False}
        path = self.reliability.absolute() / "reliability.sqlite3"
        db = None
        try:
            require(not any(p.is_symlink() for p in (path, *path.parents)))
            for target in (path.parent, path):
                info = target.stat()
                require(info.st_uid == os.getuid() and not info.st_mode & 0o077)
            require(stat.S_ISREG(path.stat().st_mode) and path.stat().st_nlink == 1)
            db = sqlite3.connect(
                path.as_uri() + "?mode=ro", uri=True, timeout=1, isolation_level=None
            )
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA query_only=ON")
            db.execute("PRAGMA trusted_schema=OFF")
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 131072)
            deadline = time.monotonic() + 1
            db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
            require(db.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID)
            require(db.execute("PRAGMA user_version").fetchone()[0] == 1)
            reader = bounded_reader(self.directory)
            try:
                host = reader.one("SELECT value FROM metadata WHERE key='host_id'", ())["value"]
            finally:
                reader.close()
            db.execute("BEGIN")
            identity = db.execute(
                "SELECT host_id,config FROM identity WHERE singleton=1"
            ).fetchone()
            require(tuple(identity) == (host, self.config.fingerprint))
            health = db.execute(
                "SELECT state,checked_at,generation,reconciled FROM health"
            ).fetchone()
            if health:
                health = dict(health)
                require(health["state"] in set(State))
                health["checked_at"] = timestamp(health["checked_at"])
                require(
                    type(health["generation"]) is int
                    and type(health["reconciled"]) is int
                    and 0 <= health["reconciled"] <= health["generation"]
                )
            cp = db.execute("SELECT version,event_at FROM checkpoint").fetchone()
            gaps = db.execute(
                "SELECT id,detected_at,boundary_from,boundary_to,reason,reconciliation_attempted,current_state_observed,history_recovered FROM gaps ORDER BY id DESC LIMIT 50"
            ).fetchall()
            rec = db.execute(
                "SELECT at,outcome FROM reconciliations ORDER BY id DESC LIMIT 1"
            ).fetchone()
            events = db.execute(
                "SELECT id,event_at,message_id,transition,generation FROM events ORDER BY id DESC LIMIT 50"
            ).fetchall()
            from datetime import datetime

            if cp:
                cp = dict(cp)
                require(cp["version"] == 1)
                cp["event_at"] = timestamp(cp["event_at"])
            if rec:
                rec = dict(rec)
                rec["at"] = timestamp(rec["at"])
                require(rec["outcome"] in {"ok", "partial", "unavailable", "storage_failure"})
            events = [dict(event) for event in events]
            gaps = [dict(gap) for gap in gaps]
            for event in events:
                event["event_at"] = timestamp(event["event_at"])
                require(event["message_id"] in MESSAGE_IDS)
                require(event["transition"] == MESSAGE_IDS[event["message_id"]])
                require(type(event["generation"]) is int and event["generation"] > 0)
            for gap in gaps:
                require(
                    gap["reason"] in set(State) - {State.CONTINUATION}
                    and gap["history_recovered"] == 0
                )
                gap["detected_at"] = timestamp(gap["detected_at"])
                for key in ("boundary_from", "boundary_to"):
                    if gap[key] is not None:
                        gap[key] = timestamp(gap[key])
                require(
                    gap["current_state_observed"] in {0, 1}
                    and gap["reconciliation_attempted"] in {0, 1}
                )
            age = (
                (
                    datetime.fromisoformat(self.clock())
                    - datetime.fromisoformat(health["checked_at"])
                ).total_seconds()
                if health
                else None
            )
            result = {
                "state": health["state"] if health else "never_observed",
                "schema_version": 1,
                "source": SOURCE,
                "stale": age is None or not 0 <= age <= self.config.stale_seconds,
                "storage_failure": read_private(path.parent / "reliability-health", 1) != b"0",
                "checked_at": health["checked_at"] if health else None,
                "checkpoint": {"version": cp["version"], "event_at": cp["event_at"]}
                if cp
                else None,
                "pending_reconciliation": bool(
                    health and health["generation"] > health["reconciled"]
                ),
                "last_reconciliation": {"at": rec["at"], "outcome": rec["outcome"]}
                if rec
                else None,
                "gap_count": db.execute("SELECT count(*) FROM gaps").fetchone()[0],
                "gaps": [
                    {
                        k: g[k]
                        for k in (
                            "id",
                            "detected_at",
                            "boundary_from",
                            "boundary_to",
                            "reason",
                            "reconciliation_attempted",
                            "current_state_observed",
                            "history_recovered",
                        )
                    }
                    for g in gaps
                ],
                "events": [
                    {
                        "id": e["id"],
                        "at": e["event_at"],
                        "message_id": e["message_id"],
                        "transition": e["transition"],
                        "meaning": "manager_report_not_inventory_evidence",
                        "generation": e["generation"],
                    }
                    for e in events
                ],
                "history_recovered": False,
                "limit": 50,
            }
            if alert_id:
                saved = db.execute(
                    "SELECT record FROM investigations WHERE alert_id=? ORDER BY id DESC LIMIT 1",
                    (alert_id,),
                ).fetchone()
                from .reliability.timeline import validate_record

                result["investigation"] = None
                if saved:
                    record = strict_json(saved[0])
                    validate_record(record)
                    result["investigation"] = record
            return result
        except (OSError, sqlite3.Error, ValueError, TypeError):
            return {"state": "storage_or_contract_failure", "history_recovered": False}
        finally:
            if db is not None:
                db.close()
