"""Isolated bounded synthetic posture store and shared read-only query operations."""

from datetime import datetime
import os
from pathlib import Path
import sqlite3
import stat
import time

from ..investigation.contracts import require, strict_json
from ..model import digest, encode, now
from ..queries import read_private
from ..store import private_directory, private_file
from .contracts import MAX_CONTAINERS, MAX_RECORD, Result, hex_id, instant, record
from .detection import RULES, context, drift, posture

APPLICATION_ID = 0x53454344
MAX_ROWS = 512
MAX_DATABASE = 8 * 1024 * 1024  # Another 8 MiB reserved for the rollback journal.
SCHEMA = (
    "CREATE TABLE health (singleton INTEGER PRIMARY KEY CHECK(singleton=1), source TEXT NOT NULL, at TEXT NOT NULL, status TEXT NOT NULL, reason TEXT NOT NULL)",
    "CREATE TABLE evidence (ref TEXT PRIMARY KEY, data TEXT NOT NULL)",
    "CREATE TABLE objects (id TEXT PRIMARY KEY, complete_ref TEXT REFERENCES evidence(ref), current_ref TEXT REFERENCES evidence(ref), last_seen TEXT NOT NULL, presence TEXT NOT NULL)",
    "CREATE TABLE findings (id INTEGER PRIMARY KEY, context TEXT UNIQUE NOT NULL, object_id TEXT NOT NULL, rule TEXT NOT NULL, kind TEXT NOT NULL, state TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, before_ref TEXT REFERENCES evidence(ref), after_ref TEXT REFERENCES evidence(ref))",
)


def check_private_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.getuid()
            and not info.st_mode & 0o077
            and info.st_nlink == 1
            and info.st_size <= MAX_DATABASE
        )
    finally:
        os.close(fd)


def open_reader(directory):
    directory = directory.absolute()
    require(not any(p.is_symlink() for p in (directory, *directory.parents)))
    info = directory.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077)
    path = directory / "docker-posture.sqlite3"
    # Validate metadata without materializing the DB or creating any runtime file.
    check_private_file(path)
    for suffix in ("-journal", "-wal", "-shm"):
        candidate = Path(str(path) + suffix)
        if candidate.exists() or candidate.is_symlink():
            check_private_file(candidate)
    db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=1, isolation_level=None)
    try:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA temp_store=MEMORY")
        db.execute("PRAGMA cache_size=-1024")
        deadline = time.monotonic() + 1
        db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        require(db.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID)
        require(db.execute("PRAGMA user_version").fetchone()[0] == 1)
        return db
    except BaseException:
        db.close()
        raise


def evidence(db, ref):
    if ref is None:
        return None
    require(hex_id(ref))
    row = db.execute(
        "SELECT substr(data,1,?) FROM evidence WHERE ref=?", (MAX_RECORD + 1, ref)
    ).fetchone()
    require(row is not None)
    value = record(strict_json(row[0], MAX_RECORD))
    require(digest(value) == ref)
    return value


class PostureStore:
    """Writes only synthetic state, with atomic inventories and fail-closed budgets."""

    def __init__(self, directory: Path):
        self.directory = private_directory(directory)
        self.path = self.directory / "docker-posture.sqlite3"
        os.close(private_file(self.path))
        for suffix in ("-journal", "-wal", "-shm"):
            candidate = Path(str(self.path) + suffix)
            if candidate.exists() or candidate.is_symlink():
                os.close(private_file(candidate))
        self.db = sqlite3.connect(self.path, timeout=1, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        try:
            self.db.execute("PRAGMA foreign_keys=ON")
            self.db.execute("PRAGMA trusted_schema=OFF")
            self.db.execute("PRAGMA journal_mode=DELETE")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA temp_store=MEMORY")
            self.db.execute("PRAGMA cache_size=-1024")
            pages = MAX_DATABASE // self.db.execute("PRAGMA page_size").fetchone()[0]
            require(self.db.execute("PRAGMA page_count").fetchone()[0] <= pages)
            self.db.execute(f"PRAGMA max_page_count={int(pages)}")
            self.db.execute("BEGIN IMMEDIATE")
            version = self.db.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                require(not self.db.execute("SELECT 1 FROM sqlite_master").fetchone())
                for sql in SCHEMA:
                    self.db.execute(sql)
                self.db.execute(f"PRAGMA application_id={APPLICATION_ID}")
                self.db.execute("PRAGMA user_version=1")
            require(version in {0, 1})
            require(self.db.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID)
            self.db.execute("COMMIT")
        except BaseException:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def mark_failure(self, failed):
        try:
            fd = private_file(self.directory / "docker-health")
            try:
                os.pwrite(fd, b"1" if failed else b"0", 0)
                os.ftruncate(fd, 1)
                os.fsync(fd)
            finally:
                os.close(fd)
        except (OSError, ValueError):
            pass  # Caller still fails; missing/invalid marker is degraded on reads.

    def ingest(self, result: Result):
        result.validate()
        db = self.db
        deadline = time.monotonic() + 2
        db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        try:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute("SELECT * FROM health WHERE singleton=1").fetchone()
            if previous:
                require(previous["source"] == result.source_id, "docker_source_mismatch")
                require(result.collected_at > previous["at"], "docker_observation_not_newer")
            known = {r["id"]: dict(r) for r in db.execute("SELECT * FROM objects")}
            require(
                len(known.keys() | result.containers.keys()) <= MAX_CONTAINERS,
                "docker_inventory_union_limit",
            )
            db.execute("UPDATE objects SET presence='unknown' WHERE presence!='absent'")
            db.execute(
                "UPDATE findings SET state='unknown' WHERE kind='posture' AND state!='resolved'"
            )
            for key, item in result.containers.items():
                prior = known.get(key)
                before_ref = prior["complete_ref"] if prior else None
                before = evidence(db, before_ref)
                ref = digest(item)
                db.execute("INSERT OR IGNORE INTO evidence VALUES (?,?)", (ref, encode(item)))
                complete = all(v is not None for v in item.values())
                if not prior or prior["presence"] == "absent":
                    self._finding(result, key, "container_added", "change", None, ref, ref)
                if before:
                    fields = drift(before, item)
                    if fields:
                        self._finding(
                            result,
                            key,
                            "configuration_drift",
                            "change",
                            before_ref,
                            ref,
                            {k: [before[k], item[k]] for k in fields},
                        )
                if complete:
                    db.execute(
                        "UPDATE findings SET state='resolved' WHERE object_id=? AND kind='posture'",
                        (key,),
                    )
                for rule, facts in posture(item):
                    self._finding(result, key, rule, "posture", None, ref, facts)
                db.execute(
                    """INSERT INTO objects VALUES (?,?,?,?, 'observed') ON CONFLICT(id) DO UPDATE SET
                    complete_ref=excluded.complete_ref,current_ref=excluded.current_ref,last_seen=excluded.last_seen,presence='observed'""",
                    (key, ref if complete else before_ref, ref, result.collected_at),
                )
            if result.status == "ok":
                for key, prior in known.items():
                    if key not in result.containers and prior["presence"] != "absent":
                        self._finding(
                            result,
                            key,
                            "container_removed",
                            "change",
                            prior["current_ref"],
                            None,
                            prior["current_ref"],
                        )
                        db.execute("UPDATE objects SET presence='absent' WHERE id=?", (key,))
                        db.execute(
                            "UPDATE findings SET state='resolved' WHERE object_id=? AND kind='posture'",
                            (key,),
                        )
            db.execute(
                "INSERT INTO health VALUES (1,?,?,?,?) ON CONFLICT(singleton) DO UPDATE SET at=excluded.at,status=excluded.status,reason=excluded.reason",
                (result.source_id, result.collected_at, result.status, result.reason),
            )
            require(
                db.execute("SELECT count(*) FROM evidence").fetchone()[0] <= MAX_ROWS,
                "docker_evidence_budget",
            )
            require(
                db.execute("SELECT count(*) FROM findings").fetchone()[0] <= MAX_ROWS,
                "docker_findings_budget",
            )
            db.execute("COMMIT")
            self.mark_failure(False)
        except BaseException:
            db.set_progress_handler(None, 0)
            if db.in_transaction:
                db.execute("ROLLBACK")
            self.mark_failure(True)
            raise
        finally:
            db.set_progress_handler(None, 0)

    def _finding(self, result, key, rule, kind, before, after, facts):
        self.db.execute(
            """INSERT INTO findings(context,object_id,rule,kind,state,first_seen,last_seen,before_ref,after_ref)
            VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(context) DO UPDATE SET last_seen=excluded.last_seen,state=excluded.state""",
            (
                context(result.source_id, key, rule, facts),
                key,
                rule,
                kind,
                "observed" if kind == "posture" else "recorded",
                result.collected_at,
                result.collected_at,
                before,
                after,
            ),
        )


class PostureQueries:
    def __init__(self, directory: Path | None, clock=now):
        self.directory, self.clock = directory, clock

    def overview(self, limit=25, before=2**63 - 1):
        require(type(limit) is int and 1 <= limit <= 100, "invalid_page_limit")
        require(type(before) is int and 1 <= before <= 2**63 - 1, "invalid_page_cursor")
        if self.directory is None:
            return {
                "schema_version": 1,
                "state": "not_configured",
                "host_validated": False,
                "items": [],
                "next_before": None,
            }
        db = open_reader(self.directory)
        try:
            db.execute("BEGIN")
            health = db.execute("SELECT * FROM health WHERE singleton=1").fetchone()
            require(health is not None and hex_id(health["source"]))
            Result(
                health["source"], health["at"], health["status"], health["reason"], {}
            ).validate()
            age = (
                datetime.fromisoformat(instant(self.clock())) - datetime.fromisoformat(health["at"])
            ).total_seconds()
            items = []
            for row in db.execute(
                "SELECT * FROM findings WHERE id<? ORDER BY id DESC LIMIT ?", (before, limit + 1)
            ):
                require(row["rule"] in RULES and hex_id(row["object_id"]))
                require(
                    row["kind"] in {"posture", "change"}
                    and row["state"] in {"observed", "unknown", "resolved", "recorded"}
                )
                severity, summary = RULES[row["rule"]]
                items.append(
                    {
                        "id": row["id"],
                        "object_id": row["object_id"],
                        "rule": row["rule"],
                        "detector_version": 1,
                        "kind": row["kind"],
                        "state": row["state"],
                        "severity": severity,
                        "summary": summary,
                        "at": instant(row["last_seen"]),
                    }
                )
            try:
                failed = read_private(self.directory / "docker-health", 1) != b"0"
            except (OSError, ValueError):
                failed = True
            return {
                "schema_version": 1,
                "state": health["status"],
                "reason": health["reason"],
                "origin": "synthetic",
                "host_validated": False,
                "at": health["at"],
                "stale": age < 0 or age > 300,
                "storage_failure": failed,
                "items": items[:limit],
                "next_before": items[limit - 1]["id"] if len(items) > limit else None,
                "notice": "Только synthetic evidence. Нет оценки безопасности текущего хоста, принятого Docker baseline или автоматических действий.",
            }
        finally:
            db.close()

    def detail(self, finding_id):
        require(type(finding_id) is int and 1 <= finding_id <= 2**31 - 1, "invalid_alert_id")
        require(self.directory is not None, "docker_not_configured")
        db = open_reader(self.directory)
        try:
            db.execute("BEGIN")
            row = db.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
            require(row is not None, "alert_not_found")
            require(row["rule"] in RULES and hex_id(row["object_id"]))
            before, after = evidence(db, row["before_ref"]), evidence(db, row["after_ref"])
            return {
                "schema_version": 1,
                "origin": "synthetic",
                "host_validated": False,
                "id": finding_id,
                "object_id": row["object_id"],
                "rule": row["rule"],
                "summary": RULES[row["rule"]][1],
                "before": before,
                "after": after,
                "changed_fields": drift(before, after) if before and after else [],
                "at": instant(row["last_seen"]),
                "before_ref": row["before_ref"],
                "after_ref": row["after_ref"],
                "manual_check": "Сопоставьте выбранные поля с ожидаемой конфигурацией workload. Проверка настоящего daemon требует отдельного согласованного способа доступа; не выводите полный inspect или env.",
                "limitations": "Snapshot может пропустить кратковременные изменения. Rootless/userns, firewall, маршруты, фактические UID/capabilities и WAN-доступность не проверены.",
                "automatic_action": "none",
            }
        finally:
            db.close()
