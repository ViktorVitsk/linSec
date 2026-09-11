"""Dedicated M2c SQLite. Events, gaps and checkpoint commit atomically."""

from contextlib import contextmanager
from dataclasses import asdict
import os
from pathlib import Path
import sqlite3

from ..investigation.contracts import require
from ..model import encode, now
from ..store import private_directory, private_file
from .contracts import Batch, Checkpoint, Gap, SOURCE, State, VERSION

SCHEMA_VERSION = 1
APPLICATION_ID = 0x53454343
MIGRATION_1 = (
    """CREATE TABLE identity (singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    host_id TEXT NOT NULL, config TEXT NOT NULL)""",
    """CREATE TABLE checkpoint (source TEXT PRIMARY KEY CHECK(source='journal_user_units'),
    version INTEGER NOT NULL CHECK(version=1), cursor TEXT NOT NULL CHECK(length(cursor) BETWEEN 1 AND 1024),
    boot_id TEXT NOT NULL CHECK(length(boot_id)=32), event_at TEXT NOT NULL)""",
    """CREATE TABLE health (source TEXT PRIMARY KEY CHECK(source='journal_user_units'),
    state TEXT NOT NULL CHECK(state IN ('continuation','first_observation','cursor_unavailable',
    'cursor_invalid','cursor_lost','rotated_beyond_cursor','access_failure','access_or_source_failure','source_unavailable',
    'parser_failure','configuration_mismatch','boot_boundary')), checked_at TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation>=0), reconciled INTEGER NOT NULL DEFAULT 0,
    CHECK(reconciled>=0 AND reconciled<=generation))""",
    """CREATE TABLE events (id INTEGER PRIMARY KEY, identity TEXT NOT NULL UNIQUE CHECK(length(identity)=64),
    version INTEGER NOT NULL CHECK(version=1), cursor TEXT NOT NULL, boot_id TEXT NOT NULL,
    event_at TEXT NOT NULL, message_id TEXT NOT NULL CHECK(length(message_id)=32),
    unit TEXT NOT NULL CHECK(length(unit) BETWEEN 1 AND 256),
    transition TEXT NOT NULL CHECK(transition IN ('started','stopped','failed')),
    observed_at TEXT NOT NULL, generation INTEGER NOT NULL CHECK(generation>0))""",
    """CREATE TABLE gaps (id INTEGER PRIMARY KEY, source TEXT NOT NULL CHECK(source='journal_user_units'),
    detected_at TEXT NOT NULL, boundary_from TEXT, boundary_to TEXT,
    reason TEXT NOT NULL CHECK(reason IN ('first_observation','cursor_unavailable','cursor_invalid',
    'cursor_lost','rotated_beyond_cursor','access_failure','access_or_source_failure','source_unavailable','parser_failure',
    'configuration_mismatch','boot_boundary')),
    recoverability TEXT NOT NULL CHECK(recoverability='history_unknown'),
    reconciliation_attempted INTEGER NOT NULL DEFAULT 0 CHECK(reconciliation_attempted IN (0,1)),
    current_state_observed INTEGER NOT NULL DEFAULT 0 CHECK(current_state_observed IN (0,1)),
    history_recovered INTEGER NOT NULL DEFAULT 0 CHECK(history_recovered=0),
    unknown TEXT NOT NULL, generation INTEGER NOT NULL CHECK(generation>0))""",
    """CREATE TABLE reconciliations (id INTEGER PRIMARY KEY, at TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation>=0),
    outcome TEXT NOT NULL CHECK(outcome IN ('ok','partial','unavailable','storage_failure')),
    history_recovered INTEGER NOT NULL CHECK(history_recovered=0))""",
    "CREATE INDEX gaps_generation ON gaps(generation)",
    "CREATE INDEX events_generation ON events(generation)",
    """CREATE TABLE investigations (id INTEGER PRIMARY KEY, alert_id INTEGER NOT NULL CHECK(alert_id>0),
    at TEXT NOT NULL, record TEXT NOT NULL CHECK(length(record)<=65536))""",
    "CREATE INDEX investigations_alert ON investigations(alert_id,id)",
)


class ReliabilityStore:
    def __init__(self, directory: Path, host_id: str, config: str):
        self.directory = private_directory(directory)
        self.path = self.directory / "reliability.sqlite3"
        health_fd = private_file(self.directory / "reliability-health")
        try:
            if os.fstat(health_fd).st_size == 0:
                os.write(health_fd, b"0")
                os.fsync(health_fd)
        finally:
            os.close(health_fd)
        os.close(private_file(self.path))
        for suffix in ("-journal", "-wal", "-shm"):
            target = Path(str(self.path) + suffix)
            if target.exists() or target.is_symlink():
                os.close(private_file(target))
        self.db = sqlite3.connect(self.path, timeout=1, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        try:
            self.db.execute("PRAGMA foreign_keys=ON")
            self.db.execute("PRAGMA trusted_schema=OFF")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA journal_mode=DELETE")
            self.db.execute("PRAGMA temp_store=MEMORY")
            self.db.execute("PRAGMA cache_size=-2048")
            page_size = self.db.execute("PRAGMA page_size").fetchone()[0]
            pages = 32 * 1024 * 1024 // page_size  # Another 32 MiB reserved for rollback journal.
            require(
                self.db.execute("PRAGMA page_count").fetchone()[0] <= pages,
                "reliability_storage_budget",
            )
            self.db.execute(f"PRAGMA max_page_count={int(pages)}")
            with self.transaction():
                version = self.db.execute("PRAGMA user_version").fetchone()[0]
                if version == 0:
                    require(not self.db.execute("SELECT 1 FROM sqlite_master").fetchone())
                    for sql in MIGRATION_1:
                        self.db.execute(sql)
                    self.db.execute("INSERT INTO identity VALUES (1,?,?)", (host_id, config))
                    self.db.execute(f"PRAGMA application_id={APPLICATION_ID}")
                    self.db.execute("PRAGMA user_version=1")
                require(version in {0, SCHEMA_VERSION}, "unsupported_reliability_schema")
                require(self.db.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID)
                row = self.db.execute(
                    "SELECT host_id,config FROM identity WHERE singleton=1"
                ).fetchone()
                require(tuple(row) == (host_id, config), "reliability_identity_mismatch")
        except BaseException:
            self.db.close()
            raise

    def close(self) -> None:
        self.db.close()

    @contextmanager
    def transaction(self):
        try:
            self.db.execute("BEGIN IMMEDIATE")
            yield
            self.db.execute("COMMIT")
            self.mark_failure(False)
        except BaseException as error:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            if isinstance(error, (OSError, sqlite3.Error)):
                self.mark_failure(True)
            raise

    def mark_failure(self, failed: bool) -> None:
        try:
            fd = private_file(self.directory / "reliability-health")
            try:
                os.pwrite(fd, b"1" if failed else b"0", 0)
                os.fsync(fd)
            finally:
                os.close(fd)
        except (OSError, ValueError):
            pass

    def checkpoint(self) -> Checkpoint | None:
        row = self.db.execute("SELECT * FROM checkpoint WHERE source=?", (SOURCE,)).fetchone()
        return (
            Checkpoint(row["cursor"], row["boot_id"], row["event_at"], row["version"])
            if row
            else None
        )

    def ingest(self, previous: Checkpoint | None, batch: Batch, at: str | None = None) -> int:
        batch.validate()
        at = at or now()
        with self.transaction():
            require(self.checkpoint() == previous, "checkpoint_conflict")
            if batch.anchor_checkpoint:
                require(batch.anchor_checkpoint == previous, "checkpoint_conflict")
                known_anchor = self.db.execute(
                    "SELECT 1 FROM events WHERE identity=?",
                    (previous.identity,),
                ).fetchone()
                require(not known_anchor or batch.anchor is not None, "conflicting_event_identity")
            health = self.db.execute("SELECT * FROM health WHERE source=?", (SOURCE,)).fetchone()
            generation = (health["generation"] if health else 0) + 1
            inserted = 0
            for event in ((batch.anchor,) if batch.anchor else ()) + batch.events:
                cp = event.checkpoint
                old = self.db.execute(
                    "SELECT * FROM events WHERE identity=?", (event.identity,)
                ).fetchone()
                fields = (
                    VERSION,
                    cp.cursor,
                    cp.boot_id,
                    cp.event_at,
                    event.message_id,
                    event.unit,
                    event.transition,
                )
                if old:
                    require(
                        tuple(
                            old[k]
                            for k in (
                                "version",
                                "cursor",
                                "boot_id",
                                "event_at",
                                "message_id",
                                "unit",
                                "transition",
                            )
                        )
                        == fields,
                        "conflicting_event_identity",
                    )
                    continue
                self.db.execute(
                    "INSERT INTO events(identity,version,cursor,boot_id,event_at,message_id,unit,transition,observed_at,generation) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (event.identity, *fields, at, generation),
                )
                inserted += 1
            gap = batch.state != State.CONTINUATION
            # One gap per unchanged failure episode; a resumed continuation permits a new episode.
            new_gap = gap and (
                not health
                or health["state"] != batch.state
                or batch.checkpoint is not None
                and batch.checkpoint != previous
            )
            if new_gap:
                value = Gap(
                    SOURCE,
                    at,
                    previous.event_at if previous else None,
                    batch.checkpoint.event_at if batch.checkpoint else None,
                    batch.state,
                )
                data = asdict(value)
                self.db.execute(
                    "INSERT INTO gaps(source,detected_at,boundary_from,boundary_to,reason,recoverability,reconciliation_attempted,current_state_observed,history_recovered,unknown,generation) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (*data.values(), generation),
                )
            needs_scan = bool(inserted or new_gap)
            generation = generation if needs_scan else generation - 1
            self.db.execute(
                "INSERT INTO health(source,state,checked_at,generation) VALUES (?,?,?,?) ON CONFLICT(source) DO UPDATE SET state=excluded.state,checked_at=excluded.checked_at,generation=excluded.generation",
                (SOURCE, batch.state, at, generation),
            )
            if batch.checkpoint:
                cp = batch.checkpoint
                self.db.execute(
                    "INSERT INTO checkpoint VALUES (?,?,?,?,?) ON CONFLICT(source) DO UPDATE SET version=excluded.version,cursor=excluded.cursor,boot_id=excluded.boot_id,event_at=excluded.event_at",
                    (SOURCE, cp.version, cp.cursor, cp.boot_id, cp.event_at),
                )
            return generation

    def pending(self) -> bool:
        row = self.db.execute(
            "SELECT generation>reconciled FROM health WHERE source=?", (SOURCE,)
        ).fetchone()
        return bool(row and row[0])

    def reconciled(
        self,
        generation: int,
        outcome: str,
        at: str | None = None,
        *,
        current_observed: bool = False,
    ) -> None:
        require(outcome in {"ok", "partial", "unavailable", "storage_failure"})
        require(type(current_observed) is bool)
        require(not current_observed or outcome in {"ok", "partial"})
        with self.transaction():
            self.db.execute(
                "INSERT INTO reconciliations(at,generation,outcome,history_recovered) VALUES (?,?,?,0)",
                (at or now(), generation, outcome),
            )
            self.db.execute(
                "UPDATE gaps SET reconciliation_attempted=1,current_state_observed=max(current_state_observed,?) WHERE generation<=?",
                (int(outcome == "ok" or current_observed), generation),
            )
            if outcome != "storage_failure":
                self.db.execute(
                    "UPDATE health SET reconciled=max(reconciled,?) WHERE source=?",
                    (generation, SOURCE),
                )

    def save_investigation(self, alert_id: int, record: dict) -> None:
        from .timeline import validate_record

        validate_record(record)
        payload = encode(record)
        require(type(alert_id) is int and 0 < alert_id < 2**31 and len(payload) <= 65536)
        with self.transaction():
            self.db.execute(
                "INSERT INTO investigations(alert_id,at,record) VALUES (?,?,?)",
                (alert_id, now(), payload),
            )
