"""SQLite persistence and private runtime files. All writes are local application state."""

from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
import stat
import uuid

from .model import InvalidInput


MIGRATION_1 = (
    "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    """CREATE TABLE snapshots (
        id INTEGER PRIMARY KEY, host_id TEXT NOT NULL, source TEXT NOT NULL,
        schema_version INTEGER NOT NULL, collector_version TEXT NOT NULL,
        created_at TEXT NOT NULL, scope TEXT NOT NULL, completeness TEXT NOT NULL,
        fingerprint TEXT NOT NULL, data TEXT NOT NULL)""",
    """CREATE TABLE sources (
        source TEXT PRIMARY KEY, status TEXT NOT NULL, reason TEXT NOT NULL,
        collected_at TEXT NOT NULL, last_ok TEXT, scope TEXT NOT NULL,
        snapshot_id INTEGER REFERENCES snapshots(id))""",
    """CREATE TABLE baseline (
        source TEXT PRIMARY KEY, snapshot_id INTEGER NOT NULL REFERENCES snapshots(id))""",
    """CREATE TABLE alerts (
        id INTEGER PRIMARY KEY, context TEXT NOT NULL UNIQUE, source TEXT NOT NULL,
        object_key TEXT NOT NULL, detector_id TEXT NOT NULL, detector_version INTEGER NOT NULL,
        severity TEXT NOT NULL, change_type TEXT NOT NULL,
        before_id INTEGER REFERENCES snapshots(id), after_id INTEGER NOT NULL REFERENCES snapshots(id),
        first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, occurrences INTEGER NOT NULL,
        lifecycle TEXT NOT NULL CHECK(lifecycle IN ('open','reviewed','closed')),
        active INTEGER NOT NULL, notified INTEGER NOT NULL DEFAULT 0)""",
    "CREATE INDEX alerts_time ON alerts(last_seen)",
    """CREATE TABLE exceptions (
        id INTEGER PRIMARY KEY, context TEXT NOT NULL, kind TEXT NOT NULL,
        reason TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT,
        provenance TEXT NOT NULL, UNIQUE(context,kind))""",
    """CREATE TABLE audit (
        id INTEGER PRIMARY KEY, at TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL)""",
)

MIGRATION_2 = (
    "ALTER TABLE baseline ADD COLUMN collected_at TEXT",
    "ALTER TABLE baseline ADD COLUMN last_ok TEXT",
    "ALTER TABLE baseline ADD COLUMN reason TEXT",
)


def private_directory(path: Path) -> Path:
    # Refuse symlink components and permissive existing runtime directories instead of chmod.
    path = path.absolute()
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise InvalidInput("runtime_symlink_refused")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise InvalidInput("runtime_requires_owned_private_directory")
    return path


def private_file(path: Path) -> int:
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
        or info.st_nlink != 1
    ):
        os.close(fd)
        raise InvalidInput("runtime_requires_owned_private_regular_file")
    return fd


class Store:
    def __init__(self, directory: Path, storage_mib: int = 512):
        self.directory = private_directory(directory)
        self.path = self.directory / "watchdog.sqlite3"
        self.budget = storage_mib * 1024 * 1024
        health_fd = private_file(self.directory / "storage-health")
        try:
            if os.fstat(health_fd).st_size == 0:
                os.write(health_fd, b"0")
                os.fsync(health_fd)
        finally:
            os.close(health_fd)
        os.close(private_file(self.path))
        for suffix in ("-journal", "-wal", "-shm"):
            sidecar = Path(str(self.path) + suffix)
            if sidecar.exists() or sidecar.is_symlink():
                os.close(private_file(sidecar))
        self.db = sqlite3.connect(self.path, timeout=2, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        try:
            self.db.execute("PRAGMA foreign_keys=ON")
            self.db.execute("PRAGMA trusted_schema=OFF")
            self.db.execute("PRAGMA temp_store=MEMORY")
            self.db.execute("PRAGMA cache_size=-4096")
            self.db.execute("PRAGMA journal_mode=DELETE")
            self.db.execute("PRAGMA synchronous=FULL")
            page_size = self.db.execute("PRAGMA page_size").fetchone()[0]
            # Reserve half the budget for rollback journal and a 1 MiB control margin.
            max_pages = (self.budget - 1024 * 1024) // 2 // page_size
            if self.db.execute("PRAGMA page_count").fetchone()[0] > max_pages:
                raise InvalidInput("storage_budget_exceeded")
            self.db.execute(f"PRAGMA max_page_count={int(max_pages)}")
            with self.transaction():
                version = self.db.execute("PRAGMA user_version").fetchone()[0]
                if version not in {0, 1, 2}:
                    raise InvalidInput("unsupported_database_version")
                if version == 0:
                    for statement in MIGRATION_1:
                        self.db.execute(statement)
                    self.db.execute(
                        "INSERT INTO metadata VALUES ('host_id', ?)", (str(uuid.uuid4()),)
                    )
                    self.db.execute("INSERT INTO metadata VALUES ('baseline_revision', '0')")
                    self.db.execute("PRAGMA user_version=1")
                if version < 2:
                    for statement in MIGRATION_2:
                        self.db.execute(statement)
                    # Legacy acceptance metadata is unknown, not reconstructed from current sources.
                    self.db.execute("PRAGMA user_version=2")
        except BaseException:
            self.db.close()
            raise

    def close(self) -> None:
        self.db.close()

    def mark_storage_error(self, failed: bool) -> None:
        # A preallocated byte provides best-effort health even when SQLite cannot grow.
        # If the filesystem also rejects this write, CLI stderr/nonzero exit remains the signal.
        try:
            fd = private_file(self.directory / "storage-health")
            try:
                os.pwrite(fd, b"1" if failed else b"0", 0)
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            pass

    def storage_failed(self) -> bool:
        fd = private_file(self.directory / "storage-health")
        try:
            return os.pread(fd, 2, 0) != b"0"
        finally:
            os.close(fd)

    @contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.execute("COMMIT")
        except BaseException as error:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            if isinstance(error, (OSError, sqlite3.Error)):
                self.mark_storage_error(True)
            raise

    def meta(self, key: str) -> str:
        row = self.db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
        if row is None:
            raise InvalidInput("missing_database_metadata")
        return row[0]

    def rows(self, sql: str, params: tuple = ()) -> list[dict]:
        # Internal SQL only. User values always use bind parameters.
        return [dict(row) for row in self.db.execute(sql, params)]

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
