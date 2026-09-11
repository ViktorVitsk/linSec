"""Read-only M2a evidence and deny-by-default export projection. No raw text export."""

from contextlib import contextmanager
from datetime import datetime
import ipaddress
from pathlib import Path
import os
import sqlite3
import stat

from ..explanations import GUIDANCE
from ..model import (
    MAX_PAYLOAD,
    SOURCES,
    Collection,
    decode_items,
    detector,
    digest,
    encode,
    now,
)
from .contracts import integer, require

LIMITS = [
    "Baseline — acknowledged state, не доказательство чистоты хоста.",
    "Listener inventory не доказывает WAN reachability; доступ из Интернета неизвестен.",
    "Partial/устаревшие observations не подтверждают текущее наличие или отсутствие.",
    "Metadata и model output недоверенные; AI не меняет severity или состояние alert.",
    "Псевдонимы скрывают детали; происхождение изменения необходимо проверить локально.",
]


def timestamp(value):
    require(isinstance(value, str) and len(value) <= 40)
    try:
        parsed = datetime.fromisoformat(value)
        require(parsed.utcoffset().total_seconds() == 0)
        return parsed.isoformat()
    except (ValueError, AttributeError) as error:
        raise ValueError("invalid_evidence_timestamp") from error


class EvidenceReader:
    """Never initialize/migrate a database or write monitoring state."""

    def __init__(self, directory: Path):
        path = directory.absolute() / "watchdog.sqlite3"
        require(not any(p.is_symlink() for p in (path, *path.parents)), "evidence_symlink")
        for target in (path.parent, path):
            info = target.stat()
            require(
                info.st_uid == os.getuid() and not info.st_mode & 0o077,
                "evidence_requires_private_owned_files",
            )
        require(stat.S_ISREG(path.stat().st_mode) and path.stat().st_nlink == 1)
        self.db = sqlite3.connect(
            path.as_uri() + "?mode=ro", uri=True, timeout=1, isolation_level=None
        )
        try:
            self.db.row_factory = sqlite3.Row
            self.db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_PAYLOAD + 65536)
            self.db.execute("PRAGMA query_only=ON")
            self.db.execute("PRAGMA trusted_schema=OFF")
            self.db.execute("PRAGMA temp_store=MEMORY")
            self.db.set_progress_handler(lambda: 1 if self._ticks_exceeded() else 0, 10000)
            self._ticks = 0
            require(
                self.db.execute("PRAGMA user_version").fetchone()[0] == 2,
                "investigation_requires_M2a_database_v2",
            )
            # Views/triggers in a locally replaced database are not application tables.
            for name in ("alerts", "snapshots", "sources", "baseline", "metadata"):
                row = self.db.execute(
                    "SELECT type FROM sqlite_master WHERE name=?", (name,)
                ).fetchone()
                require(row is not None and row[0] == "table")
        except BaseException:
            self.db.close()
            raise

    def _ticks_exceeded(self):
        self._ticks += 1
        return self._ticks > 2000

    @contextmanager
    def read(self):
        self._ticks = 0
        self.db.execute("BEGIN")
        try:
            yield
        finally:
            self.db.execute("ROLLBACK")

    def close(self):
        self.db.close()

    def one(self, sql, params):
        row = self.db.execute(sql, params).fetchone()
        require(row is not None, "missing_evidence")
        return dict(row)


class PackBuilder:
    def __init__(self, reader: EvidenceReader, stale_seconds: int = 900, clock=now):
        self.reader, self.stale_seconds, self.clock = reader, stale_seconds, clock
        self.aliases = {}
        self.raw_revisions = []

    def alias(self, category, value):
        key = (category, encode(value))
        if key not in self.aliases:
            self.aliases[key] = f"{category}-{len(self.aliases) + 1}"
        return self.aliases[key]

    def record(self, item):
        if item is None:
            return None
        kind = item["kind"]
        data = {"kind": kind}
        if kind == "endpoint":
            address = ipaddress.ip_address(item["bind"].split("%", 1)[0])
            data.update(
                protocol=item["protocol"],
                family=item["family"],
                port=item["port"],
                bind_class="wildcard"
                if address.is_unspecified
                else "loopback"
                if address.is_loopback
                else "private"
                if address.is_private
                else "other",
                bind_alias=self.alias("address", item["bind"]),
                context_complete=item["context_complete"],
                uid_is_root=item["uid"] == 0,
                owner_count=len(item["owners"]),
                owners=[
                    {
                        "exe": self.alias("executable", o["exe"]),
                        "user": self.alias("user", o["uid"]),
                        "uid_is_root": o["uid"] == 0,
                    }
                    for o in item["owners"][:8]
                ],
                owners_truncated=len(item["owners"]) > 8,
            )
        elif kind == "file":
            data.update(
                path=self.alias("path", item["path"]),
                exists=item["exists"],
                mode=item["mode"],
                uid_is_root=item["uid"] == 0,
            )
            for field in ("sha256", "link_sha256", "uid", "gid"):
                data[field] = self.alias(field, item[field]) if item[field] is not None else None
        elif kind == "unit":
            data.update(
                name=self.alias("unit", item["name"]),
                scope=item["scope"] if item["scope"] in ("user", "system") else "unknown",
                enablement=item["enablement"]
                if item["enablement"]
                in (
                    "enabled",
                    "disabled",
                    "static",
                    "masked",
                    "indirect",
                    "alias",
                    "generated",
                    "transient",
                    "enabled-runtime",
                    "masked-runtime",
                )
                else "unknown",
            )
        elif kind in ("uid0", "group"):
            data.update(name=self.alias(kind, item["name"]), gid=self.alias("gid", item["gid"]))
            if kind == "uid0":
                data["uid_is_root"] = True
            else:
                data.update(
                    member_count=len(item["members"]),
                    members=[self.alias("member", m) for m in item["members"][:16]],
                    members_truncated=len(item["members"]) > 16,
                )
        return data

    def snapshot(self, snapshot_id, source, key):
        if snapshot_id is None:
            return None, None
        require(integer(snapshot_id, 1))
        row = self.reader.one("SELECT * FROM snapshots WHERE id=?", (snapshot_id,))
        require(
            row["source"] == source
            and row["schema_version"] == 1
            and row["collector_version"] == "1",
            "unsupported_evidence_contract",
        )
        items = decode_items(row["data"])
        Collection(
            source, items, row["completeness"], scope=row["scope"], collected_at=row["created_at"]
        ).validate()
        self.raw_revisions.append(digest(row))
        return items.get(key), {
            "id": f"snapshot:{snapshot_id}",
            "source": source,
            "schema_version": 1,
            "collector_version": "1",
            "collected_at": timestamp(row["created_at"]),
            "completeness": row["completeness"],
            "scope": self.alias("scope", row["scope"]),
            "stale": not 0
            <= (
                datetime.fromisoformat(self.clock()) - datetime.fromisoformat(row["created_at"])
            ).total_seconds()
            <= self.stale_seconds,
            "untrusted_record": self.record(items.get(key)),
            "absence_is_deletion": False,
        }

    def alert(self, alert_id):
        require(integer(alert_id, 1))
        row = self.reader.one("SELECT * FROM alerts WHERE id=?", (alert_id,))
        source, key = row["source"], row["object_key"]
        require(source in SOURCES and isinstance(key, str) and len(key) <= 4096)
        before, pre = self.snapshot(row["before_id"], source, key)
        after, post = self.snapshot(row["after_id"], source, key)
        require(before != after and (before is not None or after is not None))
        change = {
            "key": key,
            "before": before,
            "after": after,
            "change": "added" if before is None else "removed" if after is None else "changed",
        }
        finding = detector(source, change)
        require(
            all(
                row[k] == finding[k]
                for k in (
                    "context",
                    "detector_id",
                    "detector_version",
                    "severity",
                )
            )
            and row["change_type"] == change["change"],
            "inconsistent_detector_evidence",
        )
        self.raw_revisions.append(digest(row))
        return (
            row,
            {
                "id": f"alert:{alert_id}",
                "source": source,
                "detector_id": finding["detector_id"],
                "detector_version": 1,
                "severity": finding["severity"],
                "change": change["change"],
                "first_seen": timestamp(row["first_seen"]),
                "last_seen": timestamp(row["last_seen"]),
                "observations": [r for r in (pre, post) if r is not None],
            },
            (after or before)["kind"],
        )

    def build(self, alert_id, history_limit=0):
        self.aliases, self.raw_revisions = {}, []
        with self.reader.read():
            row, alert, kind = self.alert(alert_id)
            source = self.reader.one("SELECT * FROM sources WHERE source=?", (row["source"],))
            require(source["status"] in ("ok", "partial", "unavailable"))
            at = timestamp(source["collected_at"])
            age = (
                datetime.fromisoformat(self.clock()) - datetime.fromisoformat(at)
            ).total_seconds()
            coverage = {
                "status": source["status"],
                "collected_at": at,
                "stale": not 0 <= age <= self.stale_seconds,
            }
            base = self.reader.db.execute(
                "SELECT snapshot_id FROM baseline WHERE source=?", (row["source"],)
            ).fetchone()
            baseline = None
            if base:
                _, baseline = self.snapshot(base[0], row["source"], row["object_key"])
            history = []
            require(integer(history_limit, 0, 5))
            if history_limit:
                for other in self.reader.db.execute(
                    "SELECT id FROM alerts WHERE source=? AND object_key=? AND id<>? "
                    "ORDER BY last_seen DESC,id DESC LIMIT ?",
                    (row["source"], row["object_key"], alert_id, history_limit),
                ).fetchall():
                    _, item, _ = self.alert(other[0])
                    history.append(item)
            self.raw_revisions.append(digest(source))
            pack = {
                "schema_version": 1,
                "alert": alert,
                "source_coverage": coverage,
                "baseline": baseline,
                "history": history,
                "runbook": {"id": f"runbook:{kind}:1", **GUIDANCE[kind]},
                "limitations": LIMITS,
                "untrusted_evidence": True,
                "privacy": "metadata_aliases_v1; raw strings/reasons/content omitted",
            }
            require(len(encode(pack)) <= 24000, "evidence_pack_limit")
            # Local approval binding only; never part of the provider request.
            return pack, digest(self.raw_revisions)


def references(pack):
    refs = {pack["alert"]["id"], pack["runbook"]["id"]}
    for alert in [pack["alert"], *pack["history"]]:
        refs.add(alert["id"])
        refs.update(s["id"] for s in alert["observations"])
    if pack["baseline"]:
        refs.add(pack["baseline"]["id"])
    return refs


def fallback(pack, reason):
    return {
        "schema_version": 1,
        "mode": "deterministic",
        "reason": reason,
        "summary": "Обнаружен drift; причина и легитимность требуют ручной проверки.",
        "detector": pack["alert"],
        "guidance": pack["runbook"],
        "source_coverage": pack["source_coverage"],
        "limitations": LIMITS,
        "references": sorted(references(pack)),
        "automatic_action": "Отсутствует",
    }
