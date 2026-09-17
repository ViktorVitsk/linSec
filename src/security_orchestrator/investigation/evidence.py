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


GENERIC_SUMMARY = "Обнаружен drift; причина и легитимность требуют ручной проверки."
_PROTOCOLS = {"tcp": "TCP", "udp": "UDP"}
_FAMILIES = {4: "IPv4", 6: "IPv6"}
_BIND_CLASSES = {
    "wildcard": "wildcard",
    "loopback": "loopback",
    "private": "частный адрес",
    "other": "иная",
}
_ENDPOINT_COMPARE = (
    "protocol",
    "family",
    "port",
    "bind_class",
    "context_complete",
    "uid_is_root",
    "owner_count",
    "owners_truncated",
)
_INSUFFICIENT_CHANGE = "Контекст изменился; доступных сведений недостаточно для детализации."


def _observation_pair(alert):
    observations = alert.get("observations")
    if not isinstance(observations, list) or not observations:
        return None, None
    if len(observations) == 1:
        if alert.get("change") == "removed":
            return observations[0], None
        return None, observations[0]
    return observations[0], observations[-1]


def _projected_endpoint(observation):
    if not isinstance(observation, dict):
        return None
    record = observation.get("untrusted_record")
    if isinstance(record, dict) and record.get("kind") == "endpoint":
        return record
    return None


def _endpoint_facts(record):
    if not isinstance(record, dict):
        return None
    protocol = _PROTOCOLS.get(record.get("protocol"))
    family = _FAMILIES.get(record.get("family"))
    bind = _BIND_CLASSES.get(record.get("bind_class"))
    port = record.get("port")
    if protocol is None or family is None or bind is None:
        return None
    if type(port) is not int or not 1 <= port <= 65535:
        return None
    return f"{protocol}, {family}, порт {port}, категория bind {bind}"


def _changed_clause(before, after):
    if not isinstance(before, dict) or not isinstance(after, dict):
        return _INSUFFICIENT_CHANGE
    if before.get("kind") != "endpoint" or after.get("kind") != "endpoint":
        return _INSUFFICIENT_CHANGE
    owners_differ = before.get("owners") != after.get("owners")
    field_diff = {key for key in _ENDPOINT_COMPARE if before.get(key) != after.get(key)}
    # Truncation can hide the actual delta; do not invent a specific owner change.
    if not owners_differ and field_diff <= {"owners_truncated"}:
        return _INSUFFICIENT_CHANGE
    context = owners_differ or bool(field_diff & {"uid_is_root", "owner_count", "owners_truncated"})
    completeness = "context_complete" in field_diff
    bind = "bind_class" in field_diff
    if context and completeness:
        return "Изменение касается доступного process context и его полноты."
    if context:
        return "Изменение касается доступного process context."
    if completeness:
        return "Изменение касается полноты process context."
    if bind:
        return "Изменение касается категории bind."
    return _INSUFFICIENT_CHANGE


def _coverage(pack):
    value = pack.get("source_coverage") if isinstance(pack, dict) else None
    return value if isinstance(value, dict) else {}


def _limitations_clause(change, record, before_obs, after_obs, described, coverage):
    parts = []
    stale = coverage.get("stale") is True or (
        isinstance(described, dict) and described.get("stale") is True
    )
    if change == "removed":
        parts.append("это результат сохранённого наблюдения, а не установленное текущее состояние")
        if stale:
            parts.append("описанная привязка не является текущим наблюдением")
    elif stale:
        parts.append("сохранённое evidence не является текущим наблюдением")
    if isinstance(record, dict) and record.get("context_complete") is False:
        parts.append("полный process context недоступен, идентичность процесса не установлена")
    partial = coverage.get("status") in {"partial", "unavailable"}
    if isinstance(described, dict) and described.get("completeness") == "partial":
        partial = True
    if change == "removed" and isinstance(after_obs, dict):
        if after_obs.get("completeness") == "partial":
            partial = True
    if isinstance(before_obs, dict) and before_obs.get("completeness") == "partial":
        partial = True
    if partial:
        parts.append("неполный снимок не подтверждает отсутствие")
    if not parts:
        return None
    text = "; ".join(parts)
    return text[0].upper() + text[1:] + "."


def _endpoint_summary(pack):
    # Closed templates over the minimized pack only; never copy telemetry or aliases.
    alert = pack.get("alert") if isinstance(pack, dict) else None
    if not isinstance(alert, dict) or alert.get("detector_id") != "endpoint-drift":
        return GENERIC_SUMMARY
    change = alert.get("change")
    if change not in {"added", "removed", "changed"}:
        return GENERIC_SUMMARY
    before_obs, after_obs = _observation_pair(alert)
    before = _projected_endpoint(before_obs)
    after = _projected_endpoint(after_obs)
    record = before if change == "removed" else after or before
    facts = _endpoint_facts(record)
    # Observations are the original comparison. pack["baseline"] is current and
    # does not prove which baseline, if any, existed when the alert was formed.
    if change == "added":
        lead = (
            "Сохранённый результат сравнения на момент формирования фиксирует "
            + (
                f"добавление сетевой привязки: {facts}."
                if facts
                else "добавление сетевой привязки."
            )
        )
    elif change == "removed":
        lead = (
            "Сохранённый результат сравнения на момент формирования фиксирует, "
            "что в соответствующем сохранённом снимке отсутствует "
            + (f"сетевая привязка: {facts}." if facts else "сетевая привязка.")
        )
    else:
        lead = (
            "Сохранённый результат сравнения на момент формирования фиксирует, "
            "что изменился сохранённый контекст сетевой привязки"
            + (f": {facts}." if facts else ".")
        )
    sentences = [lead]
    if isinstance(record, dict) and record.get("bind_class") == "wildcard":
        sentences.append(
            "Привязка ко всем локальным адресам не доказывает доступность из Интернета."
        )
    if change == "changed":
        sentences.append(_changed_clause(before, after))
    described = before_obs if change == "removed" else after_obs or before_obs
    limits = _limitations_clause(
        change, record, before_obs, after_obs, described, _coverage(pack)
    )
    if limits:
        sentences.append(limits)
    elif len(sentences) < 3:
        sentences.append("Причина и легитимность требуют ручной проверки.")
    return " ".join(sentences)


def fallback(pack, reason):
    alert = pack["alert"]
    summary = (
        _endpoint_summary(pack) if alert.get("detector_id") == "endpoint-drift" else GENERIC_SUMMARY
    )
    return {
        "schema_version": 1,
        "mode": "deterministic",
        "reason": reason,
        "summary": summary,
        "detector": alert,
        "guidance": pack["runbook"],
        "source_coverage": pack["source_coverage"],
        "limitations": LIMITS,
        "references": sorted(references(pack)),
        "automatic_action": "Отсутствует",
    }
