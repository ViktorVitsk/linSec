"""Portable, bounded inventory contracts and deterministic change detection."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import ipaddress
import json


SCHEMA_VERSION = 1
COLLECTOR_VERSION = "1"
SOURCES = (
    "tcp4",
    "tcp6",
    "udp4",
    "udp6",
    "systemd_system",
    "systemd_user",
    "accounts",
    "persistence",
)
MAX_ITEMS = 12000
MAX_PAYLOAD = 4 * 1024 * 1024


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def encode(value: object) -> str:
    # Escape control characters, bidi controls and terminal escape sequences in all UI data.
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def digest(value: object) -> str:
    return hashlib.sha256(encode(value).encode()).hexdigest()


class InvalidInput(ValueError):
    """Safe, fixed diagnostic; never echo malformed input or raw OS exceptions."""


def text_field(value: object, limit: int = 4096) -> bool:
    return isinstance(value, str) and len(value) <= limit and "\x00" not in value


def validate_items(items: dict) -> None:
    if not isinstance(items, dict) or len(items) > MAX_ITEMS:
        raise InvalidInput("inventory_limit")
    shapes = {
        "endpoint": {
            "kind",
            "protocol",
            "family",
            "bind",
            "port",
            "uid",
            "owners",
            "context_complete",
        },
        "file": {"kind", "path", "exists", "sha256", "mode", "uid", "gid", "link_sha256"},
        "unit": {"kind", "name", "scope", "enablement"},
        "uid0": {"kind", "name", "uid", "gid"},
        "group": {"kind", "name", "gid", "members"},
    }
    size = 2
    for key, data in items.items():
        if not text_field(key) or not isinstance(data, dict):
            raise InvalidInput("invalid_inventory")
        kind = data.get("kind")
        if not isinstance(kind, str) or kind not in shapes or set(data) != shapes[kind]:
            raise InvalidInput("invalid_inventory_schema")
        strings = {"kind", "protocol", "bind", "path", "name", "scope", "enablement"}
        if any(name in strings and not text_field(value) for name, value in data.items()):
            raise InvalidInput("invalid_string_field")
        for name, value in data.items():
            if isinstance(value, str) and not text_field(value):
                raise InvalidInput("field_limit")
            if name in {"uid", "gid", "mode", "port", "family"}:
                if value is not None and (type(value) is not int or not 0 <= value < 2**32):
                    raise InvalidInput("invalid_numeric_field")
        if kind == "endpoint":
            if (
                data["protocol"] not in {"tcp", "udp"}
                or data["family"] not in {4, 6}
                or data["port"] is None
                or not 1 <= data["port"] <= 65535
                or data["uid"] is None
                or type(data["context_complete"]) is not bool
                or not isinstance(data["owners"], list)
                or len(data["owners"]) > 128
            ):
                raise InvalidInput("invalid_endpoint")
            for owner in data["owners"]:
                if (
                    not isinstance(owner, dict)
                    or set(owner) != {"exe", "uid"}
                    or not text_field(owner["exe"])
                    or not owner["exe"].startswith("/")
                    or type(owner["uid"]) is not int
                    or not 0 <= owner["uid"] < 2**32
                ):
                    raise InvalidInput("invalid_owner")
            if data["context_complete"] and not data["owners"]:
                raise InvalidInput("missing_owner")
            try:
                address = ipaddress.ip_address(data["bind"].split("%", 1)[0])
                if address.version != data["family"]:
                    raise ValueError
            except ValueError as error:
                raise InvalidInput("invalid_bind_address") from error
        if kind == "group" and (
            not isinstance(data["members"], list)
            or len(data["members"]) > MAX_ITEMS
            or not all(text_field(m, 256) for m in data["members"])
        ):
            raise InvalidInput("invalid_members")
        if kind == "file":
            if type(data["exists"]) is not bool:
                raise InvalidInput("invalid_file")
            for name in ("sha256", "link_sha256"):
                val = data[name]
                if val is not None and (
                    not isinstance(val, str)
                    or len(val) != 64
                    or any(c not in "0123456789abcdef" for c in val)
                ):
                    raise InvalidInput("invalid_fingerprint")
        if kind == "uid0" and (data["uid"] != 0 or data["gid"] is None):
            raise InvalidInput("invalid_privileged_account")
        if kind == "group" and data["gid"] is None:
            raise InvalidInput("invalid_group_gid")
        # Check one bounded record at a time, not one giant temporary JSON representation.
        size += len(encode(key)) + len(encode(data)) + 2
        if size > MAX_PAYLOAD:
            raise InvalidInput("inventory_limit")


def decode_items(raw: str) -> dict:
    if not isinstance(raw, str) or len(raw) > MAX_PAYLOAD:
        raise InvalidInput("stored_evidence_limit")
    try:
        items = json.loads(raw)
        validate_items(items)
        return items
    except (ValueError, TypeError, RecursionError) as error:
        raise InvalidInput("invalid_stored_evidence_contents_omitted") from error


@dataclass
class Collection:
    source: str
    items: dict = field(default_factory=dict)
    status: str = "ok"
    reason: str = "none"
    scope: str = ""
    collected_at: str = field(default_factory=now)

    def validate(self) -> None:
        if (
            not isinstance(self.source, str)
            or self.source not in SOURCES
            or not isinstance(self.status, str)
            or self.status not in {"ok", "partial", "unavailable"}
        ):
            raise InvalidInput("invalid_collection")
        if not isinstance(self.reason, str) or self.reason not in {
            "none",
            "access_or_io",
            "invalid_input",
            "limit",
            "timeout",
            "command_failed",
            "missing_command",
            "context_missing",
            "unsupported_platform",
            "source_missing",
            "cancelled",
        }:
            raise InvalidInput("invalid_diagnostic")
        if not text_field(self.scope) or self.status == "unavailable" and self.items:
            raise InvalidInput("invalid_scope")
        if not text_field(self.collected_at, 64):
            raise InvalidInput("invalid_timestamp")
        try:
            if datetime.fromisoformat(self.collected_at).utcoffset().total_seconds() != 0:
                raise ValueError
        except (TypeError, ValueError, AttributeError) as error:
            raise InvalidInput("invalid_timestamp") from error
        validate_items(self.items)
        kinds = (
            {"endpoint"}
            if self.source[:3] in {"tcp", "udp"}
            else {"unit", "file"}
            if self.source.startswith("systemd_")
            else {"uid0", "group"}
            if self.source == "accounts"
            else {"file"}
        )
        if any(data["kind"] not in kinds for data in self.items.values()):
            raise InvalidInput("source_kind_mismatch")


def changes(before: dict, after: dict, *, complete: bool) -> list[dict]:
    keys = before.keys() | after.keys() if complete else after.keys()
    return [
        {
            "key": key,
            "before": before.get(key),
            "after": after.get(key),
            "change": "added"
            if key not in before
            else "removed"
            if key not in after
            else "changed",
        }
        for key in sorted(keys)
        if before.get(key) != after.get(key)
    ]


def detector(source: str, change: dict) -> dict:
    data = change["after"] or change["before"]
    kind = data["kind"]
    severity = "high" if kind in {"uid0", "group"} else "medium"
    if change["change"] == "removed":
        severity = "info"
    if kind == "endpoint" and data["bind"] in {"0.0.0.0", "::"}:  # noqa: S104 -- detector data
        severity = "high" if change["change"] != "removed" else "info"
    return {
        "detector_id": f"{kind}-drift",
        "detector_version": 1,
        "severity": severity,
        "context": digest([source, 1, change]),
        "source": source,
        **change,
    }
