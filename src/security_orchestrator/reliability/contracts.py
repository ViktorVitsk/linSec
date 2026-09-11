"""Versioned, minimal journal and observation-gap contracts."""

from dataclasses import dataclass
from enum import StrEnum
import re

from ..investigation.contracts import require
from ..investigation.evidence import timestamp
from ..model import digest

SOURCE = "journal_user_units"
VERSION = 1
MAX_BATCH = 256

MESSAGE_IDS = {
    "39f53479d3a045ac8e11786248231fbf": "started",
    "9d1aaa27d60140bd96365438aad20286": "stopped",
    "be02cf6855d2428ba40df7e9d022f03d": "failed",
    "d9b373ed55a64feb8242e02dbe79a49c": "failed",
}


class State(StrEnum):
    CONTINUATION = "continuation"
    FIRST = "first_observation"
    CURSOR_UNAVAILABLE = "cursor_unavailable"
    CURSOR_INVALID = "cursor_invalid"
    CURSOR_LOST = "cursor_lost"
    ROTATED = "rotated_beyond_cursor"
    ACCESS = "access_failure"
    DIAGNOSTIC = "access_or_source_failure"
    UNAVAILABLE = "source_unavailable"
    PARSER = "parser_failure"
    VERSION = "configuration_mismatch"
    REBOOT = "boot_boundary"


def cursor_valid(value: object) -> bool:
    # Cursor is opaque. Validate transport bounds, never depend on its internal layout.
    return isinstance(value, str) and bool(re.fullmatch(r"[\x21-\x7e]{1,1024}", value))


@dataclass(frozen=True)
class Checkpoint:
    cursor: str
    boot_id: str
    event_at: str
    version: int = VERSION

    @property
    def identity(self) -> str:
        return digest([SOURCE, VERSION, self.boot_id, self.cursor])

    def validate(self) -> None:
        require(cursor_valid(self.cursor), "cursor_invalid")
        require(bool(re.fullmatch(r"[0-9a-f]{32}", self.boot_id)), "invalid_boot_id")
        timestamp(self.event_at)
        require(type(self.version) is int and self.version == VERSION, "checkpoint_version")


@dataclass(frozen=True)
class JournalEvent:
    checkpoint: Checkpoint
    message_id: str
    unit: str
    transition: str

    @property
    def identity(self) -> str:
        # Exact transport identity; time alone, unit, and message text are insufficient.
        return self.checkpoint.identity

    def validate(self) -> None:
        self.checkpoint.validate()
        require(self.transition in {"started", "stopped", "failed"})
        require(bool(re.fullmatch(r"[0-9a-f]{32}", self.message_id)))
        require(isinstance(self.unit, str) and 1 <= len(self.unit) <= 256)
        require(self.unit.endswith((".service", ".timer")))
        require(all(32 <= ord(c) < 127 for c in self.unit))


@dataclass(frozen=True)
class Batch:
    state: State
    checkpoint: Checkpoint | None = None
    events: tuple[JournalEvent, ...] = ()
    anchor: JournalEvent | None = None
    anchor_checkpoint: Checkpoint | None = None

    def validate(self) -> None:
        require(isinstance(self.state, State))
        require(isinstance(self.events, tuple) and len(self.events) <= MAX_BATCH)
        if self.checkpoint:
            self.checkpoint.validate()
        require(not self.events or self.checkpoint is not None)
        for event in self.events:
            event.validate()
        if self.anchor:
            self.anchor.validate()
            require(self.anchor.checkpoint == self.anchor_checkpoint)
        if self.anchor_checkpoint:
            self.anchor_checkpoint.validate()


@dataclass(frozen=True)
class Gap:
    source: str
    detected_at: str
    boundary_from: str | None
    boundary_to: str | None
    reason: State
    recoverability: str = "history_unknown"
    reconciliation_attempted: bool = False
    current_state_observed: bool = False
    history_recovered: bool = False
    unknown: str = "Intermediate events and exact loss interval are unknown."
