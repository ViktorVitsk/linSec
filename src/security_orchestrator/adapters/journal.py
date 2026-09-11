"""Bounded user-manager journal hints, no MESSAGE/command lines or journal writes."""

from datetime import UTC, datetime
import os
import selectors
import subprocess
import time

from ..investigation.contracts import require, strict_json
from ..model import InvalidInput
from ..reliability.contracts import Batch, Checkpoint, JournalEvent, MAX_BATCH, State, cursor_valid

MESSAGE_IDS = {
    "39f53479d3a045ac8e11786248231fbf": "started",
    "9d1aaa27d60140bd96365438aad20286": "stopped",
    "be02cf6855d2428ba40df7e9d022f03d": "failed",
    "d9b373ed55a64feb8242e02dbe79a49c": "failed",
}
FIELDS = "__CURSOR,__REALTIME_TIMESTAMP,_BOOT_ID,_UID,_COMM,_EXE,MESSAGE_ID,USER_UNIT"


class JournalFailure(Exception):
    def __init__(self, state: State):
        self.state = state


def fetch(cursor: str | None) -> list[dict]:
    """Stop our own reader after 257 complete lines, never tail a continuation."""
    require(cursor is None or cursor_valid(cursor), "cursor_invalid")
    argv = [
        "/usr/bin/journalctl",
        "--user",
        "--no-pager",
        "--output=json",
        "--output-fields=" + FIELDS,
        "_COMM=systemd",
        "_UID=" + str(os.getuid()),
    ]
    argv += ["--no-tail", "--cursor=" + cursor] if cursor else ["--lines=1"]
    rows, buffer, total, stderr_seen = [], bytearray(), 0, False
    try:
        with subprocess.Popen(  # noqa: S603 -- fixed executable/options, bounded opaque cursor only.
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        ) as process:
            deadline = time.monotonic() + 5
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ, True)
                    selector.register(process.stderr, selectors.EVENT_READ, False)
                    while selector.get_map() and len(rows) < MAX_BATCH + 1:
                        if time.monotonic() >= deadline:
                            raise JournalFailure(State.UNAVAILABLE)
                        for key, _ in selector.select(0.1):
                            chunk = os.read(key.fileobj.fileno(), 16384)
                            if not chunk:
                                selector.unregister(key.fileobj)
                                continue
                            total += len(chunk)
                            if total > 2 * 1024 * 1024:
                                raise JournalFailure(State.PARSER)
                            if not key.data:
                                stderr_seen = True
                                continue
                            buffer.extend(chunk)
                            while b"\n" in buffer and len(rows) < MAX_BATCH + 1:
                                line, _, buffer = buffer.partition(b"\n")
                                if line.strip():
                                    row = strict_json(bytes(line), 16384)
                                    require(isinstance(row, dict))
                                    rows.append(row)
                            if len(buffer) > 32768:
                                raise JournalFailure(State.PARSER)
                if stderr_seen:
                    # Includes access diagnostics; never parse natural-language errors.
                    raise JournalFailure(State.DIAGNOSTIC)
                if len(rows) < MAX_BATCH + 1:
                    rc = process.wait(timeout=max(0.001, deadline - time.monotonic()))
                    if rc:
                        raise JournalFailure(State.UNAVAILABLE)
                    if buffer.strip():
                        raise JournalFailure(State.PARSER)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)
        return rows
    except PermissionError as error:
        raise JournalFailure(State.ACCESS) from error
    except (OSError, subprocess.TimeoutExpired) as error:
        raise JournalFailure(State.UNAVAILABLE) from error
    except (ValueError, UnicodeError) as error:
        raise JournalFailure(State.PARSER) from error


def checkpoint(row: dict) -> Checkpoint:
    value = row.get("__REALTIME_TIMESTAMP")
    require(isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= 17)
    cp = Checkpoint(
        row.get("__CURSOR"),
        row.get("_BOOT_ID"),
        datetime.fromtimestamp(int(value) / 1_000_000, UTC).isoformat(),
    )
    cp.validate()
    return cp


def read_batch(previous: Checkpoint | None, reader=fetch) -> Batch:
    state = State.CONTINUATION if previous else State.FIRST
    cursor = previous.cursor if previous else None
    if previous:
        try:
            previous.validate()
        except (ValueError, TypeError):
            state = State.VERSION if previous.version != 1 else State.CURSOR_INVALID
            cursor = None
    try:
        rows = reader(cursor)
        require(isinstance(rows, list) and len(rows) <= MAX_BATCH + 1)
        if not rows:
            return Batch(State.CURSOR_LOST if cursor else State.CURSOR_UNAVAILABLE)
        first = checkpoint(rows[0])
        if cursor:
            if first != previous:
                # A seek can land near a vacuumed cursor. Cause is not provable from CLI.
                state = State.CURSOR_LOST
                rows = rows[:MAX_BATCH]
            else:
                rows = rows[1:]
        events = []
        last = first
        for row in rows:
            cp = checkpoint(row)
            require(row.get("_UID") == str(os.getuid()) and row.get("_COMM") == "systemd")
            if cp.boot_id != last.boot_id:
                state = State.REBOOT
            last = cp
            message = row.get("MESSAGE_ID")
            require(message is None or isinstance(message, str))
            if message not in MESSAGE_IDS:
                continue
            require(row.get("_EXE") in {"/usr/lib/systemd/systemd", "/lib/systemd/systemd"})
            unit = row.get("USER_UNIT")
            require(isinstance(unit, str) and len(unit) <= 256)
            if not unit.endswith((".service", ".timer")):
                continue
            event = JournalEvent(cp, message, unit, MESSAGE_IDS[message])
            event.validate()
            events.append(event)
        result = Batch(state, last, tuple(events))
        result.validate()
        return result
    except JournalFailure as error:
        if cursor and error.state in {State.UNAVAILABLE, State.ACCESS, State.DIAGNOSTIC}:
            # A failed seek alone does not distinguish a lost cursor from unavailable source.
            # Re-anchor only if an independent bounded current read actually succeeds.
            anchor = read_batch(None, reader)
            if anchor.checkpoint is not None:
                return Batch(State.CURSOR_LOST, anchor.checkpoint, anchor.events)
        return Batch(error.state)
    except (InvalidInput, ValueError, TypeError, OverflowError, AttributeError):
        return Batch(State.PARSER)
