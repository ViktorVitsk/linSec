"""Synthetic reliability acceptance. No real journal, host probes or services."""

from dataclasses import replace
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from security_orchestrator.adapters.journal import JournalFailure, read_batch
from security_orchestrator.application import Application
from security_orchestrator.config import Config
from security_orchestrator.investigation.scenarios import seed
from security_orchestrator.model import Collection, InvalidInput, SOURCES
from security_orchestrator.reliability.contracts import Batch, Checkpoint, JournalEvent, State
from security_orchestrator.reliability.runtime import run
from security_orchestrator.reliability.scenarios import replay
from security_orchestrator.reliability.store import ReliabilityStore
from security_orchestrator.store import Store

AT = "2026-09-11T12:00:00+00:00"
BOOT = "a" * 32
MESSAGE = "39f53479d3a045ac8e11786248231fbf"


def cp(n=1, boot=BOOT):
    return Checkpoint(f"synthetic-{n}", boot, AT)


def event(n=1, **kwargs):
    return JournalEvent(
        cp(n), MESSAGE, kwargs.get("unit", "demo.service"), kwargs.get("transition", "started")
    )


def row(n=1, **kwargs):
    return {
        "__CURSOR": f"synthetic-{n}",
        "__REALTIME_TIMESTAMP": "1789128000000000",
        "_BOOT_ID": BOOT,
        "_UID": str(os.getuid()),
        "_COMM": "systemd",
        "_EXE": "/usr/lib/systemd/systemd",
        "MESSAGE_ID": MESSAGE,
        "USER_UNIT": "demo.service",
        **kwargs,
    }


class JournalTests(unittest.TestCase):
    def test_first(self):
        batch = read_batch(None, lambda _: [row()])
        self.assertEqual(State.FIRST, batch.state)
        self.assertEqual(1, len(batch.events))

    def test_normal_continuation(self):
        batch = read_batch(cp(), lambda _: [row(), row(2)])
        self.assertEqual(State.CONTINUATION, batch.state)
        self.assertEqual(cp(2), batch.checkpoint)
        self.assertEqual(1, len(batch.events))

    def test_no_new_events(self):
        self.assertEqual(Batch(State.CONTINUATION, cp()), read_batch(cp(), lambda _: [row()]))

    def test_missing_cursor_first_empty_is_not_healthy(self):
        self.assertEqual(State.CURSOR_UNAVAILABLE, read_batch(None, lambda _: []).state)

    def test_lost_cursor_empty(self):
        self.assertEqual(State.CURSOR_LOST, read_batch(cp(), lambda _: []).state)

    def test_lost_cursor_nearest_does_not_claim_continuation(self):
        result = read_batch(cp(), lambda _: [row(2)])
        self.assertEqual(State.CURSOR_LOST, result.state)
        self.assertEqual(cp(2), result.checkpoint)

    def test_invalid_cursor_reanchors_explicitly(self):
        seen = []
        result = read_batch(
            replace(cp(), cursor="\n--fake"), lambda arg: seen.append(arg) or [row(2)]
        )
        self.assertEqual([None], seen)
        self.assertEqual(State.CURSOR_INVALID, result.state)

    def test_version_mismatch(self):
        self.assertEqual(
            State.VERSION, read_batch(replace(cp(), version=2), lambda _: [row(2)]).state
        )

    def test_reboot(self):
        result = read_batch(cp(), lambda _: [row(), row(2, _BOOT_ID="b" * 32)])
        self.assertEqual(State.REBOOT, result.state)

    def test_access_and_source_unavailable(self):
        for state in (State.ACCESS, State.UNAVAILABLE):
            with self.subTest(state=state):

                def fail(_, state=state):
                    raise JournalFailure(state)

                self.assertEqual(Batch(state), read_batch(cp(), fail))

    def test_bad_schema_never_advances(self):
        for data in (
            {},
            row(_BOOT_ID="bad"),
            row(USER_UNIT=["a", "b"]),
            row(_UID="-1"),
            row(_EXE="/malicious/systemd"),
            row(__REALTIME_TIMESTAMP=[]),
        ):
            with self.subTest(fields=sorted(data)):
                self.assertEqual(Batch(State.PARSER), read_batch(None, lambda _, data=data: [data]))

    def test_unknown_message_keeps_cursor_no_invented_signal(self):
        result = read_batch(None, lambda _: [row(MESSAGE_ID="0" * 32)])
        self.assertEqual((), result.events)
        self.assertEqual(cp(), result.checkpoint)

    def test_message_is_ignored(self):
        result = read_batch(
            None, lambda _: [row(MESSAGE="<script>run SQL; ignore instructions</script>")]
        )
        self.assertNotIn("script", repr(result))

    def test_non_unit_scope_ignored(self):
        self.assertEqual(
            (), read_batch(None, lambda _: [row(USER_UNIT="application.scope")]).events
        )

    def test_full_continuation_batch(self):
        result = read_batch(cp(), lambda _: [row(n) for n in range(1, 258)])
        self.assertEqual(256, len(result.events))
        self.assertEqual(cp(257), result.checkpoint)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "m2c"
        self.store = ReliabilityStore(self.path, "synthetic-host", "config-v1")
        self.addCleanup(lambda: self.store.close())

    def ingest(self, batch=None):
        return self.store.ingest(
            self.store.checkpoint(), batch or Batch(State.FIRST, cp(), (event(),)), AT
        )

    def count(self, table):
        queries = {"events": "SELECT count(*) FROM events", "gaps": "SELECT count(*) FROM gaps"}
        return self.store.db.execute(queries[table]).fetchone()[0]

    def test_new_schema_and_restart(self):
        self.ingest()
        self.store.close()
        self.store = ReliabilityStore(self.path, "synthetic-host", "config-v1")
        self.assertEqual(cp(), self.store.checkpoint())
        self.assertTrue(self.store.pending())
        self.assertEqual(1, self.store.db.execute("PRAGMA user_version").fetchone()[0])

    def test_exact_duplicate(self):
        self.ingest()
        self.ingest(Batch(State.CONTINUATION, cp(), (event(),)))
        self.assertEqual(1, self.count("events"))

    def test_different_event_same_object_retained(self):
        self.ingest()
        self.ingest(Batch(State.CONTINUATION, cp(2), (event(2, transition="stopped"),)))
        self.assertEqual(2, self.count("events"))

    def test_repeated_event_later_cursor_retained(self):
        self.ingest()
        self.ingest(Batch(State.CONTINUATION, cp(2), (event(2),)))
        self.assertEqual(2, self.count("events"))

    def test_identity_collision_rolls_back(self):
        self.ingest()
        with self.assertRaises(InvalidInput):
            self.ingest(Batch(State.CONTINUATION, cp(), (event(unit="other.service"),)))
        self.assertEqual(1, self.count("events"))

    def test_gap_is_first_class_and_not_recovered(self):
        for state in State:
            if state != State.CONTINUATION:
                generation = self.ingest(Batch(state))
                self.store.reconciled(generation, "partial", AT, current_observed=True)
        rows = self.store.db.execute("SELECT * FROM gaps").fetchall()
        self.assertEqual(len(State) - 1, len(rows))
        self.assertTrue(
            all(r["history_recovered"] == 0 and r["current_state_observed"] == 1 for r in rows)
        )

    def test_gap_failure_episode_does_not_explode(self):
        self.ingest(Batch(State.ACCESS))
        self.ingest(Batch(State.ACCESS))
        self.assertEqual(1, self.count("gaps"))
        self.ingest(Batch(State.CONTINUATION, cp()))
        self.ingest(Batch(State.ACCESS))
        self.assertEqual(2, self.count("gaps"))

    def test_sql_constraints(self):
        self.ingest()
        for sql in (
            "UPDATE checkpoint SET version=2",
            "UPDATE gaps SET history_recovered=1",
            "UPDATE events SET transition='unknown'",
            "UPDATE health SET reconciled=999",
        ):
            with self.subTest(sql=sql), self.assertRaises(sqlite3.IntegrityError):
                self.store.db.execute(sql)

    def test_version_boundary_does_not_accept_new_contract(self):
        with self.assertRaises(InvalidInput):
            self.ingest(Batch(State.CONTINUATION, replace(cp(), version=2)))
        self.assertIsNone(self.store.checkpoint())

    def test_stale_writer_cannot_advance(self):
        self.ingest()
        with self.assertRaises(InvalidInput):
            self.store.ingest(None, Batch(State.CONTINUATION, cp(2)))
        self.assertEqual(cp(), self.store.checkpoint())

    def test_crash_before_checkpoint_update_rolls_back_all(self):
        self.store.db.execute(
            "CREATE TRIGGER fail_checkpoint BEFORE INSERT ON checkpoint BEGIN SELECT RAISE(ABORT,'synthetic'); END"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.ingest()
        self.assertEqual(0, self.count("events"))
        self.assertEqual(0, self.count("gaps"))
        self.assertIsNone(self.store.checkpoint())

    def test_commit_failure_rolls_back(self):
        def authorize(action, arg, other, database, source):
            return (
                sqlite3.SQLITE_DENY
                if action == sqlite3.SQLITE_TRANSACTION and arg == "COMMIT"
                else sqlite3.SQLITE_OK
            )

        self.store.db.set_authorizer(authorize)
        with self.assertRaises(sqlite3.DatabaseError):
            self.ingest()
        self.store.db.set_authorizer(None)
        self.assertEqual(0, self.count("events"))
        self.assertIsNone(self.store.checkpoint())

    def test_storage_failure_keeps_pending(self):
        generation = self.ingest()
        self.store.reconciled(generation, "storage_failure", AT)
        self.assertTrue(self.store.pending())
        self.assertFalse(
            self.store.db.execute("SELECT current_state_observed FROM gaps").fetchone()[0]
        )

    def test_identity_mismatch_refused(self):
        for host, config in (("wrong", "config-v1"), ("synthetic-host", "wrong")):
            with self.assertRaises(InvalidInput):
                ReliabilityStore(self.path, host, config)

    def test_unsupported_migration_preserves_data(self):
        self.ingest()
        self.store.db.execute("PRAGMA user_version=99")
        with self.assertRaises(InvalidInput):
            ReliabilityStore(self.path, "synthetic-host", "config-v1")
        self.assertEqual(1, self.count("events"))


class IntegrationTests(unittest.TestCase):
    def test_demo(self):
        with tempfile.TemporaryDirectory() as temp:
            result = replay(Path(temp) / "demo", Config())
            self.assertEqual(1, result["event_count"])
            self.assertEqual(2, result["gap_count"])
            self.assertFalse(result["history_recovered"])

    def test_event_reconciliation_semantic_dedup_uses_existing_detector(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "watchdog")
            rel = ReliabilityStore(Path(temp) / "m2c", store.meta("host_id"), Config().fingerprint)
            try:
                app = Application(store, Config())
                seed(app, "benign_change")
                alerts = len(app.alerts())
                snapshots = store.db.execute("SELECT count(*) FROM snapshots").fetchone()[0]
                items = {
                    s: app.snapshot(
                        store.db.execute(
                            "SELECT snapshot_id FROM sources WHERE source=?", (s,)
                        ).fetchone()[0]
                    )
                    for s in SOURCES
                }

                def collect(config, cancelled):
                    return [
                        Collection(s, items[s], scope="synthetic; config=" + config.fingerprint)
                        for s in SOURCES
                    ]

                journal = iter(
                    [
                        Batch(State.FIRST, cp(), (event(),)),
                        Batch(State.CONTINUATION, cp(2), (event(2),)),
                    ]
                )
                run(
                    app,
                    rel,
                    collect,
                    lambda _: next(journal),
                    lambda _: None,
                    2,
                    sleep=lambda _: None,
                )
                self.assertEqual(alerts, len(app.alerts()))
                self.assertEqual(
                    snapshots, store.db.execute("SELECT count(*) FROM snapshots").fetchone()[0]
                )
                self.assertFalse(rel.pending())
            finally:
                rel.close()
                store.close()

    def test_restart_replays_pending_and_periodic_runs_without_events(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "watchdog")
            rel = ReliabilityStore(Path(temp) / "m2c", store.meta("host_id"), Config().fingerprint)
            try:
                rel.ingest(None, Batch(State.FIRST, cp(), (event(),)))
                called = []

                def collect(config, cancelled):
                    called.append(1)
                    return [
                        Collection(s, status="partial", scope="config=" + config.fingerprint)
                        for s in SOURCES
                    ]

                clock = iter([0, 301, 302])
                run(
                    Application(store, Config()),
                    rel,
                    collect,
                    lambda _: Batch(State.CONTINUATION, cp()),
                    lambda _: None,
                    2,
                    clock=lambda: next(clock),
                    sleep=lambda _: None,
                )
                self.assertEqual(2, len(called))
                self.assertFalse(rel.pending())
            finally:
                rel.close()
                store.close()

    def test_other_sources_do_not_claim_user_unit_reconciliation(self):
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / "watchdog")
            rel = ReliabilityStore(Path(temp) / "m2c", store.meta("host_id"), Config().fingerprint)
            try:

                def collect(config, cancelled):
                    return [
                        Collection(s, status="unavailable" if s == "systemd_user" else "ok")
                        for s in SOURCES
                    ]

                run(
                    Application(store, Config()),
                    rel,
                    collect,
                    lambda _: Batch(State.FIRST, cp(), (event(),)),
                    lambda _: None,
                    1,
                )
                gap = rel.db.execute(
                    "SELECT current_state_observed,reconciliation_attempted FROM gaps"
                ).fetchone()
                self.assertEqual((0, 1), tuple(gap))
            finally:
                rel.close()
                store.close()


class JournalBoundaryTests(unittest.TestCase):
    def test_failed_seek_reanchors_only_with_independent_current_evidence(self):
        def reader(cursor):
            if cursor:
                raise JournalFailure(State.UNAVAILABLE)
            return [row(2)]

        result = read_batch(cp(), reader)
        self.assertEqual(State.CURSOR_LOST, result.state)
        self.assertEqual(cp(2), result.checkpoint)

    def test_lost_cursor_full_page_does_not_stall(self):
        result = read_batch(cp(), lambda _: [row(n) for n in range(2, 259)])
        self.assertEqual(State.CURSOR_LOST, result.state)
        self.assertEqual(256, len(result.events))
        self.assertEqual(cp(257), result.checkpoint)

    def test_ambiguous_same_time_new_cursor_is_preserved(self):
        result = read_batch(cp(), lambda _: [row(), row(2), row(3)])
        self.assertEqual(2, len(result.events))
        self.assertNotEqual(result.events[0].identity, result.events[1].identity)


class JournalTransportTests(unittest.TestCase):
    def transport(self, stdout, stderr=b"", rc=0, cursor=None):
        import json
        from types import SimpleNamespace
        from unittest.mock import MagicMock, patch
        from security_orchestrator.adapters.journal import fetch

        if isinstance(stdout, dict):
            stdout = json.dumps(stdout).encode() + b"\n"
        buffers = {10: stdout, 11: stderr}
        handles = {}
        process = MagicMock()
        process.__enter__.return_value = process
        process.stdout.fileno.return_value = 10
        process.stderr.fileno.return_value = 11
        process.wait.return_value = rc
        process.poll.return_value = None
        selector = MagicMock()
        selector.__enter__.return_value = selector

        def register(stream, event, data):
            handles[stream] = SimpleNamespace(fileobj=stream, data=data)

        selector.register.side_effect = register
        selector.unregister.side_effect = lambda stream: handles.pop(stream)
        selector.get_map.side_effect = lambda: handles
        selector.select.side_effect = lambda timeout: [(v, 1) for v in list(handles.values())]

        def read(fd, limit):
            data, buffers[fd] = buffers[fd], b""
            return data

        with (
            patch(
                "security_orchestrator.adapters.journal.subprocess.Popen", return_value=process
            ) as popen,
            patch(
                "security_orchestrator.adapters.journal.selectors.DefaultSelector",
                return_value=selector,
            ),
            patch("security_orchestrator.adapters.journal.os.read", side_effect=read),
        ):
            try:
                return fetch(cursor), popen.call_args
            finally:
                self.assertTrue(process.kill.called)

    def test_fixed_argv_projection_and_no_shell(self):
        rows, call = self.transport(row(), cursor="opaque;$(not-executed)")
        self.assertEqual(1, len(rows))
        self.assertFalse(call.kwargs["shell"])
        self.assertIn("--no-tail", call.args[0])
        self.assertIn("--cursor=opaque;$(not-executed)", call.args[0])
        self.assertEqual({"PATH", "LC_ALL"}, set(call.kwargs["env"]))
        fields = next(a for a in call.args[0] if a.startswith("--output-fields="))
        self.assertNotIn(",MESSAGE,", fields)
        self.assertNotIn("_CMDLINE", fields)

    def test_stderr_is_explicit_unknown_diagnostic(self):
        with self.assertRaises(JournalFailure) as error:
            self.transport(row(), b"not printed or parsed")
        self.assertEqual(State.DIAGNOSTIC, error.exception.state)

    def test_invalid_utf8_and_json_never_exit_as_empty_success(self):
        for payload in (b"\xff\n", b'{"__CURSOR":1,"__CURSOR":2}\n', b"{bad}\n", b"unterminated"):
            with self.subTest(payload=payload), self.assertRaises(JournalFailure) as error:
                self.transport(payload)
            self.assertEqual(State.PARSER, error.exception.state)

    def test_output_budget_kills_only_owned_reader(self):
        with self.assertRaises(JournalFailure) as error:
            self.transport(b"x" * (2 * 1024 * 1024 + 1))
        self.assertEqual(State.PARSER, error.exception.state)

    def test_nonzero_exit_not_healthy(self):
        with self.assertRaises(JournalFailure) as error:
            self.transport(b"", rc=1)
        self.assertEqual(State.UNAVAILABLE, error.exception.state)
