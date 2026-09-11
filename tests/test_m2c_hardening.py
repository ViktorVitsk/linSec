"""Pre-acceptance adversarial tests; only synthetic state and in-memory transports."""

from dataclasses import replace
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from security_orchestrator.adapters.journal import JournalFailure, read_batch
from security_orchestrator.application import Application
from security_orchestrator.config import Config
from security_orchestrator.investigation.scenarios import seed
from security_orchestrator.local_ui.server import Access, Handler, Routes
from security_orchestrator.model import Collection, InvalidInput
from security_orchestrator.queries import Queries
from security_orchestrator.reliability.contracts import Batch, State
from security_orchestrator.reliability.runtime import run
from security_orchestrator.reliability.store import ReliabilityStore
from security_orchestrator.store import Store
import test_reliability
from test_reliability import AT, cp, event, row

AUTHORITY = "127.0.0.1:8765"
KEY = "synthetic-test-only-" + "a" * 32


def http(routes, request):
    output = io.BytesIO()

    class Connection:
        def makefile(self, mode, *args):
            return io.BytesIO(request)

        def sendall(self, data):
            output.write(data)

        def settimeout(self, value):
            pass

    class Server:
        pass

    server = Server()
    server.routes = routes
    Handler(Connection(), ("127.0.0.1", 1), server)
    return output.getvalue()


class Isolated(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.main = Store(self.base / "main")
        self.addCleanup(self.main.close)
        self.config = Config()
        self.app = Application(self.main, self.config, clock=lambda: AT)
        self.alert = seed(self.app, "benign_change")
        self.rel = ReliabilityStore(
            self.base / "rel", self.main.meta("host_id"), self.config.fingerprint
        )
        self.addCleanup(lambda: self.rel.close())
        self.queries = Queries(
            self.main.directory, self.config, self.rel.directory, clock=lambda: AT
        )
        self.routes = Routes(self.queries, Access(KEY, AUTHORITY))

    def ingest(self, batch=None):
        return self.rel.ingest(
            self.rel.checkpoint(), batch or Batch(State.FIRST, cp(), (event(),)), AT
        )

    def counts(self):
        return tuple(
            self.rel.db.execute(sql).fetchone()[0]
            for sql in (
                "SELECT count(*) FROM events",
                "SELECT count(*) FROM gaps",
                "SELECT count(*) FROM checkpoint",
                "SELECT count(*) FROM health",
            )
        )

    def request(self, target="/api/overview", method="GET", extra=b"", headers=None):
        if headers is None:
            headers = (
                f"Host: {AUTHORITY}\r\nAuthorization: Bearer {KEY}\r\n"
                f"Origin: http://{AUTHORITY}\r\nX-Sec-UI: 1\r\n"
            ).encode()
        return http(
            self.routes, f"{method} {target} HTTP/1.1\r\n".encode() + headers + extra + b"\r\n"
        )


class JournalHardeningTests(Isolated):
    def test_operator_summary_minimizes_sample_and_refuses_ambiguity(self):
        from scripts.summarize_m2c_journal import summarize

        result = summarize(json.dumps(row()).encode() + b"\n")
        self.assertEqual(1, result["accepted_service_events"])
        self.assertNotIn("demo.service", json.dumps(result))
        self.assertNotIn("synthetic-1", json.dumps(result))
        self.assertFalse(summarize(b"")["target_events_observed"])
        for raw in (b'{"_UID":"1","_UID":"2"}\n', b"x" * (2 * 1024 * 1024 + 1)):
            with self.assertRaises(ValueError):
                summarize(raw)

    def test_anchor_provenance_is_validated(self):
        for mutation in (
            {"_UID": "-1"},
            {"_COMM": "other"},
            {"_EXE": "/bad/systemd"},
            {"USER_UNIT": ["a.service", "b.service"]},
            {"MESSAGE_ID": []},
        ):
            with self.subTest(mutation=mutation):
                self.assertEqual(
                    State.PARSER,
                    read_batch(cp(), lambda _, mutation=mutation: [row(**mutation)]).state,
                )

    def test_unknown_message_still_requires_provenance(self):
        self.assertEqual(
            State.PARSER,
            read_batch(None, lambda _: [row(MESSAGE_ID="unknown", _EXE="/bad/systemd")]).state,
        )

    def test_same_cursor_changed_anchor_rejected_without_advancing(self):
        self.ingest()
        for mutation in (
            {"USER_UNIT": "different.service"},
            {"MESSAGE_ID": "unknown"},
            {"USER_UNIT": "ignored.scope"},
        ):
            batch = read_batch(cp(), lambda _, mutation=mutation: [row(**mutation), row(2)])
            with self.subTest(mutation=mutation), self.assertRaises(InvalidInput):
                self.ingest(batch)
            self.assertEqual(cp(), self.rel.checkpoint())
            self.assertEqual((1, 1, 1, 1), self.counts())

    def test_repeated_cursor_within_batch_is_ambiguous(self):
        for rows in ([row(), row(2), row()], [row(), row(2), row(2, USER_UNIT="other.service")]):
            self.assertEqual(State.PARSER, read_batch(cp(), lambda _, rows=rows: rows).state)

    def test_hostile_fields_fail_without_checkpoint(self):
        for key, value in (
            ("_COMM", ["systemd", "other"]),
            ("_EXE", None),
            ("_UID", None),
            ("USER_UNIT", "x" * 257 + ".service"),
            ("USER_UNIT", "x\u202e.service"),
            ("USER_UNIT", "x\x1b.service"),
            ("__CURSOR", "x\n"),
            ("__CURSOR", "x" * 1025),
            ("_BOOT_ID", None),
            ("__REALTIME_TIMESTAMP", "9" * 100),
        ):
            with self.subTest(key=key):
                self.assertEqual(
                    Batch(State.PARSER),
                    read_batch(None, lambda _, key=key, value=value: [row(**{key: value})]),
                )

    def test_wall_clock_order_is_not_cursor_order(self):
        rows = [
            row(),
            row(2, __REALTIME_TIMESTAMP="1000000"),
            row(3, __REALTIME_TIMESTAMP="9000000000000000"),
        ]
        batch = read_batch(cp(), lambda _: rows)
        self.assertEqual(cp(3).cursor, batch.checkpoint.cursor)
        self.assertEqual(2, len(batch.events))
        self.ingest(Batch(State.FIRST, cp(), (event(),)))
        self.ingest(batch)
        self.assertEqual(3, self.counts()[0])

    def test_distinct_consecutive_lost_anchors_record_distinct_gaps(self):
        self.ingest(Batch(State.CURSOR_LOST, cp()))
        self.ingest(Batch(State.CURSOR_LOST, cp(2)))
        self.assertEqual(2, self.counts()[1])
        self.ingest(Batch(State.CURSOR_LOST, cp(2)))
        self.assertEqual(2, self.counts()[1])

    def test_dedup_restart_restore_and_semantic_near_collisions(self):
        self.ingest()
        backup = sqlite3.connect(self.base / "backup.sqlite3")
        self.rel.db.backup(backup)
        self.ingest(Batch(State.CONTINUATION, cp(2), (event(2),)))
        backup.backup(self.rel.db)
        backup.close()
        self.rel.close()
        self.rel = ReliabilityStore(
            self.base / "rel", self.main.meta("host_id"), self.config.fingerprint
        )
        self.ingest(read_batch(cp(), lambda _: [row(), row(2)]))
        self.assertEqual(2, self.counts()[0])
        self.ingest(
            Batch(
                State.CONTINUATION,
                cp(3),
                (
                    replace(event(3), unit="ab.service"),
                    replace(event(4), unit="a.service", checkpoint=cp(4, "b" * 32)),
                ),
            )
        )
        self.assertEqual(4, self.counts()[0])

    def test_nonzero_partial_stdout_is_failure(self):
        helper = test_reliability.JournalTransportTests()
        with self.assertRaises(JournalFailure) as failure:
            helper.transport(row(), rc=1)
        self.assertEqual(State.UNAVAILABLE, failure.exception.state)

    def test_nonzero_exit_at_full_page_is_failure(self):
        helper = test_reliability.JournalTransportTests()
        payload = b"".join(json.dumps(row(n)).encode() + b"\n" for n in range(257))
        with self.assertRaises(JournalFailure) as failure:
            helper.transport(payload, rc=1, poll=1)
        self.assertEqual(State.UNAVAILABLE, failure.exception.state)

    def test_transport_timeout_and_permission_are_typed(self):
        from security_orchestrator.adapters.journal import fetch

        with patch(
            "security_orchestrator.adapters.journal.subprocess.Popen", side_effect=PermissionError
        ):
            with self.assertRaises(JournalFailure) as failure:
                fetch(None)
            self.assertEqual(State.ACCESS, failure.exception.state)
        with patch("security_orchestrator.adapters.journal.time.monotonic", side_effect=[0, 6]):
            with self.assertRaises(JournalFailure) as failure:
                test_reliability.JournalTransportTests().transport(row())
            self.assertEqual(State.UNAVAILABLE, failure.exception.state)


class CrashTests(Isolated):
    def test_partial_reconciliation_only_claims_positive_current_evidence(self):
        for items, expected in (
            ({}, 0),
            (
                {
                    "unit": {
                        "kind": "unit",
                        "name": "synthetic.service",
                        "scope": "user",
                        "enablement": "enabled",
                    }
                },
                1,
            ),
        ):

            def collect(*args, items=items, **kwargs):
                return [
                    Collection(
                        "systemd_user",
                        items,
                        status="partial",
                        collected_at=AT,
                        scope="config=" + self.config.fingerprint,
                    )
                ]

            run(self.app, self.rel, collect, lambda _: Batch(State.ACCESS), lambda _: None, 1)
            gap = self.rel.db.execute(
                "SELECT current_state_observed,history_recovered FROM gaps"
            ).fetchone()
            self.assertEqual((expected, 0), tuple(gap))

    def test_every_write_boundary_rolls_back_before_checkpoint(self):
        triggers = (
            "CREATE TRIGGER injected BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'synthetic'); END",
            "CREATE TRIGGER injected AFTER INSERT ON events BEGIN SELECT RAISE(ABORT,'synthetic'); END",
            "CREATE TRIGGER injected AFTER INSERT ON gaps BEGIN SELECT RAISE(ABORT,'synthetic'); END",
            "CREATE TRIGGER injected AFTER INSERT ON health BEGIN SELECT RAISE(ABORT,'synthetic'); END",
            "CREATE TRIGGER injected AFTER INSERT ON checkpoint BEGIN SELECT RAISE(ABORT,'synthetic'); END",
        )
        for sql in triggers:
            self.rel.db.execute(sql)
            with self.subTest(sql=sql), self.assertRaises(sqlite3.Error):
                self.ingest()
            self.assertEqual((0, 0, 0, 0), self.counts())
            self.assertFalse(self.rel.db.in_transaction)
            self.rel.db.execute("DROP TRIGGER injected")
        self.ingest()
        self.assertTrue(self.rel.pending())

    def test_failure_immediately_after_commit_preserves_pending(self):
        with patch.object(self.rel, "mark_failure", side_effect=RuntimeError("synthetic crash")):
            with self.assertRaises(RuntimeError):
                self.ingest()
        self.assertEqual((1, 1, 1, 1), self.counts())
        self.assertTrue(self.rel.pending())
        self.ingest(read_batch(cp(), lambda _: [row()]))
        self.assertEqual(1, self.counts()[0])

    def test_reconciliation_rollback_keeps_generation_pending(self):
        generation = self.ingest()
        for sql in (
            "CREATE TRIGGER injected AFTER INSERT ON reconciliations BEGIN SELECT RAISE(ABORT,'synthetic'); END",
            "CREATE TRIGGER injected AFTER UPDATE ON gaps BEGIN SELECT RAISE(ABORT,'synthetic'); END",
            "CREATE TRIGGER injected AFTER UPDATE ON health BEGIN SELECT RAISE(ABORT,'synthetic'); END",
        ):
            self.rel.db.execute(sql)
            with self.assertRaises(sqlite3.Error):
                self.rel.reconciled(generation, "ok", AT)
            self.assertTrue(self.rel.pending())
            self.assertEqual(
                0, self.rel.db.execute("SELECT count(*) FROM reconciliations").fetchone()[0]
            )
            self.rel.db.execute("DROP TRIGGER injected")

    def test_reconciliation_faults_leave_work_for_restart(self):
        valid = [
            Collection("systemd_user", scope="config=" + self.config.fingerprint, collected_at=AT)
        ]
        for stage in ("collect", "ingest", "record"):
            self.ingest(
                Batch(State.CURSOR_LOST, cp({"collect": 2, "ingest": 3, "record": 4}[stage]))
            )

            def collect(*a, **k):
                return valid

            target = {"collect": None, "ingest": self.app, "record": self.rel}[stage]
            if stage == "collect":

                def collect(*a, **k):
                    raise RuntimeError("synthetic crash")

                with self.assertRaises(RuntimeError):
                    run(
                        self.app,
                        self.rel,
                        collect,
                        lambda _: Batch(State.UNAVAILABLE),
                        lambda _: None,
                        1,
                    )
            else:
                with patch.object(
                    target,
                    "ingest" if stage == "ingest" else "reconciled",
                    side_effect=RuntimeError("synthetic crash"),
                ):
                    with self.assertRaises(RuntimeError):
                        run(
                            self.app,
                            self.rel,
                            collect,
                            lambda _: Batch(State.UNAVAILABLE),
                            lambda _: None,
                            1,
                        )
            self.assertTrue(self.rel.pending())
        run(
            self.app,
            self.rel,
            lambda *a, **k: valid,
            lambda _: Batch(State.UNAVAILABLE),
            lambda _: None,
            1,
        )
        self.assertFalse(self.rel.pending())

    def test_begin_lock_failure_sets_health_flag(self):
        other = sqlite3.connect(self.rel.path, isolation_level=None)
        self.addCleanup(other.close)
        other.execute("BEGIN IMMEDIATE")
        start = time.monotonic()
        with self.assertRaises(sqlite3.OperationalError):
            self.ingest()
        self.assertLess(time.monotonic() - start, 3)
        self.assertEqual(b"1", (self.rel.directory / "reliability-health").read_bytes())
        other.execute("ROLLBACK")
        self.ingest()
        self.assertEqual(b"0", (self.rel.directory / "reliability-health").read_bytes())

    def test_stale_or_foreign_inventory_cannot_claim_current(self):
        for at, scope, reason in (
            ("2000-01-01T00:00:00+00:00", "config=" + self.config.fingerprint, "none"),
            ("2099-01-01T00:00:00+00:00", "config=" + self.config.fingerprint, "none"),
            (AT, "config=foreign", "none"),
            (AT, "config=" + self.config.fingerprint, "invalid_input"),
        ):
            with self.subTest(at=at, scope=scope, reason=reason):
                run(
                    self.app,
                    self.rel,
                    lambda *a, at=at, scope=scope, reason=reason, **k: [
                        Collection("systemd_user", collected_at=at, scope=scope, reason=reason)
                    ],
                    lambda _: Batch(State.ACCESS),
                    lambda _: None,
                    1,
                )
                self.assertEqual(
                    0, self.rel.db.execute("SELECT current_state_observed FROM gaps").fetchone()[0]
                )
                self.assertEqual(
                    "unavailable",
                    self.rel.db.execute(
                        "SELECT outcome FROM reconciliations ORDER BY id DESC"
                    ).fetchone()[0],
                )


class HTTPHardeningTests(Isolated):
    def test_in_memory_hostile_request_matrix(self):
        for target in (
            "//api/overview",
            "/api/over\tview",
            "http://" + AUTHORITY + "/api/overview",
            "/" + "x" * 66000,
            "/%2e%2e/%2fetc/passwd",
            "/api/alerts?limit=1&limit=2",
            "/api/alerts?limit=-1",
            "/api/alerts?before=9999999999999999999",
        ):
            with self.subTest(target=target[:80]):
                self.assertNotIn(b"200 OK", self.request(target))
        for extra in (
            b"Host: evil.example\r\n",
            b"Authorization: Bearer other\r\n",
            b"Content-Length: 0\r\nContent-Length: 0\r\n",
            b"Content-Length: 0\r\nContent-Length: 1\r\n",
            b"Transfer-Encoding: chunked\r\n",
            b"Content-Length: 2\r\n",
            b"Expect: 100-continue\r\n",
            b"Content-Type: text/plain\r\n",
            b"Malformed header\r\n",
            b"X-Folded: a\r\n b\r\n",
            b"X-Huge: " + b"x" * 9000 + b"\r\n",
        ):
            with self.subTest(extra=extra[:80]):
                response = self.request(extra=extra)
                self.assertNotIn(b"200 OK", response)
                self.assertNotIn(KEY.encode(), response)
        for host in ("", "127.0.0.1", "LOCALHOST:8765", "[::1]:8765", AUTHORITY + ":80"):
            self.assertNotIn(b"200 OK", self.request(headers=f"Host: {host}\r\n".encode()))
        for method in ("HEAD", "OPTIONS", "TRACE", "CONNECT", "POST", "FOO"):
            self.assertNotIn(b"200 OK", self.request(method=method))

    def test_header_name_casing_is_accepted(self):
        self.assertIn(b"200 OK", self.request("/", headers=f"hOsT: {AUTHORITY}\r\n".encode()))

    def test_forged_metadata_never_replaces_bearer(self):
        for origin in ("null", "http://foreign", "http://" + AUTHORITY + "/", "http://[broken"):
            response = self.request(
                headers=(
                    f"Host: {AUTHORITY}\r\nOrigin: {origin}\r\n"
                    f"Authorization: Bearer {KEY}\r\nSec-Fetch-Site: same-origin\r\nX-Sec-UI: 1\r\n"
                ).encode()
            )
            self.assertNotIn(b"200 OK", response)
        for value in ("Bearer", "bearer " + KEY, "Bearer  " + KEY, "Bearer " + "x" * 1000):
            response = self.request(
                headers=(
                    f"Host: {AUTHORITY}\r\nAuthorization: {value}\r\n"
                    "Sec-Fetch-Site: same-origin\r\nX-Sec-UI: 1\r\n"
                ).encode()
            )
            self.assertNotIn(b"200 OK", response)

    def test_repeated_unauthenticated_calls_do_not_query_db(self):
        with patch.object(self.queries, "overview", side_effect=AssertionError("must not read")):
            for _ in range(100):
                response = self.request(headers=f"Host: {AUTHORITY}\r\n".encode())
                self.assertIn(b"401 Unauthorized", response)

    def test_all_error_paths_omit_internal_details(self):
        for exception in (
            OSError("synthetic-private-path"),
            sqlite3.DatabaseError("synthetic-private-path"),
            RuntimeError("synthetic-private-path"),
        ):
            with patch.object(self.queries, "overview", side_effect=exception):
                response = self.request()
                self.assertIn(b"503 Service Unavailable", response)
                self.assertNotIn(b"synthetic-private-path", response)
                self.assertNotIn(b"Traceback", response)


class QueryHardeningTests(Isolated):
    def test_timestamp_unicode_separator_is_normalized(self):
        self.ingest()
        unusual = AT.replace("T", "\u202e")
        self.rel.db.execute("UPDATE checkpoint SET event_at=?", (unusual,))
        self.assertEqual(AT, self.queries.reliability_view()["checkpoint"]["event_at"])
        self.main.db.execute("UPDATE alerts SET last_seen=?", (unusual,))
        self.assertTrue(all(item["at"] == AT for item in self.queries.alerts()["items"]))

    def test_sidecar_strings_are_validated_before_export(self):
        generation = self.ingest()
        self.rel.reconciled(generation, "ok", AT)
        for sql in (
            "UPDATE checkpoint SET event_at=?",
            "UPDATE gaps SET boundary_from=?",
            "UPDATE gaps SET boundary_to=?",
            "UPDATE reconciliations SET at=?",
            "UPDATE events SET event_at=?",
        ):
            originals = self.rel.path.read_bytes()
            self.rel.db.execute(sql, ("synthetic-private-path",))
            result = self.queries.reliability_view()
            self.assertEqual("storage_or_contract_failure", result["state"], sql)
            self.assertNotIn("synthetic-private-path", json.dumps(result))
            self.rel.close()
            self.rel.path.write_bytes(originals)
            self.rel = ReliabilityStore(
                self.base / "rel", self.main.meta("host_id"), self.config.fingerprint
            )

    def test_corrupt_and_incomplete_sidecar_fail_closed(self):
        self.rel.close()
        for payload in (b"", b"not a sqlite database", b"SQLite format 3\x00" + b"\x00" * 84):
            self.rel.path.write_bytes(payload)
            self.assertEqual(
                "storage_or_contract_failure", self.queries.reliability_view()["state"]
            )

    def test_readers_observe_atomic_ingest_and_rollback(self):
        failures = []
        barrier = threading.Barrier(4)

        def writer():
            rel = None
            try:
                rel = ReliabilityStore(self.rel.directory, host, self.config.fingerprint)
                barrier.wait(timeout=5)
                for n in range(1, 61):
                    rel.ingest(
                        rel.checkpoint(),
                        Batch(State.FIRST if n == 1 else State.CONTINUATION, cp(n), (event(n),)),
                        AT,
                    )
                    if n % 5 == 0:
                        try:
                            with rel.transaction():
                                rel.db.execute("UPDATE health SET state='access_failure'")
                                raise RuntimeError("rollback")
                        except RuntimeError:
                            pass
            except Exception as exc:
                failures.append(type(exc).__name__)
            finally:
                if rel:
                    rel.close()

        def reader():
            try:
                barrier.wait(timeout=5)
                for _ in range(30):
                    overview = self.queries.overview()
                    self.queries.detail(self.alert)
                    self.queries.alerts(100)
                    rel = overview["reliability"]
                    if rel["state"] == "never_observed":
                        continue
                    self.assertIn(rel["state"], {"first_observation", "continuation"})
                    self.assertEqual(rel["checkpoint"]["event_at"], rel["events"][0]["at"])
                    self.assertEqual(1, rel["gap_count"])
                    self.assertFalse(rel["history_recovered"])
            except Exception as exc:
                failures.append(type(exc).__name__)

        host = self.main.meta("host_id")
        workers = [threading.Thread(target=writer)] + [
            threading.Thread(target=reader) for _ in range(3)
        ]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(15)
            self.assertFalse(worker.is_alive())
        self.assertEqual([], failures)

    def test_reader_during_schema_initialization_fails_closed_then_recovers(self):
        directory = self.base / "initializing"
        directory.mkdir(mode=0o700)
        path = directory / "reliability.sqlite3"
        path.touch(mode=0o600)
        db = sqlite3.connect(path, isolation_level=None)
        self.addCleanup(db.close)
        db.execute("BEGIN EXCLUSIVE")
        db.execute("CREATE TABLE incomplete (id INTEGER)")
        queries = Queries(self.main.directory, self.config, directory)
        start = time.monotonic()
        self.assertEqual("storage_or_contract_failure", queries.reliability_view()["state"])
        self.assertLess(time.monotonic() - start, 3)
        db.execute("ROLLBACK")
        initialized = ReliabilityStore(
            directory, self.main.meta("host_id"), self.config.fingerprint
        )
        self.addCleanup(initialized.close)
        self.assertEqual("never_observed", queries.reliability_view()["state"])

    def test_large_alert_count_pagination_and_notification_predicate(self):
        # Clone schema-valid summaries with distinct contexts; details use the seeded real fixture.
        with self.main.transaction():
            self.main.db.executemany(
                "INSERT INTO alerts(context,source,object_key,detector_id,detector_version,severity,change_type,before_id,after_id,first_seen,last_seen,occurrences,lifecycle,active,notified) "
                "SELECT ?,source,object_key,detector_id,detector_version,severity,change_type,before_id,after_id,first_seen,last_seen,occurrences,lifecycle,active,notified FROM alerts WHERE id=?",
                ((f"synthetic-context-{n}", self.alert) for n in range(1000)),
            )
        seen, before = set(), 2**63 - 1
        while before:
            page = self.queries.alerts(100, before)
            ids = {item["id"] for item in page["items"]}
            self.assertFalse(ids & seen)
            self.assertLessEqual(len(ids), 100)
            seen.update(ids)
            before = page["next_before"]
        self.assertEqual(
            self.main.db.execute("SELECT count(*) FROM alerts").fetchone()[0], len(seen)
        )
        self.assertEqual(
            len(self.app.pending_notifications()), self.app.pending_notification_count()
        )
        self.main.db.execute("UPDATE alerts SET notified=1 WHERE id%2=0")
        self.main.db.execute("UPDATE alerts SET lifecycle='closed' WHERE id%3=0")
        self.main.db.execute("UPDATE alerts SET active=0 WHERE id%5=0")
        self.assertEqual(
            len(self.app.pending_notifications()), self.app.pending_notification_count()
        )

    def test_many_gaps_and_keyset_pages_are_bounded(self):
        for n in range(1, 301):
            self.ingest(Batch(State.CURSOR_LOST, cp(n), (event(n),)))
        result = self.queries.reliability_view()
        self.assertEqual(300, result["gap_count"])
        self.assertEqual(50, len(result["gaps"]))
        self.assertEqual(50, len(result["events"]))
        self.assertLess(len(json.dumps(result)), 65536)
        for value in (-1, 0, 101, 2**100, True):
            with self.assertRaises(InvalidInput):
                self.queries.alerts(value)


if __name__ == "__main__":
    unittest.main()
