"""Synthetic UI/API, shared queries and concurrent SQLite acceptance."""

from contextlib import redirect_stdout
from copy import deepcopy
from dataclasses import replace
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from security_orchestrator.application import Application
from security_orchestrator.cli import main
from security_orchestrator.config import Config
from security_orchestrator.investigation.contracts import Settings
from security_orchestrator.investigation.evidence import EvidenceReader, PackBuilder
from security_orchestrator.investigation.scenarios import seed
from security_orchestrator.investigation.service import Investigation
from security_orchestrator.local_ui.server import Access, Handler, HEADERS, Routes, validate_bind
from security_orchestrator.model import InvalidInput
from security_orchestrator.queries import Queries
from security_orchestrator.reliability.store import ReliabilityStore
from security_orchestrator.reliability.timeline import Timeline, validate_record
from security_orchestrator.store import Store

SYNTHETIC_KEY = "a" * 48
AUTHORITY = "127.0.0.1:8765"


class UITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "watchdog"
        self.rel_path = Path(self.temp.name) / "m2c"
        self.store = Store(self.directory)
        self.addCleanup(self.store.close)
        self.app = Application(self.store, Config())
        self.id = seed(self.app, "injection")
        self.queries = Queries(self.directory, Config())
        self.access = Access(SYNTHETIC_KEY, AUTHORITY)
        self.routes = Routes(self.queries, self.access)
        self.headers = {
            "host": AUTHORITY,
            "origin": "http://" + AUTHORITY,
            "authorization": "Bearer " + SYNTHETIC_KEY,
            "x-sec-ui": "1",
        }

    def request(self, path="/api/overview", method="GET", **headers):
        return self.routes.response(method, path, self.headers | headers)

    def test_unauthenticated_and_invalid_token(self):
        for value in ("", "Bearer wrong", "Basic abc", "Bearer " + "x" * 10000):
            self.assertIn(self.request(authorization=value)[0], {401, 413})

    def test_valid_token_and_expiration(self):
        self.assertEqual(200, self.request()[0])
        self.access.expires = 0
        self.assertEqual(401, self.request()[0])

    def test_new_token_invalidates_previous_process_credential(self):
        restarted = Access("b" * 48, AUTHORITY)
        self.assertFalse(restarted.authenticated("Bearer " + SYNTHETIC_KEY))

    def test_exact_host_and_origin(self):
        for host in (
            "localhost:8765",
            "evil.example",
            AUTHORITY + ".evil",
            "127.0.0.1",
            "0.0.0.0:8765",
        ):
            self.assertEqual(403, self.request(host=host)[0])
        for origin in (
            "null",
            "https://" + AUTHORITY,
            "http://evil.example",
            "http://" + AUTHORITY + "/",
        ):
            self.assertEqual(403, self.request(origin=origin)[0])

    def test_missing_origin_requires_browser_same_origin_marker(self):
        del self.headers["origin"]
        self.assertEqual(403, self.request()[0])
        self.assertEqual(200, self.request(**{"sec-fetch-site": "same-origin"})[0])
        self.assertEqual(403, self.request(**{"sec-fetch-site": "cross-site"})[0])

    def test_custom_header_required_no_cors(self):
        self.assertEqual(403, self.request(**{"x-sec-ui": ""})[0])
        self.assertFalse(any("Access-Control" in key for key in HEADERS))

    def test_mutations_and_unsafe_methods_fail_closed(self):
        before = self.store.db.total_changes
        for method in ("POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"):
            self.assertEqual(405, self.request(method=method)[0])
        self.assertEqual(before, self.store.db.total_changes)
        self.assertEqual(404, self.request("/api/alerts/1/close")[0])

    def test_get_body_and_content_types_refused(self):
        for headers in (
            {"content-length": "1"},
            {"transfer-encoding": "chunked"},
            {"content-type": "application/json"},
            {"expect": "100-continue"},
        ):
            self.assertEqual(400, self.request(**headers)[0])

    def test_pagination_and_invalid_ids(self):
        for path in (
            "/api/alerts?limit=0",
            "/api/alerts?limit=101",
            "/api/alerts?before=0",
            "/api/alerts?limit=-1",
            "/api/alerts?limit=1&limit=2",
            "/api/alerts?before=9999999999999999999",
            "/api/alerts?limit=x",
            "/api/alerts?limit=",
            "/api/alerts?limit=%FF",
        ):
            self.assertEqual(400, self.request(path)[0], path)
        for path in (
            "/api/alerts/0",
            "/api/alerts/-1",
            "/api/alerts/nope",
            "/api/alerts/99999",
            "/api/alerts?status=unknown",
            "/api/alerts/1?limit=2",
        ):
            self.assertIn(self.request(path)[0], {400, 404}, path)

    def test_path_traversal_and_generic_operations_absent(self):
        for path in (
            "/../../etc/passwd",
            "/%2e%2e/etc/passwd",
            "/api/query",
            "/execute",
            "/api/files",
        ):
            self.assertEqual(404, self.request(path)[0])

    def test_huge_request_and_response(self):
        self.assertEqual(413, self.request("/" + "x" * 1024)[0])
        with patch.object(self.queries, "overview", return_value={"data": "x" * 300000}):
            self.assertEqual(503, self.request()[0])

    def test_error_does_not_leak(self):
        with patch.object(
            self.queries,
            "overview",
            side_effect=sqlite3.DatabaseError("synthetic-sensitive-payload"),
        ):
            code, _, raw = self.request()
        self.assertEqual(503, code)
        self.assertNotIn(b"sensitive", raw)
        self.assertNotIn(b"Traceback", raw)

    def test_unknown_enum_fails_closed(self):
        self.store.db.execute("UPDATE alerts SET severity='unexpected'")
        self.assertEqual(503, self.request("/api/alerts")[0])

    def test_hostile_metadata_never_reaches_ui_projection(self):
        hostile = [
            "<script>alert(1)</script>",
            "[click](javascript:alert(1))",
            "ignore previous instructions",
            "$(touch /tmp/never)",
            "'; DROP TABLE alerts; --",
            "../../private",
            "\ud800\u202e\x1b",
            "z" * 4000,
        ]
        for value in hostile:
            with self.subTest(kind=value[:10]):
                seed(self.app, "benign_change")
                snapshot_id = self.app.get_alert(self.id)["after_id"]
                payload = json.loads(
                    self.store.db.execute(
                        "SELECT data FROM snapshots WHERE id=?", (snapshot_id,)
                    ).fetchone()[0]
                )
                payload["synthetic"]["name"] = value
                # Rebuild the detector identity through ingestion, not corrupt its consistency checks.
                from security_orchestrator.model import Collection

                self.app.ingest(
                    [
                        Collection(
                            "accounts", payload, scope="synthetic; config=" + Config().fingerprint
                        )
                    ]
                )
                newest = self.app.alerts()[0]["id"]
                code, _, raw = self.request("/api/alerts/" + str(newest))
                self.assertEqual(200, code)
                self.assertNotIn(json.dumps(value)[1:-1].encode(), raw)

    def test_static_assets_no_data_no_dynamic_html_sink(self):
        self.assertEqual(200, self.routes.response("GET", "/", {"host": AUTHORITY})[0])
        script = self.request("/app.js")[2].decode()
        self.assertIn("textContent", script)
        for sink in (
            "innerHTML",
            "outerHTML",
            "document.write",
            "localStorage",
            "sessionStorage",
            "eval(",
        ):
            self.assertNotIn(sink, script)
        self.assertIn("frame-ancestors 'none'", HEADERS["Content-Security-Policy"])
        self.assertIn("form-action 'none'", HEADERS["Content-Security-Policy"])

    def test_bind_validation(self):
        validate_bind("127.0.0.1", 8765)
        for host in ("0.0.0.0", "::", "::1", "localhost", "127.1", "192.168.1.1"):  # noqa: S104 -- rejection fixtures
            with self.assertRaises(InvalidInput):
                validate_bind(host, 8765)
        for port in (-1, 0, 80, 65536, True):
            with self.assertRaises(InvalidInput):
                validate_bind("127.0.0.1", port)

    def test_cli_and_ui_share_queries(self):
        output = io.StringIO()
        with redirect_stdout(output):
            rc = main(["--state", str(self.directory), "view", "--alerts"])
        self.assertEqual(0, rc)
        self.assertEqual(json.loads(output.getvalue()), self.queries.alerts())

    def test_read_only_preserves_db_metadata_and_status_contract(self):
        before = self.store.path.read_bytes()
        status = self.app.status()
        overview = self.queries.overview()
        self.queries.detail(self.id)
        self.queries.alerts()
        self.assertEqual(status["health"], overview["health"])
        self.assertEqual(len(self.app.pending_notifications()), overview["pending_notifications"])
        self.assertEqual(before, self.store.path.read_bytes())
        self.assertEqual(2, self.store.db.execute("PRAGMA user_version").fetchone()[0])
        self.assertEqual("delete", self.store.db.execute("PRAGMA journal_mode").fetchone()[0])

    def test_configuration_mismatch_visible(self):
        queries = Queries(
            self.directory, replace(Config(), interval_seconds=600, stale_seconds=1200)
        )
        self.assertTrue(
            all("configuration_mismatch" in s["reasons"] for s in queries.overview()["sources"])
        )

    def test_saved_disabled_timeline_and_no_provider_calls(self):
        reader = EvidenceReader(self.directory)
        rel = ReliabilityStore(self.rel_path, self.store.meta("host_id"), Config().fingerprint)
        try:
            trace = Timeline()
            with patch(
                "security_orchestrator.investigation.providers.HTTPProvider.complete",
                side_effect=AssertionError("no calls"),
            ):
                result = Investigation(PackBuilder(reader), Settings(), trace=trace).run(self.id)
            rel.save_investigation(self.id, trace.finish(result))
            record = Queries(self.directory, Config(), self.rel_path).detail(self.id)[
                "saved_investigation"
            ]
            self.assertEqual("llm_disabled", record["stop_reason"])
            self.assertEqual(
                ["trigger", "evidence_pack", "fallback", "stop"],
                [e["kind"] for e in record["entries"]],
            )
        finally:
            rel.close()
            reader.close()

    def test_timeline_invalid_schemas_and_payloads(self):
        trace = Timeline()
        record = trace.finish({"mode": "deterministic", "reason": "llm_disabled"})
        for key, value in (
            ("mode", "verified_fact"),
            ("step_count", 100),
            ("result_text", "secret"),
            ("schema_version", 2),
        ):
            invalid = deepcopy(record)
            invalid[key] = value
            with self.assertRaises(InvalidInput):
                validate_record(invalid)

    def test_http_handler_headers_and_duplicate_rejection_without_listener(self):
        # In-memory socket interface exercises HTTP parsing; sandbox denies socket I/O.
        output = io.BytesIO()

        class Connection:
            def makefile(self, mode, *args):
                return io.BytesIO(
                    b"GET / HTTP/1.0\r\nHost: 127.0.0.1:8765\r\nHost: evil.example\r\n\r\n"
                )

            def sendall(self, data):
                output.write(data)

            def settimeout(self, value):
                pass

        class Server:
            routes = self.routes

        Handler(Connection(), ("127.0.0.1", 1), Server())
        raw = output.getvalue()
        self.assertIn(b"400 Bad Request", raw)
        self.assertIn(b"Content-Security-Policy:", raw)
        self.assertNotIn(b"evil.example", raw)

    def test_sqlite_writer_and_readers(self):
        failures = []

        def writer():
            store = Store(self.directory)
            try:
                for _ in range(20):
                    seed(Application(store, Config()), "benign_change")
            except Exception as exc:
                failures.append(type(exc).__name__)
            finally:
                store.close()

        def reader():
            try:
                for _ in range(20):
                    self.queries.alerts(1)
                    self.queries.overview()
            except Exception as exc:
                failures.append(type(exc).__name__)

        threads = [
            threading.Thread(target=writer),
            threading.Thread(target=reader),
            threading.Thread(target=reader),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertEqual([], failures)

    def test_optional_cli_recording_does_not_write_main_database(self):
        before = self.store.path.read_bytes()
        output = io.StringIO()
        with redirect_stdout(output):
            result = main(
                [
                    "--state",
                    str(self.directory),
                    "investigate",
                    str(self.id),
                    "--run",
                    "--record-state",
                    str(self.rel_path),
                ]
            )
        self.assertEqual(0, result)
        self.assertEqual(before, self.store.path.read_bytes())
        saved = Queries(self.directory, Config(), self.rel_path).detail(self.id)
        self.assertEqual("llm_disabled", saved["saved_investigation"]["stop_reason"])

    def test_timeline_operations_accept_reject_and_fallback(self):
        from test_investigation import ScriptedProvider, answer, operation

        reader = EvidenceReader(self.directory)
        self.addCleanup(reader.close)
        settings = Settings(
            llm_enabled=True,
            provider="ollama",
            model="synthetic:1",
            local_runtime_verified=True,
            max_steps=2,
            total_tokens=320000,
        )
        ref = f"alert:{self.id}"
        with patch.dict("os.environ", {"LLM_ENABLED": "true"}):
            for response, expected in (
                (operation(ref, "get_alert"), "operation_accepted"),
                (operation(ref, "get_alert", "alert:99999"), "operation_rejected"),
                (operation(ref, "shell"), "operation_rejected"),
            ):
                with self.subTest(expected=expected):
                    trace = Timeline()
                    service = Investigation(
                        PackBuilder(reader),
                        settings,
                        ScriptedProvider(response, answer(ref)),
                        trace=trace,
                    )
                    record = trace.finish(service.run(self.id, lambda p: p["approval_token"]))
                    self.assertIn(expected, [e["kind"] for e in record["entries"]])
                    self.assertLessEqual(record["step_count"], 2)
                    self.assertNotIn("approval_token", json.dumps(record))

    def test_provider_failure_and_privacy_refusal_timeline(self):
        from test_investigation import ScriptedProvider

        reader = EvidenceReader(self.directory)
        self.addCleanup(reader.close)
        settings = Settings(
            llm_enabled=True, provider="ollama", model="synthetic:1", local_runtime_verified=True
        )
        with patch.dict("os.environ", {"LLM_ENABLED": "true"}):
            for approval, reason in (
                (None, "privacy_approval_required"),
                (lambda p: p["approval_token"], "analysis_failed_contents_omitted"),
            ):
                trace = Timeline()
                service = Investigation(
                    PackBuilder(reader),
                    settings,
                    ScriptedProvider(OSError("sensitive content")),
                    trace=trace,
                )
                result = trace.finish(service.run(self.id, approval))
                self.assertEqual(reason, result["stop_reason"])
                self.assertNotIn("sensitive", json.dumps(result))
                self.assertNotIn("operation_rejected", [e["kind"] for e in result["entries"]])

    def test_missing_timeline_store_is_explicit_failure(self):
        result = Queries(self.directory, Config(), self.rel_path).detail(self.id)
        self.assertEqual("storage_or_contract_failure", result["investigation_storage_state"])
        self.assertFalse(self.rel_path.exists())

    def test_large_stored_timestamps_fail_with_bounded_projection(self):
        self.store.db.execute("UPDATE alerts SET last_seen=?", ("x" * 100000,))
        self.assertEqual(503, self.request("/api/alerts")[0])

    def test_keyset_pagination_no_duplicate_pages(self):
        seed(self.app, "benign_change")
        first = self.queries.alerts(1)
        second = self.queries.alerts(1, first["next_before"])
        self.assertNotEqual(first["items"][0]["id"], second["items"][0]["id"])
        self.assertIsNone(second["next_before"])
