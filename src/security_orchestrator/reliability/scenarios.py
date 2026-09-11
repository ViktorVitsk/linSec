"""Deterministic M2c scenarios, disposable synthetic state only."""

from pathlib import Path
import tempfile

from ..application import Application
from ..investigation.contracts import Settings
from ..investigation.evidence import EvidenceReader, PackBuilder
from ..investigation.scenarios import seed
from ..investigation.service import Investigation
from ..model import now
from ..queries import Queries
from ..store import Store, private_directory
from .contracts import Batch, Checkpoint, JournalEvent, State
from .store import ReliabilityStore
from .timeline import Timeline


def replay(directory: Path, config) -> dict:
    root = private_directory(directory)
    target = Path(tempfile.mkdtemp(prefix="synthetic-m2c-", dir=root))
    store = Store(target / "watchdog")
    reliability = ReliabilityStore(target / "m2c", store.meta("host_id"), config.fingerprint)
    try:
        app = Application(store, config)
        alert_id = seed(app, "injection")
        cp = Checkpoint("synthetic-cursor-1", "a" * 32, now())
        event = JournalEvent(cp, "39f53479d3a045ac8e11786248231fbf", "synthetic.service", "started")
        reliability.ingest(None, Batch(State.FIRST, cp, (event,)))
        reliability.ingest(cp, Batch(State.CONTINUATION, cp, (event,)))
        generation = reliability.ingest(cp, Batch(State.ROTATED))
        reliability.reconciled(generation, "partial")
        reader = EvidenceReader(target / "watchdog")
        try:
            trace = Timeline()
            result = Investigation(PackBuilder(reader), Settings(), trace=trace).run(alert_id)
            reliability.save_investigation(alert_id, trace.finish(result))
        finally:
            reader.close()
        queries = Queries(target / "watchdog", config, target / "m2c")
        view = queries.overview()
        return {
            "scenario_version": "m2c-synthetic-1",
            "state_directory": str(target),
            "scenarios": [
                "first",
                "continuation",
                "duplicate",
                "gap",
                "reconciliation_after_gap",
                "deterministic_alert",
                "timeline_llm_disabled",
                "hostile_metadata_alias",
            ],
            "event_count": reliability.db.execute("SELECT count(*) FROM events").fetchone()[0],
            "gap_count": view["reliability"]["gap_count"],
            "history_recovered": False,
            "alert_id": alert_id,
            "llm_enabled": False,
        }
    finally:
        reliability.close()
        store.close()
