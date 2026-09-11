"""Explicit M2c foreground runtime. Existing M2a runtime remains unchanged."""

import sqlite3
import time

from ..model import InvalidInput
from ..runtime import monitor_lock


def run(
    app,
    reliability,
    collect,
    read_batch,
    emit,
    iterations=0,
    *,
    clock=time.monotonic,
    sleep=time.sleep,
    notify=None,
):
    directory = app.store.directory
    with monitor_lock(directory):
        due, completed = 0.0, 0
        last_report = None
        while not (directory / "disabled").exists():
            previous = reliability.checkpoint()
            batch = read_batch(previous)
            generation = reliability.ingest(previous, batch)
            if reliability.pending() or clock() >= due:
                results = collect(app.config, cancelled=lambda: (directory / "disabled").exists())
                if (directory / "disabled").exists():
                    return
                try:
                    result = app.ingest(results)
                except (OSError, sqlite3.Error, InvalidInput):
                    reliability.reconciled(generation, "storage_failure")
                    raise
                relevant = next((r for r in results if r.source == "systemd_user"), None)
                outcome = relevant.status if relevant else "unavailable"
                current_observed = bool(
                    relevant
                    and (relevant.status == "ok" or relevant.status == "partial" and relevant.items)
                )
                reliability.reconciled(generation, outcome, current_observed=current_observed)
                if notify is not None:
                    app.notify(notify)
                due = clock() + app.config.interval_seconds
                emit(
                    {
                        "reconciliation": result,
                        "journal_state": batch.state,
                        "history_recovered": False,
                    }
                )
            elif last_report != (batch.state, batch.checkpoint):
                emit(
                    {
                        "journal_state": batch.state,
                        "checkpoint_committed": batch.checkpoint is not None,
                    }
                )
            last_report = (batch.state, batch.checkpoint)
            completed += 1
            if iterations and completed >= iterations:
                return
            # Poll journal metadata at 5 seconds; periodic reconciliation is independent.
            for _ in range(5):
                if (directory / "disabled").exists():
                    return
                sleep(1)
