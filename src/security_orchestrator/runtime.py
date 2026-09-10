"""Foreground scheduling and a cooperative persistent kill switch; no service installation."""

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import time

from .model import InvalidInput
from .store import private_directory, private_file


@contextmanager
def monitor_lock(directory: Path):
    fd = private_file(directory / "monitor.lock")
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise InvalidInput("monitor_already_running") from error
        yield
    finally:
        os.close(fd)


def service_status(directory: Path) -> dict:
    path = directory / "monitor.lock"
    running = False
    if path.exists():
        fd = private_file(path)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                running = True
        finally:
            os.close(fd)
    return {
        "foreground_running": running,
        "disabled": (directory / "disabled").exists(),
        "service_installation": "Приложение не устанавливает systemd service или timers.",
    }


def set_disabled(directory: Path, disabled: bool) -> dict:
    directory = private_directory(directory)
    flag = directory / "disabled"
    if disabled:
        fd = private_file(flag)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    else:
        flag.unlink(missing_ok=True)
    return {
        "disabled": disabled,
        "effect": "Изменён только kill switch orchestrator; firewall/hardening не затронуты.",
    }


def run_monitor(app, collect, notify, emit, iterations: int = 0) -> None:
    directory = app.store.directory
    with monitor_lock(directory):
        completed = 0
        while not (directory / "disabled").exists():
            result = collect(app.config, cancelled=lambda: (directory / "disabled").exists())
            if (directory / "disabled").exists():
                break
            summary = app.ingest(result)
            emit({**summary, **app.notify(notify)})
            completed += 1
            if iterations and completed >= iterations:
                break
            deadline = time.monotonic() + app.config.interval_seconds
            while time.monotonic() < deadline:
                if (directory / "disabled").exists():
                    return
                time.sleep(min(1, max(0, deadline - time.monotonic())))
