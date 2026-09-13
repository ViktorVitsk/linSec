"""New opt-in commands; default M2a/M2b routes remain untouched."""

import getpass
import sys

from ..application import Application
from ..investigation.contracts import require
from ..model import InvalidInput
from ..queries import Queries
from ..store import Store
from .store import ReliabilityStore


def dispatch(args, config, emit):
    if args.command in {"view", "ui"}:
        queries = Queries(args.state, config, args.m2c_state)
        if args.command == "view":
            emit(
                queries.detail(args.id)
                if args.id is not None
                else queries.alerts(args.limit, args.before)
                if args.alerts
                else queries.overview()
            )
            return 0
        from ..local_ui.server import LocalServer, validate_bind

        validate_bind(args.bind, args.port)
        require(sys.stdin.isatty(), "ui_key_requires_interactive_terminal")
        token = getpass.getpass("Ключ из password manager (32–128 random ASCII, скрытый ввод): ")
        server = LocalServer(args.bind, args.port, queries, token)
        del token
        emit(
            {
                "ui": "running",
                "address": f"http://{args.bind}:{args.port}",
                "access": "bearer_required; 8h maximum; read_only",
                "browser_opened": False,
            }
        )
        try:
            server.serve_forever(poll_interval=0.5)
        finally:
            server.server_close()
        return 0
    if args.command == "m2c-demo":
        from .scenarios import replay

        emit(replay(args.state, config))
        return 0
    require(args.command == "monitor-reliable")
    require(args.m2c_state is not None, "explicit_m2c_state_required")
    if (args.state / "disabled").exists():
        raise InvalidInput("monitoring_disabled")
    store = Store(args.state, config.storage_mib)
    reliability = None
    try:
        reliability = ReliabilityStore(args.m2c_state, store.meta("host_id"), config.fingerprint)
        from ..adapters.journal import read_batch
        from ..adapters.linux import collect, command
        from .runtime import run

        run(
            Application(store, config),
            reliability,
            collect,
            read_batch,
            emit,
            args.iterations,
            notify=lambda: command("notify"),
        )
        return 0
    finally:
        if reliability:
            reliability.close()
        store.close()
