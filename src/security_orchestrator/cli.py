"""CLI transport: all business operations live in application.py."""

import argparse
import json
from pathlib import Path
import sqlite3
import sys
import unicodedata

from .application import Application
from .config import load_config
from .demo import replay
from .explanations import explain
from .model import InvalidInput
from .store import Store, private_directory


def emit(value: object) -> None:
    output = json.dumps(value, ensure_ascii=False, indent=2)
    output = "".join(
        json.dumps(c, ensure_ascii=True)[1:-1]
        if (
            unicodedata.category(c) in {"Cf", "Cs", "Zl", "Zp"}
            or unicodedata.category(c) == "Cc"
            and c != "\n"
        )
        else c
        for c in output
    )
    print(output, flush=True)


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally echoes invalid argument values, potentially including credentials.
        self.print_usage(sys.stderr)
        self.exit(2, "sec: invalid arguments (values omitted); use --help\n")


def parser() -> argparse.ArgumentParser:
    root = SafeArgumentParser(
        prog="sec", description="Локальный watchdog; AI отдельно, без remediation"
    )
    root.add_argument(
        "--state", type=Path, default=Path("runtime/watchdog"), help="Приватный каталог состояния"
    )
    root.add_argument("--config", type=Path, help="TOML config v1; без файла используются defaults")
    commands = root.add_subparsers(dest="command", required=True)
    for name in ("scan", "status", "doctor", "disable", "enable", "demo"):
        commands.add_parser(name)
    for name in ("alerts", "history"):
        commands.add_parser(name).add_argument("--limit", type=int, default=100)
    commands.add_parser("explain").add_argument("id", type=int)
    investigation = commands.add_parser("investigate", help="M2b: read-only evidence и optional AI")
    investigation.add_argument("id", type=int)
    investigation.add_argument("--ai-config", type=Path)
    investigation.add_argument(
        "--record-state",
        type=Path,
        help="Opt-in M2c timeline; requires --run; separate private directory",
    )
    investigation.add_argument(
        "--run", action="store_true", help="Явный запуск с review каждого запроса"
    )
    investigation.add_argument("--approve", help="Токен только первого точного preview")
    benchmark = commands.add_parser("ai-benchmark", help="M2b: отдельные synthetic scenarios")
    benchmark.add_argument("--ai-config", type=Path)
    benchmark.add_argument(
        "--run", action="store_true", help="Запустить явно настроенный local runtime"
    )
    view = commands.add_parser("view", help="M2c: общие с UI read-only queries; без migrations")
    view.add_argument("id", type=int, nargs="?")
    view.add_argument("--alerts", action="store_true")
    view.add_argument("--limit", type=int, default=25)
    view.add_argument("--before", type=int, default=2**63 - 1)
    view.add_argument("--m2c-state", type=Path)
    ui = commands.add_parser("ui", help="Локальная read-only UI; ключ через скрытый ввод")
    ui.add_argument("--bind", default="127.0.0.1")
    ui.add_argument("--port", type=int, default=8765)
    ui.add_argument("--m2c-state", type=Path)
    reliable = commands.add_parser(
        "monitor-reliable", help="Opt-in M2c runtime; активировать после trial review"
    )
    reliable.add_argument("--m2c-state", type=Path, required=True)
    reliable.add_argument("--iterations", type=int, default=0)
    commands.add_parser("m2c-demo", help="Только synthetic data в новом изолированном каталоге")
    commands.add_parser("docker-demo", help="M3: synthetic Docker posture; без daemon")
    acquire = commands.add_parser(
        "docker-acquire", help="M3: preview; одноразовое чтение daemon только с --approve"
    )
    acquire.add_argument("--output", type=Path, required=True)
    acquire.add_argument(
        "--approve", help="Токен точного plan; разрешает единственный real-host capture"
    )
    docker_review = commands.add_parser(
        "docker-review", help="M3: проверить сохранённый capture без Docker/БД"
    )
    docker_review.add_argument("--capture", type=Path, required=True)
    docker_review.add_argument("--sha256", required=True, help="capture_sha256 из результата сбора")
    docker_review.add_argument(
        "--details", action="store_true",
        help="Локальные ID/state и evidence по контейнерам; содержит bind addresses/ports",
    )
    docker_view = commands.add_parser("docker-view", help="M3: read-only synthetic Docker evidence")
    docker_view.add_argument("id", type=int, nargs="?")
    docker_view.add_argument("--docker-state", type=Path, required=True)
    docker_view.add_argument("--limit", type=int, default=25)
    docker_view.add_argument("--before", type=int, default=2**63 - 1)
    ui.add_argument(
        "--docker-state", type=Path, help="Отдельный synthetic state M3; daemon не вызывается"
    )
    monitor = commands.add_parser("monitor")
    monitor.add_argument("--iterations", type=int, default=0, help="0: до Ctrl-C или sec disable")
    lifecycle = commands.add_parser("alert")
    lifecycle.add_argument("id", type=int)
    lifecycle.add_argument("state", choices=("open", "reviewed", "closed"))
    baseline = commands.add_parser("baseline").add_subparsers(dest="action", required=True)
    baseline.add_parser("show")
    baseline.add_parser("diff")
    update = baseline.add_parser("update")
    update.add_argument("--approve", required=True, help="Токен конкретного baseline diff")
    update.add_argument("--reason", required=True, help="Причина без secrets")
    trust = commands.add_parser("trust")
    trust.add_argument("id", type=int)
    trust.add_argument("--reason", required=True)
    trust.add_argument("--hours", type=int)
    suppression = commands.add_parser("suppress").add_subparsers(dest="action", required=True)
    add = suppression.add_parser("add")
    add.add_argument("id", type=int)
    add.add_argument("--reason", required=True)
    add.add_argument("--hours", type=int)
    suppression.add_parser("list")
    suppression.add_parser("remove").add_argument("id", type=int)
    commands.add_parser("config").add_argument("action", choices=("validate",))
    commands.add_parser("service").add_argument("action", choices=("status",))
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    store = None
    try:
        config = load_config(args.config)
        if not 1 <= getattr(args, "limit", 100) <= 1000:
            raise InvalidInput("limit_must_be_1_to_1000")
        if not 0 <= getattr(args, "iterations", 0) <= 100000:
            raise InvalidInput("invalid_iterations")
        if args.command == "config":
            emit({"valid": True, "schema_version": 1, "fingerprint": config.fingerprint})
            return 0
        if sys.platform != "linux":
            raise InvalidInput("CLI_requires_Linux_core_is_portable")
        if args.command == "docker-demo":
            from .docker_posture.scenarios import replay as docker_replay

            emit(docker_replay(args.state / "synthetic-docker"))
            return 0
        if args.command == "docker-acquire":
            from .docker_posture.acquisition import plan, run

            result = (
                run(args.output, args.approve) if args.approve is not None else plan(args.output)
            )
            emit(result)
            return 0 if result.get("status", "ok") == "ok" else 2
        if args.command == "docker-review":
            from .docker_posture.review import review

            result = review(args.capture, args.sha256, details=args.details)
            emit(result)
            return 0 if result["status"] == "ok" else 2
        if args.command == "docker-view":
            from .docker_posture.service import PostureQueries

            queries = PostureQueries(args.docker_state)
            emit(
                queries.detail(args.id)
                if args.id is not None
                else queries.overview(args.limit, args.before)
            )
            return 0
        if args.command in {"investigate", "ai-benchmark"}:
            from .investigation.cli import dispatch

            return dispatch(args, config, emit)
        if args.command in {"view", "ui", "monitor-reliable", "m2c-demo"}:
            from .reliability.cli import dispatch

            return dispatch(args, config, emit)
        from . import runtime

        if args.command in {"disable", "enable"}:
            emit(runtime.set_disabled(args.state, args.command == "disable"))
            return 0
        if args.command == "service":
            emit(runtime.service_status(args.state))
            return 0
        directory = (
            private_directory(args.state) / "synthetic-demo"
            if args.command == "demo"
            else args.state
        )
        store = Store(directory, config.storage_mib)
        app = Application(store, config)
        if args.command in {"scan", "monitor"}:
            if (store.directory / "disabled").exists():
                raise InvalidInput("monitoring_disabled_use_sec_enable_explicitly")
            from .adapters.linux import collect, command

            if args.command == "monitor":
                runtime.run_monitor(app, collect, lambda: command("notify"), emit, args.iterations)
            else:
                with runtime.monitor_lock(store.directory):
                    results = collect(
                        config, cancelled=lambda: (store.directory / "disabled").exists()
                    )
                    if (store.directory / "disabled").exists():
                        raise InvalidInput("monitoring_disabled")
                    outcome = app.ingest(results)
                    emit({**outcome, **app.notify(lambda: command("notify"))})
                    return 0 if all(r.status == "ok" and r.reason == "none" for r in results) else 2
        elif args.command in {"status", "doctor"}:
            result = app.doctor() if args.command == "doctor" else app.status()
            emit(result)
            return 0 if result.get("healthy", result["health"] == "current") else 2
        elif args.command == "alerts":
            emit(app.alerts(args.limit))
        elif args.command == "history":
            emit(app.history(args.limit))
        elif args.command == "explain":
            emit(explain(app, args.id))
        elif args.command == "alert":
            emit(app.lifecycle(args.id, args.state))
        elif args.command == "baseline":
            if args.action == "show":
                emit(app.baseline_show())
            elif args.action == "diff":
                emit(app.baseline_preview())
            else:
                emit(app.baseline_update(args.approve, args.reason))
        elif args.command == "trust":
            emit(app.exception(args.id, "trust", args.reason, args.hours))
        elif args.command == "suppress":
            if args.action == "list":
                emit(app.exceptions())
            elif args.action == "remove":
                emit(app.remove_exception(args.id))
            else:
                emit(app.exception(args.id, "suppression", args.reason, args.hours))
        elif args.command == "demo":
            emit(replay(app))
        return 0
    except KeyboardInterrupt:
        emit({"stopped": "foreground", "system_changes": False})
        return 130
    except (OSError, sqlite3.Error):
        if store is not None:
            store.mark_storage_error(True)
        # Never expose raw DB/file/command exception text. A full disk can prevent saving health:
        # nonzero exit and stderr are the fallback, with stale evidence visible on the next status.
        print(
            "DEGRADED: storage/access failure; данные не подтверждены. Выполните sec doctor.",
            file=sys.stderr,
        )
        return 2
    except ValueError as error:
        if isinstance(error, InvalidInput):
            emit({"error": str(error)})
        else:
            emit({"error": "invalid_input_contents_omitted"})
        return 2
    except Exception:
        # Collector cancellation/errors and malformed runtime evidence cannot leak raw telemetry.
        emit({"error": "operation_failed_contents_omitted", "health": "degraded"})
        return 2
    finally:
        if store is not None:
            store.close()


if __name__ == "__main__":
    raise SystemExit(main())
