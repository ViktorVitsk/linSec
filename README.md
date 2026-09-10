# Security Orchestrator

> Publication redaction: workstation-specific evidence/settings were withheld. Methods, dated outcomes and limitations remain historical; omitted values are not replacement measurements.

Личный Linux security monitor: замечать важные изменения, понимать доказательства
и учиться безопасности на реальных событиях. **Безопасность → надёжность → понятность
→ простота → автоматизация → функции.**

## Состояние на 2026-09-10

**M0/M1 завершены в согласованном scope. Реализован foreground runtime M2a:**
устанавливаемый `sec`, Linux collectors, SQLite, baseline/diff, история, предупреждения
с русскими объяснениями, узкие исключения, freshness/doctor и kill switch.
Проверены synthetic replay и обработка ограничений sandbox. Полнота сбора на хосте
и семидневная эксплуатационная приёмка ещё не подтверждены. M2a не объявлен закрытым.
Systemd service не устанавливался; AI integration отсутствует.

- [Roadmap: M2a watchdog → M2b AI → M2c надёжность/UI → M3 Docker](docs/ROADMAP.md).
- [Архитектура, ежедневный цикл и данные](docs/architecture/overview.md).
- [AI-расследователь и замена моделей](docs/architecture/llm-security.md).
- [Разработка, проверки и границы CI](docs/operations/development.md).
- [Правила безопасности](docs/operations/safety-rules.md).
- [Запуск M2a, CLI и приёмка](docs/operations/M2A-WATCHDOG.md).
- [Детекторы и ручная проверка](docs/detections/M2A-WATCHDOG.md).

## Попробовать безопасный пример

В подготовленной project `.venv`:

```bash
uv run --cache-dir .cache/uv --no-sync sec demo
```

Создаётся отдельная synthetic database в `runtime/watchdog/synthetic-demo`.
Пример показывает повтор, trust, изменение executable и drop-in через реальные
application operations. Повторный demo требует нового явно выбранного каталога:
существующая база автоматически не очищается.

Foreground-сбор: `uv run --cache-dir .cache/uv --no-sync sec monitor`.
Остановить: Ctrl-C или из второго терминала `uv run --cache-dir .cache/uv --no-sync sec disable`.
Первый снимок требует ручного review через `sec baseline diff`; автоматического
доверия нет. Все команды должны использовать один и тот же `--state` и `--config`.

## Последнее подтверждённое состояние машины

Источник — аудит **E15/E16 от 2026-09-10**, не новый live scan. UFW применён и
проверен для IPv4/IPv6; согласованные exceptions и Docker rules сохранены,
CUPS/DNS/HTTPS checks прошли в указанном scope.

[Publication redaction: private workstation observation/configuration omitted.]



- [Решения и оставшиеся ограничения M1](docs/operations/NEXT_STEPS.md).
- [История аудита E01–E16](docs/audit/INITIAL_SECURITY_AUDIT.md).
- [Модель угроз](docs/architecture/INITIAL_THREAT_MODEL.md).
- [Архив выполненной firewall-процедуры](docs/operations/HOST_FIREWALL_HARDENING_PLAN.md).

## Локальные проверки

Для уже установленной project `.venv` с Python 3.13 и Ruff:

```bash
uv run --cache-dir .cache/uv --no-sync python scripts/check_m0.py
uv run --cache-dir .cache/uv --no-sync python -m unittest discover -s tests -v
uv run --cache-dir .cache/uv --no-sync ruff check --no-cache .
git diff --check
```

Подготовка среды и обновление lockfile описаны в [development](docs/operations/development.md).
System/user Python не изменяется. `uv.lock` редактирует только uv. Gate проверяет
repository hygiene, Ruff — Python constructs; они не заменяют sandbox, secret
scanning или host audit. Тесты работают с disposable repositories и synthetic data.
CI настроен на GitHub-hosted runner; локальные тесты не подтверждают удалённый CI run.

## Ближайшая польза

Ближайший шаг — проверить покрытие M2a в обычном пользовательском окружении и
провести семидневный foreground trial. M2b добавит ручное расследование с LLM/SLM
после этой проверки. В M2a нет облачных запросов и host remediation;
`LLM_ENABLED=false` сохраняет весь реализованный цикл.
