# Security Orchestrator

> Publication redaction: workstation-specific evidence/settings were withheld. Methods, dated outcomes and limitations remain historical; omitted values are not replacement measurements.

Личный Linux security monitor: замечать важные изменения, понимать доказательства
и учиться безопасности на реальных событиях. **Безопасность → надёжность → понятность
→ простота → автоматизация → функции.**

## Состояние на 2026-09-13

**M0/M1 завершены в согласованном scope. Реализован foreground runtime M2a:**
устанавливаемый `sec`, Linux collectors, SQLite, baseline/diff, история, предупреждения
с русскими объяснениями, узкие исключения, freshness/doctor и kill switch.
Проверены synthetic replay и обработка ограничений sandbox. Полнота сбора на хосте
и семидневная эксплуатационная приёмка ещё не подтверждены. M2a не объявлен закрытым.
Владелец остановил monitor после начального soak (~23ч38м на последнем checkpoint).
Полный семидневный trial перенесён на integration/release-candidate stage и не блокирует
M2c acceptance; [результаты и решение](docs/operations/M2A_TRIAL.md).
Добавлен M2b: read-only evidence packs, privacy preview, bounded typed investigation,
OpenRouter/Ollama adapters и synthetic benchmark. AI выключен по умолчанию;
реальные provider calls, сравнительные измерения моделей и human acceptance ещё открыты.
M2a sensors/config/storage contracts сохраняются. M2c implementation и pre-acceptance
hardening завершены; M2c принят: **PASS WITH KNOWN LIMITATIONS**.
[Итог acceptance и непроверенные пункты](docs/operations/M2C-ACCEPTANCE.md).
M3 начат: реализован synthetic Docker posture — adapter/result v1, отдельная SQLite,
детекторы, dedup/drift и общий CLI/UI. Постоянный сбор с Docker daemon не подключён;
полная host acceptance и весь M3 ещё открыты.
2026-09-13: подготовлен одноразовый `docker-acquire` (по умолчанию только preview).
Первая попытка владельца завершилась отказом на version; найденная ошибка
шаблона исправлена. После отдельного разрешения выполнен успешный host capture:
Docker 29.1.3, три остановленных контейнера, status ok; полная host acceptance открыта;
[план и границы approval](docs/operations/M3-DOCKER-ACQUISITION.md).
Добавлен `docker-review`: offline проверка сохранённого capture по SHA-256, схеме
и полноте с агрегированной сводкой posture. Команда не вызывает Docker и не
заменяет human acceptance; [применение](docs/operations/M3-DOCKER-ACQUISITION.md#локальная-проверка-сохранённого-capture).

- [Roadmap: M2a watchdog → M2b AI → M2c надёжность/UI → M3 Docker](docs/ROADMAP.md).
- [Архитектура, ежедневный цикл и данные](docs/architecture/overview.md).
- [AI-расследователь и замена моделей](docs/architecture/llm-security.md).
- [Разработка, проверки и границы CI](docs/operations/development.md).
- [Правила безопасности](docs/operations/safety-rules.md).
- [Запуск M2a, CLI и приёмка](docs/operations/M2A-WATCHDOG.md).
- [M2b: privacy preview, расследование и local benchmark](docs/operations/M2B-INVESTIGATION.md).
- [Детекторы и ручная проверка](docs/detections/M2A-WATCHDOG.md).
- [M3: synthetic Docker posture, запуск и границы](docs/operations/M3-DOCKER-POSTURE.md).
- [Trust boundaries: watchdog, hostile evidence и coding agent](docs/architecture/trust-boundaries.md).

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

Следующий шаг M3 — согласовать минимизированный real-host acquisition и проверить
Docker posture на фактическом Engine. Synthetic contract/adapter/CLI/UI уже реализованы;
[границы и приёмка](docs/operations/M3-DOCKER-POSTURE.md).
Полный семидневный operational trial пройдёт позже на существенно более полном runtime;
исходный soak не подтверждает многодневную стабильность. Реальная M2b provider/model
acceptance также остаётся отдельной задачей. В M2a нет облачных запросов и host remediation;
`LLM_ENABLED=false` сохраняет весь реализованный цикл.

## M2c: reliability и local UI

Реализованы отдельные cursor/gaps/dedup и read-only local UI. Существующий M2a
monitor/SQLite v2 сохраняют поведение; новый `monitor-reliable` активируется отдельно
после отдельного решения владельца, без ожидания отложенного полного trial. UI не запускает AI и не меняет baseline/alerts/host settings.

- [Запуск, безопасность ключа и ручная приёмка](docs/operations/M2C-LOCAL-UI.md).
- [Итог M2c acceptance: PASS WITH KNOWN LIMITATIONS](docs/operations/M2C-ACCEPTANCE.md).
- [Journald scope, gaps, reconciliation и schema](docs/architecture/M2C-RELIABILITY.md).
- [Threat model локального интерфейса](docs/architecture/M2C-UI-SECURITY.md).

`sec view` — read-only запросы без migration; `sec ui --help` — отдельный foreground
интерфейс. A/B PASS и C service PASS подтверждены владельцем; D пройдена отдельной
real-host серией. Timer events, аварийные сценарии и длительный soak не объявлены
проверенными. Постоянный monitor/autostart и M3 этой приёмкой не запущены.
