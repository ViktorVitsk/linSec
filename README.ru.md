# linSec — архив Linux security watchdog

> Public history notice (2026-10-08): this is a separately sanitized publication copy. Private workstation, network and deployment observations were withheld throughout Git history; local paths/VM labels are publication placeholders. Original commit dates, author names, chronology and development work remain. Git email uses the owner-provided GitHub noreply address; commit hashes changed. Historical results are dated records, not new tests or current security attestations. See [publication review](docs/PUBLICATION_REVIEW.md) for evidence limitations.

[English README](README.md)

linSec замечает изменения на личной Linux workstation и позволяет разобраться
в доказательствах: что изменилось, относительно какого reviewed baseline,
насколько полон сбор и что остаётся неизвестным. Python package называется
`security-orchestrator`, CLI — `sec`.

Разработка остановлена по решению владельца. Старые планы и инструкции trial
сохранены как история. Это инженерный прототип, не готовый EDR/SIEM.
Полный семидневный operational trial **не завершён**.

## Реализовано

- **M2a:** ограниченные Linux collectors, SQLite snapshots/history, baseline/diff,
  freshness, предупреждения, узкие trust/suppression и kill switch.
- **M2b:** read-only evidence packs, privacy preview/approval, bounded investigation,
  deterministic fallback, адаптеры Ollama/OpenRouter. AI выключен по умолчанию;
  real-provider и human acceptance остались открытыми.
- **M2c:** journald cursor/gaps/reconciliation и локальный read-only Web UI.
  Историческая приёмка — PASS WITH KNOWN LIMITATIONS; развитие заморожено.
- **M3:** одноразовый Docker capture и offline review. Synthetic Docker store/demo/UI
  удалены после архитектурного пересмотра; постоянный Docker monitor не реализован.

ASCP — отдельный проект, читающий минимизированные статусы linSec. Он не владеет
его collectors, базой, scheduler или подсистемой расследования.

## Свидетельства инженерной работы

[ADR-002](docs/decisions/ADR-002-m2a-snapshots.md) объясняет, почему частичный сбор
не должен создавать ложные удаления и почему baseline не означает «хост чист».
[AI boundary](docs/decisions/ADR-003-m2b-investigation-boundary.md) ограничивает
операции связанными evidence IDs без произвольного shell/SQL/path/URL.
[Pre-acceptance review](docs/operations/M2C-PRE-ACCEPTANCE.md) связывает ошибки
provenance/cursor/reconciliation/UI с исправлениями и regression tests.
[ADR-007](docs/decisions/ADR-007-reuse-first-orchestrator.md) сохраняет решение
уменьшить собственную реализацию и не продолжать подсистемы без доказанной пользы.

[Первый soak](docs/operations/M2A_TRIAL.md) наблюдался 23:38:07 на последнем
checkpoint; это не семидневная стабильность и не доказанный kernel suspend.
[M2c acceptance](docs/operations/M2C-ACCEPTANCE.md) отделяет проверки владельца
от агентской real-host серии и сохраняет ограничения. После удаления synthetic
Docker subsystem 13 сентября записаны 237 synthetic tests, Ruff, hygiene, DOM
и package checks. Эти исторические результаты не объявлены новым прогоном.

## Агентная разработка

По сообщению владельца, код создавался с активной помощью ИИ-агентов; он не
приписывается ручному написанию человеком. Правила заданий, отдельное разрешение
host-операций, исправления после review и решение остановить лишнюю разработку
можно проследить по документам и коммитам. M2c acceptance содержит конкретный
пример: владелец отклонил смешанную Phase D серию, прежние данные сохранили,
а агент выполнил отдельно разрешённую чистую серию.

Это свидетельства управления качеством, но не полный журнал prompts и не
достоверное авторство каждой строки или решения. Подробная карта доказательств,
архитектурная схема и технологии — в [основном README](README.md).

## Безопасный пример

Linux, уже установленный Python 3.13, чистый checkout:

```bash
PYTHONPATH=src python3.13 -B -m security_orchestrator.cli --state runtime/portfolio-demo demo
```

Отдельная synthetic DB создаётся в ignored
`runtime/portfolio-demo/synthetic-demo/`. Пример использует реальные application
operations на искусственных данных; host collection, system changes, AI и Docker
не запускаются. Для повторения выбрать новый `--state`, старые данные не стираются.

[Отчёт подготовки к публикации](docs/PUBLICATION_REVIEW.md) описывает оставшиеся
решения о раскрытии workstation/network metadata, истории и лицензии. Исходники,
тесты, исторические документы и локальные artifacts сохранены. Push не выполнялся.
