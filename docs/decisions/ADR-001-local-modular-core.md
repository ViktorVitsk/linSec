# ADR-001 — Локальное модульное ядро и ранний ограниченный AI

Дата: 2026-09-10. Статус: принято; runtime ещё не реализован.

## Контекст

M0/M1 дали проектную основу и аудит одной Pop!_OS workstation. Пользователю нужны
ежедневная польза и обучение. Старый M2 слишком широк, AI отложен до M4, а Python
тестов расходится с уже выбранной `.python-version` 3.13.

## Решение

Python 3.13 в uv project environment, SQLite, один пакет с отдельно тестируемыми
ядром, OS adapters, application services и интерфейсами. CLI первым, затем локальная
UI; переносимость ядра без Windows-сенсоров сейчас. AI после минимального watchdog,
сначала объяснение, затем до пяти шагов через validated read-only operation registry.
Detection независим от AI; автоматическая remediation и cloud escalation выключены.

## Альтернативы

Системный Python 3.10 привязывает продукт к OS interpreter и близкому upstream EOL.
Переписывание на Rust/Go сейчас не решает измеренной проблемы. SIEM/microservices,
универсальный plugin/agent framework и собственный Sigma engine увеличат обслуживание.
Полное внедрение OCSF преждевременно; при реальном внешнем потребителе добавить mapping.

## Последствия

Ранний работающий вертикальный срез и замена LLM/SLM через adapter и evals.
Потребуются явные platform boundaries, migrations, данные о пробелах покрытия,
контроль зависимостей и ограничения ресурсов. Нет обещания tamper-proof защиты
локальной SQLite или обнаружения любого кратковременного события.

Источники проверены 2026-09-10:
[Python lifecycle](https://devguide.python.org/versions/),
[uv project layout](https://docs.astral.sh/uv/concepts/projects/layout/),
[OCSF](https://ocsf.io/). Детали: [архитектура](../architecture/overview.md).
