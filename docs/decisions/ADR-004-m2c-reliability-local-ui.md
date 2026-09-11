# ADR-004 — M2c: отдельная reliability DB и локальная UI

Дата: 2026-09-11. Статус: реализовано, synthetic acceptance; host activation открыта.

## Контекст

M2a проходит семидневный operational trial. ADR-003 сохраняет watchdog SQLite v2,
Config v1 и detector/collector contracts. UI должна читать текущую evidence без
миграций и без второго detection backend. Journald не является универсальным
источником auth evidence для непривилегированного пользователя.

## Решение

Отдельная `reliability.sqlite3`, application_id `0x53454343`, schema v1. Она связана
с host_id и config fingerprint watchdog; несовпадение отклоняется. Её создание и
миграция 0→1 относятся только к явно выбранному приватному каталогу M2c. Никакого
ALTER/PRAGMA journal_mode/write к trial DB через UI или `sec view`.

Journal adapter принимает структурированные сообщения user manager о jobs/units,
только для services/timers. Они являются hints к запуску существующего inventory
scan, не дополнительным детектором compromise. `MESSAGE` исключён. Точное совпадение
cursor проверяется после seek. Records + gaps + checkpoint сохраняются одной
transaction с synchronous FULL. Durable generation/reconciled обеспечивают повтор
сверки после crash; две SQLite не объявляются общей атомарной transaction.

Новая команда `monitor-reliable` использует прежний Application.ingest и collectors,
но отдельный scheduler. Обычный `monitor` не импортирует M2c и не меняется. При активации
новой команды число scans/alert occurrences может увеличиться: до окончания trial
её не активировать. Event source не заменяет interval из Config.

Read-only Queries повторно использует Application.status и M2b PackBuilder/fallback;
`sec view` и UI используют один query service. `sec alerts/explain/status` сохраняют
свои форматы/exit codes. Узкая дополнительная pagination проекция не является новой
state machine. M2b получает optional trace observer, выключенный по умолчанию;
`investigate --run --record-state` сохраняет только минимизированную timeline.

UI: стандартная библиотека Python, небольшой HTTPServer с собственным Handler и
allowlist маршрутов/статических assets, обычные HTML/CSS/JS. Никакого file-serving
handler, шаблонизатора, CDN, npm runtime, WebSocket/SSE, account system или cloud UI.
Stdlib HTTP server сам по себе не даёт достаточной защиты — ограничения Host,
Origin, bearer, methods, headers, deadlines реализованы явно и покрыты negative tests.
Это локальный single-user инструмент, не Internet-facing deployment.

Access: random key владельца через скрытый getpass; process хранит SHA-256 digest,
браузер — bearer только в closure. Максимум 8 часов; страница/«Забыть ключ» очищает
локальную память и evidence. Нет cookies, URL credentials, localStorage или журнала
HTTP-запросов. Restart уничтожает process state; если вручную повторить тот же ключ,
он снова будет действовать. Поэтому для каждого запуска выбирается новый ключ.
Полная модель и residual risks: [threat model](../architecture/M2C-UI-SECURITY.md).

## Альтернативы и последствия

- Миграция main DB или refactor M2a scheduler загрязнили бы trial; отвергнуты.
- FastAPI/Flask/ASGI добавили бы зависимости и отдельный lifecycle без нужной здесь
  функции. Стандартный Python runtime уже используется проектом. Новых dependencies
  и opportunistic upgrades нет; uv.lock неизменён.
- Полный journal/auth parsing требует иного доступного scope и стабильных полей;
  текстовый parser SSH/sudo/PAM и повышение privileges не добавлены.
- sd-journal bindings дают более точную работу с cursor, но требуют дополнительного
  FFI/dependency boundary. Здесь bounded journalctl и консервативные gaps проще.
- UI не показывает raw metadata или произвольный provider text. Для локальных
  оригиналов остаётся `sec explain`; для AI — исходный вывод явно запущенного CLI.
- Нет межбазовых foreign keys. Sidecar host/config binding и проверка alert ID при
  записи через application boundary связывают данные; старые записи не превращаются
  в подтверждение актуальности main evidence после retention.

Источники проверены 2026-09-11:
[Python HTTP server](https://docs.python.org/3.13/library/http.server.html),
[SQLite isolation](https://www.sqlite.org/isolation.html),
[SQLite atomic commit](https://www.sqlite.org/atomiccommit.html),
[systemd v249 message IDs](https://raw.githubusercontent.com/systemd/systemd/v249/src/systemd/sd-messages.h).
