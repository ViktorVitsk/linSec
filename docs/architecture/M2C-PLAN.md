# M2c — план реализации

Дата: 2026-09-11. Основа: ADR-002/003, SQLite watchdog v2, Config v1.
Первичная проверка: 93 synthetic tests PASS. Во время inspection владелец сохранил
M2b и trial notes коммитами; изменения M2c начинаются после `cf1d7f3`.

1. Отдельный versioned reliability store: checkpoint + минимизированные journal
   records + typed gaps в одной SQLite transaction. Main watchdog DB не мигрировать.
2. Journald — только структурированные user-manager unit lifecycle hints.
   Они ускоряют существующий inventory scan; не доказывают изменение unit file,
   auth failure или compromise. MESSAGE не читать. Checkpoint подтверждать только
   вместе с durable records. Проверять точное совпадение cursor перед continuation.
3. Новый opt-in foreground runtime: scheduled full reconciliation + bounded journal
   batches, crash-safe pending reconciliation. Старый monitor/collectors/detectors
   и baseline contracts сохранить. Gap не закрывается как восстановленная история.
4. Общий read-only query service над Application и M2b PackBuilder: overview,
   pagination alerts, evidence, guidance, сохранённая opt-in timeline. UI не получает
   write Store и provider capabilities. Отдельная CLI read-only команда использует
   тот же query service.
5. Local-only stdlib HTTP transport; static allowlisted assets. Точный Host/Origin,
   bearer в памяти браузера, credential вводится через getpass на старте (не argv,
   URL или logs), ограниченный срок жизни; cookies и mutations отсутствуют.
   CSP, textContent, fail-closed methods/body limits и bounded queries.
6. Synthetic integration, crash/rollback, migrations, concurrency, hostile-input,
   HTTP negative tests; полный M2a/M2b regression, Ruff, format, lock и hygiene.
7. ADR + contracts/threat model/operator acceptance; host activation отдельно после
   trial review. Не запускать новый monitor/UI на host и не применять host changes.

Feasibility: systemd 249 на установленной системе; минимальный read-only `journalctl`
probe из sandbox увидел 3 записи с MESSAGE_ID/USER_UNIT/cursor/boot/timestamps,
без stderr. Scope этой проверки ограничен; system/auth coverage не подтверждено.
Прочитаны installed journalctl man/catalog и upstream journal fields/journalctl docs.
