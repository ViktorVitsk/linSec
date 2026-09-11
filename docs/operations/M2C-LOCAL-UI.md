# M2c — запуск, проверка и совместимость с trial

> Publication redaction: workstation-specific evidence/settings were withheld. Methods, dated outcomes and limitations remain historical; omitted values are not replacement measurements.

Дата: 2026-09-11, проверки завершены 2026-09-12. Код/synthetic acceptance готовы; активация нового monitor отдельно.
[Архитектура/контракты](../architecture/M2C-RELIABILITY.md),
[threat model](../architecture/M2C-UI-SECURITY.md),
[ADR-004](../decisions/ADR-004-m2c-reliability-local-ui.md).

[Итоговый отчёт и результаты validation](M2C-IMPLEMENTATION.md).

## Что доступно

- `sec view`: read-only обзор через те же Queries, что UI; без миграций main DB.
- `sec view --alerts --limit 25 --before ID`: bounded keyset pagination по ID.
- `sec view ID`: проверенный evidence pack, guidance и optional timeline.
- `sec ui`: foreground local UI, только `127.0.0.1:8765`, ручное открытие браузера.
- `sec monitor-reliable --m2c-state DIRECTORY`: новый явно выбранный scheduler.
- `sec investigate ID --run --record-state DIRECTORY`: opt-in trace M2b в отдельной
  M2c DB. Без AI config при LLM_ENABLED=false сохраняется deterministic fallback;
  с provider config продолжает действовать прежний explicit privacy approval flow.
- `sec m2c-demo`: synthetic events/gap/reconciliation/hostile metadata/fallback/timeline
  в НОВОМ каталоге внутри явно выбранного --state. Это пишет только synthetic DB.

`view` exit 0 означает, что query выполнен, а не healthy host; состояние находится
в полях ответа. Прежние `scan/status/doctor` exit 2 для partial/degraded сохранены.

## Важное для текущего семидневного trial

Обычный `monitor`, collectors, detector/context/snapshot fingerprints, Config v1,
baseline/partial/retention semantics и watchdog SQLite v2 не изменены. Existing
foreground процесс не перезапускался, trial DB не открывалась writable и не мигрировалась,
baseline/alerts/notifications/sensor settings не менялись. LLM/providers не включались.
Trial может продолжаться прежним процессом без restart/migration.

До завершения trial/review НЕ заменять его на monitor-reliable. Event-triggered scans
меняют частоту collection/occurrences/resource usage, поэтому это новая operational
серия. Не использовать synthetic-demo DB как baseline реального host. Новый UI —
отдельный процесс и потребление ресурсов: для строгих trial resource measurements
также лучше активировать после trial либо явно отметить отдельное окно.

## Access control и запуск UI

Создайте новый random key 32–128 ASCII `[A-Za-z0-9_-]` в существующем password manager.
Не вставляйте ключ в команду, URL или env. `sec ui` запросит его через getpass; вставьте
тот же ключ в password input страницы. Обычный URL содержит только loopback/port.
По умолчанию browser не открывается. Срок ключа максимум 8 часов; новый запуск — новый
ключ. «Забыть ключ» очищает вкладку, не отзывает другие уже имеющиеся копии bearer.
Ctrl-C останавливает только UI. Состояние monitor/baseline не меняется.

Watchdog и M2c directories должны быть отдельными private owned directories. При
wrong permissions/symlink приложение отказывает, а не исправляет host chmod.
Если optional M2c path не задан, overview показывает not_configured, main evidence
и deterministic explanations доступны. Если path задан, но DB недоступна/несовместима,
это storage_or_contract_failure, а не пустая timeline. Не повторять migration через
ручной SQL; неизвестная schema требует review.

## Ручная приёмка после review

Обновлено 2026-09-12 после [pre-acceptance hardening](M2C-PRE-ACCEPTANCE.md).
Ниже команды **для человека**, они не были выполнены агентом на host.
Из корня repo, уже подготовленная `.venv`; без install/sync, sudo, services,
изменения групп/permissions, AI/provider calls. `TRIAL_STATE` и `DEMO_DIRECTORY`
заменить на проверенные пути, не копировать placeholders буквально.
Для каждой фазы записать результат и ограничения; отсутствие данных — UNKNOWN.

### Phase A — M2c read-only inspection

```bash
uv run --cache-dir .cache/uv --no-sync sec ui --help
uv run --cache-dir .cache/uv --no-sync sec monitor-reliable --help
uv run --cache-dir .cache/uv --no-sync sec --state TRIAL_STATE view
uv run --cache-dir .cache/uv --no-sync sec --state TRIAL_STATE view --alerts --limit 5
uv run --cache-dir .cache/uv --no-sync sec --state TRIAL_STATE view ALERT_ID
```

Первые две команды показывают интерфейс. Следующие читают обзор, bounded страницу
и детали существующего ID через SQLite `mode=ro/query_only`. Listener и collectors
не запускаются; main DB не мигрируется. Python/uv могут создать project cache/bytecode.
Успех: JSON без raw metadata, версии main DB=2, различимы partial/stale/config mismatch;
exit 0 означает выполненную query, **не** healthy host. Без sidecar нормально
`not_configured`. Ошибка locked/corrupt/missing DB — остановить приёмку этого шага,
не «лечить» trial SQL/PRAGMA. Ctrl-C завершает только query, cleanup не требуется.
`status/doctor` здесь не заменяют `view`: их старый Store открывается writable.

### Phase B — isolated local UI

```bash
uv run --cache-dir .cache/uv --no-sync sec --state runtime/m2c-lab m2c-demo
```

Создаёт новый synthetic subdirectory и обе БД только внутри `runtime/m2c-lab`.
Успех: JSON `state_directory`; collectors/providers/listener отсутствуют. Данные
не представляют workstation. Сохранить возвращённый путь как `DEMO_DIRECTORY`.
После завершения процесс остановлен; оставить synthetic directory для review.

```bash
uv run --cache-dir .cache/uv --no-sync sec --state DEMO_DIRECTORY/watchdog ui --m2c-state DEMO_DIRECTORY/m2c
```

Создаёт foreground listener `127.0.0.1:8765`; БД только читаются. Риск: дополнительная
нагрузка и занятый порт; если порт занят, не останавливать чужой процесс. При строгом
учёте trial resources отметить отдельное окно или отложить B до конца trial.
Новый random key из password manager ввести скрыто; вручную открыть **реальный
локальный browser** на адресе stdout. Не использовать remote browser/proxy/forwarding.

Успех проверить вручную:

- Wrong key отвергается, верный открывает overview, alerts, detail, timeline.
- Gaps остаются после reconciliation; AI hypothesis отделена от deterministic facts.
- Hostile metadata — inert text/псевдонимы, отсутствуют внешние requests и CSP violations.
- Pagination, две вкладки, reload, back/forward, pagehide, «Забыть ключ»; после logout
  поздний ответ не возвращает evidence. Ключ отсутствует в URL/storage/cookies.
- 200% zoom и узкое окно читаемы. Не делиться screenshots с ключом/headers/evidence.

Ограничения: logout очищает только эту вкладку; другие bearer copies действуют до
expiry/остановки сервера. Reload страницы забывает ключ; кнопка «Обновить» обновляет
данные и сохраняет текущую сессию. 8h server expiry проверен synthetic clock, ожидание
8 часов здесь не обязательно. Clipboard/password-manager/browser extensions вне
контроля UI; после ввода очистить clipboard средствами пользователя.
Ctrl-C в **терминале UI** закрывает listener; повторное открытие URL не обслуживается.
Закрыть вкладки; synthetic directories можно сохранить. Trial monitor не трогать.

### Phase C — journald read-only validation

```bash
/usr/bin/journalctl --version
```

Только версия установленного journalctl, без БД/настроек. Успех: версия и features;
сверить поддержку следующей команды. Ранее записанная v249 — dated evidence, не новая
проверка host. Команда завершается сама, cleanup нет.

[Publication redaction: private workstation observation/configuration omitted.]


Читает до 256 последних сообщений своего user manager и передаёт JSON в reviewed
minimizer; текст **не исполняется**. Только счётчики service/timer/records выходят
из minimizer; raw MESSAGE, environment/argv не запрашиваются. Скрипт не запускает
процессы и не пишет state; максимум входа 2 MiB, строка 16 KiB. Ничего не сохранять
через tee/redirection в Git. stderr journalctl не является командой и не публикуется.

Успех: **exit 0 всей pipeline** и `target_events_observed=true` демонстрируют наличие
хотя бы одного подходящего события в выборке, с проверенными UID/COMM/EXE/ID.
`accepted_service_events` и `accepted_timer_events` отдельно показывают, какой тип
реально найден. Нули не доказывают отсутствия событий; exit 2 означает неподтверждённый
scope или invalid sample; exit 124 — timeout. Если один тип отсутствует, его acceptance
остаётся открытой. Не создавать units/атаки, не перезапускать services и не менять
journal retention ради PASS. Можно повторить позже после обычной работы пользователя.
Никакого полного auth coverage/history recovery эта команда не подтверждает.
Timeout/Ctrl-C останавливает только эту pipeline; нет host изменений и cleanup.

### Phase D — post-trial reliable monitor acceptance

**DO NOT RUN DURING CURRENT M2a TRIAL.** Только после завершения trial и отдельного
решения об activation. Проверить, что следующие directories ещё не существуют;
не подставлять trial или demo directory. Если существуют — остановиться и выбрать
новые имена после проверки, не удалять evidence.

```bash
uv run --cache-dir .cache/uv --no-sync sec --state runtime/m2c-acceptance monitor-reliable --m2c-state runtime/m2c-reliability --iterations 1
uv run --cache-dir .cache/uv --no-sync sec --state runtime/m2c-acceptance view --m2c-state runtime/m2c-reliability
uv run --cache-dir .cache/uv --no-sync sec --state runtime/m2c-acceptance monitor-reliable --m2c-state runtime/m2c-reliability --iterations 1
uv run --cache-dir .cache/uv --no-sync sec --state runtime/m2c-acceptance view --m2c-state runtime/m2c-reliability
```

Первый runtime читает host collectors/journal и создаёт **новые** watchdog/sidecar БД,
lock/health files. Возможны обычные notifications согласно текущему Config; не менять
trial Config. Успех: first observation/gap либо честная недоступность, записанная
reconciliation без `history_recovered=true`. Это новая monitoring series без trusted
baseline. Второй runtime проверяет restart/continuation по доступному anchor; при
потере cursor ожидается явный gap, не выдуманное восстановление истории. `view`
между запусками только читает состояние. Даже runtime exit 0 требует проверки полей.

Не ожидать детекции кратковременных изменений без inventory evidence. При storage/
parser/access error сохранить fixed diagnostics, остановить acceptance; не исправлять
permissions/migration/retention автоматически. После одной итерации процесс завершится;
Ctrl-C останавливает только запущенный здесь runtime. Не использовать `sec disable`
на trial. Сохранить новые state directories приватно; rollback host settings не нужен,
поскольку команды их не меняют. Удаление evidence — отдельное ручное решение.

## Development validation

```bash
uv run --cache-dir .cache/uv --no-sync python scripts/check_m0.py
uv run --cache-dir .cache/uv --no-sync python -m unittest discover -s tests -v
uv run --cache-dir .cache/uv --no-sync ruff check --no-cache .
uv run --cache-dir .cache/uv --no-sync ruff format --check --output-format concise .
uv lock --check --offline --cache-dir .cache/uv --python .venv/bin/python --no-python-downloads
uv run --cache-dir .cache/uv --no-sync sec ai-benchmark
node --check src/security_orchestrator/local_ui/app.js
node tests/ui_dom_test.cjs
uv build --offline --cache-dir .cache/uv --out-dir .cache/m2c-review/dist
uv run --cache-dir .cache/uv --no-sync python scripts/check_m2c_package.py
git diff --check
```

Node нужен только optional synthetic JS DOM smoke, не runtime/installation dependency
пакета. Python tests не запускают host collectors/providers/listener. HTTP parser
проверяется in-memory connection, concurrency — disposable SQLite.
Полный format check выявляет существовавшее до M2c форматирование `scripts/check_m0.py`
и `tests/test_m0_safety.py`; unrelated файлы не переписываются. Все изменённые/new Python
файлы M2c проходят отдельный format check. Type checker в проекте не настроен.

## Известные ограничения

- Реальные browser layout/CSP/TCP и service/timer journal acceptance ещё открыты.
- Event hints только user systemd services/timers; никакого полного auth/security journal.
- First anchor не backfill; rate-limit/drop до journal и частичная visibility не всегда
  доказуемы. Нет гарантии всей event history даже без обнаруженного gap.
- Sidecar bounded; automatic retention отсутствует. Заполнение требует review, не
  удаления gaps. Checkpoint raw string остаётся локально; UI показывает version/time.
- Timeline показывает последнюю opt-in запись, metadata stages/IDs/budgets и тип результата;
  prompts/provider text намеренно не архивируются. Старые M2b runs не реконструируются.
- UI read-only, без acknowledgement/suppression/cloud controls. M3/remediation не начат.
