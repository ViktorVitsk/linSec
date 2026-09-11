# M2c — запуск, проверка и совместимость с trial

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

Команды ниже — checklist для человека, а не уже выполненные host operations.
`TRIAL_STATE` заменяется человеком на фактический приватный каталог trial; его путь
здесь не угадывается. Все команды запускаются из корня repo. Python/uv environment
уже подготовлена, sync/install не требуется.

### A. Pure read-only

```bash
uv run --cache-dir .cache/uv --no-sync sec ui --help
uv run --cache-dir .cache/uv --no-sync sec monitor-reliable --help
uv run --cache-dir .cache/uv --no-sync sec --state TRIAL_STATE view
uv run --cache-dir .cache/uv --no-sync sec --state TRIAL_STATE view --alerts --limit 5
```

По полученному alert ID: `sec --state TRIAL_STATE view ID`. Проверить reason/source
freshness/config mismatch, pending notifications, baseline revision; не трактовать
not_running/lock observation как долговременную гарантию. `sec status/doctor` не
использованы здесь как strictly read-only DB inspection: их прежний Store writable.

### B. Starts local process / isolated application state

Сначала synthetic demo (не monitor и не host collector):

```bash
uv run --cache-dir .cache/uv --no-sync sec --state runtime/m2c-lab m2c-demo
```

Команда вернёт НОВЫЙ `state_directory`; внутри `watchdog/` и `m2c/`. Подставьте этот
конкретный путь в следующие команды, не trial path:

```bash
uv run --cache-dir .cache/uv --no-sync sec --state DEMO_DIRECTORY/watchdog ui --m2c-state DEMO_DIRECTORY/m2c
```

Введите random key скрыто, вручную откройте адрес из stdout. Проверить login/wrong key,
обзор/alert detail/timeline, gap остаётся после reconciliation, текст AI не выдаётся
за факт, hostile metadata остаётся псевдонимом, refresh/logout, 200% zoom/narrow window,
CSP в browser console, отсутствие внешних запросов в Network. Не публиковать key,
headers/evidence screenshots. Ctrl-C; проверить, что URL больше не обслуживается.

После завершения trial и отдельного решения можно проверить read-only UI на trial
DB. Новый runtime — отдельная явно выделенная monitoring series:

```bash
uv run --cache-dir .cache/uv --no-sync sec --state runtime/m2c-acceptance monitor-reliable --m2c-state runtime/m2c-reliability --iterations 1
```

Команда запускает read-only host collectors и пишет НОВУЮ monitoring DB. Это
не silent activation во время trial. Не вызывать на production/trial DB без решения.
Проверить реально доступные service/timer journal events обычной работы, checkpoint,
source states и restart continuation. Не создавать атаки, systemd units или менять
journal retention/vacuum ради теста. Полный auth scope не ожидается.

Verification/rollback для B: main trial hash/config/baseline revision остаются прежними;
Ctrl-C останавливает только запущенный процесс. Новые synthetic/M2c directories можно
сохранить для review; автоматическое удаление evidence не предлагается. Изменений
firewall/services/permissions нет, системный rollback не требуется.

### C. Changes host/user configuration

Не нужны для M2c. Никаких autostart, system/user service/timer, journald/group/network
changes. Любая такая будущая операция требует отдельного описания команд, риска,
verification/rollback и approval по workstation policy.

### D. Requires privilege

Нет. Не использовать sudo/root для получения более полного journal или запуска UI.

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
