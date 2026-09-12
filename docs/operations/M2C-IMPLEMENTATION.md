# M2c — итоговый отчёт реализации

Завершение проверки: 2026-09-12. Основа изменений: `cf1d7f3`.
Статус: **реализация и synthetic acceptance завершены; real-host/browser acceptance открыта**.
На момент составления отчёта изменения находились в рабочем дереве; commit/push
этой задачей не выполнялись. Позднее implementation зафиксирован в `afde9f8`.

## Implemented

Отдельные versioned journal/checkpoint/gap contracts, transactional reliability store,
bounded journalctl adapter, новый opt-in foreground scheduler, shared read-only Queries,
local UI, optional M2b timeline, synthetic demo, regression/security/concurrency tests.
CLI: `view`, `ui`, `monitor-reliable`, `m2c-demo`, optional `investigate --record-state`.
[Архитектура](../architecture/M2C-RELIABILITY.md),
[план до implementation](../architecture/M2C-PLAN.md).

## Architecture decisions

[ADR-004](../decisions/ADR-004-m2c-reliability-local-ui.md): отдельная SQLite ради trial,
journal как сигнал досрочной сверки, прежний detector единственный, read-only query
service для CLI/UI, stdlib transport без новых dependencies. Application.status и
M2b PackBuilder/fallback переиспользуются. Notification eligibility вынесена в общий
SQL constant без изменения запроса; UI count не копирует business predicate.

## Journald scope

Только сообщения user systemd manager о start/stop jobs и failure для `.service`/
`.timer`, с проверкой UID/COMM/EXE, MESSAGE_ID и schema. Это подсказка выполнить
inventory scan, не доказательство изменения файла/compromise. MESSAGE, argv/env,
общие auth logs, system journal, GNOME/COSMIC integration не добавлены.

Два минимальных probes подтвердили структуру и manager provenance в трёх записях,
но это были `.scope`: фактическая польза выбранного services/timers scope на этом host
ещё требует ручной приёмки. Upstream IDs/job semantics и installed v249 docs проверены.
Никакого повышения privileges или изменения journald permissions.

## Gap semantics

Typed source/reason/time/boundaries/recoverability, attempted reconciliation,
current_state_observed, history_recovered=false и описание неизвестного. Раздельные
cursor missing/invalid/lost, access/source/diagnostic/parser/version/reboot states.
Причина rotation не выдумывается: adapter сообщает cursor_lost, если vacuum нельзя
доказать. First observation также явно обозначает неизвестную прежнюю историю.
Gaps сохраняются после возобновления наблюдения; SQL запрещает history_recovered=true.

## Dedup

Exact identity = hash(source, contract version, boot ID, opaque cursor). Конфликт
содержимого под тем же identity отклоняется, новый cursor сохраняется даже при том
же объекте/времени. Journal hint и snapshot — разные assertions, не склеиваются.
Повторные snapshots/alerts объединяет существующий M2a fingerprint/context contract.

## Reconciliation

Startup, periodic Config interval и journal-triggered scans. Events/gaps/checkpoint
commit атомарно; durable generation сохраняет pending scan после crash/restart.
Сбой между main ingest и reconciliation record допускает повтор scan, не silent loss.
Partial не создаёт removals и сохраняет positive evidence. Отметка current state
для journal gap зависит именно от systemd_user, не от успеха других sources.
Пустой partial не подтверждает наличие объектов; intermediate history не восстановлена.

## Local UI

Python stdlib HTTPServer с ограниченным Handler, локальные HTML/CSS/JS. Отдельный
foreground process, default/exclusive bind `127.0.0.1:8765`, без autostart/browser launch.
Random bearer вводится через getpass и password input, живёт в памяти, максимум 8 часов.
Новый запуск требует нового выбранного ключа; повтор того же ключа снова даст доступ.
Logout очищает вкладку, остановка процесса отзывает listener. Нет account/session DB.

Overview: monitor lock state, disabled, source reasons/freshness, alerts, notifications,
baseline, storage, journal/gaps/reconciliation. Alert detail: validated pseudonymized
facts, observations/IDs, coverage, learning guidance и latest optional timeline.

## Security controls

Exact Host/Origin, conditional same-origin Fetch Metadata, обязательные bearer и
custom header; нет CORS/cookies. GET только читает, все остальные методы запрещены,
GET bodies/content type/transfer encoding/duplicate headers отклоняются. Mutations,
cloud/provider UI, generic SQL/path/operations отсутствуют. Static allowlist, CSP,
frame protection, no-store/no-referrer/nosniff/CORP/COOP; textContent вместо HTML/Markdown.
Фиксированные ошибки без sensitive logs/tracebacks. Bounded requests/responses и
SQLite queries. [Полная модель и residual risks](../architecture/M2C-UI-SECURITY.md).

## Database

Watchdog остаётся **SQLite v2**. Новая отдельная **reliability SQLite v1**, миграция
0→1 только в явно выбранном isolated/private каталоге. Host/config binding, unique
identity, constraints/indexes, transactional checkpoint; upgrade/restart/rollback
проверены synthetic tests. Sidecar ~32 MiB DB + rollback reserve; auto retention нет.
UI использует mode=ro/query_only, не меняет main journal mode. Реальная trial DB не
мигрировалась и не открывалась writable этим заданием.

## Trial compatibility на момент implementation

Последующее обновление 2026-09-12: владелец завершил начальный soak и остановил
monitor; полный семидневный trial перенесён и не блокирует M2c acceptance.
[Результаты и решение](M2A_TRIAL.md), [актуальная процедура M2c](M2C-LOCAL-UI.md).
Ниже — историческая совместимость и ограничения на момент implementation; прежнее
ожидание окончания trial заменено новым решением, evidence о невмешательстве сохранено.

- Runtime-поведение уже работающего M2a monitor не менялось; restart/reload не выполнялся.
- Existing collectors, config, model/detectors, Store и старый runtime файлы неизменны.
- Detection/baseline/partial/retention semantics и exit 2 scan/status/doctor сохранены.
- Migration trial DB для M2c не требуется. Новые данные M2c находятся в другой DB.
- Текущий 7-day trial может продолжаться без restart/migration.
- До окончания/review trial не активировать monitor-reliable на trial state: он
  меняет частоту scans/occurrences и resource profile. UI resource measurements также
  проводить отдельно или явно отметить дополнительную нагрузку.
- LLM/providers не включались, реальных OpenRouter/Ollama calls не было; settings,
  baseline, suppressions и host security configuration не менялись.

## Tests

**164 unittest PASS**, включая исходные 93 и 71 новый тест. Финальный полный прогон
после возобновления задания также прошёл. Категории: cursor states/parser/transport,
exact/semantic dedup, crash/commit/restart, schema constraints, partial/reconciliation,
negative HTTP/auth/Origin/IDs/pagination, hostile inputs, shared services/M2b trace,
concurrent SQLite writer и два readers.

Результаты команд (полные команды также в [operator/development checklist](M2C-LOCAL-UI.md)):

- `python -m unittest discover -s tests`: PASS, 164 tests.
- `python scripts/check_m0.py`: M0_SAFETY_CHECK_OK.
- `ruff check --no-cache .`: PASS.
- `ruff format --check` для всех 17 изменённых/new Python файлов: PASS.
- `ruff format --check --output-format concise .`: **exit 1**, только два прежних
  неизменённых файла: `scripts/check_m0.py`, `tests/test_m0_safety.py`. Их равенство
  HEAD проверено; unrelated formatting не внесено. Не объявляем весь validation зелёным.
- `uv lock --check --offline --cache-dir .cache/uv --python .venv/bin/python --no-python-downloads`:
  PASS; lock/pyproject неизменны, новых dependencies нет.
- `sec ai-benchmark`: PASS, 5 deterministic synthetic scenarios, provider_calls=0.
  validated_answers=0 здесь ожидаемо: inference не запускался.
- `node --check .../local_ui/app.js`: PASS.
- `node tests/ui_dom_test.cjs`: PASS; real UI JS с synthetic DOM, inert hostile text,
  login/overview/alerts/detail/logout, без browser/listener/network.
- `sec --state .cache/m2c-cli-demo m2c-demo`: PASS; 8 сценариев, 1 event после dedup,
  2 explicit gaps, history_recovered=false, LLM выключен.
- `uv build --offline --cache-dir .cache/uv --out-dir .cache/m2c-dist`: PASS, wheel/sdist.
  Wheel содержит все 3 UI assets. Archive inventory: 42/43 members, runtime/cache/env
  paths отсутствуют, несмотря на общий warning uv о cache внутри workspace.
- `git diff --check`: PASS. Type checker в проекте отсутствует, его результат не заявлен.

## Known limitations

Реальный TCP listener/browser layout/CSP enforcement не проверялся: socket I/O в
sandbox запрещён, HTTP parser проверен in-memory. Host/browser acceptance и длительные
resource/latency measurements открыты. Минимальные journal probes не доказывают полное
покрытие services/timers/auth. Нельзя гарантировать обнаружение всех journald drops,
rate limits и permission gaps. Same-UID/root/browser-extension compromise остаётся
residual risk. Две старые format-check проблемы указаны выше.

Timeline хранит stages/evidence IDs/budgets/тип результата, а не prompts/provider text.
Старые незаписанные M2b runs не реконструируются; UI показывает последнюю opt-in запись.
Raw local metadata доступны через прежний CLI, не через browser API. Sidecar retention
требует будущего отдельного решения; при лимите storage система явно отказывает.

## Real-host acceptance plan

[Готовый checklist A/B/C/D с точными командами](M2C-LOCAL-UI.md#ручная-приёмка-после-review):
A — read-only help/view; B — isolated synthetic demo/UI и отдельно новый monitor после
trial review; C — host/user configuration changes не требуются; D — privileges не нужны.
Команды запуска UI/monitor и изменения реального host автоматически не выполнялись.

## Deferred

Full auth/system journal, additional sensors, acknowledgements/mutations из браузера,
cloud UI, autonomous remediation, services/autostart, account system, remote/LAN access,
WAL migration и M3. Это не скрытые незавершённые реализации внутри текущего scope.

## Последующий review

2026-09-12: отдельный [pre-acceptance review/hardening](M2C-PRE-ACCEPTANCE.md)
обнаружил и исправил defects поверх commit `afde9f8`. Исходные результаты выше —
история implementation; актуальные validation и manual checklist находятся в новом отчёте.
