# M2c — pre-acceptance review и hardening

> Publication redaction: workstation-specific evidence/settings were withheld. Methods, dated outcomes and limitations remain historical; omitted values are not replacement measurements.

Дата: 2026-09-12. Рекомендация: **READY WITH KNOWN LIMITATIONS** — для ручной M2c
приёмки, не для автоматической активации на workstation. M3 не начат.

Implementation уже был отдельным commit `afde9f8`; pre-M2c база — `cf1d7f3`.
На старте рабочее дерево чистое; global/project AGENTS прочитаны, неожиданных
изменений policy/config не обнаружено. Hardening выполнен отдельным рабочим diff.
Новых dependencies, persistent schema migrations, privileged actions нет.

## Defects found

### D1 — P1: journal anchor обходил provenance и проверку identity

Компоненты: `adapters/journal.py`, `reliability/contracts.py`, `reliability/store.py`.
Первую запись continuation исключали после сравнения только cursor/boot/time:
wrong UID/COMM/EXE или изменённый USER_UNIT/MESSAGE_ID не доходили до validator/dedup.
Неизвестный MESSAGE_ID также позволял пропустить EXE check. Повторный cursor внутри
порции мог возвращать checkpoint назад без явного отказа. Сценарий: повреждённый или
неоднозначный adapter output создаёт ложную continuation либо теряет distinct evidence
под уже известным cursor. Это не доказательство, что remote webpage может подделать
trusted journal fields на исправном хосте.

Fix: единый `parse_row` для каждого record, включая anchor и unknown IDs; repeated
cursor в batch — parser_failure. Проверенный anchor и его checkpoint передаются
отдельно от новых events в атомарную ingest transaction. Сохранённый hint сравнивается
целиком, включая случай его исчезновения из выбранного scope; conflict → rollback.
Identity lookup использует существующий UNIQUE index. Persisted schema v1 неизменна.

[Publication redaction: private workstation observation/configuration omitted.]



### D2 — P2: разные потери cursor с одинаковым reason сливались в один gap

Компонент: `reliability/store.py`. Episode dedup сравнивал только state. Две
последовательные потери разных anchor с `cursor_lost` оставляли одну gap-запись;
если новых hints не было, новая reconciliation также не запрашивалась.
Fix: изменившийся checkpoint при gap state создаёт отдельные gap/generation;
неизменная failure episode по-прежнему объединяется.

Regression: `test_distinct_consecutive_lost_anchors_record_distinct_gaps`,
`test_many_gaps_and_keyset_pages_are_bounded`. Вторая проверка сохраняет 300 gaps,
а query возвращает последние 50 без потери общего count.

### D3 — P1: stale/config-mismatched inventory выдавался за current observation

Компонент: `reliability/runtime.py`. Reconciliation смотрела только `status` и наличие
items. Старый/future timestamp, чужой config scope или `invalid_input` diagnostic
могли выставить `current_state_observed=true`, включая `ok` с пустым inventory.
Fix: M2c проверяет freshness, текущий config fingerprint и parser diagnostic перед
recording результата. Непригодный результат записывается как unavailable; positive
partial признаётся только при fresh/current-config evidence. M2a ingest не изменён.

Regression: `test_stale_or_foreign_inventory_cannot_claim_current`,
`test_partial_reconciliation_only_claims_positive_current_evidence`.
Partial/ok сверка никогда не выставляет history_recovered.

### D4 — P2: BEGIN lock failure не выставлял storage-health flag

Компонент: `reliability/store.py`. `BEGIN IMMEDIATE` находился до error handler.
Другой writer мог удерживать lock дольше busy timeout: процесс получал ошибку, а
preallocated health byte оставался «последняя запись успешна».
Fix: BEGIN включён в обработку transaction failure; bounded отказ отмечает health.
События/checkpoint не меняются. Успешная последующая transaction сбрасывает flag.

Regression: `test_begin_lock_failure_sets_health_flag`: isolated writer lock,
bounded failure менее 3 s, health=1, rollback чужой synthetic transaction, recovery=0.

### D5 — P2: unchecked sidecar fields попадали в browser response

Компонент: `queries.py`. Некоторые timestamps, boundaries, message/transition,
reconciliation outcome и generation читались напрямую. Повреждённая/локально
подменённая БД могла вывести ненужный arbitrary text в API; HTML при этом оставался
inert, но minimization boundary нарушалась.
Fix: validate перед projection, fixed failure вместо raw value; timestamps нормализуются
в ISO UTC, включая нестандартный Unicode separator. Source/alert timestamp output также
нормализован в M2c query. M2b projection и исходная БД не переписываются.

Regression: `test_sidecar_strings_are_validated_before_export`,
`test_timestamp_unicode_separator_is_normalized`,
`test_corrupt_and_incomplete_sidecar_fail_closed`.

### D6 — P2: permissive HTTP parsing обходил strict request contract

Компонент: `local_ui/server.py`. Stdlib превращает `//api/overview` в `/api/overview`;
email-style header parser принимает folding и может оставить malformed trailing header
как parser defect. Routes видела уже нормализованный target и не проверяла defects.
С корректным bearer такие неоднозначные requests получали 200. Auth bypass не найден.
Fix: сравнение raw request target с разобранным, strict request line, отказ при header
parser defects/folding/control characters. Duplicate/Host/Origin/body policy сохранена.

Regression: `test_in_memory_hostile_request_matrix` через настоящий Handler с BytesIO
connection; проверяет также методы, sizes, conflicting/duplicate lengths, transfer
encoding, traversal и query pollution. Header **name** casing разрешён, Host authority
остаётся точным.

### D7 — P2: поздний 401 от старого ключа очищал новую client session

Компонент: `local_ui/app.js`. Проверка session generation происходила после успешного
JSON response, но не перед 401→forget. После logout/relogin старый запрос мог очистить
новый token и evidence. Утечки новому серверу/remote origin не выявлено; это availability
и нарушение lifecycle.
Fix: проверять generation сразу после fetch, до обработки status. Поздний response
старой сессии не меняет новую; существующий guard после JSON сохраняется.

Regression: `tests/ui_dom_test.cjs`: old login → logout → new login → old 401;
дополнительно pagehide до завершения response.json не возвращает evidence в DOM.
На исходном JS новый тест падает с `old 401 must not forget the new session`.

### D8 — P2: non-zero journalctl exit игнорировался на полной порции

Компонент: `adapters/journal.py`. При достижении 257 lines код не вызывал wait и не
проверял уже доступный return code. Process, завершившийся с ошибкой после partial
stdout ровно на границе, мог дать «успешный» batch.
Fix: проверять `poll()` на известный non-zero exit до принятия bounded prefix.
Останавливается только собственный reader. Ошибка → source_unavailable без checkpoint.

Regression: `test_nonzero_exit_at_full_page_is_failure`; исходный commit не вызывает
ожидаемый JournalFailure. Отдельно проверены non-zero с коротким stdout, stderr,
timeout, PermissionError, malformed/duplicate JSON и output limit.

## Security review

API остаётся read-only, exact IPv4 loopback, exact Host/Origin, required bearer/custom
header. Forged Fetch Metadata не заменяет bearer. Одинаковые имена headers с разным
casing распознаются как duplicates. Неправильный Origin, null, foreign/IPv6-like Host,
лишние ports, absolute targets, body framing и опасные методы закрыты. Unknown method
возвращает fixed 501; перечисленные unsupported методы — 405. 400/401/403/404/405/413,
stdlib 414/431/501 и service 503 не отражают request/exception; exception не создаёт
Python traceback/HTML 500. Credentials не логируются.

Проверены все JS creation/fetch/render sites: textContent/JSON text, fixed assets,
relative API routes с server-validated numeric IDs. Нет innerHTML, outerHTML,
insertAdjacentHTML, eval, Function, dynamic script creation, Markdown rendering,
telemetry href. DOM fixtures включают script/img/SVG/closing tags/entities/templates,
javascript/Markdown, bidi, длинные unbroken strings, ANSI, shell/SQL/prompt injection.
Raw metadata в evidence projection заменяются псевдонимами. Cookie/storage нет.

Residual risks: same-UID/root/browser extension compromise, loopback plaintext,
clipboard и отсутствие гарантированного memory erasure. Случайность ключа задаёт
пользователь: regex проверяет формат, не entropy. При 32 равномерно случайных символах
алфавита из 64 — 192 bits; human/repeated key такой гарантии не имеет. Comparison digest
constant-time; expiry 8h проверяется server-side. Restart с тем же введённым ключом
снова разрешит bearer; нужен новый random key каждый запуск. Logout только локальный,
не global revocation в других вкладках. Уже показанные данные остаются до logout/
pagehide/нового запроса, даже если серверный срок истёк. Rate limit/account system не
добавлялись. Sequential handler/queue 4/connection deadlines ограничивают ресурсы,
но локальный клиент способен ухудшить UI availability.

Header parser сначала применяет stdlib caps (до ~6.5 MiB header lines), затем 8 KiB
application cap. Не заявляется Internet DoS protection. GET без framing не имеет HTTP
body; лишние байты после unframed request не используются и connection закрывается.
Real browser CSP/TCP/clipboard/back-forward/layout enforcement **не проверены** здесь.

## Reliability review

Проверены first/missing checkpoint, valid continuation, invalid/version mismatch,
lost cursor/nearest seek, boot transition, access/diagnostic/unavailable/parser/storage
failure; synthetic rotated state не приписывает реальному host rotation без evidence.
Empty first read не означает здоровый источник. Empty continuation seek — gap.
Unknown MESSAGE_ID не создаёт detector; valid ID с wrong provenance не принимается.

Fault injection: до/после event insert, после gap/generation/checkpoint statements,
перед commit (SQLite authorizer), сразу после commit, до/во время collection/main
ingest, после scan до reconciliation record, внутри record/gap/health updates.
До commit все writes откатываются вместе. После durable commit pending переживает
исключение и повторяет работу. Повторная обработка предпочитается потере evidence.
Это exception/transaction tests, **не** power-cut, kernel crash или filesystem fault
simulation; SQLite durability всё ещё зависит от исправного storage/filesystem.

Dedup: новый cursor при том же объекте/времени сохраняется, conflict identity вызывает
rollback, restart/backup restore replay не теряет новые events. Journal hints и inventory
не сливаются по unit name. Отсутствие сохранённого вне-scope payload не доказывает его
неизменность. Opaque cursor нельзя сортировать; wallclock может идти назад/вперёд.
Distinct reordered rows не отбрасываются по timestamp; repeated cursors отвергаются.
Полнота history не выводится из отсутствия обнаруженных gaps. Prefix cap не доказывает,
что после намеренной остановки reader не было других records/diagnostics.

Concurrency: новая нагрузка — 1 sidecar writer, 60 commits с rollback каждые 5,
3 reader threads × 30 проходов overview+detail+alerts. Нет locks/deadlocks/timeouts в
этом тесте. Отдельно подтверждён bounded lock failure, reader при незавершённой schema
initialization, empty/corrupt DB; после завершения initialization query восстанавливается.
Оригинальный M2c test также проверяет main watchdog writer с двумя readers. Это
ограниченный synthetic stress, не обещание отсутствия contention на любом filesystem.
Reader transactions закрываются до rendering/network. Snapshot main и sidecar внутри
себя согласованы; **общей** атомарности между БД/разными HTTP requests нет.

Bounds: 1001 synthetic alerts, keyset pagination по 100 без повторов, 300 gaps/events
с projection последних 50, giant/malformed strings, invalid/overflow pagination,
100 unauthenticated requests без query calls. Existing M2a/M2b tests покрывают limits
inventory/pack/timeline/owners/members и deterministic fallback. Unbounded retry не
добавлен. Persistent sidecar 32 MiB + rollback reserve; retention автоматом нет.

## M2a/M2b regressions

Diff от `cf1d7f3`: collectors `adapters/linux.py`, model/detectors, Config/fingerprint,
main Store/schema v2, M2a runtime, M2b evidence/contracts/providers, pyproject/uv.lock
**не изменились**. `scripts/check_m0.py`, `tests/test_m0_safety.py` также идентичны.
M2c implementation вынес существующий notification predicate в общую SQL constant и
добавил bounded count; predicate прежний, explicit count/list regression добавлен.
CLI additions opt-in; M2b trace без `--record-state` не пишет sidecar. Privacy preview,
LLM disabled default и deterministic fallback покрыты исходными tests/benchmark.
Hardening не меняет эти shared M2a/M2b файлы или их public semantics.

## Validation — точные команды и результаты

После последнего code fix:

- `uv run --cache-dir .cache/uv --no-sync python scripts/check_m0.py` — **PASS**, exit 0.
- `uv run --cache-dir .cache/uv --no-sync python -m unittest discover -s tests -v` —
  **PASS**, exit 0, **195 tests**, 11.444 s.
- `uv run --cache-dir .cache/uv --no-sync ruff check --no-cache .` — **PASS**, exit 0.
- `uv run --cache-dir .cache/uv --no-sync ruff format --check --output-format concise .`
  — **FAIL**, exit 1: только `scripts/check_m0.py`, `tests/test_m0_safety.py`;
  39 files formatted. Эти pre-existing файлы не переписаны.
- `uv run --cache-dir .cache/uv --no-sync ruff format --check src/security_orchestrator scripts/check_m2c_package.py scripts/summarize_m2c_journal.py tests/test_local_ui.py tests/test_reliability.py tests/test_m2c_hardening.py`
  — **PASS**, exit 0, 34 files formatted.
- `uv lock --check --offline --cache-dir .cache/uv --python .venv/bin/python --no-python-downloads`
  — **PASS**, exit 0, 2 packages.
- `uv run --cache-dir .cache/uv --no-sync sec ai-benchmark` — **PASS**, exit 0,
  deterministic fixture replay, provider_calls=0, host_collection=false, cloud_calls=false.
- `node --check src/security_orchestrator/local_ui/app.js` — **PASS**, exit 0.
- `node tests/ui_dom_test.cjs` — **PASS**, exit 0, in-memory DOM; sockets/network отсутствуют.
- `uv build --offline --cache-dir .cache/uv --out-dir .cache/m2c-review/dist` —
  **PASS**, exit 0, wheel и sdist. uv предупреждает, что cache внутри source directory;
  содержимое архивов проверено следующей командой, cache туда не попал.
- `uv run --cache-dir .cache/uv --no-sync python scripts/check_m2c_package.py` —
  **PASS**, exit 0: по 36 regular files, exact reviewed source/assets + metadata.
  Все три UI assets включены; runtime DB, .env, cache, logs, token files, test secrets,
  user-specific paths и real-host journal samples не включены. Архивы не извлекаются
  и не исполняются при inspection.
- `git diff --check` — **PASS**, exit 0.

До исправлений: исходные 164 tests — PASS. Новые 26 tests на archived `afde9f8`
получили **20 failure assertions**, включая subtests, что не равно числу defects.
Дополнительный full-page journal test отдельно — FAIL; расширенный DOM test на
старом JS — FAIL. Это ожидаемое reproduction, не скрытые failures финального кода.
Первый промежуточный Ruff run обнаружил 9 замечаний в новых test lambdas; исправлены.
Локальные validation logs/archives находятся в ignored `.cache/m2c-review/`, не в Git.
Remote CI, реальный listener/browser и host acceptance не выполнялись.

## Real-host acceptance checklist

Полные команды, expected result/limitations, modification scope и stop/cleanup для
каждого шага: [M2C-LOCAL-UI.md, phases A–D](M2C-LOCAL-UI.md#ручная-приёмка-после-review).

1. **A:** help и `view`/alerts/detail — read-only inspection, без listener/migration.
2. **B:** новый `m2c-demo` directory → отдельный loopback UI → browser negative/UX checks;
   Ctrl-C только UI. Отметить дополнительную нагрузку, если выполнять во время trial.
3. **C:** версия journalctl, bounded unprivileged sample → trusted minimizer → только
   counts. Каждый тип service/timer подтверждается отдельно; zero/error — UNKNOWN.
4. **D:** **DO NOT RUN DURING CURRENT M2a TRIAL**. После отдельного решения новая
   monitoring series, две одиночные итерации/restart, между ними read-only `view`.

## Trial compatibility и рекомендация

Running M2a operational trial **не затронут действиями review**: его DB не открывалась
даже read-only, path не искался, pragmas/schema/state/baseline/config не менялись;
monitor не останавливался и не перезапускался. Host collectors/journal probes,
listeners, реальные OpenRouter/Ollama calls, sudo/services/permissions/attacks отсутствуют.
Обычная нагрузка от локальных tests/build была; zero resource impact не заявляется.

**READY WITH KNOWN LIMITATIONS**: воспроизведённые defects исправлены в пределах M2c,
195 tests PASS; остаются два pre-existing formatting FAIL и обязательная manual
real-host/browser acceptance. Target service/timer presence и реальная browser
совместимость пока не подтверждены. Не активировать M2c runtime во время M2a trial.

## Проверенные первоисточники

2026-09-12, только публичная документация без telemetry:
[systemd v249 journalctl options](https://raw.githubusercontent.com/systemd/systemd/v249/man/journalctl.xml),
[systemd v249 MESSAGE_ID definitions](https://raw.githubusercontent.com/systemd/systemd/v249/src/systemd/sd-messages.h),
[Python 3.13 HTTP server](https://docs.python.org/3.13/library/http.server.html),
[SQLite atomic commit](https://www.sqlite.org/atomiccommit.html).
Версионированная freedesktop man page вернула HTTP 403; использован upstream v249 source.
Локально прочитан stdlib parser project Python 3.13.15. Эти справки не подтверждают
текущее host состояние и не заменяют manual acceptance.
