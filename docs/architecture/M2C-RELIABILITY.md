# M2c — reliability и общая read-only UI

> Publication redaction: workstation-specific evidence/settings were withheld. Methods, dated outcomes and limitations remain historical; omitted values are not replacement measurements.

Дата: 2026-09-11. Реализация и synthetic acceptance; host activation отдельно.
[План до implementation](M2C-PLAN.md), [ADR-004](../decisions/ADR-004-m2c-reliability-local-ui.md),
[операторская процедура](../operations/M2C-LOCAL-UI.md).

## Feasibility journald и выбранный сценарий

M2a systemd_user обнаруживает новый unit, enablement и изменение fingerprint файлов.
Сообщение user manager о завершении start/stop job или failure ускоряет повторную
проверку этого inventory. Само сообщение не доказывает изменение unit file, его
содержимое, текущую активность сервиса или malicious intent. Изменение unit без
lifecycle сообщения находит обычная scheduled reconciliation.

[Publication redaction: private workstation observation/configuration omitted.]



Принимаемые поля: `__CURSOR`, `__REALTIME_TIMESTAMP`, `_BOOT_ID`, `_UID`, `_COMM`,
`_EXE`, `MESSAGE_ID`, `USER_UNIT`. journalctl может автоматически добавить monotonic
field; он игнорируется. Trusted underscore fields проверяют источник; MESSAGE_ID и
USER_UNIT всё равно считаются недоверенными данными. Требуются собственный UID,
`_COMM=systemd`, `_EXE=/usr/lib/systemd/systemd` или `/lib/systemd/systemd`.
Выбранные MESSAGE_ID:

- `39f53479d3a045ac8e11786248231fbf`: start job завершился; `started` — event hint.
- `9d1aaa27d60140bd96365438aad20286`: stop job завершился; `stopped` — event hint.
- `be02cf6855d2428ba40df7e9d022f03d`: failed start job, а не доказательство unit failed state.
- `d9b373ed55a64feb8242e02dbe79a49c`: manager сообщил unit failed.

Последние два имеют категорию `failed`, но исходный message_id сохраняется, поэтому
их смысл и identity не смешиваются. `.scope` и другие типы исключены. Неизвестные
MESSAGE_ID не превращаются в новые детекторы. MESSAGE/argv/env/account passwords не
запрашиваются; arbitrary journal match из CLI/UI отсутствует. Права/группы и journald
configuration не меняются. Полное SSH/sudo/PAM/auth/system journal coverage отсутствует.

Основание: [systemd journal fields](https://github.com/systemd/systemd/blob/main/man/systemd.journal-fields.xml),
[journalctl](https://www.freedesktop.org/software/systemd/man/255/journalctl.html),
[точные message IDs и job semantics v249](https://raw.githubusercontent.com/systemd/systemd/v249/src/systemd/sd-messages.h).
Также прочитаны installed journalctl man и systemd catalog, совместимые с host v249.

## Cursor/checkpoint contract v1

`Checkpoint(cursor, boot_id, event_at, version=1)`; opaque cursor ограничен 1024
печатными ASCII символами, не разбирается на внутренние компоненты. Scope/version
adapter входят в contract; host/config связывают sidecar с watchdog.

- `first_observation`: нет checkpoint; берётся одна последняя запись как anchor,
  сохраняется gap о неизвестной предыдущей истории. Backfill не обещается.
- `continuation`: `--cursor` вернул ТОЧНО прежний checkpoint первым; эта запись
  исключается из новой порции. Нет новых записей после anchor — нормальная continuation
  только видимого отфильтрованного scope.
- `cursor_unavailable`: первый read пуст; это не «источник здоров, событий нет».
- `cursor_invalid`: сохранённый cursor нарушает локальный transport contract;
  re-anchor по ограниченному current read с отдельным gap.
- `cursor_lost`: после seek пусто/другая запись либо seek не удался, но отдельный
  current read успешно дал anchor. Причина потери неизвестна.
- `rotated_beyond_cursor`: отдельное typed состояние для доказанной rotation; текущий
  CLI adapter не приписывает rotation/vacuum без доказательств. Synthetic fixture
  покрывает contract. Production adapter использует `cursor_lost`.
- `access_failure`: структурированный PermissionError на OS boundary.
- `access_or_source_failure`: journalctl выдал diagnostic stderr; точная причина
  не выводится и не угадывается по локализованному тексту. Это не доказательство
  конкретного permission error или отсутствия событий.
- `source_unavailable`: отсутствующая команда, timeout, ошибка вызова без подтверждённого
  anchor. Ошибка seek и глобальная недоступность различаются отдельным current read.
- `parser_failure`: malformed/oversized JSON, неожиданные types/encoding/поля; cursor
  не подтверждается, предыдущие durable данные остаются.
- `configuration_mismatch`: несовместимая версия checkpoint. Чужой host/config
  sidecar отклоняется при открытии, не переиспользуется молча.
- `boot_boundary`: увиден переход boot ID в продолжаемой порции; history unknown.

Rotation сама по себе не gap, если cursor остаётся доступен. Vacuum может удалить
точный anchor: близкая запись не является подтверждением continuity. Частичный
доступ и drop/rate-limit до durable journald нельзя всегда обнаружить этим scope.
Отсутствие gap не является гарантией полной event history.

## Durability и restart

Read previous → bounded fetch → validate/normalize → BEGIN IMMEDIATE → exact identity
checks → records/gap/generation → checkpoint → COMMIT. Все writes находятся в ОДНОЙ
transaction. Изменение cursor statement до COMMIT не является подтверждением для
другого процесса; durability наступает вместе с событиями. Synchronous FULL и rollback
journal сохраняют SQLite guarantees при корректном filesystem/storage.

Checkpoint compare-and-swap отклоняет stale writer. Crash/commit error откатывает
records и cursor вместе. После успешного commit crash до inventory scan оставляет
`generation > reconciled`; после restart scan повторяется. Crash после main ingest,
но до sidecar reconciliation record тоже повторяет scan: possible at-least-once
collection, без потери pending work. Это не распределённая атомарная transaction.

`monitor-reliable` сохраняет тот же monitor lock/disabled flag. Startup всегда сверяет
inventory, journal poll каждые 5 секунд, periodic full scan по interval Config остаётся
обязательным. Полная порция не использует `--lines=N`, поскольку это tail и может
пропустить начало: `--no-tail --cursor=…`, bounded streaming и остановка только своего
journalctl после 257 complete JSON lines (anchor + 256 records). Timeout 5 s на вызов,
не более двух вызовов при failed seek. Runtime выводит изменение состояния/сверку,
не одинаковую строку на каждый idle poll. Optional notifications используют прежний flow.

## Gaps и reconciliation

`Gap` хранит source, detected_at, known boundary_from/to, typed reason,
recoverability=`history_unknown`, reconciliation_attempted, current_state_observed,
history_recovered=false, unknown. Период и точное число пропущенных событий неизвестны,
если source не дал доказательств. Один неизменный failure episode не создаёт новый gap
каждые 5 секунд; после возобновления наблюдения повторный сбой создаёт новый gap.

Reconciliation record относится к `systemd_user`: успех другого collector не выдаётся
за восстановленное unit-наблюдение. Complete inventory (включая пустой) подтверждает
текущее ограниченное состояние; partial подтверждает только положительные records.
Пустой partial и unavailable не выставляют current_state_observed. Успешный scan
никогда не меняет history_recovered: SQL CHECK запрещает true. Прежние gaps остаются
доступны после healthy continuation. UI показывает их отдельно от текущего source health.

Fresh/current-config partial продолжает попадать в прежний Application.ingest;
ложных removals не создаёт, positive evidence детектируется. Unavailable/stale/config
mismatch/parser/storage failure не являются PASS и не смешиваются с partial.

## Deduplication

Transport identity: SHA-256 от canonical JSON `[source, contract_version, boot_id, cursor]`.
Exact replay не создаёт второй event. Другая metadata под тем же identity — explicit
contract error с rollback, а не silent ignore. Новый cursor при том же unit/message/time
сохраняется: timestamp не является уникальным идентификатором.

Journal hint и inventory snapshot описывают разные утверждения и не объединяются
по имени unit. Детектор запускается ТОЛЬКО на inventory. Две одинаковые сверки повторно
используют существующие snapshot fingerprints/alert context M2a; occurrences сохраняют
его прежнюю семантику. Hints имеют отдельную provenance и generation. Нельзя доказать,
что именно hint вызвал изменение inventory, поэтому UI не рисует ложную causal link.

## SQLite, bounded queries и версии

Main watchdog v2 не меняется. M2c schema v1 создаётся миграцией 0→1 в отдельной БД:
identity, checkpoint, health, events, gaps, reconciliations, investigations. IDs PK,
exact-event identity UNIQUE, enum/boolean/version CHECK, indexes по generation и
(alert_id,id). Между разными DB нет поддерживаемых SQLite foreign keys; host/config
binding + application validation используются явно. Неизвестная schema отклоняется.

Sidecar: DELETE journal, FULL sync, 1 s busy timeout, ~32 MiB DB + резерв rollback
до ~32 MiB; без auto retention, удаления evidence или изменения trial retention.
При заполнении — fixed error и best-effort preallocated reliability-health byte;
если даже он недоступен, stderr/nonzero exit и затем stale status — fallback.

UI/CLI Queries: новые mode=ro/query_only соединения на запрос, main PRAGMAs/версия
не меняются. Transactions отпускаются до rendering/provider calls; deadline/SQLite
progress handler ограничивает запросы. DELETE writer/reader concurrency проверена
synthetic нагрузкой. WAL на реальной DB не включается.

Alerts keyset pagination по ID: 25 по умолчанию, максимум 100; 50 последних gaps/events,
64 entries timeline, 5 provider steps; последний сохранённый result данного alert.
Snapshot decode ограничен 4 MiB, M2b projection 24 KiB, timeline record 64 KiB,
API response 256 KiB. Нет полного event-store load, offset scan, aggressive polling.

## Investigation timeline

Optional trace observer в прежнем M2b service отмечает trigger, pack/evidence IDs,
privacy preview/accept/reject, provider attempt/result, operation request/accept/reject,
new evidence, fallback/stop. Сохраняются fixed codes, timestamps, steps, bounded
numeric budgets. Raw request/response, approval tokens/digests и model text не
сохраняются в sidecar. Disabled run остаётся полезным deterministic fallback.

Обычный M2b без --record-state не сохраняет timeline. Её отсутствие не доказывает,
что расследований не было. UI не вызывает provider; описание результата AI всегда
отделено от пересчитанного deterministic evidence. Historical timeline не является
доказательством актуальности evidence после нового scan/retention.
