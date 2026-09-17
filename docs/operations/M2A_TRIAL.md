# M2a Operational Trial

> Publication redaction: workstation-specific evidence/settings were withheld. Methods, dated outcomes and limitations remain historical; omitted values are not replacement measurements.

## Текущее решение — 2026-09-13

После аудита владелец выбрал оценку существующего M2a на 5–7 обычных рабочих днях
как ближайший этап. Это заменяет прежнее решение отложить trial до расширения
runtime/integration stage. Дата новой серии будет определена после отдельного
разрешения запуска; на момент подготовки monitor не запущен.
[Команды, продолжение состояния и критерии](M2A-WATCHDOG.md#m2a-daily-trial).
Повседневный просмотр без обязательного технического аудита:
[передача владельцу](M2A-WATCHDOG.md#m2a-owner-handoff). Эта ссылка не закрывает
оценку и не подтверждает, что monitor работает сейчас.

Подготовительная проверка сохранённого `runtime/watchdog` без host collectors:
read-only reader подтвердил schema v2, baseline revision 1, совпадение текущей
`config.example.toml` со scope всех восьми sources и baseline. SQLite quick check
и evidence links прошли. Блокировка monitor свободна в доступном окружении,
disabled=false; это не глобальная проверка процессов/services.
Все sources stale; последние сохранённые времена сбора — 2026-09-12 13:45:38–40 UTC.
Последний systemd_system partial/access_or_io остаётся историческим наблюдением.
Есть 5 active/unclosed и 5 pending alerts, всего 949 alerts, 53 snapshots,
300 audit entries, 8 baseline sources, исключений 0; размер DB 999424 bytes.
Ненулевое число alerts не является диагнозом; их полезность/шум ещё нужно оценить.
Fingerprint config: `4477f262868897fba816eb32561f323b78f9bd5cfa36b6a1746b063a3901c056`.
Каталог 0700, DB/control files 0600; checksum DB до/после read-only проверки совпал.
Сырые observations не выводились, baseline/история/исключения не изменялись.

Далее — неизменённая история первой серии и решений на 2026-09-12. Её прежние
«следующие шаги» не являются текущим планом и не подтверждают состояние хоста сейчас.

## Trial status

Обновлено: 2026-09-12.

- Начальная серия: 2026-09-11 → 2026-09-12, operational soak завершён.
- Monitor остановлен владельцем; это сообщение владельца, не новый live probe.
- На последнем checkpoint наблюдалось `23:38:07` работы. Точное время и способ
  последующей остановки отдельно не зафиксированы.
- Полный семидневный trial **не завершён**: перенесён на integration/release-candidate
  stage, не отменён и не блокирует ручную M2c acceptance или дальнейшую разработку.
- Новый runtime не активирован этой записью. Сохранённая trial DB — evidence первой
  серии; её не использовать как synthetic state и не изменять ради M2c acceptance.

Ниже сохранены observations начального запуска и итоговый soak checkpoint.
PID, source freshness и `orchestrator disabled=false` относятся к моментам измерений,
а не к текущему состоянию после остановки.

## Start state

- baseline revision: 1
- active alerts: 0
- pending notifications: 0
- LLM: disabled
- host permissions/security settings changed: no

### Coverage

- tcp4: ok, context may be incomplete
- tcp6: ok, context may be incomplete
- udp4: ok, context may be incomplete
- udp6: ok, context may be incomplete
- systemd_system: partial / access_or_io
- systemd_user: ok
- accounts: ok
- persistence: ok

### Known coverage gaps

- systemd-timesyncd dangling unit links
- root-owned netplan-ovs-cleanup runtime unit unreadable by dev
- process context unavailable for some privileged/foreign sockets

These limitations are intentionally not resolved by elevating watchdog privileges.

## Real-host acceptance findings

- Initial baseline on legitimate partial source exposed an M2a defect.
- Baseline semantics were corrected to support reviewed partial snapshots.
- Partial snapshots do not create false removals.
- unavailable/stale/config mismatch/storage failures still block baseline.
- SQLite schema migrated v1 → v2.
- Regression suite: 68 tests passing.

## Initial runtime checkpoint

Actual trial observation start: 2026-09-11T17:11:21.752213+03:00
Originally planned trial end: 2026-09-18T17:11:21.752213+03:00

Эта первоначальная дата больше не действует после переноса полного trial.
Новая дата старта/завершения семидневной серии не назначена.

Initial runtime checkpoint:

- monitor PID=[withheld]
- monitor mode: `sec monitor --iterations 0`
- monitor instances observed: 1
- cycle interval observed: approximately 5 minutes
- active/pending notifications at start: 0
- second monitor cycle: pending_notifications=0
- health: degraded
- expected degraded source: `systemd_system=partial`, reason=`access_or_io`
- TCP/UDP sources: collection successful; some process context remains unavailable (`context_missing`) as expected
- baseline revision: 1
- baseline scope changed: false
- collector configuration changed: false
- storage: 708608 bytes (692 KiB)
- storage budget: 536870912 bytes (512 MiB)
- last storage write failed: false
- LLM enabled: false
- orchestrator disabled: false
- `sec status` exit code: 2, expected because of known degraded/partial coverage



## Initial operational soak — 2026-09-11 → 2026-09-12

The first M2a operational soak was intentionally ended after approximately one day of normal workstation use.

This run is **not** considered completion of the originally planned 7-day operational trial.

The purpose of this first soak was to obtain an initial real-world stability/resource checkpoint while development continued. The full 7-day operational soak is deferred until a later integration/release-candidate stage, when its results will characterize a substantially more complete system.

### Run

Monitor command:

`sec monitor --iterations 0`

Process:

* PID: `95568`
* started: `2026-09-11 17:11:18 +03:00`
* final checkpoint: `2026-09-12T16:49:26+03:00`
* observed elapsed runtime at final checkpoint: `23:38:07`
* foreground monitor instances observed: `1`
* foreground state at final checkpoint: `true`
* orchestrator disabled: `false`

The monitor survived at least one desktop lock/sleep-like transition and continued operating afterwards. This observation does not by itself prove that the host entered a kernel/system suspend state.

### Source health at final checkpoint

Expected source state remained stable:

* `tcp4`: `ok`, `reason=context_missing`
* `tcp6`: `ok`, `reason=context_missing`
* `udp4`: `ok`, `reason=context_missing`
* `udp6`: `ok`, `reason=context_missing`
* `systemd_system`: `partial`, `reason=access_or_io`
* `systemd_user`: `ok`
* `accounts`: `ok`
* `persistence`: `ok`

The known `systemd_system=partial/access_or_io` condition remained expected and was not treated as a defect.

At the final checkpoint:

* `health=degraded`
* `stale=false` for all reported sources
* `baseline_revision=1`
* `baseline_scope_changed=false`
* `config_changed=false`
* `last_storage_write_failed=false`
* `llm_enabled=false`
* `sec status` exit code was `2`, as expected for the known degraded/partial state.

No privilege escalation or host-security configuration change was performed to obtain a healthier status.

### Resource observations

Initial checkpoint:

[Publication redaction: private workstation observation/configuration omitted.]



Final checkpoint after `23:38:07`:

[Publication redaction: private workstation observation/configuration omitted.]



Observed change over the run:

[Publication redaction: private workstation observation/configuration omitted.]



These are endpoint samples, not proof of average CPU/memory usage or a long-term growth rate.

Storage remained far below the configured budget:

* final storage: `999424 bytes`
* storage budget: `536870912 bytes`

No storage-write failure was reported.

### Assessment

The approximately 24-hour foreground run did not reveal an operational blocker.

Observed behaviour was consistent with the accepted M2a model:

* the monitor remained alive;
* periodic collection continued;
* known partial coverage remained stable;
* baseline/config scope did not change;
* no storage failure was reported;
* memory and SQLite growth remained modest during this limited observation window.

This run is sufficient as an **initial operational soak**, but not as evidence for multi-day stability, reboot recovery, long-term database growth, or completion of the planned 7-day trial.

### Trial sequencing decision

The originally planned 7-day operational trial is deferred rather than cancelled.

It will be performed at a later integration/release-candidate stage, after current development and milestone acceptance work is substantially complete.

Rationale:

* running the full soak in the middle of active development would characterize an intermediate build;
* later milestones can intentionally change runtime/resource behaviour;
* the final soak is more valuable when performed against a version close to normal long-term operation;
* ordinary suspend/reboot/logout behaviour should be included in that later operational trial rather than requiring 168 hours of uninterrupted uptime.

The initial M2a soak therefore does **not** block continued M2c acceptance or subsequent development.

Актуальный следующий шаг: [ручная M2c acceptance, phases A–D](M2C-LOCAL-UI.md#ручная-приёмка-после-review).
Остановка monitor не является автоматическим разрешением запускать новый runtime
или выполнять host/system-changing операции.
