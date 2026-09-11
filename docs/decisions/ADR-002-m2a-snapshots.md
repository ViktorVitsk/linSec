# ADR-002 — Снимки, явное покрытие и foreground M2a

Дата: 2026-09-10. Статус: реализовано; эксплуатационная приёмка открыта.

## Контекст

Нужен завершённый collection → SQLite → diff → alert → explanation → exception
без root daemon, AI, новых runtime dependencies и системной установки.
Periodic collection может видеть только часть inventory и не даёт доказательства
безопасности первого снимка. Предыдущий аудит не является baseline.

## Решение

Один пакет: `model` (переносимые типы и детекторы), `store` (SQLite), `application`
(общие операции), `adapters/linux` (ОС), `cli`, `runtime` (foreground/kill switch).
Python standard library в runtime; `uv_build==0.12.12` использует уже установленный
uv 0.12.12. Установка проекта и lock resolution проверены offline в `.venv`.

Восемь источников: TCP/UDP × IPv4/IPv6, system/user systemd, local accounts,
selected persistence. TCP через `ss -l`, UDP через `ss -a`: connected UDP тоже
имеет local bind. Netlink через штатный ss предпочтён deprecated `/proc/net/tcp`.
Параметры исполняемых команд находятся в фиксированном реестре; telemetry в argv
не входит. Numeric PID/fd сопоставляются с inode перед чтением `/proc/PID/exe`.
Путь executable и UID сохраняются; argv/env, remote peer, cgroup и process-name
strings из ss отбрасываются. Не проверяется содержимое executable/скрипта.

Systemd: `list-unit-files` даёт existence/enablement; отдельно хешируются main
unit files и drop-ins в стандартных путях. Сохраняются также shadowed files и
symlinks wants/requires: это консервативный disk inventory, не собственный resolver
эффективной конфигурации systemd. Никаких daemon-reload, start, enable или D-Bus
вызовов изменения. Нестандартные environment overrides намеренно не наследуются.

Immutable snapshot является группой observations источника: ID — локальный
`event_id`/evidence reference; stable случайный `host_id`, source, UTC collection
time, schema/collector versions, scope/completeness, minimized records. Время
изменения ОС неизвестно: collection time не выдаётся за точное время события.
Без изменений inventory обновляется только freshness; события не дублируются.
Alert хранит object key и ссылки на before/after snapshots, не копию полного evidence.

При partial положительные изменения видимых объектов детектируются, пропавшие
объекты не объявляются удалёнными; последний доступный inventory сохраняется.
Unavailable не заменяет evidence пустым снимком. Уточнение 2026-09-11: baseline
можно принять после актуального `ok`/`partial` inventory всех восьми источников
с текущей конфигурацией и явным review ограничений. `context_missing`
у сети отдельно предупреждает об отсутствии владельцев: доступность всех bind
записей не равна полноте process context. Такой baseline требует review, а
trust/suppression endpoint без подтверждённого executable/user запрещены.

Preview token привязан к host/config, версии baseline, конкретным snapshots,
полноте, scope и временам последнего сбора. Обновление пересчитывает token под
`BEGIN IMMEDIATE`; любой новый scan требует нового preview. Повторное использование,
stale data, изменённый config, unavailable и ошибка записи отклоняются.
Это compare-and-swap на локальных наблюдениях, не атомарный snapshot всего хоста:
изменение ОС после последнего scan может быть найдено только следующим scan.

Lifecycle, baseline, trust и suppression — разные операции. Исключения совпадают
только по полному detector/source/object/before/after context, с причиной, временем,
provenance и optional expiry. Trust означает осознанно ожидаемый контекст;
suppression — временное/осознанное подавление уведомления. Оба сохраняют alert и
не меняют baseline. Их можно посмотреть и удалить через `suppress list/remove`.
Изменение контекста создаёт новый alert; исчезновение и возвращение прежнего
контекста переоткрывает сгруппированный alert. PID churn не является новым контекстом.

SQLite schema v2 мигрируется транзакционно через `user_version`; неизвестная версия
отклоняется. Foreign keys сохраняют evidence links. DELETE journal + FULL synchronous;
половина storage budget резервируется для rollback journal, ещё 1 MiB — запас.
Ошибки записи откатывают весь scan. Приватный предварительно выделенный health byte
сохраняет degraded state по возможности; stderr/nonzero exit работает, когда и этот
write невозможен. Никаких бесконечных retries, удаления evidence ради ложного PASS
или переписывания baseline. Retention: не связанные events 30 дней, неактивные alerts
90 дней; активные alerts, baseline и их evidence закреплены до дальнейшего review.

## Альтернативы

Уточнение partial baseline (2026-09-11): запрет любого partial не позволяет начать
unprivileged trial при устойчивых access gaps. Повышение прав ради полного inventory
не принято. Простое снятие запрета с заменой baseline последним snapshot тоже
не подходит: полный промежуточный scan мог убрать старый объект, а последующий
partial уже не доказывает его удаление. Поэтому partial update сохраняет union
прежнего baseline и последнего известного inventory, с приоритетом новых значений.
Если union отличается от исходного snapshot, создаётся отдельный immutable partial
snapshot; наблюдения источника не переписываются. Preview проверяет лимиты union
и показывает дополнительно сохранённые ключи. Removals при partial запрещены.

Полнота остаётся в snapshot, причина и времена принятого покрытия — в baseline
(миграция v1 → v2), а исходный/принятый snapshot, scope, полнота и причина — в audit.
Метаданные старого принятия неизвестны и остаются null. Это provenance на уровне
источника, не свежесть каждого объекта: partial inventory может содержать ранее
наблюдавшиеся записи. Полный следующий scan заменяет inventory и разрешает removals
в том же scope. Принятие baseline не устраняет gaps и не переводит partial в PASS.

SQLite WAL полезен при большом числе читателей, но усложняет контроль sidecars и
checkpoint budget для первого foreground процесса. In-memory-only pipeline теряет
историю при выключении ПК. Root service расширяет полномочия и не нужен для
проверки доступного scope. osquery/dependency scanners отложены по roadmap.
Реконструкция эффективных systemd properties через собственный parser сложнее и
менее надёжна, чем явный ограниченный inventory с оговорённой семантикой.

## Последствия и ограничения

Polling пропускает кратковременные события. SQLite/user files не tamper-proof для
скомпрометированного пользователя/root. Private directory/file checks ограничивают
случайные symlinks/permissions, но не являются sandbox против того же пользователя.
Команды ограничены 10 s и 2 MiB, файл 1 MiB, inventory 12000 records / 4 MiB.
File sources используют nonblocking open, regular-file check и ограниченный read;
зависший filesystem I/O всё ещё может задержать collection/kill switch.
Unit traversal ограничен одним уровнем и 20 s; большие/необычные inventory дают partial.
Pinned evidence может исчерпать storage: тогда нужен review владельца, а не скрытая потеря.
Документированы реальные ограничения [первой проверки](../operations/M2A-WATCHDOG.md).

Первичные источники проверены 2026-09-10:
[ss upstream](https://github.com/iproute2/iproute2/blob/main/misc/ss.c),
[systemd units](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml),
[systemctl](https://github.com/systemd/systemd/blob/main/man/systemctl.xml),
[SQLite pragmas](https://www.sqlite.org/pragma.html),
[uv build backend](https://docs.astral.sh/uv/concepts/build-backend/),
[kernel proc TCP](https://docs.kernel.org/networking/proc_net_tcp.html).
Для локальной совместимости прочитаны установленные man pages systemctl/systemd.unit.
Upstream код не скопирован; используется описанный формат штатных инструментов.
