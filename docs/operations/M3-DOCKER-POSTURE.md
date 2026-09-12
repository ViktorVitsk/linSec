# M3 — первый synthetic Docker posture increment

> Publication redaction: workstation-specific evidence/settings were withheld. Methods, dated outcomes and limitations remain historical; omitted values are not replacement measurements.

Дата: 2026-09-12. Статус: **synthetic этап реализован**.
Real-host acquisition, реальная Docker acceptance и browser acceptance нового
экрана остаются открытыми. M3 целиком не закрыт. Scanners идут отдельным increment.
[Решение](../decisions/ADR-005-m3-synthetic-docker-posture.md).

Дополнение 2026-09-13: подготовлен отдельный одноразовый collector с exact-plan
approval. Его capture не импортируется в synthetic DB и не превращает её в host
evidence. [Процедура real-host acquisition](M3-DOCKER-ACQUISITION.md).

## Что работает

Чистый adapter принимает bounded synthetic inspect-shaped envelope, минимизирует
поля и возвращает `Result` v1. Отдельный `PostureStore` атомарно сохраняет evidence,
объекты, posture findings, изменения и coverage. `PostureQueries` используется
CLI и локальной UI; интерфейсы не дублируют правила. AI выключен, нет provider calls.

Покрыты publications/binds IPv4/IPv6, privileged, host/shared namespaces,
socket/sensitive bind mounts, добавленные capabilities и CapDrop, класс пользователя,
restart policy, image digest и configuration drift. [Логика и ограничения](../detections/M3-DOCKER-POSTURE.md).
Контейнеры с `running=false` тоже оцениваются как конфигурация; это не работающий listener.

## Воспроизводимая демонстрация

Из корня проекта, с уже подготовленной `.venv`, без сети и Docker:

```bash
uv run --cache-dir .cache/uv --no-sync sec --state runtime/m3-example docker-demo
uv run --cache-dir .cache/uv --no-sync sec docker-view --docker-state runtime/m3-example/synthetic-docker
uv run --cache-dir .cache/uv --no-sync sec docker-view 1 --docker-state runtime/m3-example/synthetic-docker
```

`docker-demo` требует **новый** каталог `synthetic-docker`: повторный запуск с тем
же путём отклоняется. Для новой серии выберите новый `--state`. Он не перезаписывает
host state, не запускает containers/services и не читает Docker socket. Все строки
fixtures искусственные, включая env marker; его значения отсутствуют в БД/выводе.

Серия: initial → posture/config changes → repeat → partial missing → unavailable.
Последний `unavailable/access_denied` создан fixture, это **не ошибка доступа,
измеренная на workstation**. Число findings/evidence не растёт при repeat.
После partial missing не появляется `container_removed`, старый posture становится
`unknown`. Полное пустое inventory и возврат объекта отдельно проверены unittest.

`docker-view` — чтение файла, не запуск acquisition. Exit 0 означает успешное чтение
контракта, **не PASS источника**: смотрите `state`, `stale`, `storage_failure` и
`host_validated=false`. ID относится к отдельному Docker namespace; не передавайте
его в M2a `sec explain`/`investigate`. Для evidence используйте `docker-view ID`.

UI: в уже согласованной процедуре локального UI добавьте
`--docker-state runtime/m3-example/synthetic-docker` к `sec ... ui` и выберите
«Docker · synthetic». Без аргумента экран показывает `not_configured` и не создаёт
хранилище. Вход в UI по-прежнему требует доступной main M2a БД; при необходимости
подготовьте отдельную штатную `sec demo`, а не меняйте trial state.
Запуск HTTP listener отдельно подчиняется host approval policy; разработка M3
не запускала listener или браузер. Ключ/Host/Origin/CSP сохраняются.

## Contract v1 и доверие

Envelope parser: ровно `schema_version=1`, `complete: bool`, `inspect: list`.
Result: `schema_version=1`, `adapter_version=1`, `origin=synthetic`, `source_id`,
UTC `collected_at`, `status`, `reason`, `containers` по полному hex ID.
Это собственный envelope; он не является ответом Docker API целиком.

В каждом container record фиксированный allowlist:

- `image`: hex digest без image/repository name; `running`, `privileged`: bool;
- `network`, `pid`, `ipc`, `uts`, `userns`: нормализованный namespace mode;
- `configured_ports` из `HostConfig.PortBindings` и `observed_ports` из
  `NetworkSettings.Ports`: IP, host/container port и tcp/udp/sctp;
- `mounts`: bind/volume/tmpfs, категория, rw, SHA-256 source/target references;
- `cap_add`, `cap_drop`: sorted allowlist Linux capability names;
- `user`: default_root / explicit_root / nonroot_numeric / named_unknown;
- `restart`: name и bounded MaximumRetryCount.

Missing/invalid field → `null` и `partial`; это не false/empty. Явный Docker null
в CapAdd/CapDrop/PortBindings/Ports означает пустую коллекцию. `EXPOSE` без bindings
не считается публикацией. Пустой HostIp означает unspecified bind, не loopback;
пустой HostPort остаётся `null` (например routed IPv6), не «закрыт» и не порт 0.
Configured и observed поля не подменяют друг друга.

Raw names/labels/env/Cmd/Entrypoint/paths не сохраняются. Env не участвует даже
в configuration fingerprint; изменения env/names/labels этим detector не видны.
При неизвестной capability или неподдержанном mount type соответствующее поле
становится unknown. Metadata никогда не становится shell, URL, SQL или HTML.

`complete` — утверждение synthetic источника, не результат проверки daemon.
Неподдержанная версия, duplicate JSON keys/IDs, malformed envelope дают unavailable.
Если поле отсутствует, положительные факты из других полей всё ещё обнаруживаются.
Повреждение одного элемента массива делает неизвестным **всё это поле**; нет
претензии на полное покрытие оставшихся элементов.

## Dedup, drift и история

Evidence имеет content hash, finding — context hash source/object/rule/значимых
полей. Повторы обновляют last_seen, сохраняют исходную ссылку evidence и не добавляют
новые строки. Изменившийся существенный контекст создаёт другое finding.
Drift исключает `running` и observed ports; это volatile runtime state.

Для сравнения хранится последнее полное **наблюдение объекта**. При partial record
оно сохраняется: null не создаёт ложный drift. Если объект никогда не наблюдался
полностью, configuration drift пока недоступен, posture по положительным полям работает.
Предыдущие наблюдения не являются доверенным baseline.

`observed` — текущий положительный posture; `unknown` — последующее неполное или
недоступное evidence; `resolved` — полный record/полный inventory больше не даёт
это условие; `recorded` — историческое событие добавления/изменения/удаления.
Resolved не означает закрытие человеком или безопасный хост.
Удаления допустимы только при `status=ok` той же source identity. При partial/unavailable
отсутствующие объекты не удаляются. Между list/inspect в будущем потребуется явно
учитывать гонки acquisition; текущий fixture этого не доказывает.

## Лимиты и отказ

[Publication redaction: private workstation observation/configuration omitted.]



Ошибки транспорта и БД не отражают исходное сообщение/metadata. Механизм private
files отказывает symlink/permissive paths; не исправляет permissions автоматически.
Same-UID race/tampering и аппаратные сбои остаются residual risks.

## Приёмка и оставшаяся работа

Synthetic unittest проверяют минимизацию, hostile metadata, publications/routed,
привилегии/namespace/user/caps/mounts, drift, partial/removals, repeat/restart,
бюджеты/rollback, stale evidence, read-only paths, corrupted evidence и CLI/API parity.
DOM test выполняет настоящий UI JS с искусственным DOM, проверяет Docker navigation,
pagination, inert text, logout и общий session guard; sockets/network отсутствуют.

Команды полного gate:

```bash
uv run --cache-dir .cache/uv --no-sync python scripts/check_m0.py
uv run --cache-dir .cache/uv --no-sync python -m unittest discover -s tests -v
uv run --cache-dir .cache/uv --no-sync ruff check --no-cache .
node tests/ui_dom_test.cjs
uv lock --check --offline --cache-dir .cache/uv --python .venv/bin/python --no-python-downloads
git diff --check
```

Подтверждено локально 2026-09-12: **222 unittest PASS**, включая 26 новых M3;
Ruff, repository hygiene, DOM test, offline lock check и diff check — PASS.
Offline `uv build` создал wheel и sdist; существующий package checker с каталогом
`.cache/m3-review/dist` подтвердил в каждом 42 regular files, точное совпадение
source/assets/metadata и отсутствие runtime/cache files в package.

CLI replay выполнен в `runtime/m3-delivery-20260912/synthetic-docker`: initial —
1 finding/1 snapshot; после changes — 8 findings/2 snapshots; repeat и partial
не увеличили эти числа. Финальный synthetic `access_denied` оставил 6 posture
findings в `unknown`; 2 history events сохранены. Это воспроизводимая демонстрация,
не нагрузочный benchmark и не real-host acceptance.

В текущей сессии не было доступа к daemon, установки scanners, changes groups/socket,
container startup, host hardening, inference или autostart. Не проведены реальная
Docker acceptance, измерение нагрузки monitor, browser acceptance нового экрана,
worker isolation и удалённый CI. Семидневный integration soak остаётся открытым.
Дальше — согласовать минимизированный real-host acquisition и проверить его на
фактической версии/конфигурации Docker. Только затем переходить к scanners.
