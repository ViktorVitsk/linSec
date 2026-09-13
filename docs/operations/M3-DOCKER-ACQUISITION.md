# M3 — план первого реального Docker capture

> Publication redaction: workstation-specific evidence/settings were withheld. Methods, dated outcomes and limitations remain historical; omitted values are not replacement measurements.

Дата: 2026-09-13. Статус: **первый успешный real-host capture и offline review выполнены**.
Шаблоны работают на наблюдаемом Engine; полная host acceptance остаётся открытой.
История отказов и границы подтверждения сохранены ниже.
[ADR-006](../decisions/ADR-006-m3-one-shot-acquisition.md).

## Назначение и изменения

Один foreground capture проверит выбранные поля posture на установленном Docker.
Новый CLI по умолчанию показывает plan, включая точные argv и Go template.
Только `--approve` с token текущего plan разрешает actual acquisition.

[Publication redaction: private workstation observation/configuration omitted.]



## Точные команды

Просмотр плана, без Docker и без создания output-каталога:

```bash
uv run --cache-dir .cache/uv --no-sync sec docker-acquire --output runtime/m3-host-20260913
```

После отдельного согласования точного plan:

```text
uv run --cache-dir .cache/uv --no-sync sec docker-acquire --output runtime/m3-host-20260913 --approve TOKEN_FROM_REVIEWED_PLAN
```

TOKEN — конкретное поле `approval_token`, а не команда/выражение из telemetry.
Новый путь или изменение кода/лимитов требует нового preview. Existing output
отклоняется; повторная попытка использует новый явно проверенный каталог.

Только следующие argv из `adapters/docker_acquire.py`:

```text
/usr/bin/docker --config <output>/client-config --host unix:///run/docker.sock version --format <VERSION_FORMAT>
/usr/bin/docker --config <output>/client-config --host unix:///run/docker.sock container ls --all --no-trunc --format {{.ID}}
/usr/bin/docker --config <output>/client-config --host unix:///run/docker.sock container inspect --format <INSPECT_FORMAT> <full-hex-ID>
```

Точные значения templates раскрываются в plan как отдельные argv items.
Sequence: `lstat /run/docker.sock` → version → первый list → inspect каждого ID
→ второй list → повторный lstat. До list проверяются Linux и поддержка API **1.51**
между MinAPIVersion и ApiVersion. Переговоры API отключены явным
`DOCKER_API_VERSION=1.51`; неподдерживаемая версия даёт unavailable.
CLI также может выполнять штатный ping к тому же daemon; это не отдельный endpoint.
Системный/user Docker config, registry credentials и Docker context не используются.

## Минимизация и результат

Inspect stdout содержит лишь Id/Image, Config.User, State.Running, нужные
HostConfig flags/modes/caps/restart/ports, NetworkSettings.Ports и Type/Source/
Destination/RW mounts. Нет полного Config/HostConfig, Env/Labels/Cmd/Entrypoint,
имён containers/images/volumes, descriptions или volume driver options.
Проекция пользователя в enum и путей в categories/hashes выполняется до записи.
Raw stdout/stderr не пишутся на диск, в логи или response команды.

Сам Docker CLI получает raw inspect от daemon в памяти. Read-only API не запрещает
доступ к секретам этому процессу; минимизация stdout не является sandbox.
Path hashes тоже не гарантируют анонимность. Capture остаётся локальным; AI/cloud
export и автоматический import не реализованы. Команда печатает только status,
reason, число records и путь/hash итогового файла.

Result содержит явный `origin=docker_cli_capture`, времена начала/конца,
version/API, source reference, coverage и normalized containers. `host_validated=false`
сохраняется до human acceptance. Это отдельный формат, не synthetic Result v1.
`status=ok` означает успех ограниченного capture, **не secure/clean host**.

Изменение ID set, пропавший container или недоступное поле → partial. Различный
socket generation → unavailable и discard данных смешанного capture. Совпавший
socket не доказывает неизменность daemon; поэтому `daemon_identity_verified=false`.
Два совпавших списка не делают snapshot атомарным: изменения конфигурации между
inspect отдельных objects и кратковременные события могли быть пропущены.

## Лимиты и реалистичный риск

[Publication redaction: private workstation observation/configuration omitted.]



Реалистичные риски: временная нагрузка на daemon; частичные/неподдержанные поля;
отказ из-за отсутствующего CLI, прав, API или лимитов. Компрометированный CLI,
daemon или аккаунт с Docker доступом имеет значительно больше полномочий, чем
эта read-only команда. Same-UID filesystem races не устранены private directories.

## Verification и rollback

После разрешённого запуска проверить exit code: 0 только для capture ok, 2 для
partial/unavailable или storage failure. Затем локально проверить минимизированный
artifact, consistency flags, engine version и coverage. Не публиковать его автоматически.
Проверка Go templates и реальных M3 observations — часть host acceptance;
синтетические ответы не заменяют её.

Host settings не меняются, host rollback не требуется. При прерывании/ошибке
новый output-каталог остаётся для review; existing artifacts не перезаписываются.
После review владелец может удалить только этот новый каталог. Удаление capture
не изменяет Docker и не откатывает host hardening. Collector service не устанавливается.

## Development acceptance

`test_docker_acquisition.py` использует fake runner и mocked OS/process boundaries.
Нет Docker calls, настоящих socket probes, скачивания пакетов или inference.
Проверяются approval/path binding, приватная запись, fixed argv/environment,
minimization, version/errors/races и bounds/cleanup. Существующие synthetic,
M2a/M2b/M2c и UI tests запускаются вместе. Первичная host acceptance остаётся
запланированной, **не PASS**.

Локальные результаты 2026-09-13: **238 unittest PASS**, включая 16 новых acquisition
tests; Ruff, repository hygiene, DOM test, offline lock и diff check — PASS.
Offline wheel/sdist в `.cache/m3-acquisition-review/dist` прошли package inspection:
по 44 regular files, точное совпадение source/assets/metadata, runtime/cache не включены.
Реальный запуск collector и runtime-нагрузка этими результатами не подтверждаются.

## Первая попытка владельца и исправление

2026-09-13 владелец выполнил согласованный capture в `runtime/m3-host-20260913`.
Результат: unavailable/command_failed, 0 контейнеров, database_imported=false.
Минимизированный artifact проверен по совпадению SHA-256 из сообщения владельца;
engine/source_id отсутствуют. Отказ произошёл при `version`, до list/inspect.
Raw stderr не сохранялся, поэтому другие возможные причины этой попытки
задним числом не восстанавливаются.

В нашем VERSION_FORMAT найдено неверное `.Server.ApiVersion` (JSON tag вместо Go
field); исправлено на `.Server.APIVersion` согласно
[upstream version.go](https://raw.githubusercontent.com/docker/cli/v28.3.3/cli/command/system/version.go).
Прежние fake responses обходили выполнение template и не обнаружили эту ошибку.
Добавлена регрессия выбора typed Go field; это не запуск настоящего Go/Docker template.

При следующих отказах capture и краткий CLI summary содержат только безопасные
metadata: `last_failed_step`, `command_exit_code`, `stderr_present`, `inspect_failures`.
Текст stderr, аргументы telemetry и исходные сообщения ошибок по-прежнему не выводятся.
First capture остаётся неизменным; повтор использует новый каталог и новый token,
поскольку code fingerprint изменён. Endpoint, API 1.51, read-only операции и
лимиты не расширены. Успех на фактическом Engine ещё нужно подтвердить повтором.

После исправления: **239 unittest PASS** (17 acquisition tests), Ruff/hygiene/DOM/
offline lock/diff check и повторная wheel/sdist inspection — PASS. Новый capture
не запускался coding agent; для владельца подготовлен `runtime/m3-host-20260913-r2`.

## Локальная проверка сохранённого capture

2026-09-13 добавлен `docker-review`: проверка **текущего capture v1 с diagnostic
fields** без Docker, сети, inference и записи в БД. Старые artifacts с иной схемой
отклоняются; их нельзя переписывать ради прохождения проверки. Повторный capture
и human acceptance по-прежнему открыты.

После отдельно согласованного сбора используйте `capture_sha256` из его краткого
результата (не `approval_token`):

```text
uv run --cache-dir .cache/uv --no-sync sec docker-review --capture runtime/m3-host-20260913-r2/capture.json --sha256 SHA256_FROM_CAPTURE_SUMMARY
```

Проверяются SHA-256 точных байтов, canonical JSON, строгий список полей, версии,
UTC timestamps и порядок начала/конца, normalized records, diagnostic types и
согласованность полноты. Файл ограничен 256 KiB; duplicate JSON keys, лишние поля
(в том числе Env), ложный `host_validated=true`, неизвестные enum и `ok` с пропусками
отклоняются. Чтение не меняет permissions: нужны собственный private каталог и
regular файл без group/other permissions, hardlinks и symlinks; FIFO не блокирует
команду. Metadata проверяются до и после bounded read.

Обычный вывод содержит времена, Engine/API, status/reason, flags, diagnostics, число
контейнеров с running/stopped/unknown, неизвестные поля и количество контейнеров по
существующим posture rules с русскими объяснениями. В обычной сводке container IDs,
addresses/ports, mount hashes, approval token и raw metadata не выводятся.
Отдельный локальный режим `--details` описан ниже. Drift/removals не вычисляются из
одного снимка. Это не импорт host evidence в synthetic Result/DB/UI.

Exit 0: артефакт валиден и ограниченный capture сообщил `ok`; exit 2: ошибка
проверки либо валидный partial/unavailable. `artifact_valid=true` означает только
проверку сохранённого файла. `host_validated=false` остаётся всегда; отсутствие
findings не означает clean host. SHA-256 без независимого доверенного источника
digest не подтверждает происхождение; same-UID tampering/races не устранены.
Фактические Go templates, полнота выбранного scope, CPU/RAM и соответствие
конфигурации проверяются отдельно владельцем, по времени capture.

Synthetic tests проверяют parity CLI/application/shared rules, неизменность файла,
отсутствие process/socket calls и DB writes, partial/empty/unavailable, hash mismatch,
hostile schema, size/depth limits и отказ для небезопасных типов/permissions файла.
Используются только disposable fixtures, включая FIFO; реальный capture не выполнялся.

Результаты этой доработки 2026-09-13: **245 unittest PASS**, в том числе 23 acquisition/
review tests; Ruff, repository hygiene, UI DOM test и diff check — PASS. Зависимости
не менялись. Эти результаты не закрывают повторную host acceptance.

## Первый успешный capture и граница подтверждения

2026-09-13 владелец явно разрешил подготовленный одноразовый capture. Первая
попытка coding agent в sandbox, `runtime/m3-host-20260913-r2`, завершилась
`unavailable/socket_metadata_refused`, `last_failed_step=socket_before`: Docker CLI
ещё не запускался. SHA-256 файла отказа:
`139145e00108528fc816f159dad13fb8044d51bc03351822b47b1156d2849b42`.
`docker-review` подтвердил `artifact_valid=true`, exit 2 из-за unavailable.

[Publication redaction: private workstation observation/configuration omitted.]



Для повтора сформирован новый preview с каталогом `runtime/m3-host-20260913-r3`;
код, endpoint, API и лимиты не менялись. Повтор той же согласованной операции
выполнен через штатный `require_escalated`, без sudo и без root coding-agent session.
Оба предыдущих artifacts сохранены. Успешный capture:

[Publication redaction: private workstation observation/configuration omitted.]



[Publication redaction: private workstation observation/configuration omitted.]



Findings относятся к сохранённой конфигурации остановленных containers. Сбор не
доказывает WAN reachability или компрометацию; M1 prerequisites перед запуском
сохраняются. Containers, daemon, services, groups/socket/firewall и baseline не менялись.
Host rollback не требуется; новые каталоги остаются локальными evidence для review.

Подтверждено выполнение templates/минимизации на этом Engine и успешная проверка
отдельного capture. Открыты human review ожидаемой конфигурации/полезности findings,
отдельные CPU/RAM измерения, repeated/partial/error acceptance на хосте и worker
isolation. Импорт host evidence в DB/UI и monitoring требуют отдельного increment;
synthetic databases и текущие M2a/M2c contracts не менялись. M3 целиком не закрыт.

## Подробный разбор и контекст владельца

2026-09-13 добавлен `docker-review --details`: тот же проверенный файл, без нового
сбора, Docker, inference, DB/UI import и изменения capture. Точная команда для
сохранённого успешного результата:

```bash
uv run --cache-dir .cache/uv --no-sync sec docker-review \
  --capture runtime/m3-host-20260913-r3/capture.json \
  --sha256 be272f2096cb850dc4e2366f9bd78498403b5f1867265bc79ebe2b647172ae67 \
  --details
```

Опция выводит до 32 containers в порядке полных hex IDs: state, unknown fields,
posture findings с severity, русским объяснением и минимизированным evidence.
Для publications отдельно видны configured/observed bindings с IP, protocol и ports.
Mount evidence сохраняет category/type/rw и число записей; source/target hashes
исключены вместе с image hash, source ID и approval token. Names/env/labels/raw paths
не собираются дополнительно. Detail IDs/bindings остаются локальными metadata,
не готовым AI/cloud export. Canonical JSON результата ограничен 512 KiB;
CLI pretty printing может увеличить число выводимых байтов.

Сводка без `--details` остаётся агрегированной, дополнена `container_states`.
Running/stopped/unknown относятся к времени capture; unknown никогда не считается
stopped. Конфигурационные findings у остановленного контейнера сохраняются, но
не доказывают активную публикацию или текущую угрозу. Даже отсутствие findings
и полный capture не изменяют `host_validated=false`.

Контекст владельца от 2026-09-13: «Это давно созданные контейнеры для моих пет
проектов. Я ими не пользуюсь». Подтверждено назначение/происхождение и отсутствие
заявленного текущего использования. Это контекст человека, отдельно от измеренного
state=stopped. Владелец не подтвердил каждый bind/user/mount, поэтому соответствующая
проверка конфигурации и оценка полезности/шума правил не объявлены полной приёмкой.
Trust/suppression/baseline и lifecycle не менялись; разрешение на start/delete
из этого ответа не следует. Условия M1 перед будущим запуском сохраняются.

Проверки доработки: **250 unittest PASS**, включая 28 acquisition/review tests;
Ruff, hygiene, UI DOM, local links и diff check — PASS. Dependency/runtime changes
не добавлялись. Offline demonstration на прежнем capture r3: status ok,
3 details, running/stopped/unknown = 0/3/0. Локальный производный файл
`runtime/m3-host-20260913-r3/review-details.json` создан с mode 0600, не включён
в Git; capture неизменён. Повторного обращения к Docker не было. CPU/RAM и остальные
host acceptance gates остаются открытыми.
