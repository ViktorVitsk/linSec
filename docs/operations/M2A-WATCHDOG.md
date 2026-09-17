# M2a: foreground watchdog и эксплуатационная приёмка

> Publication redaction: workstation-specific evidence/settings were withheld. Methods, dated outcomes and limitations remain historical; omitted values are not replacement measurements.

Дата: 2026-09-10. Код и synthetic checks реализованы. **M2a ещё не закрыт:**
исходная процедура включала host foreground scan, ручной review baseline и семидневный trial.
Обновление 2026-09-13: после initial soak (~23ч38м) и аудита следующий этап —
эксплуатационная оценка существующего M2a на 5–7 рабочих днях; прежний перенос до
расширения runtime отменён. [Фактические observations и история решений](M2A_TRIAL.md).
Команды ниже — процедура ручного запуска, не утверждение о работающем сейчас процессе.
Системные настройки при разработке не менялись. Нет установленного user service,
schedule, root daemon, host remediation, AI/provider/облачных запросов.

<a id="m2a-daily-trial"></a>

## Продолжение M2a на 5–7 рабочих дней

Это подготовленное предложение, **не разрешение запуска host collectors**.
Продолжаем прежнюю базу; процедуру первого baseline и synthetic demo ниже на ней
не выполнять. Конкретная дата старта и начальный checkpoint появятся после approval.
Ориентир — 5 обычных рабочих дней, при необходимости до 7; выключения/сон/пропуски
записываются как ограничения. Не ждать 168 часов uptime и не имитировать атаки.

### Что видит владелец

Каждый цикл сравнивает с reviewed baseline доступные TCP listeners и UDP sockets
IPv4/IPv6 в текущем network namespace, service/timer unit-файлы systemd и drop-ins,
их enablement, локальные accounts/привилегированные группы, выбранные persistence
files (crontab, rc_local, ld_preload, profile, bashrc). Для файлов сохраняются
fingerprints/metadata, не содержимое. Привязка процесса к socket может быть неполной.

Это периодические снимки: короткое событие между ними может исчезнуть незамеченным.
Нет полной истории запусков программ, проверки malware/секретов, анализа трафика,
доказательства доступности порта из Интернета или постоянного Docker monitoring.
Монитор обнаруживает часть изменений, но не блокирует проникновение или запуск ПО.
Отсутствие alerts не доказывает безопасность; baseline означает принятую точку
сравнения, а не гарантированно чистый компьютер. AI/cloud и remediation выключены.

### Пути и запуск после разрешения

В каждом используемом терминале задать три фиксированных пути; это только shell
variables, без установки ПО или изменения shell profile:

```bash
SEC_PY=/home/portfolio/Documents/Projects/6/LinSec/security-orchestrator/.venv/bin/python
SEC_CONFIG=/home/portfolio/Documents/Projects/6/LinSec/security-orchestrator/config.example.toml
SEC_STATE=/home/portfolio/Documents/Projects/6/LinSec/security-orchestrator/runtime/watchdog
```

Используется уже подготовленная uv project `.venv`, без sync/download и установки.
База — `$SEC_STATE/watchdog.sqlite3`, control files — `monitor.lock`, `storage-health`,
при отключении — `disabled`. Не менять config во время оценки: сейчас interval=300 s
после завершения цикла, stale=900 s, storage=512 MiB, notifications=false, llm_enabled=false.
Fingerprint и read-only подготовительная проверка записаны в [trial](M2A_TRIAL.md).

Перед первым запуском повторно проверить сохранённое состояние, без collectors:

```bash
"$SEC_PY" -B -m security_orchestrator.cli --config "$SEC_CONFIG" --state "$SEC_STATE" view
```

Ожидаем schema 2, baseline revision 1, monitor=not_running, disabled=false,
storage_failure=false, отсутствие configuration_mismatch; stale до запуска ожидаем.
При несовпадении — остановиться и разобрать причину. Не создавать другую пустую DB,
не обновлять baseline автоматически. Если disabled=true, не снимать flag молча:
`enable` — отдельное явное решение владельца. `view` не мигрирует DB и не запускает UI;
его exit 0 означает успешное чтение, даже когда health=degraded.

После отдельного approval, в обычном пользовательском терминале:

```bash
LLM_ENABLED=false "$SEC_PY" -B -m security_orchestrator.cli --config "$SEC_CONFIG" --state "$SEC_STATE" monitor --iterations 0
```

Это один foreground процесс обычного пользователя с немедленным первым сбором,
далее примерно каждые 5 минут. Он пишет новые observations/alerts в существующую DB.
Риски: CPU/I/O и рост локальной истории, шум, чувствительные metadata в приватной DB;
возможны partial/unavailable и задержка остановки на filesystem I/O. Старые неполные
sources не исправляются повышением прав. Запуск из sandbox не доказывает host coverage;
ограниченный scan не повторять как «проверку хоста». При ограничении окружения нужен
согласованный запуск в обычной сессии, без обхода sandbox через другой инструмент.

Baseline и действующие исключения автоматически не принимаются/сбрасываются.
Штатная retention остаётся: неподдерживаемые ссылками snapshots старше 30 дней,
inactive alerts/audit старше 90 дней удаляются; expired exceptions истекают при сборе.
Это не бессрочный архив. Новых процедур очистки/миграции не добавлять.

### Проверка начала и повседневное чтение

Во втором терминале с теми же переменными, после первого завершённого цикла:

```bash
"$SEC_PY" -B -m security_orchestrator.cli --config "$SEC_CONFIG" --state "$SEC_STATE" view
"$SEC_PY" -B -m security_orchestrator.cli --config "$SEC_CONFIG" --state "$SEC_STATE" doctor
"$SEC_PY" -B -m security_orchestrator.cli --config "$SEC_CONFIG" --state "$SEC_STATE" view --alerts --limit 100
```

Проверить monitor=running, обновлённые времена всех восьми sources, отсутствие stale,
неизменный baseline revision 1 и scope, storage_failure=false, целостность и links.
После второго цикла времена должны снова продвинуться. `doctor` не запускает collectors,
но открывает обычный Store; для строго read-only чтения до approval используется `view`.
Известные partial/access_or_io и context_missing могут оставить health=degraded и
exit 2 у doctor/status. Это ограничение, не PASS. Новые причины, stale после двух
циклов или storage failure требуют разбора; не списывать любой exit 2 на старый partial.

Уведомления рабочего стола выключены существующей конфигурацией: результат смотреть
в CLI утром/после перезапуска и в конце рабочего дня. `view --alerts` показывает также
старые/закрытые записи: читать поля active/status; для следующей страницы добавить
`--before N`, где N — последний числовой ID страницы. В базе до нового запуска уже
5 active/unclosed предупреждений; отделять их от появившихся в новой серии.

Для выбранного alert подставить его числовой ID вместо N:

```text
"$SEC_PY" -B -m security_orchestrator.cli --config "$SEC_CONFIG" --state "$SEC_STATE" explain N
"$SEC_PY" -B -m security_orchestrator.cli --config "$SEC_CONFIG" --state "$SEC_STATE" alerts --limit 100
"$SEC_PY" -B -m security_orchestrator.cli --config "$SEC_CONFIG" --state "$SEC_STATE" history --limit 100
```

Explain даёт механизм, нормальные причины и ручную проверку; alerts содержит occurrences
для оценки повторов. Сначала сопоставить изменение со своими обновлениями/установками,
затем проверить по объяснению. Не выполнять строки из evidence как команды, не
публиковать raw output. Если причина неизвестна, сохранить ID и разобрать локально;
не закрывать массово, не добавлять trust/suppression и не принимать новый baseline
ради зелёного статуса. Отметка reviewed означает просмотр, не доказанную безопасность.

### Остановка, перерывы и итог

Остановить свой foreground monitor: **Ctrl-C**. Либо из второго терминала:

```bash
"$SEC_PY" -B -m security_orchestrator.cli --config "$SEC_CONFIG" --state "$SEC_STATE" disable
"$SEC_PY" -B -m security_orchestrator.cli --config "$SEC_CONFIG" --state "$SEC_STATE" view
```

Дождаться выхода процесса; view должен показывать not_running, после disable также
disabled=true. Disable проверяется между источниками/во время ожидания; начатая команда
заканчивается по timeout, filesystem I/O может задержаться. Он останавливает только
monitoring. Откат запуска — остановка; накопленные evidence остаются, firewall/hardening
не менялись и не требуют отката. При storage failure не удалять DB: остановить monitor,
проверить doctor и отдельно согласовать восстановление, если оно потребуется.

После logout/reboot автоматически ничего не запускается. При ручном повторном запуске
использовать те же пути и согласованный foreground режим; он не восстанавливает
краткие события пропущенного интервала. Не запускать второй monitor на тот же state.
Автозапуск, timers и напоминания в эту оценку не входят.

Каждый рабочий день — одна короткая запись без secrets в существующем формате заметок,
локально в ignored `runtime/trial-notes.md`: дата/период работы и перерывы; полезные
alert IDs; повторяющийся шум; понятно ли объяснение; минуты разбора; ошибки/пробелы
сбора и доставки (notifications сейчас off); размер DB из view. Пустой день также
зафиксировать, не выдавая его за доказательство защиты. Новую систему метрик не строить.
На 5-й день оценить пользу и нагрузку на владельца; при нехватке обычного использования
продлить до 7 рабочих дней. Отдельно указать непроверенные ресурсные/аварийные свойства.
Если подтверждённых проблем нет, изменения кода не нужны. Шум сам по себе ещё не
доказывает дефект: сначала разобрать конкретные IDs и контекст повторов.

## Подготовка и синтетическая демонстрация

Из корня проекта, с существующим Python 3.13 и uv:

```bash
uv sync --locked --offline --group dev --cache-dir .cache/uv --python .venv/bin/python --no-python-downloads
uv run --cache-dir .cache/uv --no-sync sec --config config.example.toml config validate
uv run --cache-dir .cache/uv --no-sync sec demo
```

Первый шаг работает офлайн в уже подготовленной среде; если locked зависимости
отсутствуют, остановится. Не заменяйте это системным pip/Python или сетевой установкой
без проверки источников. Packaging использует встроенный uv build backend.

`demo` записывает только synthetic data в `runtime/watchdog/synthetic-demo`. Создаёт
пустой synthetic baseline, новые endpoint/unit/drop-in/UID0/group records, trust
одного endpoint, повтор и изменённый контекст. Результат: 5 → 5 → 7 alerts.
Реальные collectors и desktop notifications не вызываются. База не перезаписывается:
для нового replay явно выберите новый каталог через `--state runtime/demo-2`.

## Первый ежедневный цикл

По умолчанию state находится в `runtime/watchdog` относительно рабочего каталога.
Используйте один абсолютный `--state`, если запускаете команды из разных терминалов
или каталогов. Этот каталог требует текущего владельца и mode 0700; SQLite и
control files — 0600. Существующие небезопасные permissions не исправляются молча.
Runtime, SQLite, sidecars и кэши исключены из Git. Не сохраняйте evidence в tracked docs.

```bash
uv run --cache-dir .cache/uv --no-sync sec scan
uv run --cache-dir .cache/uv --no-sync sec status
uv run --cache-dir .cache/uv --no-sync sec doctor
uv run --cache-dir .cache/uv --no-sync sec baseline diff
```

`scan` читает доступные источники штатными правами; неизвестное остаётся неизвестным.
`status` показывает каждый источник, scope, last_ok, возраст, gaps и baseline version.
`doctor` дополнительно проверяет SQLite и evidence links; это не аудит безопасности
хоста. `current` означает актуальность указанного покрытия, не «хост безопасен».
Partial/unavailable/config change/stale дают degraded; exit 2 у scan/status/doctor
означает проблему или ограничение. Foreground monitor печатает состояние каждого
цикла даже при частичных источниках и продолжает работу; ошибки хранилища останавливают
его с exit 2. Для возврата в рабочее состояние устраните причину и выполните новый scan.

Первый снимок не known-good. Просмотрите весь `baseline diff`, включая context
warnings и scope. **Принятый baseline — known/acknowledged state, не clean state;
он может описывать уже скомпрометированную машину.** Детали:
[trust boundaries](../architecture/trust-boundaries.md). После review скопируйте
точный `approval_token` в команду:

```text
sec baseline update --approve TOKEN_FROM_DIFF --reason "Причина принятия без secrets"
```

TOKEN_FROM_DIFF — placeholder, не исполняемая готовая команда. Любой новый scan,
изменение config/baseline или истечение freshness требует нового diff. Актуальный
`partial` с текущей конфигурацией можно принять после осознанного review пробелов.
`baseline diff` показывает `completeness`, `warning`, `last_ok`, scope и время сбора;
`retained_baseline_keys` перечисляет прежние baseline-объекты, отсутствующие даже
в последнем сохранённом inventory и дополнительно сохраняемые при принятии.
Partial snapshot также может содержать ранее наблюдавшиеся объекты: это последние
известные данные, не подтверждение их текущего наличия. При partial новые/изменённые
объекты остаются видимыми в diff и alerts, а отсутствие не создаёт removals и не
стирает прежние baseline-объекты. Последующий полный scan в том же scope снова
может подтвердить удаление; обновить baseline нужно отдельным review.

`baseline show` сохраняет полноту, scope, причину и времена принятого покрытия,
даже после новых scans; аудит update содержит coverage и ссылки на исходный и
принятый snapshots. Принятие partial не превращает `status` в `current`.
Например, ограничение чтения systemd unit или dangling symlink не требует root
или изменения host permissions ради baseline. `unavailable`, stale, ошибка
хранилища и несовпадение текущей конфигурации по-прежнему блокируют diff/update.
SQLite v1 автоматически мигрирует в v2 транзакционно; неизвестные времена/причина
принятия старого baseline остаются `null`, evidence сохраняется.

Отсутствие process owners при полном bind inventory
показано как отдельное предупреждение; оно не превращается в разрешённое port trust.
Принятие baseline не закрывает старые alerts и не доказывает отсутствие компрометации.

```bash
uv run --cache-dir .cache/uv --no-sync sec monitor
```

Сразу выполняется reconciliation, затем сбор каждые 300 секунд после окончания
предыдущего цикла. `--iterations 1` выполняет один foreground цикл. После выключения
ПК монитор не работает; новый запуск сравнивает текущее состояние с baseline, но
не восстанавливает пропущенные кратковременные события. Один monitor/scan на state;
параллельные CLI review операции сериализуются транзакциями SQLite.

## Разбор предупреждений и исключения

`sec alerts` / `sec history` показывают последние 100 записей; `--limit` от 1 до 1000.
`sec explain ID` связывает before/after evidence с механизмом, риском, нормальными
причинами, ограничениями и ручной проверкой. Объяснение детерминированное, на русском.
Telemetry strings отображаются как JSON data; terminal escape/bidi controls экранируются.
Не вставляйте evidence strings в shell и не вводите secrets в `--reason`.

- `sec alert ID reviewed` отмечает просмотр; `closed` закрывает, `open` переоткрывает.
- `sec trust ID --reason "..." --hours 24` принимает только этот полный контекст.
- `sec suppress add ID --reason "..." --hours 24` подавляет уведомление этого контекста.
- `sec suppress list` показывает и trust, и suppression; `remove RULE_ID` удаляет правило.
- `sec baseline show/diff/update` — отдельное осознанное изменение baseline.

Hours от 1 до 8760; без `--hours` исключение бессрочное и видимое в списке. Изменение
executable/user/bind/port, unit fingerprint/enablement или membership создаёт другой
context. Для отсутствующего/устаревшего объекта и endpoint без executable/user
исключение отклоняется. Исключение не скрывает alert/evidence и не меняет severity.
Закрытие не создаёт исключение. Идентичные повторы группируются; после исчезновения
и возвращения прежнего контекста alert переоткрывается. Accepted baseline и старые
audit decisions никогда не импортируются автоматически из Markdown.

## Notifications, config и остановка

`config.example.toml` — версия 1. Runtime dependencies отсутствуют. Неизвестные ключи,
invalid limits и `llm_enabled=true` отклоняются. `LLM_ENABLED=false` поддерживается;
другие значения не включают AI, а дают ошибку. Persistence выбирается по семи
предусмотренным именам: crontab, rc_local, ld_preload, profile, bashrc, bash_profile,
zshrc. Произвольные пути/команды в config не принимаются.

`notifications=true` включает доступный штатный `/usr/bin/notify-send`. Ничего
устанавливать не требуется; отсутствие инструмента/desktop bus явно возвращает
`notifications: unavailable` и сохраняет pending alerts. Сообщение статическое,
без имён процессов/портов/файлов. Успешно переданное предупреждение не уведомляет
каждый период. Это подтверждение приёма desktop bus, не прочтения пользователем.
Просмотреть ошибки доставки можно в `sec history`. При выключенных notifications
весь цикл и pending alerts остаются доступны в CLI.

```bash
uv run --cache-dir .cache/uv --no-sync sec disable
uv run --cache-dir .cache/uv --no-sync sec service status
```

Disable ставит persistent flag, который работает даже при повреждённой SQLite.
Во время ожидания остановка проверяется каждую секунду; во время collection — между
источниками. Уже начатая read-only команда завершается по своему timeout. Результат
после замеченного disable не записывается. Зависший filesystem I/O способен задержать
остановку. При необходимости Ctrl-C завершает свой foreground процесс.
`sec enable` снимает только flag; сам монитор не запускает. Firewall/hardening
kill switch не изменяет. `service status` показывает lock текущего foreground
процесса; системные service manager настройки не меняет и не считает их установленными.

Установка user service, автозапуск и timers — отдельное system-changing изменение:
нужны конкретный unit, команды, realistic risk, verification, rollback и согласие.
Проект не исполняет `systemctl enable/start` и не устанавливает system/user packages.

## Проверки и измерения этой поставки

Synthetic tests охватывают IPv4/IPv6 TCP и connected UDP, доступность owner context,
повторы и смену контекста, unit/drop-in fingerprints/enablement, UID0, primary и
supplementary group membership, partial/unavailable, перезапуск, invalid input,
лимиты subprocess/file, SQLite FULL/rollback, retention/evidence links, exception
expiry/remove, stale baseline approval, notifications и kill switch.
Никаких attack samples, host configuration changes, Docker или реального desktop bus
в тестах. Отдельная foreground демонстрация использовала доступные read-only sources.

Проверка после trust-boundary review 2026-09-11: **59 tests — PASS**, repository
hygiene, Ruff, offline lock check и `git diff --check` — PASS. Wheel собран offline;
проверены entry point `sec` и состав архива: только пакет/dist-info, без runtime,
SQLite, кэшей и credentials. Input/minimization fixes и отложенные решения описаны
в [trust boundaries](../architecture/trust-boundaries.md). Это локальные проверки,
не результат удалённого CI и не завершение семидневного trial.

После исправления partial baseline 2026-09-11: **68 tests — PASS**, repository
hygiene, Ruff, offline lock check и `git diff --check` — PASS. Добавлены 9 regression
tests: начальный partial, сохранение невидимых объектов, положительные изменения,
partial → complete, блокирующие состояния, миграция v1 → v2, provenance после
restart/retention, лимит union и rollback при ошибке записи. Real-host acceptance
этого исправления ещё не выполнялась; host permissions и privileges не менялись.

[Publication redaction: private workstation observation/configuration omitted.]



[Publication redaction: private workstation observation/configuration omitted.]



## Исходные критерии семидневной приёмки

Ниже — более широкие исходные критерии, не обязательное условие разработки M2b.
Текущая оценка и объём заметок заданы в разделе продолжения выше; дополнительные
измерения нужны лишь для конкретного вопроса, а не для повторного подтверждения PASS.

Сначала запустите foreground в обычном пользовательском окружении. Проверьте
`status`, причины неполного покрытия и сопоставьте сеть/units с ручной проверкой
из runbook. При сохранении gaps зафиксируйте причину; не выдавайте partial за PASS
и не добавляйте root ради обхода ограничений. Примите baseline только после review.

Каждый день фиксируйте в локальном ignored файле `runtime/trial-notes.md`:

[Publication redaction: private workstation observation/configuration omitted.]



Не создавайте атакующие сценарии на рабочем хосте ради измерения. Используйте обычную
работу и synthetic replay для предсказуемых изменений. По окончании сравните с
целями roadmap, документируйте false positives и решите, достаточно ли полезен
watchdog для повседневной работы. Семь дней не симулируются тестами и не объявляются пройденными заранее.

При ошибке хранилища сохраняйте базу для локального анализа; не удаляйте baseline
или evidence автоматически. Вначале `sec disable`, затем проверка места/permissions
и `sec doctor`. Очистка, перенос или восстановление evidence — отдельное решение.
