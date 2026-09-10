# M2a: foreground watchdog и эксплуатационная приёмка

> Publication redaction: workstation-specific evidence/settings were withheld. Methods, dated outcomes and limitations remain historical; omitted values are not replacement measurements.

Дата: 2026-09-10. Код и synthetic checks реализованы. **M2a ещё не закрыт:**
нужны обычный host foreground scan, ручной review baseline и семидневный trial.
Системные настройки при разработке не менялись. Нет установленного user service,
schedule, root daemon, host remediation, AI/provider/облачных запросов.

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
warnings и scope. После review скопируйте точный `approval_token` в команду:

```text
sec baseline update --approve TOKEN_FROM_DIFF --reason "Причина принятия без secrets"
```

TOKEN_FROM_DIFF — placeholder, не исполняемая готовая команда. Любой новый scan,
изменение config/baseline или истечение freshness требует нового diff. Неполный
inventory принимать нельзя. Отсутствие process owners при полном bind inventory
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

[Publication redaction: private workstation observation/configuration omitted.]



[Publication redaction: private workstation observation/configuration omitted.]



## Семидневная приёмка перед M2b/расширением

Сначала запустите foreground в обычном пользовательском окружении. Проверьте
`status`, причины неполного покрытия и сопоставьте сеть/units с ручной проверкой
из runbook. При сохранении gaps зафиксируйте причину; не выдавайте partial за PASS
и не добавляйте root ради обхода ограничений. Примите baseline только после review.

Каждый день фиксируйте в локальном ignored файле `runtime/trial-notes.md`:

[Publication redaction: private workstation observation/configuration omitted.]



Не создавайте атакующие сценарии на рабочем хосте ради измерения. Используйте обычную
работу и synthetic replay для предсказуемых изменений. По окончании сравните с
целями roadmap, документируйте false positives и решите, достаточно ли полезен
watchdog для M2b. Семь дней не симулируются тестами и не объявляются пройденными заранее.

При ошибке хранилища сохраняйте базу для локального анализа; не удаляйте baseline
или evidence автоматически. Вначале `sec disable`, затем проверка места/permissions
и `sec doctor`. Очистка, перенос или восстановление evidence — отдельное решение.
