# Детекторы M2a и ручной разбор

Дата: 2026-09-10, уточнение detail summary: 2026-09-17. Версия detector/collector/schema: 1.
Правила написаны для проекта;
Sigma rules и чужой код не копировались. Все сравнения детерминированные, без AI.

## Общая логика и evidence

Каждый вид наблюдений имеет detector ID: `endpoint-drift`, `file-drift`, `unit-drift`,
`uid0-drift`, `group-drift`. Сравнивается точный normalized record с принятым baseline.
Без baseline все наблюдения — unreviewed additions. Изменение существующего record
считается changed, отсутствие — removed только при полном inventory того же scope.
Partial может доказать положительное изменение видимого record; не доказать удаление.

Evidence: локальный host ID, source, UTC collection time, schema/collector versions,
scope/completeness и минимальные поля; alert хранит ссылки before/after snapshots.
Идентичные snapshots не копируются каждый период. Raw logs, unit contents, passwd
password field, argv/env и peer addresses не сохраняются. Хеш файла не является
оценкой его содержимого. Metadata и история под тем же UID не tamper-proof.

Severity: добавление/изменение UID0 или выбранной группы — high; wildcard endpoint
— high; прочие additions/changes — medium; removed records — info. Это приоритет
проверки, не утверждение «атака». Изменение selected file на `exists=false` — changed
record и medium; удаление record из полного inventory — removed и info.

## Endpoint drift: сеть

Purpose: замечать новый local bind и изменение доступного executable/user context.
TCP socket в LISTEN может принимать соединения; UDP socket бывает UNCONN или ESTAB,
но оба могут иметь local bind. `0.0.0.0`/`::` означает wildcard в соответствующем
семействе, не WAN reachability: firewall, routes, interfaces и Docker здесь не проверяются.

Источник: штатный `ss -H -O -n -e -p`, раздельно `-l -t -4/-6` и `-a -u -4/-6`.
Каждая семья/протокол имеет собственную полноту. Контекст владельца получен через
numeric PID/fd и проверку socket inode в `/proc`, затем executable symlink и UID.
Нет чтения cmdline/env. При отсутствии прав bind inventory может быть полным,
но `context_complete=false` и `context_missing` видны; trust/suppression запрещены.

Record: protocol, family, bind с IPv6 zone, port, socket UID, доступные owners
(executable path, process UID), context completeness. Ключ объекта — family/protocol/
bind/port/socket UID. Несколько сокетов с одинаковым ключом объединяют owners;
PID/fd/inode не сохраняются как стабильный context, чтобы обычный restart не шумел.
Смена owners или bind предупреждает заново. Bin/script contents не проверяются:
тот же interpreter/executable/user/port способен исполнять другой код без нового alert.

Нормальные причины: браузер/игра/dev server, обновление, адрес интерфейса, ephemeral
UDP клиент. Wildcard bind иногда ожидаем для LAN; narrow exception требует явного
review. При неизвестном owner не расширяйте правило до «любой процесс на этом порту».

Проверка вручную: выполните фиксированные read-only команды
`ss -H -O -n -l -t -e -p` и `ss -H -O -n -a -u -e -p` локально, сопоставьте bind и
executable/user. Разберите назначение приложения. Не устанавливайте дополнительные
продукты или firewall rules по одному alert. Network namespaces других контейнеров
и кратковременные события между polls не покрываются.

## Unit/file drift: systemd и persistence

Purpose: видеть persistence через новый unit/timer, enablement или изменение уже
существующего main unit/drop-in. Drop-in способен менять запуск, сохраняя имя unit.

Источники: system/user `systemctl list-unit-files --type=service --type=timer`,
стандартные unit paths `/etc`, `/run`, `/usr/local/lib`, `/usr/lib` и user config/data
locations; transient/generator/control paths. Сканируется верхний уровень и один
уровень `.d`, `.wants`, `.requires`. SHA-256 main files и drop-ins дополняется
mode/UID/GID и hash symlink target; содержимое не сохраняется. Unit symlink target
вне известных roots даёт partial; `/dev/null` распознаётся как mask. Произвольные
symlink directories не обходятся. Ошибка одного участка не делает inventory полным.

Record unit: name, system/user scope, enablement. Record file: path, exists,
SHA-256, mode/UID/GID, link target hash. Изменение bytes/прав/владельца/ссылки
предупреждает, даже если название main unit и состояние enablement прежние.
Это disk inventory: shadowed files тоже наблюдаются. Наличие файла не доказывает
его исполнение; active state и in-memory manager properties не реконструируются.
Custom `SYSTEMD_UNIT_PATH`/XDG overrides, external linked units и часть transient
семантики требуют отдельной проверки. Service-manager environment не наследуется.

Persistence вне systemd: только выбранные /etc/crontab, /etc/rc.local,
/etc/ld.so.preload, ~/.profile, ~/.bashrc и optional ~/.bash_profile/~/.zshrc.
Symlink выбранного файла даёт partial: его target не читается автоматически.
Нет обхода home/диска, cron.d, authorized_keys, браузерных profiles, sudoers или
произвольных credentials. Не считать этот список полным Linux persistence inventory.

Нормальные причины: package update, установка приложения, правка dotfiles.
Проверка: сравните локально system/user list-unit-files, metadata и SHA-256
проверенного пути. Просматривайте unit content локально только при необходимости,
поскольку Environment/ExecStart могут содержать secrets; не публикуйте raw contents.
Не делайте daemon-reload/start/restart только ради верификации detector. Изменение
или восстановление файла требует review последствий; fingerprint baseline не backup.

## UID0/group drift: локальные привилегии

Purpose: замечать дополнительный UID0 и изменения выбранных привилегированных групп.
В Linux UID0 привилегирован независимо от имени. Group access даётся как primary
GID из passwd, так и supplementary membership из group: отслеживаются оба механизма.

Источник: ограниченное чтение обычных /etc/passwd и /etc/group; password fields,
home, shell и GECOS отбрасываются. Неверный формат, дубликаты имён или лимит делают
источник unavailable, не «пустым успешным». В persisted record остаются name/UID/GID
для UID0 и name/GID/members для выбранных групп.

Defaults: root, sudo, admin, wheel, docker, lxd, disk, shadow, libvirt, adm,
systemd-journal. Их смысл зависит от local policy; high означает необходимость
проверить изменение доступа. Пользователь может выбрать другой явный список
групп в versioned config; после изменения нужен новый scan/baseline review.

Нормальные причины: согласованное администрирование и установка developer tools.
Проверка: локально сопоставьте только name/UID/GID и membership двух файлов с
согласованными изменениями. /etc/shadow не нужен. Внешний NSS/LDAP, sudoers,
capabilities и cached group credentials уже открытых сессий не покрываются.
Удаление пользователя из группы не гарантирует немедленную потерю его старой сессией доступа.

## Исключения, ответ и сохранение evidence

Подробный read-only detail и `investigate` для `endpoint-drift` берут тот же
минимизированный pack: детерминированный summary кратко говорит, что изменилось
относительно baseline, и указывает протокол, семейство, порт, категорию bind и
существенные ограничения coverage. Это не замена ручной проверки `ss` и не вывод
о легитимности, завершении процесса или текущем состоянии хоста.

`sec explain ID` даёт краткую версию этого runbook. `reviewed/closed` меняют только
lifecycle. Trust/suppression ограничены полным контекстом alert, имеют reason,
provenance, created_at/optional expiry и list/remove. Удалённый, изменившийся после
alert или stale object не допускает exception. Смена контекста предупреждает заново.
Baseline update — отдельный preview и exact token. Host remediation отсутствует.

Если изменение неожиданно: сохраните evidence IDs/времена и локальную историю,
сопоставьте штатные обновления, затем исследуйте происхождение. Не удаляйте файл,
не закрывайте процесс и не перезапускайте unit автоматически: это может разрушить
volatile evidence. Containment, отключение учётной записи, firewall change или
восстановление — конкретные system-changing действия с отдельным согласованием,
проверкой и rollback. При признаках компрометации сначала обеспечьте независимые
evidence/recovery; credential rotation выполняется с доверенной среды и после
определения затронутого scope. Post-incident: проверьте доступ, сохранённую причину,
восстановление и новый baseline diff; не автоматически поглощайте изменения.

Первичные источники проверены 2026-09-10:
[ss](https://man7.org/linux/man-pages/man8/ss.8.html),
[systemd unit format](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml),
[systemctl interface](https://github.com/systemd/systemd/blob/main/man/systemctl.xml),
[passwd](https://man7.org/linux/man-pages/man5/passwd.5.html),
[group](https://man7.org/linux/man-pages/man5/group.5.html).
Местные man pages использованы для проверки формата установленной версии systemd.
