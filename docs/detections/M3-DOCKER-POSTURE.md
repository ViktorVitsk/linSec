# Детекторы M3 Docker posture v1

Дата: 2026-09-12. Источник: только synthetic inspect-shaped envelope;
host coverage отсутствует. [Contract/лимиты](../operations/M3-DOCKER-POSTURE.md).
Все правила собственные; Sigma/сторонние rule packs не копировались.

## Publications

`publication`, medium: хотя бы одна configured/observed публикация с пустым IP
или адресом, не относящимся к loopback. Evidence сохраняет bind/protocol/ports и
различает configured/observed. Docker связывает опубликованный порт с сетью хоста;
более широкий bind требует проверки intended audience. Это не утверждение об атаке,
работающем сервисе или WAN reachability. Разрешённый LAN service — нормальная причина.
Loopback mapping не даёт универсальной гарантии изоляции: нужны версия Engine,
gateway mode, direct routing, firewall и topology, которые не собираются.

## Привилегии и namespaces

`privileged`, high: `Privileged=true`. Это широкий набор прав контейнера, требующий
обоснования workload. `host_namespace`, high: хотя бы один mode network/pid/ipc/uts/userns
равен host. `shared_namespace`, medium: mode container означает разделение namespace
с соседом; имя соседа минимизировано. Для разработческого debugger такое изменение
может быть ожидаемым. Evidence содержит только соответствующие mode/flags.
Не делается вывод об exploit или фактической привилегии конкретного процесса.

## Mounts

`sensitive_mount`, high: **bind** source — `/`, известный чувствительный system/device
prefix или credential directory component; либо source/destination basename —
`docker.sock`. Evidence: категория, rw, тип и ссылки-хеши путей. Обычный named volume
в Docker storage не считается bind всего Docker storage. tmpfs тоже не даёт finding.

Механизм: bind открывает workload выбранный ресурс хоста; socket может предоставлять
daemon API независимо от read-only mount flag. Нормальная причина — осознанный
development workflow, но privileged docker socket — отдельная граница доверия.
Сравнивать source/destination с ожидаемой конфигурацией вручную после согласования
acquisition. Не разрешать broad trust на все mount paths.

Классификация лексическая: symlinks, переименованные sockets, volume driver options,
propagation, devices вне Mounts и другие пути могут менять реальный риск. Мы не
разрешаем пути на хосте и не читаем их содержимое. Хеши не делают путь неугадываемым.

## Capabilities и user

`capabilities`, medium: непустой explicit CapAdd; evidence также показывает CapDrop.
CapAdd может расширять действия workload, но эффективные sets процесса не измерены.
`root_user`, medium: пустой Config.User, root или числовой 0 (с optional group).
`unknown_user`, info: вместо numeric UID задано имя, которое мы не разрешаем в image.
Нормальные причины — image default, installation tools, debugger или daemon workload.
UID контейнера нельзя приравнивать к UID хоста без userns/rootless evidence.
Числовой nonzero UID тоже не является доказательством безопасности контейнера.

## Configuration drift и inventory events

`configuration_drift`, medium: known non-null поля image, privileged, namespaces,
mounts, caps, user, restart и configured ports отличаются от последнего полностью
наблюдавшегося record. Before/after evidence доступны через finding ID. Env, names,
labels и runtime running/observed ports исключены; это намеренный scope минимизации.
Нормальные причины — обновление image/compose, изменение dev service или restart policy.

`container_added`, info: впервые замечен ID или появился после полного отсутствия.
`container_removed`, info: ранее наблюдавшийся ID отсутствует в полном inventory
той же серии. Это история inventory, а не удаление host файлов. Неполное evidence
не создаёт removals и не означает восстановление событий между snapshots.

## Разбор и реакция

1. Откройте `sec docker-view ID --docker-state <synthetic-directory>` или detail в UI.
   Сначала проверьте origin, source coverage/freshness и то, что это synthetic сценарий.
2. Сопоставьте поля before/after с ожидаемым workflow. ID/строки evidence — данные,
   никогда не команды для shell. Для настоящего daemon нужен отдельно согласованный
   минимизированный сбор; не копируйте полный inspect/env в терминал или облако.
3. Если изменение неожиданно, сначала сохраните минимизированное evidence и время;
   затем обсудите containment. Stop/remove/recreate контейнера может изменить или
   уничтожить forensic evidence. В M3 такие операции не реализованы.
4. Host change требует exact plan, approval, verification и rollback. При подозрении
   на компрометацию отдельно определить preservation, проверку credentials exposure,
   необходимость rotation и recovery/post-incident проверки; секреты не переносить
   в evidence. Само posture finding не доказывает утечку credentials.

Снятие текущего условия (`resolved`) не означает доверие/закрытие. Trust/suppression
для Docker в этом этапе отсутствуют; baseline не принимается автоматически.

Проверенные первоисточники 2026-09-12:
[port publishing](https://docs.docker.com/engine/network/port-publishing/),
[container privileges/capabilities/user](https://docs.docker.com/engine/containers/run/),
[daemon security](https://docs.docker.com/engine/security/),
[user namespace mapping](https://docs.docker.com/engine/security/userns-remap/),
[API v1.51](https://raw.githubusercontent.com/moby/moby/v28.3.3/docs/api/v1.51.yaml).
Совместимость с установленным Engine ещё не проверена.
