# ADR-005 — M3: Docker posture с отдельной synthetic границей

Дата: 2026-09-12. Статус: реализовано для synthetic acceptance;
решение о real-host acquisition и его приёмка **открыты**.

## Контекст

После принятого M2c следующий increment roadmap — read-only Docker posture.
Нужно проверить полезность детекторов и доверие к metadata до доступа к daemon.
Read-only намерение программы не ограничивает полномочия Docker socket. Нельзя
унаследовать rootful доступ coding agent, AI, web UI или обычным monitor.
Начальный M2a soak и будущий семидневный integration trial сохраняют свой scope.

## Решение

Первый этап M3 реализует чистый adapter `adapters/docker.py`, versioned result v1,
детерминированные правила и отдельную SQLite v1 `docker-posture.sqlite3`.
`parse_synthetic` получает только bytes встроенных fixtures; не имеет subprocess,
HTTP, socket, filesystem acquisition, Docker context или registry credentials.
CLI предоставляет `docker-demo` и read-only `docker-view`; UI вызывает тот же
`PostureQueries` через существующий защищённый transport. Новый endpoint не
запускает collection, AI или mutations.

Origin жёстко ограничен `synthetic`. Контракт не принимает `origin=host`.
Source ID отделяет серии, полный Docker ID отделяет объекты. Main watchdog
SQLite v2, reliability SQLite v1, SOURCES, config v1/fingerprint, monitor и
AI export registry не расширяются. В synthetic каталоге нет host baseline.

Сохраняются лишь выбранные posture поля. Raw inspect, env, labels, names,
argv/entrypoint, image names и descriptions не хранятся и не выводятся.
Mount paths заменены категориями и SHA-256 references для обнаружения изменений.
Это минимизация, **не криптографическая анонимизация**: предсказуемый путь можно
угадать по хешу. Cloud export этих данных не реализован.

Posture сравнивается с явными правилами даже при первом наблюдении. Drift —
сравнение с последним полным наблюдением объекта, а не accepted baseline.
Это автоматическое обновление observation checkpoint, **не создание доверия**.
В этом этапе нет baseline acceptance, trust/suppression, закрытия findings,
desktop notifications или включения Docker в monitoring schedule.

## Альтернативы

- Прямой `docker inspect` из watchdog/coding agent: не выбран, поскольку даёт
  процессу полномочия daemon и может раскрыть env через полный JSON.
- Автоматическая установка socket proxy, rootless daemon или смена группы:
  не выбрана; это самостоятельное изменение привилегий/хоста и maintenance.
- Добавить Docker в M2a SOURCES/общую БД сразу: не выбрано, чтобы не менять
  baseline, AI projection, health и retention до согласования acquisition.
- Только Markdown contract без исполняемой проверки: недостаточно для проверки
  hostile input, deduplication, partial semantics и поведения CLI/UI.

## Последствия и следующий барьер

Получен работающий synthetic цикл projection → SQLite → findings → explain/UI.
Это не рабочий Docker monitor и не подтверждение posture реального хоста.
Техническая изоляция worker от файлов пользователя/rootful socket не создана;
venv, Python-классы и ADR не считаются sandbox.

Перед следующим этапом нужно подготовить и согласовать отдельный acquisition
change: точные API/argv, разрешённый endpoint, права выполняющего процесса,
ограничения stdout/stderr/time/resources, минимизация до записи/передачи,
проверка владельцем и rollback. Рассмотреть ручной одноразовый минимизированный
export и отдельный ограниченный collector; выбор ещё не сделан. Не передавать
coding agent произвольный socket/SSH/context/URL. Same-UID tampering остаётся
residual risk: hashes и application ID не доказывают подлинность данных.

Проверены официальные источники 2026-09-12:
[daemon security](https://docs.docker.com/engine/security/),
[socket protection](https://docs.docker.com/engine/security/protect-access/),
[API v1.51 schema](https://raw.githubusercontent.com/moby/moby/v28.3.3/docs/api/v1.51.yaml).
Это проверка формы fixture, а не определение установленной версии Docker.

[Контракт и запуск](../operations/M3-DOCKER-POSTURE.md),
[правила](../detections/M3-DOCKER-POSTURE.md).
