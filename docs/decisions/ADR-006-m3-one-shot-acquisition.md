# ADR-006 — M3: подготовленный одноразовый Docker capture

Дата: 2026-09-13. Статус: **код подготовлен и проверен без Docker**;
владелец выполнил первый согласованный запуск, получив отказ на version; шаблон
исправлен, host acceptance ещё открыта. [Evidence попытки](../operations/M3-DOCKER-ACQUISITION.md#первая-попытка-владельца-и-исправление).

## Контекст

Synthetic increment ADR-005 завершён. Владелец поручил продолжить доступную работу.
Это разрешает подготовить acquisition, но не снимает отдельное согласование
точного способа real-host доступа из roadmap. Нужна минимальная проверяемая операция,
которая не устанавливает collector service и не наследует credentials/context.

## Решение

Подготовлен `sec docker-acquire --output <новый каталог>`: по умолчанию только plan.
`--approve <токен точного plan>` разрешает один запуск. Token связан с output path,
фиксированными argv/templates/environment/лимитами и fingerprint кода адаптера,
проекции, контракта и прикладной операции. Это защита от stale review, **не credential,
подпись или техническая sandbox граница**. Код/хеши могут изменить процессы того же UID.

Transport — `/usr/bin/docker` с явным `--host unix:///run/docker.sock` и новым
пустым `--config`. У дочернего процесса минимальное environment, HOME внутри
этого каталога; без унаследованных context, auth stores, loader/proxy/SSH variables.
Только встроенные `version`, `container ls`, `container inspect --format`.
Нет произвольных commands, endpoint, format, names или IDs от пользователя/LLM.
Inspect получает только полный hex ID из bounded первого list.

`docker info` исключён: upstream CLI перечисляет plugins даже при `--format`.
Source reference — хеш device/inode/ctime фиксированного socket, проверяемого
до и после capture. Смена socket аннулирует mixed evidence. Socket должен быть
root-owned, socket type, без world-write; leaf symlink отклоняется. Это не проверка
identity/привилегий daemon, особенно при socket activation/restart за прежним socket.

Shared `project_record` не присваивает origin. Старый Result v1 остаётся только
synthetic. Отдельный `capture.json` имеет `origin=docker_cli_capture`,
`host_validated=false`, `atomic_snapshot=false`, `daemon_identity_verified=false`.
M2a/M2c/M3 synthetic DB, baseline, monitoring, AI и UI не вызывают acquisition.
Host capture пока не импортируется в БД: admission требует следующего review.

## Полномочия, альтернативы и пределы

Read-only argv не ограничивает полномочия rootful Docker socket. Нет sudo,
daemon/group/socket changes, container startup или runtime installation.
Отдельная OS-изоляция worker остаётся открытой задачей; CLI получает обычные права
запускающего пользователя. Этот риск необходимо явно согласовать перед capture.

Прямой HTTP-клиент не выбран в этой поставке: готовый Docker CLI обеспечивает
formatted projection до stdout Python-процесса. Сам Docker CLI всё равно получает
raw Engine inspect (включая Config.Env) в памяти. Он не выводит эти поля выбранным
template. Это не zero-secret-in-memory гарантия и не защита от компрометации CLI.
Shared parser принимает только выбранный bounded stdout; пути затем хешируются.

Постоянный socket proxy/rootless daemon/worker sandbox не устанавливаются под видом
приёмки. Их конфигурация, жизненный цикл и привилегии требуют отдельного решения.
Если точный способ доступа не будет одобрен, synthetic цикл остаётся рабочим.

## Проверка и последствия

Mocked acceptance проверяет fixed argv/environment, отсутствие вызовов при preview
и неверном token, root/existing-dir refusal, minimization, partial/races, socket
replacement, version refusal и bounds stdout/stderr/owned-child cleanup.
Фактические Go templates, установленный CLI/Engine, права socket, нагрузка и
реальный capture ещё не подтверждены. Ошибка несовместимости не разрешает менять
API version или транспорт автоматически.

[Точная процедура и лимиты](../operations/M3-DOCKER-ACQUISITION.md).
Официальные источники проверены 2026-09-13:
[CLI config/environment](https://docs.docker.com/reference/cli/docker/),
[inspect formatting](https://docs.docker.com/reference/cli/docker/inspect/),
[version](https://docs.docker.com/reference/cli/docker/version/),
[info implementation](https://raw.githubusercontent.com/docker/cli/v28.3.3/cli/command/system/info.go),
[socket authority](https://docs.docker.com/engine/security/protect-access/).
