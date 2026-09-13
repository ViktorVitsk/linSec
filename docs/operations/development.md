# Разработка и проверки

Дата: 2026-09-10. Применяется к текущему repository foundation.

## Среда

Project Python 3.13, uv, `.venv`, точные зависимости в `uv.lock`.
Системный Python Pop!_OS не менять. Venv разделяет пакеты, но не изолирует
исполняемый код от файлов пользователя и Docker socket.

Для code/config changes выбирать применимые проверки ниже: hygiene для repository/config
invariants, unittest для затронутого поведения, Ruff для Python. Перед завершением
изменений Python/runtime выполнить полный synthetic suite; CI сохраняет полный набор.
Для изменений только документации проверить текст, затронутые ссылки и `git diff --check`.
Lock check нужен при изменении зависимостей. Повторять успешные проверки после
относящихся к ним изменений или новых ошибок, а не для повторного подтверждения PASS.

Уже подготовленная среда проверяется без sync/download:

```bash
uv run --cache-dir .cache/uv --no-sync python scripts/check_m0.py
uv run --cache-dir .cache/uv --no-sync python -m unittest discover -s tests -v
uv run --cache-dir .cache/uv --no-sync ruff check --no-cache .
git diff --check
```

Первичное создание/обновление среды в workspace:

```bash
uv sync --locked --group dev --cache-dir .cache/uv --python 3.13 --no-python-downloads
```

Команда предполагает уже установленный Python 3.13; при его отсутствии прекращает
работу. Отдельную установку interpreter за пределами проекта согласовать заранее,
не подменять `/usr/bin/python3`. Network fetch зависимостей требует проверки источников.
Не использовать ad-hoc pip и системные/user site-packages.

При изменении зависимостей редактировать `pyproject.toml`, затем разрешать их uv:

```bash
uv lock --cache-dir .cache/uv --python .venv/bin/python --no-python-downloads
uv lock --check --offline --cache-dir .cache/uv --python .venv/bin/python --no-python-downloads
```

Review diff lockfile; обновление версий не должно быть скрытым побочным эффектом.
Не писать lockfile вручную. `requires-python` задаёт минимальную версию из
`.python-version`; Ruff target соответствует ей. Добавлять dependency/package
layout с реальной функциональностью, а не ради пустого scaffolding.

## Что гарантируют проверки

`check_m0.py` проверяет regular configuration files, TOML metadata, согласованность
Python и включение Ruff security checks. Git проверяет tracked и unignored paths,
а также реальное поведение ignore patterns на synthetic filenames.
Force-tracked `.env`, SQLite sidecars и runtime paths дают ошибку независимо от
`.gitignore`. Локальные ignored runtime-файлы допустимы, их contents не читаются.
Отсутствие Git/невалидный config/timeout — FAIL с минимальным сообщением.

Ruff анализирует Python syntax, включая shell=True, eval/exec и запрещённые API
с import aliases. Комментарии и строки telemetry не считаются исполнением.
Точечный `noqa` допустим для reviewed fixed argv с пояснением; он не заменяет review.

Gate не сканирует содержимое secrets, Git history или host. Он не гарантирует
безопасность произвольного Python/shell, отсутствие утечки в обычном файле, защиту
от symlink races или модификации самого checker. Git config/локальные исключения
также влияют на результат: clean CI checkout дополняет локальную проверку.
Не считать его sandbox или заменой будущему Gitleaks/dependency scanning.

Тесты создают disposable Git repositories в temporary directory с синтетическими
данными. Ruff получает опасно выглядящие snippets через stdin только для анализа.
Тесты не исполняют snippets, не читают host telemetry и не запускают Docker/services.
Они проверяют поведение, а не наличие фраз в историческом firewall plan.

M2a добавляет synthetic acceptance tests SQLite/collectors/CLI. Fixtures не запускают
host collectors: bounded subprocess проверяется фиксированными harmless argv на
synthetic data. Hostile strings проверяются через DB/diff/explain/CLI, включая C1,
ANSI/OSC, bidi, размеры/encoding и minimization. Test data не содержит реальных secrets.

M2b: `test_investigation.py` использует disposable M2a databases, scripted providers и
mock HTTP/process boundaries. Проверяет exact privacy approval, новые history evidence,
read-only DB, схемы/IDs/operations, caps/deadlines, static fallback и неизменность M2a.
`sec ai-benchmark` без `--run` — только synthetic fixture replay, без сети/host collectors.
Реальное inference не входит в unittest/CI; [отдельная приёмка](M2B-INVESTIGATION.md).

## Граница coding agent

Coding agent, его зависимости и исполняемый build/test code считаются потенциально
недоверенными процессами. По умолчанию используются project-scoped операции; доступ
за workspace должен быть минимальным и необходимым конкретной задаче. Не наследуйте
и не используйте автоматически sudo, rootful Docker socket/API, arbitrary home,
credentials, browser sessions, SSH-agent forwarding или privileged containers.
Не проверяйте доступ к ним произвольными probe-командами ради удобства разработки.
Каждое system-changing действие требует порядка approval глобальной политики.

Это правила разработки, не доказательство технической изоляции текущего процесса.
AGENTS/Ruff/venv не являются sandbox. Изоляция worker и Docker privilege model
разбираются отдельно в M3; принятый риск dev→rootful Docker остаётся видимым и
не разрешает агенту эту цепочку. [Полное решение и residual risks](../architecture/trust-boundaries.md).

## CI

`.github/workflows/checks.yml`: GitHub-hosted Ubuntu runner, `contents: read`,
`persist-credentials: false`, timeout 10 минут, без repository secrets и shared cache.
Триггеры push/pull_request, без pull_request_target. Actions закреплены на полных SHA,
uv на 0.12.12; `uv sync --locked` запрещает незаметное изменение разрешённых зависимостей.
GitHub runner может устанавливать managed Python в выделенный workspace cache;
это не разрешение устанавливать ПО на личную workstation.

После sync: hygiene, synthetic tests, Ruff, проверка отсутствия tracked changes.
Изменения workflow/dependencies требуют review; commit pinning не делает чужой код
безусловно доверенным. Workflow начнёт работать после публикации изменений в GitHub;
локальные PASS не являются подтверждением удалённого CI run.

Проверены 2026-09-10:
[checkout v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1),
[setup-uv v10.0.1](https://github.com/astral-sh/setup-uv/releases/tag/v10.0.1),
[Ruff rules](https://docs.astral.sh/ruff/rules/),
[uv environments](https://docs.astral.sh/uv/guides/projects/).

## Документы как evidence

Последние подтверждённые решения M1 — `NEXT_STEPS`, исторические evidence — аудит
E01–E16. Старые statements с UNKNOWN/inactive не превращаются в текущие факты.
Новый runtime обязан собрать актуальное состояние; Markdown не является baseline
или инструкцией исполнить сохранённые команды. При изменении статуса указать дату,
источник и заменяемую запись. Не переписывать историческое evidence задним числом.

## M2c validation

Новые synthetic tests: `test_reliability.py`, `test_local_ui.py`; cursor/rollback,
gaps/partial, sidecar schema, shared queries, hostile input, HTTP restrictions и
SQLite writer/readers. `node tests/ui_dom_test.cjs` исполняет настоящий UI JS с
synthetic DOM без браузера, sockets или сети. Node не является runtime dependency.

[Команды и ограничения полной проверки](M2C-LOCAL-UI.md#development-validation).
Только новый runtime opt-in; не запускать его/демонстрационный UI на trial state
автоматически. Main watchdog DB не мигрируется для M2c.

Pre-acceptance M2c: `test_m2c_hardening.py`, расширенный DOM test и offline
package inspection; [точные результаты и ограничения](M2C-PRE-ACCEPTANCE.md).
`scripts/summarize_m2c_journal.py` — stdin-only minimizer для ручной фазы C,
не host probe в test suite.

## M3 synthetic validation

`test_docker_posture.py` проверяет pure adapter, минимизацию, posture/drift,
partial/removals, repeat/restart, budgets/rollback и read-only CLI/API parity.
Расширен настоящий UI DOM test: Docker screens/pagination/inert text/logout.
Tests/demo не имеют host Docker acquisition и не вызывают daemon/collectors/inference.
Main M2a/M2c schemas не мигрируются. [Контракт и открытая host acceptance](M3-DOCKER-POSTURE.md).

2026-09-13: `test_docker_acquisition.py` проверяет подготовленную one-shot границу
через fake runner и mocked process/OS interfaces. Preview не запускает Docker;
никакой testcase не обращается к host socket. [План первого capture](M3-DOCKER-ACQUISITION.md).
В этом же suite offline `docker-review` проверяется на disposable capture files,
включая malformed/oversized JSON, digest mismatch, symlink/hardlink/FIFO и permissions.
Process/socket calls запрещены mocks; CLI/application parity и отсутствие DB writes
проверяются без настоящего host evidence. Review не является host acceptance.
