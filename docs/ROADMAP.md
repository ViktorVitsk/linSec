# Roadmap Security Orchestrator

> Publication redaction: workstation-specific evidence/settings were withheld. Methods, dated outcomes and limitations remain historical; omitted values are not replacement measurements.

Дата обновления: 2026-09-12. Статус: **актуальный согласованный порядок разработки**.
Заменяет прежнюю последовательность M2 → M3 → M4 AI → M5 UX из исходного AGENTS.
Цель — личный рабочий инструмент и обучение через реальные события. Компаниям,
multi-tenant и SaaS сейчас не посвящаем отдельную архитектуру.

## Состояние и граница текущего increment

- M0: завершён; найденная regression Python исправлена подготовкой перед M2.
- M1: завершён в согласованном scope; решения и ограничения — в
  [NEXT_STEPS](operations/NEXT_STEPS.md). Не повторять host hardening ради нового roadmap.
- Подготовка перед M2: реализованы Python 3.13, поведенческие проверки repository
  hygiene и Ruff, locked CI workflow, короткие инструкции и отдельная архитектура.
  Локально проходят 17 тестов, hygiene, Ruff и lock check; удалённый CI ещё не запускался.
- M2a: **реализован foreground runtime, эксплуатационная приёмка открыта**.
  Есть `sec`, collectors, SQLite migrations, baseline/diff, alerts/explain, исключения,
  retention, doctor и kill switch. Synthetic replay проходит; один foreground scan
  в sandbox показал unavailable сеть и partial systemd. Это не проверка полного
  покрытия workstation. Начальный real-host soak завершён владельцем 2026-09-12;
  на последнем checkpoint — ~23ч38м работы без наблюдаемого operational blocker,
  затем monitor остановлен. Полный семидневный trial перенесён на integration/release-candidate
  stage, не отменён и не блокирует M2c acceptance/дальнейшую разработку.
  Это не подтверждение многодневной стабильности; [evidence и решение](operations/M2A_TRIAL.md).
- M2b: **код и synthetic acceptance реализованы**: отдельный read-only export/policy
  layer, providers, privacy preview, typed operations, budgets и deterministic fallback.
  [Запуск и границы](operations/M2B-INVESTIGATION.md). Реальные provider/model acceptance,
  local runtime/GPU сравнительные измерения и оценка русского объяснения человеком открыты.
  AI выключен по умолчанию; во время разработки cloud/host inference не выполнялись.
- M2c: **принят в согласованном scope — PASS WITH KNOWN LIMITATIONS**: отдельная reliability SQLite v1,
  bounded user-systemd journal hints, cursor/dedup/typed gaps, opt-in reconciliation
  runtime и read-only local UI с access control. [Контракты](architecture/M2C-RELIABILITY.md),
  [приёмка/ограничения](operations/M2C-LOCAL-UI.md),
  [реализация](operations/M2C-IMPLEMENTATION.md),
  [итог acceptance 2026-09-12](operations/M2C-ACCEPTANCE.md).
  A/B PASS подтверждены владельцем; C service PASS, timer not observed; D пройдена
  отдельной real-host серией: first observation → continuation, один сохранённый gap,
  history_recovered=false. Принятые partial coverage и непроверенные аварийные/длительные
  сценарии остаются явно открытыми. Начальная M2a серия не переводилась на M2c,
  main DB остаётся v2; постоянный monitor/autostart не включён.
- M3: **synthetic этап read-only Docker posture реализован**: adapter/result v1,
  отдельная SQLite v1, deterministic findings/drift/dedup и общий CLI/UI.
  [Контракт, демонстрация и ограничения](operations/M3-DOCKER-POSTURE.md),
  [граница доступа](decisions/ADR-005-m3-synthetic-docker-posture.md).
  Real-host acquisition/acceptance, worker isolation и scanners открыты; M3 целиком не закрыт.
  2026-09-13: подготовлен opt-in одноразовый `docker-acquire` с plan/approval,
  минимизированным отдельным capture и mock acceptance. Первая согласованная
  попытка владельца остановилась на version; ошибка шаблона исправлена, повторная
  host acceptance открыта. [Процедура](operations/M3-DOCKER-ACQUISITION.md).

Уточнение 2026-09-11 перед M2b: [границы доверия](architecture/trust-boundaries.md).
Исправлены C1/DEL terminal escaping, проверка сохранённого evidence и лимит partial
union; hostile-input/minimization scenarios добавлены в acceptance tests. Baseline
явно acknowledged, не clean state. Same-UID tampering принят как residual risk;
LLM export/action boundary относится к M2b, Docker/worker isolation — к M3/отдельным изменениям.

Текущая поставка — M2a, отдельный M2b и M2c с принятой bounded host/browser acceptance.
Добавлен отдельный synthetic этап M3. Следующий шаг — согласовать real-host acquisition
и проверить его в рамках первого Docker posture increment;
[границы поставки ниже](#m3--docker-и-developer-security). История начального M2a soak
сохраняется отдельно; будущие AI/M2c результаты не смешиваются с его метриками. [Совместимость без изменения M2a contracts](decisions/ADR-003-m2b-investigation-boundary.md).
Следующий шаг M2b — сравнительный local benchmark и human review после отдельного
выбора/проверки runtime. [Процедура trial M2a](operations/M2A-WATCHDOG.md).
Системные операции не разрешаются автоматически принятием roadmap.

## M2a — Первый ежедневный watchdog

Цель: один законченный цикл collection → SQLite → diff → alert → explanation →
узкое исключение, пригодный для ежедневного использования без AI.

Покрытие:

- TCP listeners и UDP bound endpoints IPv4/IPv6; bind address и доступный
  process/executable/user context. Wildcard не доказывает WAN reachability.
- System/user systemd services/timers: existence, enablement, fingerprint основного
  unit и drop-ins, включая изменение существующего unit.
- Новые UID 0 и изменения привилегированных групп.
- Выбранные файлы persistence: ограниченный явный список вместо обхода всего диска.

Сначала штатные источники Linux, periodic collection и reconciliation при запуске.
Никакого root daemon по умолчанию; недоступный источник даёт partial/unavailable.
Детекторы не объявляют частичный inventory полным и не создают ложные удаления.

Поставка: устанавливаемый пакет, CLI, migrations, versioned configuration,
история, baseline с preview и защитой от stale approval, отдельные lifecycle/trust/
suppression, минимальные desktop notifications, freshness/doctor, kill switch.
Kill switch не отменяет firewall/hardening. Установка user service и расписаний —
отдельное согласованное изменение; до неё демонстрация в foreground.

Приёмка: synthetic replay сети, unit/drop-in, UID 0 и групп; повторное событие
объединяется, новый контекст предупреждает заново. Сбой источника, перезапуск,
повреждённый ввод и заполнение хранилища явно видимы. При `LLM_ENABLED=false`
весь цикл работает. Документировать пропуск кратковременных событий при polling.

[Publication redaction: private workstation observation/configuration omitted.]



## M2b — AI-расследование и обучение

После рабочего M2a, не ждать завершения Docker/scanners. Сначала один объясняющий
вызов, затем bounded investigation через типизированные разрешённые операции.
Локальная история/runbook lookup без vector database или общего файлового доступа.

Поставка: evidence packs, provider interface, OpenRouter по явному запросу,
local runtime benchmark, schema validation, redaction/privacy preview, budgets,
до пяти шагов, отказоустойчивый deterministic fallback, учебные synthetic scenarios.
Модель и runtime выбирать по сравнительным измерениям, не по предположению о GPU.

[Publication redaction: private workstation observation/configuration omitted.]



## M2c — Надёжность и локальная UI

Journald для нужных auth/security событий после проверки доступного scope и
формата; cursor, deduplication, явные gaps и обработка потерянного cursor.
Scheduled reconciliation сохраняется. Потерянные события не объявляются восстановленными.
Расширять только наблюдение, полезность которого подтверждается сценариями.

Компактный локальный интерфейс: состояние мониторинга, список alerts, timeline
расследования и обучение. Повторно использовать application services CLI.
Реализованы stdlib HTTP transport и локальные HTML/CSS/JS; dependencies не добавлены.
Не выставлять API публично; loopback binding сам по себе не заменяет защиту
доступа, Origin/CSRF и ограничение методов, если появится web server.

## M3 — Docker и developer security

Переход после [M2c acceptance](operations/M2C-ACCEPTANCE.md), 2026-09-12.
Первый полезный increment — read-only Docker posture; scanners и дополнительная
developer telemetry идут после него, не добавляются в ту же поставку.

Реализованы versioned минимизированный result contract, чистый synthetic adapter,
deterministic findings и CLI/UI через общие application operations, без обращения
к host Docker daemon. Synthetic проверки подтверждают unavailable/partial,
отсутствие ложных removals и разграничение bind/WAN reachability.
Ближайшая работа — выбрать и согласовать реальный acquisition с явной границей доверия;
synthetic origin не разрешает импорт host evidence или доступ к socket.

Приёмка первого increment: synthetic publications/binds, privilege/namespaces/mounts,
capabilities/user и configuration drift; hostile metadata остаются данными, env secret
values не сохраняются, повторный inventory не создаёт дубли, partial не создаёт ложные
removals. Зафиксировать timeouts/output/resource bounds и совместимость M2a/M2c.
До real-host adapter acceptance отдельно определить и разрешить точный способ доступа:
read-only намерение клиента не ограничивает полномочия rootful Docker socket.
Daemon, groups/socket permissions, container startup, scanner installation и remediation
не разрешаются этим переходом. M1 prerequisites и отложенный integration soak сохраняются.

Сначала posture: publications/binds, privileged/host namespaces, socket/sensitive
mounts, capabilities, пользователь, restart/config changes. Env secret values
не хранить и не показывать. Docker access не является обходом privilege boundary.
Условие M1 перед запуском существующих containers сохраняется.

Затем image/dependency/secret scanning, package sources и repo changes, selected
IDE/browser extension metadata без history/cookies. Не выполнять package fix.
Каждый scanner подключается adapter-ом: versioned result, ограниченные входы,
timeout, resource budget, freshness vulnerability DB, минимизированный вывод.

Готовые компоненты и решение сейчас:

- **osquery** — возможный inventory adapter для расширения/Windows, не обязательная
  установка M2. Audit-based process collection может конфликтовать с auditd:
  [upstream](https://osquery.readthedocs.io/en/stable/deployment/process-auditing/).
- **Sigma** — источник проверяемых правил/терминологии; адаптировать только правила
  с доступной telemetry, сохраняя provenance/license/tests. Универсальный engine
  не писать: [спецификация](https://sigmahq.io/sigma-specification/).
- **Gitleaks** — кандидат для Git secret scanning вместо собственной реализации:
  [проект](https://github.com/gitleaks/gitleaks). Не выводить найденные secret values.
- **Trivy** — кандидат для images/dependencies/configuration; перед интеграцией
  проверить release и advisories, включая supply-chain incident 2026:
  [advisories](https://github.com/aquasecurity/trivy/security/advisories).

Источники проверены 2026-09-10. Перед фактической установкой повторно проверить
совместимость, обслуживание, privileges, CPU/RAM/disk, false positives, лицензию,
provenance/целостность релиза и rollback. Не ставить пересекающиеся продукты без
уникальной полезной функции. Начальный CI не выдавать за уже работающие scanners.

## За пределами ближайших этапов

IoT, pentest lab, multi-host, коммерческая платформа, remote enrollment, внешние
notifications и автоматическая remediation отложены. Нет SIEM, Kubernetes,
message bus, публичного API, больших IDS stacks или ML anomaly engine.
Будущие ограничения и контекст сохранены в [deferred](future/deferred.md).

Для каждого increment: осмотреть факты → выбрать минимум → реализовать →
проверить → измерить → документировать → продемонстрировать → остановиться перед
расширением. Документация и остающиеся ограничения входят в Definition of Done.
