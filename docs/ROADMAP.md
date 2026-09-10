# Roadmap Security Orchestrator

> Publication redaction: workstation-specific evidence/settings were withheld. Methods, dated outcomes and limitations remain historical; omitted values are not replacement measurements.

Дата: 2026-09-10. Статус: **актуальный согласованный порядок разработки**.
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
  покрытия workstation. User service не установлен, семидневный trial не выполнен.
- M2b/M2c/M3: **ещё не реализованы**. AI integration и локальной UI нет.

Текущая поставка — код M2a и синтетическая демонстрация. Ближайший шаг: проверить
host coverage в обычном пользовательском окружении, просмотреть baseline и провести
семь дней эксплуатации. [Процедура и ограничения](operations/M2A-WATCHDOG.md).
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

Приёмка: injection остаётся данными; запрещённая операция не исполняется;
выдуманный evidence ID отклоняется; новые данные не обходят cloud preview;
превышение лимита останавливает расследование, монитор продолжает работать.
Качество русского объяснения и обоснованность фактов оценивает человек.
Контракт: [LLM security](architecture/llm-security.md).

## M2c — Надёжность и локальная UI

Journald для нужных auth/security событий после проверки доступного scope и
формата; cursor, deduplication, явные gaps и обработка потерянного cursor.
Scheduled reconciliation сохраняется. Потерянные события не объявляются восстановленными.
Расширять только наблюдение, полезность которого подтверждается сценариями.

Компактный локальный интерфейс: состояние мониторинга, список alerts, timeline
расследования и обучение. Повторно использовать application services CLI.
Конкретный UI framework выбирается при этом этапе; сейчас frontend не создаётся.
Не выставлять API публично; loopback binding сам по себе не заменяет защиту
доступа, Origin/CSRF и ограничение методов, если появится web server.

## M3 — Docker и developer security

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
