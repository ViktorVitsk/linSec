# Архитектура личного Security Orchestrator

> Publication redaction: workstation-specific evidence/settings were withheld. Methods, dated outcomes and limitations remain historical; omitted values are not replacement measurements.

Дата решения: 2026-09-10, обновление 2026-09-11.
Статус: **M2a foreground runtime и отдельный M2b реализованы**; M2a real-host trial
и M2b real-provider/model acceptance ещё открыты.
Порядок работ — [roadmap](../ROADMAP.md). Обоснование стека —
[ADR-001](../decisions/ADR-001-local-modular-core.md).

## Для кого и зачем

Одна личная Pop!_OS workstation программиста с начальным знанием Linux, сетей и
безопасности. Польза: заметить важное изменение, разобраться в доказательствах,
вручную проверить вывод и научиться безопасно управлять машиной.
Измерять полезность разбором реальных событий, шумом и покрытием, а не числом сенсоров.

Приоритеты: SECURITY > RELIABILITY > UNDERSTANDABILITY > SIMPLICITY > AUTOMATION > FEATURES.
Коммерческий сервис, multi-tenant управление и распределённая инфраструктура сейчас
не определяют архитектуру. Возможное будущее переиспользование — через переносимое ядро.

## Компоненты и зависимости

Один Python-пакет, обычная project `.venv` под uv, SQLite, CLI и небольшой monitor.
M2a реализован в `src/security_orchestrator` с entry point `sec`, стандартной
библиотекой Python и встроенным в uv build backend. Детали первого storage/collector
контракта — в [ADR-002](../decisions/ADR-002-m2a-snapshots.md).

1. **Адаптеры ОС** получают ограниченные наблюдения. Linux-пути, systemd, subprocess
   и особенности прав находятся здесь. Никакого выполнения текста из telemetry.
2. **Ядро** нормализует наблюдения, сравнивает baseline, запускает детекторы и хранит
   историю. Не импортирует Linux API, CLI или AI-провайдера.
3. **Прикладные операции** координируют сканирование, разбор предупреждений, baseline
   и suppression. Именно здесь проверяются разрешения и изменения состояния.
4. **Интерфейсы** — CLI, затем локальная UI — вызывают одни прикладные операции.
5. **AI-адаптеры** получают evidence packs через отдельный policy layer. Возвращают
   предложения и объяснения; права приложения не передаются модели.

M2b реализован в `investigation/`: отдельный read-only reader SQLite v2, export projection,
строгие schemas, bounded application service, adapters OpenRouter/Ollama и synthetic benchmark.
Config M2a v1/fingerprint не меняются; AI settings имеют отдельный файл и contract.
Нет writes анализа в watchdog DB. [Решение и последствия](../decisions/ADR-003-m2b-investigation-boundary.md).

Не создавать отдельный сервис на каждый модуль, event bus, vector database,
динамическую загрузку plugins или универсальный agent framework без необходимости.
Windows пока означает переносимые типы и тесты ядра. Linux-коллекторы не объявляются
совместимыми с Windows; platform support должен быть явным.

## Конвейер и минимальные контракты

OS mechanisms → collectors → normalized observations → SQLite → baseline/detectors
→ grouped alerts → deterministic explanation → optional AI investigation.

- **Observation:** `event_id`, `host_id`, необязательный `device_id`, `source_type`,
  `source`, `event_type`, время события и сбора в UTC, `schema_version`,
  `collector_version`, структурированные данные, evidence references, полнота сбора.
- **Collection result:** источник, статус `ok` / `partial` / `unavailable`, время
  последнего успешного сбора, область покрытия, диагностическая причина без raw secrets.
- **Detector result:** ID/версия детектора, необходимые источники, evidence references,
  severity и объяснение её выбора, ограничения, стабильный ключ контекста.
- **Alert:** связанные результаты, first/last seen, число повторов, состояние разбора.
- **Analysis:** версия схемы, evidence references, гипотезы и неизвестное, выполненные
  проверки, provider/model/prompt versions, расход и задержка; отдельная оценка AI.

Это минимальные контракты, не готовая миграция и не окончательная wire schema.
Идентичность host не зависит от hostname: локальный стабильный ID, без enrollment.
Одинаковое evidence не копируется в каждом alert; неизменившиеся снимки обновляют
freshness, но не создают бесконечную историю. Версии схем и миграции обязательны.
Raw logs сохранять только при доказанной необходимости после минимизации.

## Baseline, ошибки и настройка шума

Baseline означает known/acknowledged state, **не clean state**; первый baseline
может быть принят на уже скомпрометированном хосте. Первый снимок — кандидат, а не
автоматически принятое состояние. Аудит M1 не
импортируется как доверенный baseline. Принятие требует diff и явного решения.
Подтверждение относится к конкретной версии снимка: изменение между preview и
применением требует нового diff, а не незаметного принятия новых данных.

Отсутствие доступа, timeout или неполный inventory не означают удаления объектов.
Не сравнивать неполный набор как полный; сохранять последнее достоверное наблюдение
с отметкой устаревания. `sec status` показывает пробелы и freshness, не общий «% безопасности».
Periodic snapshots могут пропускать кратковременные события; event-driven источники
добавляются в M2c для конкретных пробелов, со сверкой после запуска/пропущенных сборов.

Разделять четыре решения: просмотрено, закрыто, suppression, baseline update.
Закрытие не создаёт доверие. Suppression не изменяет код детектора и baseline.
Для trust требуется узкий контекст: process/executable/user, релевантный путь,
bind address и port; если данных для безопасного правила недостаточно, сообщить это.
Хранить причину, время, происхождение, опциональный expiry; дать list/remove.
Изменившийся контекст предупреждает заново. Принятый риск M1 остаётся видимым,
но не превращается в повторяющееся одинаковое desktop notification.

## Пользовательский цикл и обучение

Будущие команды: `sec status`, `scan`, `alerts`, `explain <id>`, `history`, `doctor`;
`baseline show/diff/update`, `trust <id>`, `suppress list/remove`, `config validate`,
`service status`, `disable`. `investigate <id>` появляется в M2b, с рабочим AI.
Команды добавляются вместе с поведением, без пустых заглушек.

Краткий `explain`: что изменилось → почему важно → evidence → нормальные причины →
что проверить вручную → рекомендуемый ответ → автоматическое действие (отсутствует).
Расширение объясняет механизм ОС и точную логику детектора, ссылается на runbook.
Русский язык, стандартные термины и команды на английском. Не прерывать работу
несвязанным курсом. Синтетические учебные сценарии используют тот же конвейер,
но отдельное хранилище: они не загрязняют host baseline и реальные alerts.

## Ресурсы и эксплуатация

[Publication redaction: private workstation observation/configuration omitted.]



Monitor работает с обычными правами. Недоступное покрытие показывается явно;
дополнительный привилегированный сбор требует отдельного проекта разрешений.
User service не гарантирует наблюдение до входа пользователя: это граница покрытия.
Kill switch останавливает только orchestrator и его расписания, не отменяет hardening.
Долгие задачи планируются отдельно; выключение ПК ежедневно учитывается при catch-up.
Прогон на семь дней проверяет шум, пропуски, задержку, ресурсные цели и понятность.

SQLite и код под тем же пользователем не дают tamper-proof защиты от компрометации
этой учётной записи или root. Мониторинг дополняет updates, isolation и recovery.
Настоящие runtime-данные и credentials не хранятся в Git, CI или cloud traces.

Границы watchdog, hostile evidence, baseline, minimization и coding agent и
распределение решений между M2b/M3/residual risk — [trust boundaries](trust-boundaries.md).
AI в M2b не повышает доверие к источникам и не получает полномочия coding-agent процесса.
