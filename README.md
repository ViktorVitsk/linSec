# Security Orchestrator

> Publication redaction: workstation-specific evidence/settings were withheld. Methods, dated outcomes and limitations remain historical; omitted values are not replacement measurements.

Практический security-проект для личной Pop!_OS workstation. Приоритеты:
**безопасность → надёжность → понятность → простота → автоматизация**.

## Состояние на 2026-09-10

Создана документальная основа M0 и выполнен первоначальный read-only inventory M1.
Полный M1 **не закрыт**: привилегированные проверки не выполнились без пароля sudo;
доступность из LAN/WAN и восстановление backup не проверялись.

- [Первоначальный аудит: факты, риски, ограничения](docs/audit/INITIAL_SECURITY_AUDIT.md)
- [Начальная модель угроз](docs/architecture/INITIAL_THREAT_MODEL.md)
- [Следующие действия и ручная проверка](docs/operations/NEXT_STEPS.md)

Работающего `sec`, collectors, monitoring daemon и LLM integration пока нет.
Это документация существующей машины, а не сертификат её безопасности.

## Безопасная разработка — M0

[Publication redaction: private workstation observation/configuration omitted.]



В начале существенной сессии: проверить UID, прочитать применимые инструкции,
проверить Git status и diff policy-файлов. Не считать результат из sandbox полным
представлением процессов, групп и сети хоста. Для этой итерации запись разрешена
только внутри проекта. Диагностика системы — read-only, без исправлений.

**Git пока не инициализирован:** проверка на хосте не нашла `.git`, `git status`
вернул `not a git repository`. Поэтому историческая целостность инструкций не
подтверждена. В sandbox виден синтетический пустой `.git`; он не означает наличие
истории. Git init/commit в этой итерации не выполнялись.

Стратегия окружения для следующего небольшого шага M0:

[Publication redaction: private workstation observation/configuration omitted.]



M0 остаётся частично выполненным: Git, исполняемое окружение, lock и тесты кода
ещё не созданы. Так сохраняется согласованный минимальный объём этой итерации.

## Граница будущей автоматизации

Сначала механизмы ОС и нормализованные события, затем deterministic detection.
LLM сможет объяснять компактные evidence packs, но не выполнять действия.
`LLM_ENABLED=false` должен сохранять работоспособность будущего продукта;
cloud escalation и автоматическое изменение host state изначально отключены.
Сейчас эти параметры описывают проектное решение, а не установленную защиту.

**NO SYSTEM CHANGES WERE MADE.** Созданы только четыре документа проекта.
