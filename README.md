# Security Orchestrator

> Publication redaction: workstation-specific evidence/settings were withheld. Methods, dated outcomes and limitations remain historical; omitted values are not replacement measurements.

Практический security-проект для личной Pop!_OS workstation. Приоритеты:
**безопасность → надёжность → понятность → простота → автоматизация**.

## Состояние на 2026-09-10

**M0 и M1 завершены в согласованном scope. M2 ждёт подтверждения владельца.**
Выполнен host security audit, применён и проверен UFW для IPv4/IPv6; необходимые
exceptions и Docker rules сохранены, CUPS/DNS/HTTPS checks успешны.

[Publication redaction: private workstation observation/configuration omitted.]



- [Первоначальный аудит: факты, риски, ограничения](docs/audit/INITIAL_SECURITY_AUDIT.md)
- [Начальная модель угроз](docs/architecture/INITIAL_THREAT_MODEL.md)
- [Следующие действия и ручная проверка](docs/operations/NEXT_STEPS.md)
- [Выполненный firewall plan и аварийный rollback](docs/operations/HOST_FIREWALL_HARDENING_PLAN.md)

Работающего `sec`, collectors, monitoring daemon и LLM integration пока нет.
Это документация существующей машины, а не сертификат её безопасности.

## Безопасная разработка — M0

M0 завершён по подтверждению владельца; без regression к нему не возвращаться.
Применяются глобальный `/workspace/agent-policy/AGENTS.md` и проектный `AGENTS.md`.
Codex работает без root, с ограниченной сетью и sandbox. Проверка инструментом
не заменяет согласие владельца на system-changing operations.

В начале существенной сессии проверяются инструкции, Git status и policy diff.
Repository имеет Git history; результаты первоначального аудита об отсутствии
Git являются историческими. Данные из sandbox не всегда описывают host namespace.

Стратегия при появлении кода: отдельный project `.venv`, минимум dependencies
с точными версиями/lock, без изменения system/user Python. Tests используют
синтетические данные; subprocess — фиксированные argv, validation и bounds,
без исполнения текста telemetry. Сейчас проверяются Markdown links и diff;
runtime tests приложения отсутствуют, поскольку приложения ещё нет.
В Git не включаются реальные `.env`, credentials, raw telemetry и runtime databases.

## Граница будущей автоматизации

Сначала механизмы ОС и нормализованные события, затем deterministic detection.
LLM сможет объяснять компактные evidence packs, но не выполнять действия.
`LLM_ENABLED=false` должен сохранять работоспособность будущего продукта;
cloud escalation и автоматическое изменение host state изначально отключены.
Сейчас эти параметры описывают проектное решение, а не установленную защиту.

История разрешённого firewall change и решения владельца записаны в E15/E16 аудита.
При закрытии M1 изменена только существующая документация; новых system changes нет.
