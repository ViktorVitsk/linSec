# Security Orchestrator

> Publication redaction: workstation-specific evidence/settings were withheld. Methods, dated outcomes and limitations remain historical; omitted values are not replacement measurements.

Личный Linux security monitor: замечать важные изменения, понимать доказательства
и учиться безопасности на реальных событиях. **Безопасность → надёжность → понятность
→ простота → автоматизация → функции.**

## Состояние на 2026-09-10

**M0/M1 завершены в согласованном scope. Подготовка перед M2 реализована:** Python
согласован на 3.13, исправлен safety gate, добавлены поведенческие тесты и CI workflow,
архитектура и порядок этапов пересмотрены. Работающего `sec`, collectors, monitoring
service и LLM integration пока нет. Следующий отдельный increment — M2a.

- [Roadmap: M2a watchdog → M2b AI → M2c надёжность/UI → M3 Docker](docs/ROADMAP.md).
- [Архитектура, ежедневный цикл и данные](docs/architecture/overview.md).
- [AI-расследователь и замена моделей](docs/architecture/llm-security.md).
- [Разработка, проверки и границы CI](docs/operations/development.md).
- [Правила безопасности](docs/operations/safety-rules.md).

## Последнее подтверждённое состояние машины

Источник — аудит **E15/E16 от 2026-09-10**, не новый live scan. UFW применён и
проверен для IPv4/IPv6; согласованные exceptions и Docker rules сохранены,
CUPS/DNS/HTTPS checks прошли в указанном scope.

[Publication redaction: private workstation observation/configuration omitted.]



- [Решения и оставшиеся ограничения M1](docs/operations/NEXT_STEPS.md).
- [История аудита E01–E16](docs/audit/INITIAL_SECURITY_AUDIT.md).
- [Модель угроз](docs/architecture/INITIAL_THREAT_MODEL.md).
- [Архив выполненной firewall-процедуры](docs/operations/HOST_FIREWALL_HARDENING_PLAN.md).

## Локальные проверки

Для уже установленной project `.venv` с Python 3.13 и Ruff:

```bash
uv run --no-sync python scripts/check_m0.py
uv run --no-sync python -m unittest discover -s tests -v
uv run --no-sync ruff check --no-cache .
git diff --check
```

Подготовка среды и обновление lockfile описаны в [development](docs/operations/development.md).
System/user Python не изменяется. `uv.lock` редактирует только uv. Gate проверяет
repository hygiene, Ruff — Python constructs; они не заменяют sandbox, secret
scanning или host audit. Тесты работают с disposable repositories и synthetic data.
CI настроен на GitHub-hosted runner; локальные тесты не подтверждают удалённый CI run.

## Ближайшая польза

M2a даст baseline/diff, историю и объяснимые предупреждения без обязательного AI.
M2b добавит ручное расследование с LLM/SLM и ограниченными проверками. Облако
выключено по умолчанию, host remediation отсутствует. Эти возможности сейчас
описаны в плане и ещё не предоставляются приложением.
